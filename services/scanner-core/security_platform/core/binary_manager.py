from __future__ import annotations

import os
import platform
import re
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import httpx
import yaml

from security_platform.core.config import Settings, settings
from security_platform.core.models import BinaryStatus
from security_platform.core.process import run_command


class BinaryManager:
    def __init__(self, runtime_settings: Settings = settings) -> None:
        self.settings = runtime_settings
        self.manifests = yaml.safe_load(self.settings.manifest_path.read_text(encoding="utf-8"))

    def _platform_key(self) -> str:
        value = platform.system().lower()
        if value.startswith("win"):
            return "windows"
        if value == "darwin":
            return "darwin"
        return "linux"

    def _arch_key(self) -> str:
        machine = platform.machine().lower()
        if machine in {"amd64", "x86_64", "x64"}:
            return "amd64"
        if machine in {"arm64", "aarch64"}:
            return "arm64"
        return machine

    def _executable_name(self, tool_name: str) -> str:
        manifest = self.manifests[tool_name]
        return manifest["executable"][self._platform_key()]

    def _candidate_executable_names(self, tool_name: str) -> list[str]:
        primary = self._executable_name(tool_name)
        names = [primary]
        if self._platform_key() == "windows":
            base = Path(primary).stem
            names = []
            for candidate in (f"{base}.cmd", f"{base}.bat", primary, base, f"{base}.exe"):
                if candidate not in names:
                    names.append(candidate)
        return names

    def _env_override_name(self, tool_name: str) -> str:
        return f"SCANNER_PLATFORM_BIN_{tool_name.upper().replace('-', '_')}"

    def _bundled_candidates(self, tool_name: str) -> list[Path]:
        tool_root = self.settings.tools_dir / tool_name
        if not tool_root.exists():
            return []
        candidates: list[Path] = []
        for executable in self._candidate_executable_names(tool_name):
            candidates.extend(tool_root.rglob(executable))
        return sorted(candidates, reverse=True)

    def _managed_python_candidates(self, tool_name: str) -> list[Path]:
        env_dir = self.settings.tool_envs_dir / tool_name
        if not env_dir.exists():
            return []
        scripts_dir = env_dir / ("Scripts" if self._platform_key() == "windows" else "bin")
        candidates = [scripts_dir / executable for executable in self._candidate_executable_names(tool_name)]
        existing = [candidate for candidate in candidates if candidate.exists()]
        if self._platform_key() != "windows":
            return existing
        return sorted(existing, key=self._managed_windows_candidate_priority)

    async def get_status(self, tool_name: str) -> BinaryStatus:
        override = os.getenv(self._env_override_name(tool_name))
        if override and Path(override).exists():
            return BinaryStatus(tool=tool_name, available=True, resolved_path=str(Path(override).resolve()), version=await self._read_version(Path(override)))

        managed_candidates = self._managed_python_candidates(tool_name)
        if managed_candidates:
            return BinaryStatus(tool=tool_name, available=True, resolved_path=str(managed_candidates[0].resolve()), version=await self._read_version(managed_candidates[0]))
        local_candidates = self._bundled_candidates(tool_name)
        if local_candidates:
            return BinaryStatus(tool=tool_name, available=True, resolved_path=str(local_candidates[0].resolve()), version=await self._read_version(local_candidates[0]))

        for executable in self._candidate_executable_names(tool_name):
            which_path = shutil.which(executable)
            if which_path:
                return BinaryStatus(tool=tool_name, available=True, resolved_path=str(Path(which_path).resolve()), version=await self._read_version(Path(which_path)))

        strategy = self.manifests[tool_name].get("install", {}).get("strategy")
        if strategy in {"pip", "pipx"}:
            hint = "Tool is not installed. Use Install to provision it in the app-managed Python environment."
        elif strategy == "system":
            primary = self._executable_name(tool_name)
            hint = f"Tool is managed by the host system. Install `{Path(primary).stem}` and relaunch the desktop app."
        else:
            hint = f"Tool is not installed. Use the install endpoint or CLI to install via strategy '{strategy}'."
        return BinaryStatus(
            tool=tool_name,
            available=False,
            install_hint=hint,
        )

    async def get_all_statuses(self) -> list[BinaryStatus]:
        return [await self.get_status(tool_name) for tool_name in sorted(self.manifests)]

    async def install(self, tool_name: str) -> BinaryStatus:
        manifest = self.manifests[tool_name]
        install_spec = manifest.get("install", {})
        strategy = install_spec.get("strategy")
        if strategy == "pipx":
            package = install_spec["package"]
            await self._install_python_tool(tool_name, package)
            return await self.get_status(tool_name)
        if strategy == "pip":
            package = install_spec["package"]
            await self._install_python_tool(tool_name, package)
            return await self.get_status(tool_name)
        if strategy == "github-release":
            await self._install_from_github_release(tool_name, manifest)
            return await self.get_status(tool_name)
        if strategy == "system":
            status = await self.get_status(tool_name)
            if status.available:
                return status
            raise FileNotFoundError(status.install_hint or f"{tool_name} must be installed on the host system")
        if strategy == "go-install":
            module = install_spec["module"]
            await run_command(["go", "install", f"{module}@latest"], self.settings.data_dir, timeout_seconds=1200)
            return await self.get_status(tool_name)
        raise ValueError(f"Unsupported install strategy for {tool_name}: {strategy}")

    async def _install_from_github_release(self, tool_name: str, manifest: dict[str, Any]) -> None:
        install_spec = manifest["install"]
        repo = install_spec["repo"]
        asset_key = f"{self._platform_key()}_{self._arch_key()}"
        asset_pattern = install_spec["asset_patterns"].get(asset_key)
        if not asset_pattern:
            raise ValueError(f"No asset pattern configured for {tool_name} on {asset_key}")

        headers = {"Accept": "application/vnd.github+json"}
        if self.settings.github_token:
            headers["Authorization"] = f"Bearer {self.settings.github_token}"

        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True, headers=headers) as client:
            response = await client.get(f"https://api.github.com/repos/{repo}/releases/latest")
            response.raise_for_status()
            payload = response.json()
            asset = next((item for item in payload.get("assets", []) if re.fullmatch(asset_pattern, item["name"])), None)
            if asset is None:
                raise FileNotFoundError(f"No release asset matched pattern {asset_pattern} for {repo}")

            version = str(payload["tag_name"]).lstrip("v")
            tool_dir = self.settings.tools_dir / tool_name / version
            tool_dir.mkdir(parents=True, exist_ok=True)
            archive_path = self.settings.cache_dir / asset["name"]
            download_response = await client.get(asset["browser_download_url"])
            download_response.raise_for_status()
            archive_path.write_bytes(download_response.content)
            self._extract_archive(archive_path, tool_dir, self._executable_name(tool_name))

    def _extract_archive(self, archive_path: Path, destination: Path, executable_name: str) -> None:
        if archive_path.suffix == ".zip":
            with zipfile.ZipFile(archive_path) as archive:
                for member in archive.infolist():
                    self._validate_archive_target(destination, member.filename)
                archive.extractall(destination)
        elif archive_path.name.endswith(".tar.gz") or archive_path.suffixes[-2:] == [".tar", ".gz"]:
            with tarfile.open(archive_path, mode="r:gz") as archive:
                for member in archive.getmembers():
                    self._validate_archive_target(destination, member.name)
                archive.extractall(destination)
        else:
            executable_path = destination / executable_name
            executable_path.write_bytes(archive_path.read_bytes())
        for path in destination.rglob("*"):
            if path.is_file():
                current_mode = path.stat().st_mode
                path.chmod(current_mode | stat.S_IEXEC)

    def _validate_archive_target(self, destination: Path, member_name: str) -> None:
        target = (destination / member_name).resolve()
        if destination.resolve() not in target.parents and target != destination.resolve():
            raise ValueError(f"Refusing to extract archive member outside destination: {member_name}")

    async def update(self, tool_name: str) -> BinaryStatus:
        return await self.install(tool_name)

    async def _install_python_tool(self, tool_name: str, package: str) -> None:
        env_dir = self.settings.tool_envs_dir / tool_name
        manifest = self.manifests[tool_name]
        module_name = manifest.get("install", {}).get("module")
        python_bin = self.settings.runtime_python
        if not env_dir.exists():
            await run_command([str(python_bin), "-m", "venv", str(env_dir)], self.settings.data_dir, timeout_seconds=600)
        env_python = self._venv_python(env_dir)
        await run_command([str(env_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"], self.settings.data_dir, timeout_seconds=1200)
        await run_command(
            [str(env_python), "-m", "pip", "install", "--upgrade", "--force-reinstall", package],
            self.settings.data_dir,
            timeout_seconds=2400,
        )
        if module_name:
            self._write_python_tool_wrapper(tool_name, env_python, module_name)

    def _venv_python(self, env_dir: Path) -> Path:
        if self._platform_key() == "windows":
            return env_dir / "Scripts" / "python.exe"
        return env_dir / "bin" / "python"

    def _write_python_tool_wrapper(self, tool_name: str, env_python: Path, module_name: str) -> None:
        scripts_dir = self.settings.tool_envs_dir / tool_name / ("Scripts" if self._platform_key() == "windows" else "bin")
        if self._platform_key() == "windows":
            wrapper_path = scripts_dir / f"{Path(self._executable_name(tool_name)).stem}.cmd"
            wrapper = f'@echo off\r\n"{env_python}" -m {module_name} %*\r\n'
            wrapper_path.write_text(wrapper, encoding="utf-8")
        else:
            wrapper_path = scripts_dir / self._executable_name(tool_name)
            wrapper = f'#!/usr/bin/env bash\n"{env_python}" -m {module_name} "$@"\n'
            wrapper_path.write_text(wrapper, encoding="utf-8")
            current_mode = wrapper_path.stat().st_mode
            wrapper_path.chmod(current_mode | stat.S_IEXEC)

    def _managed_windows_candidate_priority(self, candidate: Path) -> tuple[int, str]:
        suffix = candidate.suffix.lower()
        if suffix == ".exe" and self._is_native_windows_executable(candidate):
            return (0, candidate.name.lower())
        if suffix == ".cmd":
            return (1, candidate.name.lower())
        if suffix == ".bat":
            return (2, candidate.name.lower())
        if suffix == ".exe":
            return (3, candidate.name.lower())
        return (4, candidate.name.lower())

    def _is_native_windows_executable(self, candidate: Path) -> bool:
        if candidate.suffix.lower() != ".exe":
            return False
        try:
            with candidate.open("rb") as handle:
                return handle.read(2) == b"MZ"
        except OSError:
            return False

    async def _read_version(self, binary_path: Path) -> str | None:
        version_commands = (
            [str(binary_path), "--version"],
            [str(binary_path), "version"],
            [str(binary_path), "-v"],
        )
        for command in version_commands:
            try:
                result = await run_command(command, binary_path.parent, timeout_seconds=20)
            except Exception:
                continue
            text = (result.stdout or result.stderr).strip()
            if text:
                first_line = text.splitlines()[0].strip()
                return first_line[:160]
        return None
