from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _default_data_dir() -> Path:
    override = os.getenv("SCANNER_PLATFORM_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".code-base-scanner").resolve()


def _default_reports_dir() -> Path:
    override = os.getenv("SCANNER_PLATFORM_REPORTS_DIR")
    if override:
        return Path(override).expanduser().resolve()
    documents_dir = (Path.home() / "Documents").resolve()
    base_dir = documents_dir if documents_dir.exists() else Path.home().resolve()
    return (base_dir / "Code Base Scanner Reports").resolve()


@dataclass(slots=True)
class Settings:
    app_name: str = "Code Base Scanner"
    host: str = os.getenv("SCANNER_PLATFORM_HOST", "127.0.0.1")
    port: int = int(os.getenv("SCANNER_PLATFORM_PORT", "8686"))
    data_dir: Path = _default_data_dir()
    project_root: Path = _project_root()
    max_concurrent_processes: int = int(os.getenv("SCANNER_PLATFORM_MAX_PROCESSES", "6"))
    process_timeout_seconds: int = int(os.getenv("SCANNER_PLATFORM_PROCESS_TIMEOUT", "3600"))
    github_token: str | None = os.getenv("GITHUB_TOKEN")
    openai_api_key: str | None = os.getenv("OPENAI_API_KEY")
    openai_base_url: str | None = os.getenv("OPENAI_BASE_URL")
    ollama_model: str | None = os.getenv("OLLAMA_MODEL")
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    log_level: str = os.getenv("SCANNER_PLATFORM_LOG_LEVEL", "INFO")
    default_excluded_paths: tuple[str, ...] = (
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".codex-cache",
        ".next",
        ".nuxt",
        ".parcel-cache",
        ".turbo",
        "coverage",
    )

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def tools_dir(self) -> Path:
        return self.data_dir / "tools"

    @property
    def reports_dir(self) -> Path:
        return _default_reports_dir()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "scanner.db"

    @property
    def advisory_dir(self) -> Path:
        return self.data_dir / "advisories"

    @property
    def plugin_dir(self) -> Path:
        override = os.getenv("SCANNER_PLATFORM_PLUGIN_DIR")
        if override:
            return Path(override).expanduser().resolve()
        return (self.data_dir / "plugins").resolve()

    @property
    def manifest_path(self) -> Path:
        override = os.getenv("SCANNER_PLATFORM_TOOL_MANIFEST")
        if override:
            return Path(override).expanduser().resolve()
        return (Path(__file__).resolve().parents[1] / "resources" / "tool_manifests.yaml").resolve()

    @property
    def html_template_path(self) -> Path:
        return (Path(__file__).resolve().parents[1] / "templates" / "report.html.j2").resolve()

    @property
    def tool_envs_dir(self) -> Path:
        return self.data_dir / "tool-envs"

    @property
    def project_venv_python(self) -> Path | None:
        if os.name == "nt":
            candidate = self.project_root / ".venv" / "Scripts" / "python.exe"
        else:
            candidate = self.project_root / ".venv" / "bin" / "python"
        return candidate if candidate.exists() else None

    @property
    def runtime_python(self) -> Path:
        override = os.getenv("SCANNER_PLATFORM_PYTHON")
        if override:
            candidate = _python_candidate(override)
            if candidate:
                return candidate
        if self.project_venv_python:
            return self.project_venv_python
        for candidate in _runtime_python_candidates():
            if candidate:
                return candidate
        raise FileNotFoundError(
            "Unable to locate a usable Python runtime. Install Python 3.12 or set "
            "SCANNER_PLATFORM_PYTHON to a valid python.exe path."
        )

    def ensure_directories(self) -> None:
        for directory in (
            self.data_dir,
            self.cache_dir,
            self.tools_dir,
            self.tool_envs_dir,
            self.reports_dir,
            self.advisory_dir,
            self.plugin_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_directories()


def _runtime_python_candidates() -> list[Path | None]:
    candidates: list[Path | None] = []
    candidates.append(_python_candidate(sys.executable))
    candidates.append(_python_candidate(getattr(sys, "_base_executable", None)))

    if os.name == "nt":
        candidates.extend(
            _python_candidate(path)
            for path in (
                Path.home() / "AppData" / "Local" / "Programs" / "Python" / "Python312" / "python.exe",
                Path.home() / "AppData" / "Local" / "Programs" / "Python" / "Python311" / "python.exe",
                Path.home() / "AppData" / "Local" / "Programs" / "Python" / "Python310" / "python.exe",
            )
        )
        candidates.append(_python_candidate(shutil.which("py")))
        candidates.append(_python_candidate(shutil.which("python")))
    else:
        candidates.append(_python_candidate(shutil.which("python3")))
        candidates.append(_python_candidate(shutil.which("python")))
    return candidates


def _python_candidate(value: str | Path | None) -> Path | None:
    if not value:
        return None
    candidate = Path(value).expanduser()
    name = candidate.name.lower()
    if "windowsapps" in str(candidate).lower() and name == "python.exe":
        return None
    if not candidate.exists():
        return None
    if name.startswith("python") or name in {"py", "py.exe"}:
        return candidate.resolve()
    return None
