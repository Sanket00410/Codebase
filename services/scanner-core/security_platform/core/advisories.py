from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from security_platform.core.binary_manager import BinaryManager
from security_platform.core.config import Settings, settings
from security_platform.core.process import run_command
from security_platform.core.storage import ScanStore


class AdvisoryManager:
    def __init__(self, store: ScanStore, binary_manager: BinaryManager, runtime_settings: Settings = settings) -> None:
        self.store = store
        self.binary_manager = binary_manager
        self.settings = runtime_settings
        self.state_path = self.settings.advisory_dir / "state.json"

    async def update_all(self) -> dict[str, int]:
        github_count = await self.sync_github_advisory_database()
        nvd_count = await self.sync_nvd_modified_feed()
        await self.refresh_tool_databases()
        return {"github_advisories": github_count, "nvd_advisories": nvd_count}

    async def refresh_tool_databases(self) -> None:
        for tool_name, command in {
            "trivy": ["trivy", "db", "--download-db-only"],
            "grype": ["grype", "db", "update"],
        }.items():
            status = await self.binary_manager.get_status(tool_name)
            if not status.available or not status.resolved_path:
                continue
            command[0] = status.resolved_path
            try:
                await run_command(command, self.settings.data_dir, timeout_seconds=1800)
            except Exception:
                continue

    async def sync_github_advisory_database(self) -> int:
        state = self._load_state()
        repo_dir = _github_advisory_repo_dir(self.settings)
        if repo_dir.exists():
            await run_command(["git", "-C", str(repo_dir), "pull", "--ff-only"], self.settings.advisory_dir, timeout_seconds=1200)
        else:
            repo_dir.parent.mkdir(parents=True, exist_ok=True)
            await run_command(
                ["git", "-c", "core.longpaths=true", "clone", "--depth", "1", "https://github.com/github/advisory-database.git", str(repo_dir)],
                self.settings.advisory_dir,
                timeout_seconds=1800,
            )

        current_head = await _git_head(repo_dir, self.settings)
        existing_count = self.store.count_advisories("github")
        previous_head = state.get("github_head")
        if previous_head == current_head:
            return existing_count
        if not previous_head and existing_count:
            state["github_head"] = current_head
            self._write_state(state)
            return existing_count

        if previous_head:
            advisory_files, deleted_advisories = await _list_changed_github_advisory_files(repo_dir, previous_head, current_head, self.settings)
        else:
            advisory_files = _walk_github_advisory_files(repo_dir)
            deleted_advisories = []

        if deleted_advisories:
            self.store.delete_advisories(deleted_advisories)

        count = 0
        batch: list[dict] = []
        for advisory_file in advisory_files:
            payload = _read_json_file(repo_dir / advisory_file)
            advisory_id = payload.get("id")
            affected = payload.get("affected") or []
            package_name = None
            ecosystem = None
            affected_range = None
            fixed_versions: list[str] = []
            if affected:
                package = affected[0].get("package", {})
                package_name = package.get("name")
                ecosystem = package.get("ecosystem")
                ranges = affected[0].get("ranges") or []
                if ranges:
                    affected_range = json.dumps(ranges[0])
                for version in affected[0].get("versions") or []:
                    fixed_versions.append(version)
            references = [item.get("url") for item in payload.get("references", []) if item.get("url")]
            batch.append(
                {
                    "advisory_id": advisory_id,
                    "source": "github",
                    "package_name": package_name,
                    "ecosystem": ecosystem,
                    "severity": payload.get("severity"),
                    "payload": {
                        "advisory_id": advisory_id,
                        "source": "github",
                        "aliases": payload.get("aliases", []),
                        "summary": payload.get("summary"),
                        "details": payload.get("details"),
                        "severity": payload.get("severity"),
                        "package_name": package_name,
                        "ecosystem": ecosystem,
                        "affected_range": affected_range,
                        "fixed_versions": fixed_versions,
                        "references": references,
                        "raw": payload,
                    },
                }
            )
            if len(batch) >= 500:
                self.store.upsert_advisories_batch(batch)
                count += len(batch)
                batch = []
        if batch:
            self.store.upsert_advisories_batch(batch)
            count += len(batch)

        state["github_head"] = current_head
        self._write_state(state)
        return count or self.store.count_advisories("github")

    async def sync_nvd_modified_feed(self) -> int:
        state = self._load_state()
        last_sync = state.get("nvd_last_sync")
        end_time = datetime.now(timezone.utc)
        if last_sync:
            start_time = datetime.fromisoformat(last_sync)
        else:
            start_time = end_time - timedelta(days=7)

        count = 0
        batch: list[dict] = []
        async with httpx.AsyncClient(timeout=120.0) as client:
            start_index = 0
            while True:
                response = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        "lastModStartDate": start_time.isoformat().replace("+00:00", "Z"),
                        "lastModEndDate": end_time.isoformat().replace("+00:00", "Z"),
                        "resultsPerPage": 2000,
                        "startIndex": start_index,
                    },
                )
                response.raise_for_status()
                payload = response.json()
                vulnerabilities = payload.get("vulnerabilities", [])
                for item in vulnerabilities:
                    cve = item.get("cve", {})
                    cve_id = cve.get("id")
                    descriptions = cve.get("descriptions") or []
                    references = [entry.get("url") for entry in cve.get("references") or [] if entry.get("url")]
                    metrics = cve.get("metrics", {})
                    severity = _extract_nvd_severity(metrics)
                    batch.append(
                        {
                            "advisory_id": cve_id,
                            "source": "nvd",
                            "severity": severity,
                            "package_name": None,
                            "ecosystem": None,
                            "payload": {
                                "advisory_id": cve_id,
                                "source": "nvd",
                                "aliases": [cve_id],
                                "summary": descriptions[0].get("value") if descriptions else None,
                                "details": descriptions[0].get("value") if descriptions else None,
                                "severity": severity,
                                "references": references,
                                "raw": item,
                            },
                        }
                    )
                    if len(batch) >= 500:
                        self.store.upsert_advisories_batch(batch)
                        count += len(batch)
                        batch = []
                total = payload.get("totalResults", 0)
                start_index += len(vulnerabilities)
                if start_index >= total or not vulnerabilities:
                    break
        if batch:
            self.store.upsert_advisories_batch(batch)
            count += len(batch)

        state["nvd_last_sync"] = end_time.isoformat()
        self._write_state(state)
        return count

    def _load_state(self) -> dict:
        if not self.state_path.exists():
            return {}
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_state(self, payload: dict) -> None:
        self.state_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _extract_nvd_severity(metrics: dict) -> str | None:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            return values[0].get("cvssData", {}).get("baseSeverity")
    return None


async def _list_github_advisory_files(repo_dir: Path, runtime_settings: Settings) -> list[str]:
    _ = runtime_settings
    return _walk_github_advisory_files(repo_dir)


async def _read_git_tracked_json(repo_dir: Path, relative_path: str, runtime_settings: Settings) -> dict:
    _ = runtime_settings
    return _read_json_file(repo_dir / relative_path)


async def _git_head(repo_dir: Path, runtime_settings: Settings) -> str:
    result = await run_command(
        ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
        runtime_settings.advisory_dir,
        timeout_seconds=120,
    )
    return result.stdout.strip()


async def _list_changed_github_advisory_files(
    repo_dir: Path,
    previous_head: str,
    current_head: str,
    runtime_settings: Settings,
) -> tuple[list[str], list[str]]:
    result = await run_command(
        ["git", "-C", str(repo_dir), "diff", "--name-status", previous_head, current_head, "--", "*.json"],
        runtime_settings.advisory_dir,
        timeout_seconds=1200,
    )
    changed_files: list[str] = []
    deleted_advisories: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        status, relative_path = line.split("\t", 1)
        normalized = relative_path.strip().replace("\\", "/")
        advisory_name = Path(normalized).name
        if not advisory_name.startswith("GHSA-") or not advisory_name.endswith(".json"):
            continue
        if status.startswith("D"):
            deleted_advisories.append(Path(normalized).stem)
            continue
        changed_files.append(normalized)
    return changed_files, deleted_advisories


def _walk_github_advisory_files(repo_dir: Path) -> list[str]:
    files: list[str] = []
    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [directory for directory in dirs if directory != ".git"]
        root_path = Path(root)
        for filename in filenames:
            if not filename.startswith("GHSA-") or not filename.endswith(".json"):
                continue
            files.append((root_path / filename).relative_to(repo_dir).as_posix())
    files.sort()
    return files


def _read_json_file(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _github_advisory_repo_dir(runtime_settings: Settings) -> Path:
    override = os.getenv("SCANNER_PLATFORM_GHAD_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        return Path("C:/cbsgad")
    return runtime_settings.advisory_dir / "ghad"
