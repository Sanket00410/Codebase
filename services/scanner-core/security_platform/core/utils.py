from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from security_platform.core.models import NormalizedFinding
from security_platform.core.models import Severity


def stable_fingerprint(*parts: str | None) -> str:
    payload = "|".join(part or "" for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def severity_from_string(value: str | None, default: Severity = Severity.MEDIUM) -> Severity:
    if not value:
        return default
    normalized = value.strip().lower()
    mapping = {
        "note": Severity.INFO,
        "info": Severity.INFO,
        "information": Severity.INFO,
        "low": Severity.LOW,
        "minor": Severity.LOW,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "warning": Severity.MEDIUM,
        "high": Severity.HIGH,
        "major": Severity.HIGH,
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "fatal": Severity.CRITICAL,
    }
    return mapping.get(normalized, default)


def normalize_path(base_path: Path, candidate: str | Path | None) -> str | None:
    if not candidate:
        return None
    path = Path(candidate)
    if not path.is_absolute():
        return str(path.as_posix())
    try:
        return str(path.resolve().relative_to(base_path.resolve()).as_posix())
    except ValueError:
        return str(path.resolve().as_posix())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(data: Any, path: Path) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def collect_cve_ids(*values: str | list[str] | None) -> list[str]:
    matches: list[str] = []
    pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    for value in values:
        if isinstance(value, list):
            source = " ".join(value)
        else:
            source = value or ""
        for match in pattern.findall(source):
            normalized = match.upper()
            if normalized not in matches:
                matches.append(normalized)
    return matches


def collect_cwe_ids(*values: str | list[str] | None) -> list[str]:
    matches: list[str] = []
    pattern = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
    for value in values:
        if isinstance(value, list):
            source = " ".join(value)
        else:
            source = value or ""
        for match in pattern.findall(source):
            normalized = match.upper()
            if normalized not in matches:
                matches.append(normalized)
    return matches


def path_matches_excluded(candidate: str | Path | None, excluded_paths: list[str] | tuple[str, ...]) -> bool:
    if not candidate:
        return False
    candidate_parts = _path_parts(candidate)
    if not candidate_parts:
        return False

    for excluded in excluded_paths:
        excluded_parts = _path_parts(excluded)
        if not excluded_parts or len(excluded_parts) > len(candidate_parts):
            continue
        window = len(excluded_parts)
        for start in range(len(candidate_parts) - window + 1):
            if candidate_parts[start : start + window] == excluded_parts:
                return True
    return False


def filter_findings_by_excluded_paths(
    findings: list[NormalizedFinding],
    excluded_paths: list[str] | tuple[str, ...],
) -> list[NormalizedFinding]:
    filtered: list[NormalizedFinding] = []
    for finding in findings:
        location_path = finding.location.path if finding.location else None
        if path_matches_excluded(location_path, excluded_paths):
            continue
        filtered.append(finding)
    return filtered


def exclude_regex_pattern(excluded_paths: list[str] | tuple[str, ...]) -> str | None:
    patterns: list[str] = []
    for excluded in excluded_paths:
        normalized = str(excluded).replace("\\", "/").strip().strip("/")
        if not normalized:
            continue
        escaped = re.escape(normalized).replace("/", r"[\\/]")
        patterns.append(rf"(^|.*[\\/])({escaped})([\\/].*|$)")
    if not patterns:
        return None
    return "|".join(patterns)


def repository_has_git_history(repository_path: Path) -> bool:
    git_dir = repository_path / ".git"
    head_path = git_dir / "HEAD"
    if not git_dir.exists() or not head_path.exists():
        return False
    try:
        head_value = head_path.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    if not head_value:
        return False
    if head_value.startswith("ref: "):
        ref_path = git_dir / head_value.removeprefix("ref: ").strip()
        return ref_path.exists() and bool(ref_path.read_text(encoding="utf-8").strip())
    return len(head_value) >= 7


def _path_parts(candidate: str | Path) -> list[str]:
    text = str(candidate).replace("\\", "/").strip()
    if not text:
        return []
    text = re.sub(r"^[A-Za-z]:", "", text)
    parts = [part for part in text.split("/") if part not in {"", "."}]
    return parts
