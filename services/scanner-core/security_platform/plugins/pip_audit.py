from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, normalize_path, stable_fingerprint


class PipAuditPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="pip-audit",
        display_name="pip-audit",
        category=ScanCategory.SCA,
        supported_languages=["python"],
        install_strategy="pipx",
        description="Python dependency vulnerability scanning backed by PyPI and OSV advisories",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        python_manifests = {Path(item).name for item in signal.manifests}
        supported = {"pyproject.toml", "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock"}
        return super().should_run(request, signal) and not request.offline and bool(python_manifests & supported)

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        manifest_path = self._primary_manifest(repository_path, context)
        command = [str(binary_path), "--format", "json", "--output", str(output_path)]
        if manifest_path.name == "requirements.txt":
            command.extend(["--requirement", str(manifest_path)])
        else:
            if manifest_path.name in {"poetry.lock", "Pipfile.lock", "uv.lock"}:
                command.append("--locked")
            command.append(str(manifest_path.parent))
        return command

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        location_path = normalize_path(repository_path, self._primary_manifest(repository_path, context))
        for dependency in payload.get("dependencies", []):
            package_name = dependency.get("name")
            package_version = dependency.get("version")
            for vulnerability in dependency.get("vulns", []) or []:
                aliases = vulnerability.get("aliases") or []
                fix_versions = vulnerability.get("fix_versions") or []
                severity = Severity.HIGH if collect_cve_ids(vulnerability.get("id"), aliases) else Severity.MEDIUM
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("pip-audit", vulnerability.get("id"), package_name, package_version),
                        source_tool="pip-audit",
                        category=ScanCategory.SCA,
                        severity=severity,
                        title=vulnerability.get("description") or vulnerability.get("id") or f"Vulnerability in {package_name}",
                        description=vulnerability.get("description") or f"pip-audit found a vulnerable Python dependency: {package_name}.",
                        rule_id=vulnerability.get("id"),
                        confidence=0.94,
                        cve_ids=collect_cve_ids(vulnerability.get("id"), aliases),
                        references=[],
                        package_name=package_name,
                        package_version=package_version,
                        fixed_version=", ".join(fix_versions) or None,
                        location=FindingLocation(path=location_path),
                        remediation=_pip_audit_remediation(package_name, fix_versions),
                        raw=vulnerability,
                    )
                )
        return findings, []

    def _primary_manifest(self, repository_path: Path, context: ScanExecutionContext) -> Path:
        preferred = ("requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "uv.lock")
        manifest_paths = [repository_path / item for item in context.repository_signal.manifests]
        for name in preferred:
            for path in manifest_paths:
                if path.name == name and path.exists():
                    return path
        for name in preferred:
            matches = sorted(repository_path.rglob(name))
            if matches:
                return matches[0]
        raise FileNotFoundError("No Python project manifest found for pip-audit")


def _pip_audit_remediation(package_name: str | None, fix_versions: list[str]) -> str | None:
    if not package_name:
        return None
    if fix_versions:
        return f"Upgrade {package_name} to one of the fixed versions: {', '.join(fix_versions)}."
    return f"Review and upgrade {package_name} to a non-vulnerable release."
