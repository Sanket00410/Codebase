from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, normalize_path, stable_fingerprint


class CargoAuditPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="cargo-audit",
        display_name="cargo-audit",
        category=ScanCategory.SCA,
        supported_languages=["rust"],
        install_strategy="cargo-install",
        description="RustSec-backed Cargo.lock vulnerability and advisory scanning",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and any(Path(item).name == "Cargo.lock" for item in signal.manifests)

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [str(binary_path), "audit", "--json", "--file", str(self._primary_lockfile(repository_path, context))]
        if request.offline:
            command.extend(["--no-fetch", "--stale"])
        return command

    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        lockfile_path = normalize_path(repository_path, self._primary_lockfile(repository_path, context))
        for vulnerability in payload.get("vulnerabilities", {}).get("list", []) or []:
            findings.append(_cargo_audit_finding("cargo-audit", repository_path, lockfile_path, vulnerability, Severity.HIGH))
        for kind, severity in {"unsound": Severity.HIGH, "unmaintained": Severity.MEDIUM, "yanked": Severity.MEDIUM}.items():
            for warning in payload.get("warnings", {}).get(kind, []) or []:
                findings.append(_cargo_audit_finding("cargo-audit", repository_path, lockfile_path, warning, severity, kind))
        return findings, []

    def _primary_lockfile(self, repository_path: Path, context: ScanExecutionContext) -> Path:
        manifest_paths = [repository_path / item for item in context.repository_signal.manifests]
        for path in manifest_paths:
            if path.name == "Cargo.lock" and path.exists():
                return path
        matches = sorted(repository_path.rglob("Cargo.lock"))
        if matches:
            return matches[0]
        raise FileNotFoundError("No Cargo.lock file found for cargo-audit")


def _cargo_audit_finding(
    source_tool: str,
    repository_path: Path,
    lockfile_path: str | None,
    payload: dict,
    severity: Severity,
    kind: str | None = None,
) -> NormalizedFinding:
    advisory = payload.get("advisory", {})
    package = payload.get("package", {})
    aliases = advisory.get("aliases") or []
    fixed_versions = payload.get("versions", {}).get("patched") or []
    title = advisory.get("title") or advisory.get("id") or f"Cargo advisory for {package.get('name')}"
    description = advisory.get("description") or title
    references = [value for value in [advisory.get("url")] if value]
    if kind:
        references.append(f"https://rustsec.org/advisories/{advisory.get('id', '').lower()}.html")
    return NormalizedFinding(
        fingerprint=stable_fingerprint(source_tool, advisory.get("id"), package.get("name"), package.get("version"), kind),
        source_tool=source_tool,
        category=ScanCategory.SCA,
        severity=severity,
        title=title,
        description=description,
        rule_id=advisory.get("id"),
        confidence=0.95,
        cve_ids=collect_cve_ids(advisory.get("id"), aliases),
        references=[item for item in references if item],
        package_name=package.get("name"),
        package_version=package.get("version"),
        fixed_version=", ".join(fixed_versions) or None,
        location=FindingLocation(path=lockfile_path),
        tags=[value for value in [kind, advisory.get("informational")] if value],
        remediation=_cargo_audit_remediation(package.get("name"), fixed_versions, kind),
        raw=payload,
    )


def _cargo_audit_remediation(package_name: str | None, fixed_versions: list[str], kind: str | None) -> str | None:
    if not package_name:
        return None
    if fixed_versions:
        return f"Upgrade {package_name} to one of the patched versions: {', '.join(fixed_versions)}."
    if kind == "unmaintained":
        return f"Replace or remove {package_name}; the crate is no longer maintained."
    if kind == "unsound":
        return f"Upgrade or replace {package_name}; the crate is flagged as unsound."
    return f"Review and upgrade {package_name} to a non-affected release."
