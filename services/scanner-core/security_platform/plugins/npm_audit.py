from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, collect_cwe_ids, severity_from_string, stable_fingerprint


class NpmAuditPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="npm-audit",
        display_name="npm audit",
        category=ScanCategory.SCA,
        supported_languages=["javascript", "typescript"],
        install_strategy="system",
        description="Registry-backed vulnerability scanning for Node.js dependencies",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        has_npm = any(Path(path).name in {"package.json", "package-lock.json"} for path in signal.manifests)
        return super().should_run(request, signal) and has_npm and not request.offline

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [
            str(binary_path),
            "audit",
            "--json",
            "--package-lock-only",
        ]

    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        vulnerabilities = payload.get("vulnerabilities") or {}
        for package_name, advisory in vulnerabilities.items():
            via_entries = advisory.get("via") or []
            advisory_objects = [entry for entry in via_entries if isinstance(entry, dict)]
            if advisory_objects:
                for entry in advisory_objects:
                    findings.append(_npm_finding(repository_path, package_name, advisory, entry))
                continue
            findings.append(_npm_finding(repository_path, package_name, advisory, None))
        return findings, []


def _npm_finding(
    repository_path: Path,
    package_name: str,
    advisory: dict,
    entry: dict | None,
) -> NormalizedFinding:
    url = entry.get("url") if entry else None
    title = (entry.get("title") if entry else None) or f"{package_name} vulnerability"
    severity = severity_from_string((entry.get("severity") if entry else None) or advisory.get("severity"), Severity.MEDIUM)
    cwe_ids = collect_cwe_ids(entry.get("cwe") if entry else None)
    cve_ids = collect_cve_ids(url, title, entry.get("name") if entry else None)
    cvss_score = None
    if entry and isinstance(entry.get("cvss"), dict):
        score = entry["cvss"].get("score")
        if isinstance(score, (float, int)):
            cvss_score = float(score)
    fixed_version = _fixed_version(advisory.get("fixAvailable"))
    location = None
    if advisory.get("nodes"):
        location = FindingLocation(path=str(advisory["nodes"][0]).replace("\\", "/"))
    tags = ["direct"] if advisory.get("isDirect") else []
    tags.extend(str(effect) for effect in advisory.get("effects") or [] if effect)
    description = title
    if advisory.get("range"):
        description = f"{title}. Affected range: {advisory['range']}."
    remediation = "Run `npm audit fix` and upgrade the affected package."
    if fixed_version:
        remediation = f"Upgrade {package_name} to {fixed_version} or later."
    return NormalizedFinding(
        fingerprint=stable_fingerprint("npm-audit", package_name, title, advisory.get("range")),
        source_tool="npm-audit",
        category=ScanCategory.SCA,
        severity=severity,
        title=title,
        description=description,
        rule_id=str(entry.get("source")) if entry and entry.get("source") is not None else f"npm-audit:{package_name}",
        confidence=0.9,
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        references=[item for item in [url] if item],
        package_name=package_name,
        fixed_version=fixed_version,
        location=location,
        tags=tags,
        remediation=remediation,
        raw={"package": package_name, "advisory": advisory, "entry": entry},
    )


def _fixed_version(value) -> str | None:
    if isinstance(value, dict):
        version = value.get("version")
        return str(version) if version else None
    if isinstance(value, str):
        return value
    return None
