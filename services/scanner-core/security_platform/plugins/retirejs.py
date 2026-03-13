from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, collect_cwe_ids, normalize_path, severity_from_string, stable_fingerprint


class RetireJsPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="retirejs",
        display_name="RetireJS",
        category=ScanCategory.SCA,
        supported_languages=["javascript", "typescript"],
        install_strategy="npm",
        description="JavaScript library vulnerability scanning with file and dependency detection",
    )
    accepted_exit_codes = {0}

    def should_run(self, request, signal) -> bool:
        manifests = {Path(path).name for path in signal.manifests}
        has_javascript = any(language in {"javascript", "typescript"} for language in signal.languages)
        return super().should_run(request, signal) and has_javascript and not request.offline and bool(
            manifests & {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
        )

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [
            str(binary_path),
            "--path",
            str(repository_path),
            "--outputformat",
            "json",
            "--outputpath",
            str(output_path),
            "--severity",
            "none",
            "--exitwith",
            "0",
        ]
        if request.deep_scan:
            command.append("--deep")
        if request.exclude_paths:
            command.extend(["--ignore", ",".join(str(repository_path / item) for item in request.exclude_paths)])
        return command

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        seen_fingerprints: set[str] = set()

        for item in payload.get("data") or []:
            file_path = normalize_path(repository_path, item.get("file"))
            for result in item.get("results") or []:
                package_name = result.get("npmname") or result.get("component")
                package_version = result.get("version")
                detection = result.get("detection")
                for vulnerability in result.get("vulnerabilities") or []:
                    identifiers = vulnerability.get("identifiers") or {}
                    title = identifiers.get("summary") or f"{package_name or result.get('component') or 'JavaScript library'} vulnerability"
                    rule_id = (
                        identifiers.get("retid")
                        or identifiers.get("issue")
                        or identifiers.get("githubID")
                        or ",".join(identifiers.get("CVE") or [])
                        or f"retirejs:{package_name or result.get('component') or 'unknown'}"
                    )
                    fixed_version = vulnerability.get("below")
                    affected_range = _affected_range(vulnerability)
                    fingerprint = stable_fingerprint("retirejs", package_name, package_version, str(rule_id), affected_range)
                    if fingerprint in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fingerprint)
                    references = [reference for reference in vulnerability.get("info") or [] if reference]
                    findings.append(
                        NormalizedFinding(
                            fingerprint=fingerprint,
                            source_tool="retirejs",
                            category=ScanCategory.SCA,
                            severity=severity_from_string(vulnerability.get("severity"), Severity.MEDIUM),
                            title=title,
                            description=_description(title, affected_range, detection),
                            rule_id=str(rule_id),
                            confidence=0.91,
                            cve_ids=collect_cve_ids(identifiers.get("CVE"), references, identifiers.get("githubID")),
                            cwe_ids=collect_cwe_ids(vulnerability.get("cwe")),
                            references=references,
                            package_name=package_name or result.get("component"),
                            package_version=package_version,
                            fixed_version=fixed_version,
                            location=FindingLocation(path=file_path),
                            tags=[value for value in [detection, *[license for license in result.get("licenses") or [] if license]] if value],
                            remediation=_retire_remediation(package_name or result.get("component"), fixed_version),
                            raw={"result": result, "vulnerability": vulnerability},
                        )
                    )
        return findings, []


def _affected_range(vulnerability: dict) -> str:
    lower_bound = vulnerability.get("atOrAbove")
    upper_bound = vulnerability.get("below")
    if lower_bound and upper_bound:
        return f">={lower_bound}, <{upper_bound}"
    if upper_bound:
        return f"<{upper_bound}"
    if lower_bound:
        return f">={lower_bound}"
    return "unknown"


def _description(title: str, affected_range: str, detection: str | None) -> str:
    if detection:
        return f"{title}. Affected range: {affected_range}. Detected by RetireJS via {detection} analysis."
    return f"{title}. Affected range: {affected_range}."


def _retire_remediation(package_name: str | None, fixed_version: str | None) -> str | None:
    if not package_name:
        return None
    if fixed_version:
        return f"Upgrade {package_name} to {fixed_version} or later."
    return f"Replace or upgrade {package_name} to a supported non-vulnerable release."
