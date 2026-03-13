from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, normalize_path, severity_from_string, stable_fingerprint


class TrivyPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="trivy",
        display_name="Trivy",
        category=ScanCategory.CONTAINER,
        install_strategy="github-release",
        description="Vulnerability, secret, and misconfiguration scanning for filesystems and containers",
    )

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [
            str(binary_path),
            "fs",
            "--scanners",
            "vuln,misconfig,secret",
            "--format",
            "json",
            "--output",
            str(output_path),
            str(repository_path),
        ]
        for excluded in request.exclude_paths:
            command.extend(["--skip-dirs", str(repository_path / excluded)])
        return command

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("Results", []):
            target = normalize_path(repository_path, result.get("Target"))
            for vulnerability in result.get("Vulnerabilities", []) or []:
                cvss = vulnerability.get("CVSS") or {}
                scores = [value.get("V3Score") for value in cvss.values() if isinstance(value, dict) and value.get("V3Score") is not None]
                cve_ids = collect_cve_ids(vulnerability.get("VulnerabilityID"), vulnerability.get("PrimaryURL"), vulnerability.get("References"))
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("trivy", vulnerability.get("VulnerabilityID"), vulnerability.get("PkgName"), vulnerability.get("InstalledVersion")),
                        source_tool="trivy",
                        category=ScanCategory.SCA if result.get("Class") in {"lang-pkgs", "os-pkgs"} else ScanCategory.CONTAINER,
                        severity=severity_from_string(vulnerability.get("Severity")),
                        title=vulnerability.get("Title") or vulnerability.get("VulnerabilityID") or "Trivy vulnerability",
                        description=vulnerability.get("Description") or "Package vulnerability identified by Trivy",
                        rule_id=vulnerability.get("VulnerabilityID"),
                        confidence=0.87,
                        cve_ids=cve_ids,
                        cwe_ids=vulnerability.get("CweIDs") or [],
                        cvss_score=max(scores) if scores else None,
                        references=[value for value in [vulnerability.get("PrimaryURL")] + (vulnerability.get("References") or []) if value],
                        package_name=vulnerability.get("PkgName"),
                        package_version=vulnerability.get("InstalledVersion"),
                        fixed_version=vulnerability.get("FixedVersion"),
                        location=FindingLocation(path=target),
                        raw=vulnerability,
                    )
                )
            for misconfiguration in result.get("Misconfigurations", []) or []:
                cause = misconfiguration.get("CauseMetadata") or {}
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("trivy", misconfiguration.get("ID"), target, str(cause.get("StartLine"))),
                        source_tool="trivy",
                        category=ScanCategory.IAC,
                        severity=severity_from_string(misconfiguration.get("Severity")),
                        title=misconfiguration.get("Title") or misconfiguration.get("ID") or "Misconfiguration",
                        description=misconfiguration.get("Description") or "Trivy identified an infrastructure misconfiguration",
                        rule_id=misconfiguration.get("ID"),
                        confidence=0.82,
                        cwe_ids=[],
                        references=[value for value in [misconfiguration.get("PrimaryURL")] + (misconfiguration.get("References") or []) if value],
                        location=FindingLocation(
                            path=target,
                            line=cause.get("StartLine"),
                            column=cause.get("StartColumn"),
                        ),
                        raw=misconfiguration,
                    )
                )
            for secret in result.get("Secrets", []) or []:
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("trivy", secret.get("RuleID"), target, str(secret.get("StartLine"))),
                        source_tool="trivy",
                        category=ScanCategory.SECRETS,
                        severity=severity_from_string(secret.get("Severity"), Severity.HIGH),
                        title=secret.get("Title") or secret.get("RuleID") or "Secret exposure",
                        description=secret.get("Match") or "Trivy detected a secret in repository content",
                        rule_id=secret.get("RuleID"),
                        confidence=0.88,
                        location=FindingLocation(
                            path=target,
                            line=secret.get("StartLine"),
                            column=secret.get("StartColumn"),
                        ),
                        remediation="Rotate the exposed credential and remove it from the repository history.",
                        raw=secret,
                    )
                )
        return findings, []
