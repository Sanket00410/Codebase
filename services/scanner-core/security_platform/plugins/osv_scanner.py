from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, normalize_path, severity_from_string, stable_fingerprint


class OsvScannerPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="osv-scanner",
        display_name="OSV-Scanner",
        category=ScanCategory.SCA,
        install_strategy="github-release",
        description="Dependency vulnerability scanning backed by OSV",
    )
    accepted_exit_codes = {0, 1}

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [
            str(binary_path),
            "scan",
            "source",
            "-r",
            str(repository_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ]

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("results", []):
            source_path = normalize_path(repository_path, result.get("source", {}).get("path"))
            for package in result.get("packages", []):
                package_meta = package.get("package", {})
                package_name = package_meta.get("name")
                ecosystem = package_meta.get("ecosystem")
                version = package.get("version") or package_meta.get("version")
                for vulnerability in package.get("vulnerabilities", []) or []:
                    severity = vulnerability.get("database_specific", {}).get("severity")
                    aliases = vulnerability.get("aliases") or []
                    findings.append(
                        NormalizedFinding(
                            fingerprint=stable_fingerprint("osv-scanner", vulnerability.get("id"), package_name, version),
                            source_tool="osv-scanner",
                            category=ScanCategory.SCA,
                            severity=severity_from_string(severity),
                            title=vulnerability.get("summary") or vulnerability.get("id") or "OSV vulnerability",
                            description=vulnerability.get("details") or vulnerability.get("summary") or "Dependency vulnerability detected by OSV-Scanner",
                            rule_id=vulnerability.get("id"),
                            confidence=0.9,
                            cve_ids=collect_cve_ids(vulnerability.get("id"), aliases),
                            cwe_ids=[],
                            references=[item.get("url") for item in vulnerability.get("references", []) if isinstance(item, dict) and item.get("url")],
                            package_name=package_name,
                            package_version=version,
                            fixed_version=", ".join(vulnerability.get("database_specific", {}).get("fixed_versions", []) or []) or None,
                            location=FindingLocation(path=source_path),
                            tags=[ecosystem] if ecosystem else [],
                            raw=vulnerability,
                        )
                    )
        return findings, []

