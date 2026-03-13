from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, normalize_path, severity_from_string, stable_fingerprint


class GrypePlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="grype",
        display_name="Grype",
        category=ScanCategory.SCA,
        install_strategy="github-release",
        description="Vulnerability scanning for packages, images, and SBOMs",
    )

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        sbom = context.shared_artifacts.get("sbom-cyclonedx")
        target = f"sbom:{sbom.path}" if sbom else f"dir:{repository_path}"
        return [
            str(binary_path),
            target,
            "-o",
            "json",
        ]

    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for match in payload.get("matches", []):
            vulnerability = match.get("vulnerability", {})
            artifact = match.get("artifact", {})
            package_name = artifact.get("name")
            version = artifact.get("version")
            artifact_locations = artifact.get("locations") or []
            artifact_path = None
            for location in artifact_locations:
                candidate = location.get("path")
                if candidate:
                    artifact_path = normalize_path(repository_path, candidate)
                    break
            related = vulnerability.get("relatedVulnerabilities") or []
            advisories = match.get("relatedVulnerabilities") or []
            references = [item.get("url") for item in vulnerability.get("advisories", []) if isinstance(item, dict) and item.get("url")]
            if not references:
                references = [item.get("url") for item in advisories if isinstance(item, dict) and item.get("url")]
            scores = [value.get("metrics", {}).get("baseScore") for value in vulnerability.get("cvss", []) if isinstance(value, dict)]
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("grype", vulnerability.get("id"), package_name, version),
                    source_tool="grype",
                    category=ScanCategory.SCA,
                    severity=severity_from_string(vulnerability.get("severity")),
                    title=vulnerability.get("description") or vulnerability.get("id") or "Grype vulnerability",
                    description=vulnerability.get("description") or "Package vulnerability detected by Grype",
                    rule_id=vulnerability.get("id"),
                    confidence=0.88,
                    cve_ids=collect_cve_ids(vulnerability.get("id"), [entry.get("id") for entry in related if isinstance(entry, dict)]),
                    cwe_ids=[],
                    cvss_score=max(score for score in scores if score is not None) if any(score is not None for score in scores) else None,
                    references=[value for value in references if value],
                    package_name=package_name,
                    package_version=version,
                    fixed_version=", ".join(match.get("fix", {}).get("versions", []) or []) or None,
                    location=FindingLocation(path=artifact_path),
                    raw=match,
                )
            )
        return findings, []
