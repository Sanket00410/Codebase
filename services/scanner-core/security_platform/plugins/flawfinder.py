from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import collect_cwe_ids, normalize_path, severity_from_string, stable_fingerprint


class FlawfinderPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="flawfinder",
        display_name="Flawfinder",
        category=ScanCategory.SAST,
        supported_languages=["c", "cpp"],
        install_strategy="pipx",
        description="C and C++ source security analysis with CWE mappings",
    )

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and bool({"c", "cpp"} & set(signal.languages))

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [str(binary_path), "--sarif", "--quiet", "--dataonly", str(repository_path)]

    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        runs = payload.get("runs") or []
        if not runs:
            return findings, []
        for result in runs[0].get("results", []) or []:
            location = (((result.get("locations") or [{}])[0]).get("physicalLocation") or {})
            artifact = location.get("artifactLocation") or {}
            region = location.get("region") or {}
            file_path = normalize_path(repository_path, artifact.get("uri"))
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("flawfinder", result.get("ruleId"), file_path, str(region.get("startLine"))),
                    source_tool="flawfinder",
                    category=ScanCategory.SAST,
                    severity=severity_from_string(result.get("level"), Severity.MEDIUM),
                    title=result.get("message", {}).get("text") or result.get("ruleId") or "Flawfinder hit",
                    description=result.get("message", {}).get("text") or "Flawfinder identified a risky native-code construct.",
                    rule_id=result.get("ruleId"),
                    confidence=0.82,
                    cwe_ids=collect_cwe_ids(result.get("message", {}).get("text")),
                    references=["https://dwheeler.com/flawfinder/"],
                    location=FindingLocation(
                        path=file_path,
                        line=region.get("startLine"),
                        column=region.get("startColumn"),
                    ),
                    raw=result,
                )
            )
        return findings, []
