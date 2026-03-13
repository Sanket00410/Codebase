from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import normalize_path, severity_from_string, stable_fingerprint


class BanditPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="bandit",
        display_name="Bandit",
        category=ScanCategory.SAST,
        supported_languages=["python"],
        install_strategy="pipx",
        description="Python static analysis security scanner",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and "python" in signal.languages

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [
            str(binary_path),
            "-r",
            str(repository_path),
            "-f",
            "json",
            "-o",
            str(output_path),
        ]
        if request.exclude_paths:
            command.extend(["-x", ",".join(str(repository_path / item) for item in request.exclude_paths)])
        return command

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("results", []):
            cwe = result.get("issue_cwe") or {}
            file_path = normalize_path(repository_path, result.get("filename"))
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("bandit", result.get("test_id"), file_path, str(result.get("line_number"))),
                    source_tool="bandit",
                    category=ScanCategory.SAST,
                    severity=severity_from_string(result.get("issue_severity")),
                    title=result.get("test_name") or result.get("test_id") or "Bandit issue",
                    description=result.get("issue_text") or "Bandit identified a security issue",
                    rule_id=result.get("test_id"),
                    confidence={"LOW": 0.35, "MEDIUM": 0.6, "HIGH": 0.85}.get(str(result.get("issue_confidence", "")).upper(), 0.5),
                    cwe_ids=[f"CWE-{cwe['id']}"] if cwe.get("id") else [],
                    references=[value for value in [result.get("more_info"), cwe.get("link")] if value],
                    location=FindingLocation(
                        path=file_path,
                        line=result.get("line_number"),
                        snippet=result.get("code"),
                    ),
                    raw=result,
                )
            )
        return findings, []
