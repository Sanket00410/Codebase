from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import collect_cve_ids, collect_cwe_ids, normalize_path, severity_from_string, stable_fingerprint


class SemgrepPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="semgrep",
        display_name="Semgrep",
        category=ScanCategory.SAST,
        supported_languages=["python", "javascript", "typescript", "java", "go", "csharp", "php", "ruby"],
        install_strategy="pipx",
        description="Multi-language SAST with rule packs and taint analysis",
    )

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [
            str(binary_path),
            "scan",
            "--config",
            "auto",
            "--json",
            "--output",
            str(output_path),
            str(repository_path),
        ]
        for excluded in request.exclude_paths:
            command.extend(["--exclude", excluded])
        return command

    def environment(self, repository_path: Path, request, context: ScanExecutionContext) -> dict[str, str]:
        return {
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }

    def parse_payload(self, repository_path: Path, payload: dict, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for result in payload.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})
            start = result.get("start", {})
            file_path = normalize_path(repository_path, result.get("path"))
            cwe_ids = collect_cwe_ids(metadata.get("cwe"), metadata.get("owasp"))
            cve_ids = collect_cve_ids(metadata.get("references"), extra.get("message"), extra.get("metadata", {}).get("references"))
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("semgrep", result.get("check_id"), file_path, str(start.get("line"))),
                    source_tool="semgrep",
                    category=ScanCategory.SAST,
                    severity=severity_from_string(extra.get("severity"), Severity.MEDIUM),
                    title=metadata.get("shortlink", result.get("check_id", "Semgrep finding")),
                    description=extra.get("message") or metadata.get("message") or "Semgrep identified a security issue",
                    rule_id=result.get("check_id"),
                    confidence=0.7,
                    cve_ids=cve_ids,
                    cwe_ids=cwe_ids,
                    references=[value for value in metadata.get("references", []) if isinstance(value, str)],
                    location=FindingLocation(
                        path=file_path,
                        line=start.get("line"),
                        column=start.get("col"),
                        snippet=extra.get("lines"),
                    ),
                    tags=[value for value in metadata.get("technology", []) if isinstance(value, str)],
                    raw=result,
                )
            )
        return findings, []
