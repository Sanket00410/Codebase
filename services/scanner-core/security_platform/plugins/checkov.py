from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import collect_cwe_ids, normalize_path, severity_from_string, stable_fingerprint


class CheckovPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="checkov",
        display_name="Checkov",
        category=ScanCategory.IAC,
        install_strategy="pipx",
        description="Terraform, Kubernetes, Dockerfile, and cloud configuration scanning",
    )
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        has_iac = bool(signal.kubernetes_files or signal.docker_files or signal.helm_charts or signal.terraform_files)
        return super().should_run(request, signal) and has_iac

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [
            str(binary_path),
            "-d",
            str(repository_path),
            "-o",
            "json",
            "--quiet",
        ]

    def parse_payload(self, repository_path: Path, payload: dict | list, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        documents = payload if isinstance(payload, list) else [payload]
        for document in documents:
            results = document.get("results", {})
            for failed in results.get("failed_checks", []):
                file_path = normalize_path(repository_path, failed.get("file_path"))
                line_range = failed.get("file_line_range") or []
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint("checkov", failed.get("check_id"), file_path, str(line_range[:1])),
                        source_tool="checkov",
                        category=ScanCategory.IAC,
                        severity=severity_from_string(failed.get("severity")),
                        title=failed.get("check_name") or failed.get("check_id") or "IaC policy violation",
                        description=failed.get("guideline") or failed.get("details") or "Infrastructure misconfiguration detected",
                        rule_id=failed.get("check_id"),
                        confidence=0.8,
                        cwe_ids=collect_cwe_ids(failed.get("guideline"), failed.get("details")),
                        references=[value for value in [failed.get("guideline")] if value],
                        location=FindingLocation(
                            path=file_path,
                            line=line_range[0] if line_range else None,
                            snippet="\n".join(block[1] for block in failed.get("code_block", []) if isinstance(block, list) and len(block) > 1),
                        ),
                        raw=failed,
                    )
                )
        return findings, []
