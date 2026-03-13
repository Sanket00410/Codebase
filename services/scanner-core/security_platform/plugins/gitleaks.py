from __future__ import annotations

import re
from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import normalize_path, repository_has_git_history, stable_fingerprint


class GitleaksPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="gitleaks",
        display_name="Gitleaks",
        category=ScanCategory.SECRETS,
        install_strategy="github-release",
        description="Secret discovery across repository content and git history",
    )
    accepted_exit_codes = {0, 1}

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        has_git = repository_has_git_history(repository_path)
        mode = "git" if request.include_git_history and has_git else "dir"
        command = [
            str(binary_path),
            mode,
            "--report-format",
            "json",
            "--report-path",
            str(output_path),
        ]
        config_path = output_path.with_name("gitleaks-config.toml")
        if request.exclude_paths:
            escaped = [f"'{re.escape(item).replace('\\\\', '/')}'" for item in request.exclude_paths]
            config_path.write_text(
                "[allowlist]\npaths = [\n  " + ",\n  ".join(escaped) + "\n]\n",
                encoding="utf-8",
            )
            command.extend(["--config", str(config_path)])
        command.append(str(repository_path))
        return command

    def parse_results(self, repository_path: Path, execution, output_path: Path | None, context: ScanExecutionContext):
        if output_path and output_path.exists():
            return super().parse_results(repository_path, execution, output_path, context)
        if execution.stdout.strip():
            try:
                payload = __import__("json").loads(execution.stdout)
            except Exception:
                payload = []
            return self.parse_payload(repository_path, payload, output_path or Path("."), context)
        return [], []

    def parse_payload(self, repository_path: Path, payload: list, output_path: Path, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for result in payload:
            file_path = normalize_path(repository_path, result.get("File"))
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("gitleaks", result.get("RuleID"), file_path, str(result.get("StartLine"))),
                    source_tool="gitleaks",
                    category=ScanCategory.SECRETS,
                    severity=Severity.HIGH,
                    title=result.get("Description") or result.get("RuleID") or "Secret exposed",
                    description=f"Secret pattern matched by Gitleaks rule {result.get('RuleID', 'unknown')}.",
                    rule_id=result.get("RuleID"),
                    confidence=0.92,
                    references=["https://github.com/gitleaks/gitleaks"],
                    location=FindingLocation(
                        path=file_path,
                        line=result.get("StartLine"),
                        column=result.get("StartColumn"),
                    ),
                    tags=[value for value in [result.get("Entropy"), result.get("Commit")] if value],
                    remediation="Rotate the credential, remove it from source control, and review access logs.",
                    raw=result,
                )
            )
        return findings, []
