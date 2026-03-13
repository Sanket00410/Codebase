from __future__ import annotations

import re
from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import ScanExecutionContext, ScannerPlugin
from security_platform.core.utils import normalize_path, stable_fingerprint


ACTIONLINT_PATTERN = re.compile(
    r"^(?P<path>.+):(?P<line>\d+):(?P<column>\d+):\s*(?P<message>.+?)(?:\s+\[(?P<rule>[^\]]+)\])?$"
)


class ActionlintPlugin(ScannerPlugin):
    metadata = ToolMetadata(
        name="actionlint",
        display_name="Actionlint",
        category=ScanCategory.CI_CD,
        supported_languages=["yaml"],
        install_strategy="github-release",
        description="GitHub Actions workflow validation with workflow and expression analysis",
    )
    emits_output_file = False
    accepted_exit_codes = {0, 1}

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and bool(self._workflow_files(Path(request.repository_path), context=None, signal_files=signal.ci_files))

    def build_command(
        self,
        binary_path: Path,
        repository_path: Path,
        output_path: Path | None,
        request,
        context: ScanExecutionContext,
    ) -> list[str]:
        workflow_files = self._workflow_files(repository_path, context)
        return [str(binary_path), *[str(path) for path in workflow_files]]

    def parse_results(self, repository_path: Path, execution, output_path: Path | None, context: ScanExecutionContext):
        findings: list[NormalizedFinding] = []
        output = "\n".join(part for part in [execution.stdout, execution.stderr] if part)
        for line in output.splitlines():
            match = ACTIONLINT_PATTERN.match(line.strip())
            if not match:
                continue
            file_path = normalize_path(repository_path, match.group("path"))
            message = match.group("message").strip()
            rule_id = match.group("rule")
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("actionlint", file_path, match.group("line"), match.group("column"), rule_id, message),
                    source_tool="actionlint",
                    category=ScanCategory.CI_CD,
                    severity=_actionlint_severity(rule_id, message),
                    title=_actionlint_title(message),
                    description=message,
                    rule_id=rule_id,
                    confidence=0.82,
                    references=["https://github.com/rhysd/actionlint"],
                    location=FindingLocation(
                        path=file_path,
                        line=int(match.group("line")),
                        column=int(match.group("column")),
                    ),
                    remediation="Fix the workflow step, expression, or job definition reported by actionlint and re-run the pipeline validation.",
                    raw={"message": message, "rule": rule_id, "source": "actionlint"},
                )
            )
        return findings, []

    def _workflow_files(
        self,
        repository_path: Path,
        context: ScanExecutionContext | None = None,
        signal_files: list[str] | None = None,
    ) -> list[Path]:
        files = signal_files
        if files is None and context is not None:
            files = context.repository_signal.ci_files
        if files is None:
            files = []
        workflow_files: list[Path] = []
        for relative_path in files:
            normalized = relative_path.replace("\\", "/")
            if not normalized.startswith(".github/workflows/"):
                continue
            if not normalized.endswith((".yml", ".yaml")):
                continue
            path = (repository_path / relative_path).resolve()
            if path.exists():
                workflow_files.append(path)
        return workflow_files


def _actionlint_title(message: str) -> str:
    head = message.split(".")[0].strip()
    return head or "GitHub Actions workflow issue"


def _actionlint_severity(rule_id: str | None, message: str) -> Severity:
    marker = f"{rule_id or ''} {message}".lower()
    if any(token in marker for token in ("credential", "secret", "token", "shellcheck", "unsafe", "untrusted")):
        return Severity.MEDIUM
    return Severity.LOW
