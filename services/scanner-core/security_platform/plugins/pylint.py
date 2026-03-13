from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import exclude_regex_pattern, normalize_path, stable_fingerprint


PYLINT_SECURITY_RULES: dict[str, tuple[Severity, float]] = {
    "bidirectional-unicode": (Severity.HIGH, 0.95),
    "exec-used": (Severity.HIGH, 0.9),
    "eval-used": (Severity.HIGH, 0.92),
    "subprocess-popen-preexec-fn": (Severity.HIGH, 0.86),
    "subprocess-run-check": (Severity.MEDIUM, 0.74),
    "bare-except": (Severity.MEDIUM, 0.72),
    "broad-exception-caught": (Severity.MEDIUM, 0.64),
    "broad-exception-raised": (Severity.LOW, 0.55),
}


class PylintPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="pylint",
        display_name="Pylint",
        category=ScanCategory.SAST,
        supported_languages=["python"],
        install_strategy="pipx",
        description="Python static analysis with a conservative security-focused rule filter",
    )
    accepted_exit_codes = set(range(0, 32))

    def should_run(self, request, signal) -> bool:
        return super().should_run(request, signal) and "python" in signal.languages

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        files = [normalize_path(repository_path, file_path) for file_path in repository_path.rglob("*.py")]
        files = [item for item in files if item and not any(part in item.split("/") for part in request.exclude_paths)]
        command = [str(binary_path), "--output-format=json", "--jobs=0", "--score=n"]
        exclude_pattern = exclude_regex_pattern(request.exclude_paths)
        if exclude_pattern:
            command.append(f"--ignore-paths={exclude_pattern}")
        command.extend(files or [str(repository_path)])
        return command

    def parse_payload(self, repository_path: Path, payload: list, context: ScanExecutionContext) -> tuple[list, list]:
        findings: list[NormalizedFinding] = []
        for result in payload or []:
            symbol = result.get("symbol")
            if symbol not in PYLINT_SECURITY_RULES:
                continue
            severity, confidence = PYLINT_SECURITY_RULES[symbol]
            file_path = normalize_path(repository_path, result.get("path"))
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint("pylint", result.get("message-id"), file_path, str(result.get("line"))),
                    source_tool="pylint",
                    category=ScanCategory.SAST,
                    severity=severity,
                    title=result.get("message") or symbol.replace("-", " "),
                    description=result.get("message") or f"Pylint raised the {symbol} rule.",
                    rule_id=result.get("message-id"),
                    confidence=confidence,
                    references=["https://pylint.pycqa.org/"],
                    location=FindingLocation(
                        path=file_path,
                        line=result.get("line"),
                        column=result.get("column"),
                    ),
                    remediation=_pylint_remediation(symbol),
                    raw=result,
                )
            )
        return findings, []


def _pylint_remediation(symbol: str) -> str | None:
    mapping = {
        "bidirectional-unicode": "Remove Unicode bidi control characters and re-review the surrounding source.",
        "exec-used": "Avoid exec on untrusted or dynamic input; replace it with explicit logic.",
        "eval-used": "Replace eval with ast.literal_eval or a safer explicit parser.",
        "subprocess-popen-preexec-fn": "Avoid preexec_fn in threaded programs; move setup into the child command or a wrapper process.",
        "subprocess-run-check": "Set check=True or handle the return code explicitly after subprocess.run.",
        "bare-except": "Catch specific exception types and avoid swallowing KeyboardInterrupt/SystemExit.",
        "broad-exception-caught": "Catch the narrowest exception class that matches the intended failure mode.",
        "broad-exception-raised": "Raise a more specific exception type so callers can handle failures precisely.",
    }
    return mapping.get(symbol)
