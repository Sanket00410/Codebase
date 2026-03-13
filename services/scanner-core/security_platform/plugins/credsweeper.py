from __future__ import annotations

from pathlib import Path

from security_platform.core.config import settings
from security_platform.core.models import FindingLocation, NormalizedFinding, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonFilePlugin, ScanExecutionContext
from security_platform.core.utils import normalize_path, severity_from_string, stable_fingerprint


class CredSweeperPlugin(JsonFilePlugin):
    metadata = ToolMetadata(
        name="credsweeper",
        display_name="CredSweeper",
        category=ScanCategory.SECRETS,
        install_strategy="pipx",
        description="Machine-assisted secret detection with context-aware validation heuristics",
    )
    accepted_exit_codes = {0}

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [
            str(binary_path),
            "--path",
            str(repository_path),
            "--save-json",
            str(output_path),
            "--jobs",
            str(max(1, settings.max_concurrent_processes)),
            "--no-stdout",
            "--skip_ignored",
            "--sort",
        ]

    def parse_payload(self, repository_path: Path, payload: dict | list, output_path: Path, context: ScanExecutionContext) -> tuple[list, list]:
        records = payload if isinstance(payload, list) else payload.get("results") or payload.get("credentials") or payload.get("candidates") or []
        findings: list[NormalizedFinding] = []
        for record in records:
            line_entries = [entry for entry in record.get("line_data_list") or [] if isinstance(entry, dict)]
            primary = line_entries[0] if line_entries else {}
            location_path = normalize_path(repository_path, primary.get("path") or primary.get("filename"))
            line_number = primary.get("line_num") or primary.get("line_number") or primary.get("line")
            rule_name = record.get("rule") or record.get("rule_name") or "CredSweeper secret candidate"
            validation = str(record.get("api_validation_result") or record.get("validation") or "unknown").lower()
            severity = _credsweeper_severity(record, validation)
            confidence = _credsweeper_confidence(record, validation)
            snippet = primary.get("line") or primary.get("line_data") or primary.get("line_text")
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint(
                        "credsweeper",
                        rule_name,
                        location_path,
                        str(line_number),
                        str(primary.get("value_start")),
                        str(primary.get("value_end")),
                    ),
                    source_tool="credsweeper",
                    category=ScanCategory.SECRETS,
                    severity=severity,
                    title=f"{rule_name} secret candidate",
                    description=_credsweeper_description(rule_name, validation, record.get("severity")),
                    rule_id=rule_name,
                    confidence=confidence,
                    location=FindingLocation(
                        path=location_path,
                        line=line_number,
                        snippet=snippet,
                    ),
                    tags=[tag for tag in [validation, record.get("severity"), record.get("filter_type")] if tag],
                    remediation="Validate whether the secret is active, rotate it if valid, and move the value into a managed secret store.",
                    raw=record,
                )
            )
        return findings, []


def _credsweeper_severity(record: dict, validation: str) -> Severity:
    if validation in {"valid", "true", "verified"}:
        return Severity.HIGH
    if validation in {"invalid", "false"}:
        return Severity.LOW
    return severity_from_string(record.get("severity"), Severity.MEDIUM)


def _credsweeper_confidence(record: dict, validation: str) -> float:
    if validation in {"valid", "true", "verified"}:
        return 0.96
    probability = record.get("ml_probability")
    if isinstance(probability, (float, int)):
        return min(max(float(probability), 0.05), 0.99)
    if str(record.get("severity") or "").lower() in {"critical", "high"}:
        return 0.84
    return 0.72


def _credsweeper_description(rule_name: str, validation: str, severity: str | None) -> str:
    if validation not in {"", "unknown"}:
        return f"CredSweeper identified a {rule_name} secret candidate with validation state '{validation}'."
    if severity:
        return f"CredSweeper identified a {rule_name} secret candidate with severity '{severity}'."
    return f"CredSweeper identified a {rule_name} secret candidate in repository content."
