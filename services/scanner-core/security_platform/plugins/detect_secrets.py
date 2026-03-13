from __future__ import annotations

from pathlib import Path

from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import JsonStdoutPlugin, ScanExecutionContext
from security_platform.core.utils import exclude_regex_pattern, normalize_path, stable_fingerprint


class DetectSecretsPlugin(JsonStdoutPlugin):
    metadata = ToolMetadata(
        name="detect-secrets",
        display_name="detect-secrets",
        category=ScanCategory.SECRETS,
        install_strategy="pipx",
        description="File-level secret scanning with detector plugins and entropy analysis",
    )

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        command = [str(binary_path), "scan", "--all-files", "--disable-plugin", "KeywordDetector"]
        if request.offline:
            command.append("-n")
        exclude_pattern = exclude_regex_pattern(request.exclude_paths)
        if exclude_pattern:
            command.extend(["--exclude-files", exclude_pattern])
        command.append(str(repository_path))
        return command

    def parse_payload(self, repository_path: Path, payload: dict, context: ScanExecutionContext) -> tuple[list, list[ReportArtifact]]:
        findings: list[NormalizedFinding] = []
        for file_name, entries in (payload.get("results") or {}).items():
            file_path = normalize_path(repository_path, file_name)
            for entry in entries or []:
                detector = entry.get("type") or "Potential secret"
                line_number = entry.get("line_number")
                findings.append(
                    NormalizedFinding(
                        fingerprint=stable_fingerprint(
                            "detect-secrets",
                            detector,
                            file_path,
                            str(line_number),
                            entry.get("hashed_secret"),
                        ),
                        source_tool="detect-secrets",
                        category=ScanCategory.SECRETS,
                        severity=_detect_secrets_severity(detector),
                        title=detector,
                        description=f"detect-secrets flagged a potential secret with detector {detector}.",
                        rule_id=detector,
                        confidence=0.72,
                        references=["https://github.com/Yelp/detect-secrets"],
                        location=FindingLocation(
                            path=file_path,
                            line=line_number,
                        ),
                        remediation="Review whether the value is a real credential, rotate it if valid, and remove it from source control.",
                        raw=entry,
                    )
                )
        return findings, []


def _detect_secrets_severity(detector: str) -> Severity:
    normalized = detector.lower()
    if any(token in normalized for token in ("private key", "token", "aws", "github", "gitlab", "jwt", "twilio", "sendgrid")):
        return Severity.HIGH
    if any(token in normalized for token in ("key", "auth", "secret")):
        return Severity.MEDIUM
    return Severity.LOW
