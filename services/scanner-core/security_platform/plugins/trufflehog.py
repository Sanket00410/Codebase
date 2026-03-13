from __future__ import annotations

import json
from pathlib import Path

from security_platform.core.config import settings
from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ScanCategory, Severity, ToolMetadata
from security_platform.core.plugin import ScanExecutionContext, ScannerPlugin
from security_platform.core.utils import normalize_path, repository_has_git_history, stable_fingerprint


class TruffleHogPlugin(ScannerPlugin):
    metadata = ToolMetadata(
        name="trufflehog",
        display_name="TruffleHog",
        category=ScanCategory.GIT_HISTORY,
        install_strategy="github-release",
        description="Verified and historical secret discovery across git history",
    )
    emits_output_file = False
    accepted_exit_codes = {0}

    def should_run(self, request, signal) -> bool:
        repository_path = Path(request.repository_path).expanduser()
        has_git_history = request.include_git_history and repository_has_git_history(repository_path)
        return super().should_run(request, signal) and has_git_history

    def build_command(self, binary_path: Path, repository_path: Path, output_path: Path | None, request, context: ScanExecutionContext) -> list[str]:
        return [
            str(binary_path),
            "git",
            repository_path.resolve().as_uri(),
            "--results=verified,unknown",
            "--json",
        ]

    def parse_results(self, repository_path: Path, execution, output_path: Path | None, context: ScanExecutionContext):
        records: list[dict] = []
        for line in execution.stdout.splitlines():
            text = line.strip()
            if not text or not text.startswith("{"):
                continue
            records.append(json.loads(text))

        findings: list[NormalizedFinding] = []
        for record in records:
            git_data = (((record.get("SourceMetadata") or {}).get("Data") or {}).get("Git") or {})
            file_path = normalize_path(repository_path, git_data.get("file"))
            line_number = git_data.get("line")
            detector = record.get("DetectorName") or "TruffleHog"
            verified = bool(record.get("Verified"))
            tags = ["verified" if verified else "unknown"]
            if record.get("DecoderName"):
                tags.append(str(record["DecoderName"]))
            description = (
                f"TruffleHog found a {'verified' if verified else 'historical'} {detector} secret in git history."
            )
            references = [value for value in [git_data.get("repository")] if value]
            findings.append(
                NormalizedFinding(
                    fingerprint=stable_fingerprint(
                        "trufflehog",
                        detector,
                        file_path,
                        str(line_number),
                        str(record.get("Raw")),
                    ),
                    source_tool="trufflehog",
                    category=ScanCategory.GIT_HISTORY,
                    severity=Severity.HIGH if verified else Severity.MEDIUM,
                    title=f"{detector} secret in git history",
                    description=description,
                    rule_id=detector,
                    confidence=0.96 if verified else 0.78,
                    references=references,
                    location=FindingLocation(
                        path=file_path,
                        line=line_number,
                    ),
                    tags=tags,
                    remediation="Rotate the credential, identify its introduction commit, and rewrite git history if exposure is confirmed.",
                    raw=record,
                )
            )

        artifacts: list[ReportArtifact] = []
        if execution.stdout.strip():
            raw_path = settings.reports_dir / context.scan_id / "trufflehog-raw.jsonl"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(execution.stdout, encoding="utf-8")
            artifacts.append(ReportArtifact(kind="trufflehog-raw", path=str(raw_path), media_type="application/x-ndjson"))
        return findings, artifacts
