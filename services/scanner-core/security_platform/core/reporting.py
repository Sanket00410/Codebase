from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

from security_platform.core.config import settings
from security_platform.core.models import ReportArtifact, ScanResult


def generate_reports(scan_result: ScanResult, formats: list[str]) -> list[ReportArtifact]:
    output_dir = settings.reports_dir / scan_result.scan_id
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[ReportArtifact] = []

    requested = {item.lower() for item in formats}
    if "json" in requested:
        path = output_dir / "report.json"
        path.write_text(scan_result.model_dump_json(indent=2), encoding="utf-8")
        artifacts.append(ReportArtifact(kind="report-json", path=str(path), media_type="application/json"))
    if "sarif" in requested:
        path = output_dir / "report.sarif"
        path.write_text(json.dumps(_to_sarif(scan_result), indent=2), encoding="utf-8")
        artifacts.append(ReportArtifact(kind="report-sarif", path=str(path), media_type="application/sarif+json"))
    if "html" in requested:
        path = output_dir / "report.html"
        path.write_text(_to_html(scan_result), encoding="utf-8")
        artifacts.append(ReportArtifact(kind="report-html", path=str(path), media_type="text/html"))
    if "md" in requested or "markdown" in requested:
        path = output_dir / "report.md"
        path.write_text(_to_markdown(scan_result), encoding="utf-8")
        artifacts.append(ReportArtifact(kind="report-md", path=str(path), media_type="text/markdown"))
    if "pdf" in requested:
        path = output_dir / "report.pdf"
        _to_pdf(scan_result, path)
        artifacts.append(ReportArtifact(kind="report-pdf", path=str(path), media_type="application/pdf"))

    return artifacts


def _to_sarif(scan_result: ScanResult) -> dict:
    rules = {}
    results = []
    for finding in scan_result.findings:
        rule_id = finding.rule_id or finding.fingerprint
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.description},
                "properties": {
                    "tags": finding.tags,
                    "cwe": finding.cwe_ids,
                    "cve": finding.cve_ids,
                },
            },
        )
        result = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": finding.description},
            "properties": {
                "tool": finding.source_tool,
                "confidence": finding.confidence,
                "category": finding.category.value,
            },
        }
        if finding.location and finding.location.path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.location.path},
                        "region": {
                            "startLine": finding.location.line or 1,
                            "startColumn": finding.location.column or 1,
                        },
                    }
                }
            ]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Code Base Scanner",
                        "informationUri": "https://example.invalid/code-base-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def _to_html(scan_result: ScanResult) -> str:
    environment = Environment(
        loader=FileSystemLoader(settings.html_template_path.parent),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = environment.get_template(settings.html_template_path.name)
    return template.render(scan=scan_result)


def _to_markdown(scan_result: ScanResult) -> str:
    lines = [
        f"# Scan Report `{scan_result.scan_id}`",
        "",
        f"- Repository: `{scan_result.repository_path}`",
        f"- Status: `{scan_result.status.value}`",
        f"- Security score: `{scan_result.summary.score}`",
        f"- Total findings: `{scan_result.summary.total_findings}`",
        "",
        "## Severity Distribution",
    ]
    for severity, count in scan_result.summary.by_severity.items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Findings"])
    for finding in scan_result.findings:
        location = f"{finding.location.path}:{finding.location.line}" if finding.location and finding.location.path else "n/a"
        lines.extend(
            [
                f"### {finding.title}",
                f"- Tool: `{finding.source_tool}`",
                f"- Severity: `{finding.severity.value}`",
                f"- Category: `{finding.category.value}`",
                f"- Location: `{location}`",
                f"- Rule: `{finding.rule_id or finding.fingerprint}`",
                f"- Description: {finding.description}",
                "",
            ]
        )
    return "\n".join(lines)


def _to_pdf(scan_result: ScanResult, path: Path) -> None:
    styles = getSampleStyleSheet()
    story = [
        Paragraph(f"Scan Report {scan_result.scan_id}", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Repository: {scan_result.repository_path}", styles["BodyText"]),
        Paragraph(f"Security score: {scan_result.summary.score}", styles["BodyText"]),
        Paragraph(f"Total findings: {scan_result.summary.total_findings}", styles["BodyText"]),
        Spacer(1, 12),
    ]
    for finding in scan_result.findings[:150]:
        location = "n/a"
        if finding.location and finding.location.path:
            location = f"{finding.location.path}:{finding.location.line or 1}"
        story.append(Paragraph(f"[{finding.severity.value.upper()}] {finding.title}", styles["Heading3"]))
        story.append(Paragraph(f"{finding.description}", styles["BodyText"]))
        story.append(Paragraph(f"Location: {location}", styles["BodyText"]))
        story.append(Spacer(1, 8))
    document = SimpleDocTemplate(str(path), pagesize=A4)
    document.build(story)


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")

