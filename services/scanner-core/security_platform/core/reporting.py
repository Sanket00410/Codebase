from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.dom import minidom
from xml.etree import ElementTree as ET

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

from security_platform.core.config import settings
from security_platform.core.models import FindingLocation, NormalizedFinding, ReportArtifact, ReportProfileDefinition, ScanResult


@dataclass(frozen=True, slots=True)
class ReportProfileSpec:
    id: str
    label: str
    description: str
    extension: str
    media_type: str
    renderer: str
    template_name: str | None = None
    supports_rich_evidence: bool = False
    includes_rich_evidence: bool = False


_BASE_REPORT_PROFILES: tuple[ReportProfileSpec, ...] = (
    ReportProfileSpec(
        id="traditional-report",
        label="traditional report",
        description="Classic vulnerability report with a dense findings ledger and compliance-oriented structure.",
        extension="html",
        media_type="text/html",
        renderer="html",
        template_name="traditional-report.html.j2",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="modern-report",
        label="modern report",
        description="Analyst-friendly report with modern layout, triage context, and repository risk framing.",
        extension="html",
        media_type="text/html",
        renderer="html",
        template_name="modern-report.html.j2",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="executive-summary",
        label="executive summary",
        description="Leadership summary focused on score, exposure, affected assets, and top risks.",
        extension="html",
        media_type="text/html",
        renderer="html",
        template_name="executive-summary.html.j2",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="machine-readable-json",
        label="machine-readable JSON",
        description="Structured JSON report for downstream automation, integrations, and archival workflows.",
        extension="json",
        media_type="application/json",
        renderer="json",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="sarif",
        label="SARIF",
        description="SARIF 2.1.0 report for static-analysis aware integrations and developer tooling.",
        extension="sarif",
        media_type="application/sarif+json",
        renderer="sarif",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="markdown",
        label="Markdown",
        description="Portable Markdown report suitable for tickets, pull request discussion, and local review.",
        extension="md",
        media_type="text/markdown",
        renderer="markdown",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="pdf",
        label="PDF",
        description="Printable PDF report for distribution, approvals, and offline review.",
        extension="pdf",
        media_type="application/pdf",
        renderer="pdf",
        supports_rich_evidence=True,
    ),
    ReportProfileSpec(
        id="xml",
        label="XML",
        description="Structured XML report for system interchange and archival consumption.",
        extension="xml",
        media_type="application/xml",
        renderer="xml",
        supports_rich_evidence=True,
    ),
)

_BASE_REPORT_PROFILE_BY_ID = {profile.id: profile for profile in _BASE_REPORT_PROFILES}
_PROFILE_ALIAS_MAP = {
    "traditional report": "traditional-report",
    "modern report": "modern-report",
    "executive summary": "executive-summary",
    "machine-readable json": "machine-readable-json",
    "machine readable json": "machine-readable-json",
    "json": "machine-readable-json",
    "sarif": "sarif",
    "markdown": "markdown",
    "md": "markdown",
    "pdf": "pdf",
    "xml": "xml",
    "html": "modern-report",
}


def list_report_profiles() -> list[ReportProfileDefinition]:
    return [
        ReportProfileDefinition(
            id=profile.id,
            label=profile.label,
            description=profile.description,
            media_type=profile.media_type,
            extension=profile.extension,
            supports_rich_evidence=profile.supports_rich_evidence,
        )
        for profile in _BASE_REPORT_PROFILES
    ]


def default_report_profile_ids() -> list[str]:
    return [profile.id for profile in _BASE_REPORT_PROFILES]


def resolve_report_profile_ids(requested_profiles: list[str] | None, include_plus_variants: bool = False) -> list[str]:
    source = requested_profiles or default_report_profile_ids()
    resolved: list[str] = []
    unknown: list[str] = []

    for value in source:
        normalized = _normalize_profile_id(value)
        if not normalized:
            unknown.append(value)
            continue
        if normalized not in resolved:
            resolved.append(normalized)

    if unknown:
        raise ValueError(f"Unknown report profile(s): {', '.join(sorted(unknown))}")

    if include_plus_variants:
        for profile_id in list(resolved):
            plus_id = f"{profile_id}-plus"
            if plus_id not in resolved:
                resolved.append(plus_id)

    return resolved


def generate_reports(
    scan_result: ScanResult,
    requested_profiles: list[str] | None = None,
    include_plus_variants: bool = False,
) -> list[ReportArtifact]:
    output_dir = settings.reports_dir / scan_result.scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    artifacts: list[ReportArtifact] = []
    for profile_id in resolve_report_profile_ids(requested_profiles, include_plus_variants=include_plus_variants):
        profile = _profile_spec(profile_id)
        document = _build_report_document(scan_result, profile)
        path = output_dir / f"{profile.id}.{profile.extension}"

        if profile.renderer == "html":
            path.write_text(_to_html(document, profile), encoding="utf-8")
        elif profile.renderer == "json":
            path.write_text(json.dumps(document, indent=2), encoding="utf-8")
        elif profile.renderer == "sarif":
            path.write_text(json.dumps(_to_sarif(scan_result, document, profile), indent=2), encoding="utf-8")
        elif profile.renderer == "markdown":
            path.write_text(_to_markdown(document, profile), encoding="utf-8")
        elif profile.renderer == "pdf":
            _to_pdf(document, profile, path)
        elif profile.renderer == "xml":
            path.write_text(_to_xml(document), encoding="utf-8")
        else:
            raise ValueError(f"Unsupported report renderer: {profile.renderer}")

        artifacts.append(
            ReportArtifact(
                kind=f"report-{profile.id}",
                path=str(path),
                media_type=profile.media_type,
                profile_id=profile.id,
                label=profile.label,
                description=profile.description,
            )
        )

    return artifacts


def _normalize_profile_id(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    normalized = normalized.replace("_", "-")
    if normalized in _BASE_REPORT_PROFILE_BY_ID:
        return normalized
    if normalized.endswith("-plus"):
        base_id = normalized[: -len("-plus")]
        if base_id in _BASE_REPORT_PROFILE_BY_ID:
            return normalized
    alias = _PROFILE_ALIAS_MAP.get(normalized)
    if alias:
        return alias
    normalized = normalized.replace(" ", "-")
    if normalized in _BASE_REPORT_PROFILE_BY_ID:
        return normalized
    if normalized.endswith("-plus"):
        base_id = normalized[: -len("-plus")]
        if base_id in _BASE_REPORT_PROFILE_BY_ID:
            return normalized
    alias = _PROFILE_ALIAS_MAP.get(normalized.replace("-", " "))
    return alias


def _profile_spec(profile_id: str) -> ReportProfileSpec:
    if profile_id in _BASE_REPORT_PROFILE_BY_ID:
        return _BASE_REPORT_PROFILE_BY_ID[profile_id]
    if profile_id.endswith("-plus"):
        base_id = profile_id[: -len("-plus")]
        base_profile = _BASE_REPORT_PROFILE_BY_ID.get(base_id)
        if base_profile:
            return replace(
                base_profile,
                id=profile_id,
                label=f"{base_profile.label} plus",
                description=(
                    f"{base_profile.description} Includes raw scanner output, source snippets, file and dependency "
                    "evidence, CVE/CWE/CVSS context, remediation guidance, and AI triage."
                ),
                includes_rich_evidence=True,
            )
    raise ValueError(f"Unknown report profile: {profile_id}")


def _build_report_document(scan_result: ScanResult, profile: ReportProfileSpec) -> dict[str, Any]:
    include_rich_evidence = profile.includes_rich_evidence
    findings = [_serialize_finding(scan_result, finding, include_rich_evidence) for finding in scan_result.findings]
    raw_artifacts = [
        {
            "kind": artifact.kind,
            "label": artifact.label or artifact.kind,
            "path": artifact.path,
            "media_type": artifact.media_type,
        }
        for artifact in scan_result.artifacts
        if artifact.kind.endswith("-raw")
    ]
    critical_findings = [finding for finding in findings if finding["severity"] in {"critical", "high"}]

    return {
        "profile": {
            "id": profile.id,
            "label": profile.label,
            "description": profile.description,
            "renderer": profile.renderer,
            "includes_rich_evidence": include_rich_evidence,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {
            "scan_id": scan_result.scan_id,
            "status": scan_result.status.value,
            "repository_path": scan_result.repository_path,
            "started_at": scan_result.started_at,
            "completed_at": scan_result.completed_at,
            "duration_seconds": _duration_seconds(scan_result),
        },
        "summary": {
            "security_score": scan_result.summary.score,
            "total_findings": scan_result.summary.total_findings,
            "severity_distribution": scan_result.summary.by_severity,
            "category_distribution": scan_result.summary.by_category,
            "tools_run": scan_result.summary.tools_run,
            "languages": scan_result.repository_signal.languages,
            "dependency_count": len(scan_result.dependency_graph.nodes),
            "ci_files": scan_result.repository_signal.ci_files,
            "manifests": scan_result.repository_signal.manifests,
            "raw_artifact_count": len(raw_artifacts),
            "errors": scan_result.errors,
        },
        "executive_summary": {
            "headline": _headline(scan_result),
            "top_risks": _top_risks(findings),
            "critical_and_high": len(critical_findings),
            "repository_shape": {
                "total_files": scan_result.repository_signal.total_files,
                "total_bytes": scan_result.repository_signal.total_bytes,
                "languages": scan_result.repository_signal.languages,
                "ci_files": scan_result.repository_signal.ci_files,
                "docker_files": scan_result.repository_signal.docker_files,
                "terraform_files": scan_result.repository_signal.terraform_files,
                "kubernetes_files": scan_result.repository_signal.kubernetes_files,
                "helm_charts": scan_result.repository_signal.helm_charts,
            },
        },
        "findings": findings,
        "tool_outputs": [
            _serialize_tool_execution(tool, include_rich_evidence) for tool in scan_result.tools
        ],
        "raw_scanner_output": raw_artifacts if include_rich_evidence else [],
        "dependency_graph": {
            "node_count": len(scan_result.dependency_graph.nodes),
            "edge_count": len(scan_result.dependency_graph.edges),
            "nodes": [_dependency_node_record(node) for node in scan_result.dependency_graph.nodes]
            if include_rich_evidence
            else [],
        },
        "artifacts": [
            {
                "kind": artifact.kind,
                "label": artifact.label or artifact.kind,
                "path": artifact.path,
                "media_type": artifact.media_type,
                "profile_id": artifact.profile_id,
            }
            for artifact in scan_result.artifacts
        ],
    }


def _serialize_finding(scan_result: ScanResult, finding: NormalizedFinding, include_rich_evidence: bool) -> dict[str, Any]:
    location = _serialize_location(finding.location)
    record: dict[str, Any] = {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "category": finding.category.value,
        "source_tool": finding.source_tool,
        "rule_id": finding.rule_id,
        "confidence": finding.confidence,
        "references": finding.references,
    }

    if location:
        record["location"] = location
    if finding.package_name:
        record["package"] = {
            "name": finding.package_name,
            "version": finding.package_version,
            "fixed_version": finding.fixed_version,
        }
    if finding.cve_ids:
        record["cve_ids"] = finding.cve_ids
    if finding.cwe_ids:
        record["cwe_ids"] = finding.cwe_ids
    if finding.cvss_score is not None:
        record["cvss_score"] = finding.cvss_score
    if finding.remediation:
        record["remediation"] = finding.remediation
    if finding.ai_triage:
        record["ai_triage"] = finding.ai_triage

    if include_rich_evidence:
        record["rich_evidence"] = {
            "source_snippets": _source_evidence(scan_result, finding),
            "file_line_evidence": location,
            "dependency_package_evidence": _dependency_evidence(scan_result, finding),
            "cve_cwe_cvss": {
                "cve_ids": finding.cve_ids,
                "cwe_ids": finding.cwe_ids,
                "cvss_score": finding.cvss_score,
            },
            "remediation": finding.remediation or finding.ai_triage.get("remediation"),
            "ai_triage": finding.ai_triage,
            "raw_scanner_output": _tool_output_for_finding(scan_result, finding),
        }

    return record


def _serialize_location(location: FindingLocation | None) -> dict[str, Any] | None:
    if not location or not location.path:
        return None
    return {
        "path": location.path,
        "line": location.line,
        "column": location.column,
        "snippet": location.snippet,
    }


def _dependency_evidence(scan_result: ScanResult, finding: NormalizedFinding) -> dict[str, Any] | None:
    if not finding.package_name:
        return None
    target = finding.package_name.lower()
    for node in scan_result.dependency_graph.nodes:
        node_name = _dependency_name(node)
        if node.id.lower() == target or node_name.lower() == target:
            return {
                "id": node.id,
                "name": node_name,
                "ecosystem": node.ecosystem,
                "version": node.version,
                "direct": node.direct,
                "dependencies": node.dependencies,
            }
    return {
        "name": finding.package_name,
        "version": finding.package_version,
        "fixed_version": finding.fixed_version,
    }


def _dependency_name(node) -> str:
    if "@" in node.id:
        return node.id
    if node.version:
        return f"{node.id}@{node.version}"
    return node.id


def _dependency_node_record(node) -> dict[str, Any]:
    return {
        "id": node.id,
        "name": _dependency_name(node),
        "ecosystem": node.ecosystem,
        "version": node.version,
        "direct": node.direct,
        "dependencies": node.dependencies,
    }


def _source_evidence(scan_result: ScanResult, finding: NormalizedFinding) -> dict[str, Any] | None:
    location = finding.location
    if not location or not location.path:
        return None
    if location.snippet:
        line_number = location.line or 1
        return {
            "path": location.path,
            "line": location.line,
            "column": location.column,
            "start_line": line_number,
            "end_line": line_number,
            "snippet": location.snippet,
            "origin": "scanner",
        }

    resolved_path = _resolve_finding_path(scan_result, location.path)
    if not resolved_path.exists() or not resolved_path.is_file():
        return {
            "path": location.path,
            "line": location.line,
            "column": location.column,
            "error": "Source file could not be opened during report generation.",
        }

    try:
        lines = resolved_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        return {
            "path": location.path,
            "line": location.line,
            "column": location.column,
            "error": str(error),
        }

    anchor = max((location.line or 1) - 1, 0)
    start = max(anchor - 3, 0)
    end = min(anchor + 5, len(lines))
    snippet_lines = [f"{index + 1:>5} | {lines[index]}" for index in range(start, end)]
    return {
        "path": str(resolved_path),
        "line": location.line,
        "column": location.column,
        "start_line": start + 1,
        "end_line": end,
        "snippet": "\n".join(snippet_lines),
        "origin": "reporting",
    }


def _resolve_finding_path(scan_result: ScanResult, raw_path: str) -> Path:
    candidate = Path(raw_path)
    if candidate.is_absolute():
        return candidate
    return Path(scan_result.repository_path) / raw_path


def _serialize_tool_execution(tool, include_rich_evidence: bool) -> dict[str, Any]:
    record: dict[str, Any] = {
        "tool": tool.tool,
        "category": tool.category.value if hasattr(tool.category, "value") else str(tool.category),
        "duration_seconds": tool.duration_seconds,
        "exit_code": tool.exit_code,
        "binary_path": tool.binary_path,
        "output_files": tool.output_files,
    }
    if include_rich_evidence:
        record.update(
            {
                "command": tool.command,
                "stdout": tool.stdout,
                "stderr": tool.stderr,
            }
        )
    return record


def _tool_output_for_finding(scan_result: ScanResult, finding: NormalizedFinding) -> dict[str, Any] | None:
    for tool in scan_result.tools:
        if tool.tool != finding.source_tool:
            continue
        return {
            "tool": tool.tool,
            "command": tool.command,
            "exit_code": tool.exit_code,
            "duration_seconds": tool.duration_seconds,
            "stdout_excerpt": _clip_text(tool.stdout, 1800),
            "stderr_excerpt": _clip_text(tool.stderr, 900),
            "output_files": tool.output_files,
            "binary_path": tool.binary_path,
        }
    return None


def _clip_text(value: str | None, limit: int) -> str:
    if not value:
        return ""
    compact = value.strip()
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit].rstrip()}\n... truncated ..."


def _headline(scan_result: ScanResult) -> str:
    high_risk = scan_result.summary.by_severity.get("critical", 0) + scan_result.summary.by_severity.get("high", 0)
    if high_risk:
        return f"{high_risk} critical or high-severity issues require immediate attention."
    if scan_result.summary.total_findings:
        return "The repository has medium and low-severity issues that should be triaged and scheduled."
    return "No findings were reported for the selected scan."


def _top_risks(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        findings,
        key=lambda item: (_severity_rank(item.get("severity")), -(item.get("confidence") or 0.0)),
    )
    return [
        {
            "title": finding["title"],
            "severity": finding["severity"],
            "tool": finding["source_tool"],
            "location": _location_label(finding.get("location")),
            "package": finding.get("package", {}).get("name") if finding.get("package") else None,
        }
        for finding in ordered[:5]
    ]


def _severity_rank(value: str | None) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(value or "", 5)


def _location_label(location: dict[str, Any] | None) -> str:
    if not location or not location.get("path"):
        return "n/a"
    line = location.get("line")
    return f"{location['path']}:{line}" if line else location["path"]


def _duration_seconds(scan_result: ScanResult) -> float | None:
    started_at = _parse_timestamp(scan_result.started_at)
    completed_at = _parse_timestamp(scan_result.completed_at)
    if not started_at or not completed_at or completed_at <= started_at:
        return None
    return round((completed_at - started_at).total_seconds(), 2)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _to_html(document: dict[str, Any], profile: ReportProfileSpec) -> str:
    environment = Environment(
        loader=FileSystemLoader(settings.html_template_path.parent),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = environment.get_template(profile.template_name or "modern-report.html.j2")
    return template.render(report=document)


def _to_markdown(document: dict[str, Any], profile: ReportProfileSpec) -> str:
    summary = document["summary"]
    lines = [
        f"# {profile.label.title()}",
        "",
        f"- Scan ID: `{document['scan']['scan_id']}`",
        f"- Repository: `{document['scan']['repository_path']}`",
        f"- Status: `{document['scan']['status']}`",
        f"- Security score: `{summary['security_score']}`",
        f"- Total findings: `{summary['total_findings']}`",
        "",
        "## Severity Distribution",
    ]
    for severity, count in summary["severity_distribution"].items():
        lines.append(f"- {severity}: {count}")

    lines.extend(["", "## Findings"])
    for finding in document["findings"]:
        lines.extend(
            [
                f"### {finding['title']}",
                f"- Severity: `{finding['severity']}`",
                f"- Category: `{finding['category']}`",
                f"- Tool: `{finding['source_tool']}`",
                f"- File/line evidence: `{_location_label(finding.get('location'))}`",
                f"- Rule: `{finding.get('rule_id') or finding['fingerprint']}`",
                f"- Description: {finding['description']}",
            ]
        )
        if finding.get("package"):
            package = finding["package"]
            lines.append(f"- Dependency/package evidence: `{package['name']}@{package.get('version') or 'unknown'}`")
        if profile.includes_rich_evidence:
            rich = finding.get("rich_evidence", {})
            if rich.get("source_snippets", {}).get("snippet"):
                lines.extend(["- Source snippets:", "```text", rich["source_snippets"]["snippet"], "```"])
            identifiers = rich.get("cve_cwe_cvss") or {}
            if identifiers.get("cve_ids") or identifiers.get("cwe_ids") or identifiers.get("cvss_score") is not None:
                lines.append(
                    "- CVE/CWE/CVSS: "
                    f"CVE={', '.join(identifiers.get('cve_ids') or ['n/a'])}, "
                    f"CWE={', '.join(identifiers.get('cwe_ids') or ['n/a'])}, "
                    f"CVSS={identifiers.get('cvss_score') if identifiers.get('cvss_score') is not None else 'n/a'}"
                )
            if rich.get("remediation"):
                lines.append(f"- Remediation: {rich['remediation']}")
            if rich.get("ai_triage"):
                lines.append(f"- AI triage: `{json.dumps(rich['ai_triage'], ensure_ascii=False)}`")
            raw_output = rich.get("raw_scanner_output") or {}
            if raw_output.get("stdout_excerpt") or raw_output.get("stderr_excerpt"):
                lines.extend(["- Raw scanner output:", "```text", raw_output.get("stdout_excerpt") or raw_output.get("stderr_excerpt") or "", "```"])
        lines.append("")

    if profile.includes_rich_evidence and document["tool_outputs"]:
        lines.extend(["## Raw Scanner Output"])
        for tool in document["tool_outputs"]:
            lines.extend(
                [
                    f"### {tool['tool']}",
                    f"- Exit code: `{tool['exit_code']}`",
                    f"- Duration: `{tool['duration_seconds']}` seconds",
                ]
            )
            if tool.get("command"):
                lines.append(f"- Command: `{ ' '.join(tool['command']) }`")
            if tool.get("stdout"):
                lines.extend(["```text", _clip_text(tool["stdout"], 2200), "```"])
            if tool.get("stderr"):
                lines.extend(["```text", _clip_text(tool["stderr"], 1200), "```"])
            lines.append("")

    return "\n".join(lines)


def _to_pdf(document: dict[str, Any], profile: ReportProfileSpec, path: Path) -> None:
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#173552"),
        fontSize=24,
        leading=28,
    )
    eyebrow_style = ParagraphStyle(
        "Eyebrow",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#6c7a92"),
        fontSize=9,
        leading=11,
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#173552"),
        fontSize=16,
        leading=20,
        spaceAfter=6,
    )
    card_label_style = ParagraphStyle(
        "CardLabel",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#6c7a92"),
        fontSize=8,
        leading=10,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["BodyText"],
        textColor=colors.HexColor("#1b2638"),
        fontSize=9,
        leading=12,
    )
    code_style = ParagraphStyle("CodeBlock", parent=styles["Code"], fontName="Courier", fontSize=7, leading=9)

    summary_table = Table(
        [
            [
                _summary_card("Security score", str(document["summary"]["security_score"]), title_style, card_label_style, body_style),
                _summary_card("Total findings", str(document["summary"]["total_findings"]), title_style, card_label_style, body_style),
            ],
            [
                _summary_card(
                    "Critical + high",
                    str(document["executive_summary"]["critical_and_high"]),
                    title_style,
                    card_label_style,
                    body_style,
                ),
                _summary_card("Tools run", str(len(document["summary"]["tools_run"])), title_style, card_label_style, body_style),
            ],
        ],
        colWidths=[250, 250],
        hAlign="LEFT",
    )
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f6f9fc")),
                ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#d6e0eb")),
                ("INNERGRID", (0, 0), (-1, -1), 0.75, colors.HexColor("#d6e0eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 12),
                ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                ("TOPPADDING", (0, 0), (-1, -1), 12),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
            ]
        )
    )

    story = [
        Paragraph(profile.label.title(), title_style),
        Paragraph("Code Base Scanner reporting system", eyebrow_style),
        Spacer(1, 12),
        Paragraph(document["executive_summary"]["headline"], styles["Heading3"]),
        Spacer(1, 8),
        Paragraph(f"Repository: {document['scan']['repository_path']}", body_style),
        Paragraph(f"Scan ID: {document['scan']['scan_id']}", body_style),
        Paragraph(f"Completed: {document['scan']['completed_at'] or 'n/a'}", body_style),
        Spacer(1, 12),
        summary_table,
        Spacer(1, 16),
        Paragraph("Severity Distribution", section_style),
        Spacer(1, 6),
    ]

    severity_rows = [["Severity", "Count"]]
    for severity, count in document["summary"]["severity_distribution"].items():
        severity_rows.append([severity.title(), str(count)])
    severity_table = Table(severity_rows, colWidths=[220, 120], hAlign="LEFT")
    severity_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173552")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fbff")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#c9d7e5")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d6e0eb")),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    story.append(severity_table)
    story.append(Spacer(1, 10))
    story.append(Paragraph("Findings", section_style))
    story.append(Spacer(1, 6))

    for finding in document["findings"][:150]:
        severity_color = _pdf_severity_color(finding["severity"])
        story.append(
            Paragraph(
                f'<font color="{severity_color}">[{finding["severity"].upper()}]</font> {finding["title"]}',
                styles["Heading3"],
            )
        )
        story.append(Paragraph(finding["description"], body_style))
        story.append(Paragraph(f"Tool: {finding['source_tool']} | Category: {finding['category']}", body_style))
        story.append(Paragraph(f"File/line evidence: {_location_label(finding.get('location'))}", body_style))
        if finding.get("package"):
            package = finding["package"]
            story.append(Paragraph(f"Dependency/package evidence: {package['name']} @ {package.get('version') or 'unknown'}", body_style))
        story.append(
            Paragraph(
                f"CVE: {', '.join(finding.get('cve_ids') or ['none'])} | "
                f"CWE: {', '.join(finding.get('cwe_ids') or ['none'])} | "
                f"CVSS: {finding.get('cvss_score', 'n/a')}",
                body_style,
            )
        )
        if finding.get("remediation"):
            story.append(Paragraph(f"Remediation: {finding['remediation']}", body_style))
        if profile.includes_rich_evidence:
            rich = finding.get("rich_evidence", {})
            if rich.get("source_snippets", {}).get("snippet"):
                story.append(Spacer(1, 4))
                story.append(Preformatted(rich["source_snippets"]["snippet"], code_style))
            if rich.get("ai_triage"):
                story.append(Paragraph(f"AI triage: {json.dumps(rich['ai_triage'], ensure_ascii=False)}", body_style))
            raw_output = rich.get("raw_scanner_output") or {}
            if raw_output.get("stdout_excerpt"):
                story.append(Spacer(1, 4))
                story.append(Paragraph("Raw scanner output", body_style))
                story.append(Preformatted(raw_output["stdout_excerpt"], code_style))
        story.append(Spacer(1, 8))

    if profile.includes_rich_evidence and document["tool_outputs"]:
        story.append(Paragraph("Tool Execution Detail", section_style))
        story.append(Spacer(1, 6))
        for tool in document["tool_outputs"]:
            story.append(Paragraph(tool["tool"], styles["Heading3"]))
            story.append(Paragraph(f"Exit code: {tool['exit_code']} | Duration: {tool['duration_seconds']}s", body_style))
            if tool.get("command"):
                story.append(Paragraph("Command:", body_style))
                story.append(Preformatted(" ".join(tool["command"]), code_style))
            if tool.get("stdout"):
                story.append(Paragraph("Stdout excerpt:", body_style))
                story.append(Preformatted(_clip_text(tool["stdout"], 1800), code_style))
            if tool.get("stderr"):
                story.append(Paragraph("Stderr excerpt:", body_style))
                story.append(Preformatted(_clip_text(tool["stderr"], 1200), code_style))
            story.append(Spacer(1, 8))

    SimpleDocTemplate(str(path), pagesize=A4).build(story)


def _to_xml(document: dict[str, Any]) -> str:
    root = ET.Element("code-base-scanner-report")
    profile = ET.SubElement(root, "profile", id=document["profile"]["id"])
    ET.SubElement(profile, "label").text = _xml_safe_text(document["profile"]["label"])
    ET.SubElement(profile, "description").text = _xml_safe_text(document["profile"]["description"])
    ET.SubElement(profile, "includes-rich-evidence").text = _xml_safe_text(
        str(document["profile"]["includes_rich_evidence"]).lower()
    )

    scan_node = ET.SubElement(root, "scan", id=document["scan"]["scan_id"])
    for key, value in document["scan"].items():
        if key != "scan_id":
            ET.SubElement(scan_node, key.replace("_", "-")).text = _xml_safe_text("" if value is None else str(value))

    summary_node = ET.SubElement(root, "summary")
    ET.SubElement(summary_node, "security-score").text = _xml_safe_text(document["summary"]["security_score"])
    ET.SubElement(summary_node, "total-findings").text = _xml_safe_text(document["summary"]["total_findings"])
    severity_node = ET.SubElement(summary_node, "severity-distribution")
    for severity, count in document["summary"]["severity_distribution"].items():
        item = ET.SubElement(severity_node, "severity", name=severity)
        item.text = _xml_safe_text(count)

    findings_node = ET.SubElement(root, "findings")
    for finding in document["findings"]:
        finding_node = ET.SubElement(findings_node, "finding", id=finding["finding_id"], severity=finding["severity"])
        for key in ("title", "description", "source_tool", "category", "rule_id", "fingerprint"):
            value = finding.get(key)
            if value:
                ET.SubElement(finding_node, key.replace("_", "-")).text = _xml_safe_text(value)
        location = finding.get("location")
        if location:
            location_node = ET.SubElement(finding_node, "file-line-evidence")
            for key, value in location.items():
                if value is not None:
                    ET.SubElement(location_node, key.replace("_", "-")).text = _xml_safe_text(value)
        package = finding.get("package")
        if package:
            package_node = ET.SubElement(finding_node, "dependency-package-evidence")
            for key, value in package.items():
                if value is not None:
                    ET.SubElement(package_node, key.replace("_", "-")).text = _xml_safe_text(value)
        if finding.get("cve_ids"):
            cves_node = ET.SubElement(finding_node, "cve-ids")
            for item in finding["cve_ids"]:
                ET.SubElement(cves_node, "cve").text = _xml_safe_text(item)
        if finding.get("cwe_ids"):
            cwes_node = ET.SubElement(finding_node, "cwe-ids")
            for item in finding["cwe_ids"]:
                ET.SubElement(cwes_node, "cwe").text = _xml_safe_text(item)
        if document["profile"]["includes_rich_evidence"]:
            rich = finding.get("rich_evidence", {})
            rich_node = ET.SubElement(finding_node, "rich-evidence")
            if rich.get("source_snippets"):
                source_node = ET.SubElement(rich_node, "source-snippets")
                for key, value in rich["source_snippets"].items():
                    if value is not None:
                        ET.SubElement(source_node, key.replace("_", "-")).text = _xml_safe_text(value)
            if rich.get("cve_cwe_cvss"):
                identifiers_node = ET.SubElement(rich_node, "cve-cwe-cvss")
                for key, value in rich["cve_cwe_cvss"].items():
                    if isinstance(value, list):
                        bucket = ET.SubElement(identifiers_node, key.replace("_", "-"))
                        for item in value:
                            ET.SubElement(bucket, "value").text = _xml_safe_text(item)
                    elif value is not None:
                        ET.SubElement(identifiers_node, key.replace("_", "-")).text = _xml_safe_text(value)
            if rich.get("remediation"):
                ET.SubElement(rich_node, "remediation").text = _xml_safe_text(rich["remediation"])
            if rich.get("ai_triage"):
                ET.SubElement(rich_node, "ai-triage").text = _xml_safe_text(json.dumps(rich["ai_triage"]))
            if rich.get("raw_scanner_output"):
                ET.SubElement(rich_node, "raw-scanner-output").text = _xml_safe_text(
                    json.dumps(rich["raw_scanner_output"])
                )

    if document["profile"]["includes_rich_evidence"]:
        tool_outputs_node = ET.SubElement(root, "raw-scanner-output")
        for tool in document["tool_outputs"]:
            tool_node = ET.SubElement(tool_outputs_node, "tool", name=tool["tool"])
            for key, value in tool.items():
                if key != "tool":
                    ET.SubElement(tool_node, key.replace("_", "-")).text = _xml_safe_text(
                        json.dumps(value) if isinstance(value, (list, dict)) else value
                    )

    return minidom.parseString(ET.tostring(root, encoding="utf-8")).toprettyxml(indent="  ")


def _xml_safe_text(value: Any) -> str:
    raw = "" if value is None else str(value)
    return "".join(
        character
        for character in raw
        if character in {"\t", "\n", "\r"}
        or 0x20 <= ord(character) <= 0xD7FF
        or 0xE000 <= ord(character) <= 0xFFFD
        or 0x10000 <= ord(character) <= 0x10FFFF
    )


def _summary_card(label: str, value: str, title_style: ParagraphStyle, label_style: ParagraphStyle, body_style: ParagraphStyle):
    metric_value_style = ParagraphStyle(
        "MetricValue",
        parent=title_style,
        fontSize=20,
        leading=22,
        textColor=colors.HexColor("#173552"),
    )
    return [
        Paragraph(label, label_style),
        Paragraph(value, metric_value_style),
        Paragraph("Repository reporting snapshot", body_style),
    ]


def _pdf_severity_color(severity: str) -> str:
    return {
        "critical": "#9f1d1d",
        "high": "#b45309",
        "medium": "#b08900",
        "low": "#25603d",
        "info": "#25603d",
    }.get(severity, "#173552")


def _to_sarif(scan_result: ScanResult, document: dict[str, Any], profile: ReportProfileSpec) -> dict[str, Any]:
    rules: dict[str, Any] = {}
    results: list[dict[str, Any]] = []
    for finding, record in zip(scan_result.findings, document["findings"], strict=False):
        rule_id = finding.rule_id or finding.fingerprint
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.description},
                "properties": {"tags": finding.tags, "cwe": finding.cwe_ids, "cve": finding.cve_ids},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(finding.severity.value),
            "message": {"text": finding.description},
            "properties": {
                "tool": finding.source_tool,
                "confidence": finding.confidence,
                "category": finding.category.value,
            },
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
        }
        if finding.location and finding.location.path:
            region: dict[str, Any] = {"startLine": finding.location.line or 1, "startColumn": finding.location.column or 1}
            if profile.includes_rich_evidence:
                source_snippets = record.get("rich_evidence", {}).get("source_snippets", {})
                if source_snippets.get("snippet"):
                    region["snippet"] = {"text": source_snippets["snippet"]}
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": finding.location.path}, "region": region}}]
        if profile.includes_rich_evidence:
            result["properties"].update(
                {
                    "cve_ids": finding.cve_ids,
                    "cwe_ids": finding.cwe_ids,
                    "cvss_score": finding.cvss_score,
                    "package_name": finding.package_name,
                    "package_version": finding.package_version,
                    "fixed_version": finding.fixed_version,
                    "remediation": finding.remediation,
                    "ai_triage": finding.ai_triage,
                }
            )
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Code Base Scanner", "informationUri": "https://example.invalid/code-base-scanner", "rules": list(rules.values())}},
                "properties": {
                    "profile": document["profile"]["label"],
                    "includes_rich_evidence": profile.includes_rich_evidence,
                    "security_score": document["summary"]["security_score"],
                },
                "results": results,
            }
        ],
    }


def _sarif_level(severity: str) -> str:
    return {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }.get(severity, "warning")
