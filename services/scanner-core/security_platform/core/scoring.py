from __future__ import annotations

from collections import Counter

from security_platform.core.models import NormalizedFinding, ScanSummary, Severity, ToolExecution


SEVERITY_WEIGHTS = {
    Severity.INFO: 0.5,
    Severity.LOW: 2.0,
    Severity.MEDIUM: 6.0,
    Severity.HIGH: 15.0,
    Severity.CRITICAL: 25.0,
}


def summarize_findings(findings: list[NormalizedFinding], tools: list[ToolExecution]) -> ScanSummary:
    severity_counter = Counter(item.severity.value for item in findings)
    category_counter = Counter(item.category.value for item in findings)

    penalty = 0.0
    for finding in findings:
        base = SEVERITY_WEIGHTS[finding.severity]
        confidence_multiplier = 0.75 + finding.confidence
        category_multiplier = 1.4 if finding.category.value == "secrets" else 1.0
        penalty += base * confidence_multiplier * category_multiplier

    # Keep the score responsive without collapsing to zero after a moderate-sized scan.
    score = round(max(0.0, min(100.0, 100.0 / (1.0 + (penalty / 90.0)))), 2)
    return ScanSummary(
        total_findings=len(findings),
        by_severity=dict(severity_counter),
        by_category=dict(category_counter),
        tools_run=[item.tool for item in tools],
        score=score,
    )
