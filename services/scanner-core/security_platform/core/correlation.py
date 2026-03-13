from __future__ import annotations

from collections import defaultdict

from security_platform.core.models import NormalizedFinding, Severity
from security_platform.core.storage import ScanStore
from security_platform.core.utils import stable_fingerprint


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def correlate_findings(findings: list[NormalizedFinding], store: ScanStore) -> list[NormalizedFinding]:
    buckets: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for finding in findings:
        bucket_key = finding.fingerprint
        if finding.package_name and finding.rule_id:
            bucket_key = stable_fingerprint(finding.category.value, finding.package_name, finding.package_version, finding.rule_id)
        buckets[bucket_key].append(finding)

    correlated: list[NormalizedFinding] = []
    for bucket in buckets.values():
        primary = bucket[0].model_copy(deep=True)
        if len(bucket) > 1:
            primary.confidence = min(0.99, max(item.confidence for item in bucket) + (0.05 * (len(bucket) - 1)))
            primary.tags = sorted(set(primary.tags + [f"correlated:{len(bucket)}", *[f"tool:{item.source_tool}" for item in bucket]]))
            primary.references = sorted(set(ref for item in bucket for ref in item.references))
            primary.cve_ids = sorted(set(cve for item in bucket for cve in item.cve_ids))
            primary.cwe_ids = sorted(set(cwe for item in bucket for cwe in item.cwe_ids))
            primary.cvss_score = max((item.cvss_score or 0) for item in bucket) or primary.cvss_score
            primary.severity = max(bucket, key=lambda item: SEVERITY_RANK[item.severity]).severity
            primary.raw["correlated_tools"] = [item.source_tool for item in bucket]

        if primary.package_name:
            advisories = store.find_advisories(primary.package_name, ecosystem=primary.tags[0] if primary.tags else None)
            for advisory in advisories[:10]:
                aliases = advisory.get("aliases") or []
                for alias in aliases:
                    if alias.startswith("CVE-") and alias not in primary.cve_ids:
                        primary.cve_ids.append(alias)
                for reference in advisory.get("references") or []:
                    if reference not in primary.references:
                        primary.references.append(reference)
                if not primary.remediation and advisory.get("summary"):
                    primary.remediation = advisory["summary"]

        correlated.append(primary)

    return sorted(correlated, key=lambda item: (SEVERITY_RANK[item.severity], item.confidence), reverse=True)

