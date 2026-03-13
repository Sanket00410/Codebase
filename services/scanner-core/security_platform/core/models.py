from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanCategory(StrEnum):
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"
    BINARY = "binary"
    SBOM = "sbom"
    GIT_HISTORY = "git_history"
    CI_CD = "ci_cd"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BinaryStatus(BaseModel):
    tool: str
    available: bool
    resolved_path: str | None = None
    version: str | None = None
    install_hint: str | None = None


class RepositorySignal(BaseModel):
    languages: list[str] = Field(default_factory=list)
    manifests: list[str] = Field(default_factory=list)
    ci_files: list[str] = Field(default_factory=list)
    docker_files: list[str] = Field(default_factory=list)
    helm_charts: list[str] = Field(default_factory=list)
    kubernetes_files: list[str] = Field(default_factory=list)
    terraform_files: list[str] = Field(default_factory=list)
    total_files: int = 0
    total_bytes: int = 0


class DependencyNode(BaseModel):
    id: str
    ecosystem: str
    version: str | None = None
    direct: bool = True
    dependencies: list[str] = Field(default_factory=list)


class DependencyGraph(BaseModel):
    nodes: list[DependencyNode] = Field(default_factory=list)
    edges: list[tuple[str, str]] = Field(default_factory=list)


class FindingLocation(BaseModel):
    path: str | None = None
    line: int | None = None
    column: int | None = None
    snippet: str | None = None


class ReportArtifact(BaseModel):
    kind: str
    path: str
    media_type: str


class NormalizedFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid4()))
    fingerprint: str
    source_tool: str
    category: ScanCategory
    severity: Severity
    title: str
    description: str
    rule_id: str | None = None
    confidence: float = 0.5
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    location: FindingLocation | None = None
    tags: list[str] = Field(default_factory=list)
    remediation: str | None = None
    ai_triage: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)


class ToolExecution(BaseModel):
    tool: str
    category: ScanCategory
    command: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    output_files: list[str] = Field(default_factory=list)
    binary_path: str | None = None


class PluginRunResult(BaseModel):
    tool: str
    category: ScanCategory
    findings: list[NormalizedFinding] = Field(default_factory=list)
    artifacts: list[ReportArtifact] = Field(default_factory=list)
    execution: ToolExecution


class ScanSummary(BaseModel):
    total_findings: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_category: dict[str, int] = Field(default_factory=dict)
    tools_run: list[str] = Field(default_factory=list)
    score: float = 100.0


class ScanRequest(BaseModel):
    repository_path: str
    categories: list[ScanCategory] | None = None
    tools: list[str] | None = None
    report_formats: list[str] = Field(default_factory=lambda: ["json", "sarif", "html", "md"])
    exclude_paths: list[str] = Field(
        default_factory=lambda: [
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "dist",
            "build",
            "target",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            ".ruff_cache",
            ".next",
            ".nuxt",
            ".parcel-cache",
            ".turbo",
            "coverage",
        ]
    )
    include_git_history: bool = True
    offline: bool = False
    update_advisories: bool = False
    deep_scan: bool = True


class ScanResult(BaseModel):
    scan_id: str
    status: ScanStatus
    repository_path: str
    started_at: str
    completed_at: str | None = None
    total_tools: int = 0
    completed_tools: int = 0
    progress_percent: float = 0.0
    active_tools: list[str] = Field(default_factory=list)
    repository_signal: RepositorySignal = Field(default_factory=RepositorySignal)
    dependency_graph: DependencyGraph = Field(default_factory=DependencyGraph)
    findings: list[NormalizedFinding] = Field(default_factory=list)
    artifacts: list[ReportArtifact] = Field(default_factory=list)
    tools: list[ToolExecution] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    errors: list[str] = Field(default_factory=list)


class ToolMetadata(BaseModel):
    name: str
    display_name: str
    category: ScanCategory
    supported_languages: list[str] = Field(default_factory=list)
    install_strategy: str | None = None
    description: str | None = None


class PluginDescriptor(BaseModel):
    metadata: ToolMetadata
    enabled: bool = True
    available: bool = False
    binary_status: BinaryStatus | None = None


class AdvisoryRecord(BaseModel):
    advisory_id: str
    source: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    details: str | None = None
    severity: str | None = None
    package_name: str | None = None
    ecosystem: str | None = None
    affected_range: str | None = None
    fixed_versions: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)
