import { useDeferredValue, useEffect, useMemo, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { invoke } from "@tauri-apps/api/core";

import {
  createScan,
  getPlugins,
  getScan,
  health,
  installTool,
  listResults,
  updateAdvisories,
  type Finding,
  type PluginDescriptor,
  type ScanResult,
} from "./lib/api";

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;
const severityRank = new Map(severityOrder.map((severity, index) => [severity, index]));
const toolFilters = ["all", "missing", "installed"] as const;
const views = ["overview", "findings", "runtime", "artifacts"] as const;

type ViewId = (typeof views)[number];
type ToolFilter = (typeof toolFilters)[number];

const viewMeta: Record<ViewId, { label: string; eyebrow: string; description: string }> = {
  overview: {
    label: "Overview",
    eyebrow: "Operations",
    description: "Repository posture, live scan execution, dependency intelligence, and security pressure at a glance.",
  },
  findings: {
    label: "Findings",
    eyebrow: "Investigation",
    description: "Browse, filter, and inspect normalized findings with remediation, references, and AI triage context.",
  },
  runtime: {
    label: "Runtime",
    eyebrow: "Toolchain",
    description: "Inspect scanner availability, install missing engines, and verify the local execution environment.",
  },
  artifacts: {
    label: "Artifacts",
    eyebrow: "Reports",
    description: "Open generated reports, raw scanner outputs, dependency signals, and execution telemetry.",
  },
};

function formatTimestamp(value?: string | null): string {
  if (!value) {
    return "n/a";
  }
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) {
    return "n/a";
  }
  if (seconds >= 60) {
    const minutes = Math.floor(seconds / 60);
    const remainder = seconds % 60;
    return `${minutes}m ${remainder.toFixed(1)}s`;
  }
  return `${seconds.toFixed(1)}s`;
}

function compactPath(value: string): string {
  return value.split(/[\\/]/).filter(Boolean).pop() || value;
}

function summarizePath(value: string): string {
  if (value.length <= 52) {
    return value;
  }
  return `${value.slice(0, 22)}...${value.slice(-24)}`;
}

function resolveLocationPath(scan: ScanResult | null, finding: Finding | null): string | null {
  const locationPath = finding?.location?.path;
  if (!scan || !locationPath) {
    return null;
  }
  if (/^[a-zA-Z]:[\\/]/.test(locationPath) || locationPath.startsWith("/") || locationPath.startsWith("\\\\")) {
    return locationPath;
  }
  const separator = scan.repository_path.includes("\\") ? "\\" : "/";
  const normalizedBase = scan.repository_path.replace(/[\\/]+$/, "");
  const normalizedLocation = locationPath.replace(/[\\/]+/g, separator);
  return `${normalizedBase}${separator}${normalizedLocation}`;
}

export default function App() {
  const [activeView, setActiveView] = useState<ViewId>("overview");
  const [backendReady, setBackendReady] = useState(false);
  const [repositoryPath, setRepositoryPath] = useState("");
  const [plugins, setPlugins] = useState<PluginDescriptor[]>([]);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [toolFilter, setToolFilter] = useState<ToolFilter>("all");
  const [findingQuery, setFindingQuery] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [offlineMode, setOfflineMode] = useState(false);
  const [refreshAdvisoriesOnScan, setRefreshAdvisoriesOnScan] = useState(false);
  const [maintenanceMessage, setMaintenanceMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const bootstrap = async () => {
      try {
        await invoke("start_backend");
        for (let attempt = 0; attempt < 30; attempt += 1) {
          if (await health()) {
            if (!mounted) {
              return;
            }
            setBackendReady(true);
            void refreshState().catch((cause) => {
              if (!mounted) {
                return;
              }
              setError(cause instanceof Error ? cause.message : String(cause));
            });
            return;
          }
          await new Promise((resolve) => window.setTimeout(resolve, 1000));
        }
        throw new Error("Backend failed to start within 30 seconds");
      } catch (cause) {
        if (!mounted) {
          return;
        }
        setError(cause instanceof Error ? cause.message : String(cause));
      }
    };
    void bootstrap();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!scan || scan.status === "completed" || scan.status === "failed") {
      return;
    }
    const timer = window.setInterval(async () => {
      try {
        const [updatedScan, updatedHistory] = await Promise.all([getScan(scan.scan_id), listResults()]);
        setScan(updatedScan);
        setRecentScans(updatedHistory);
      } catch {
        // Keep rendering the last known state if the backend is briefly unavailable.
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [scan]);

  const refreshState = async () => {
    const [pluginData, resultData] = await Promise.all([getPlugins(), listResults()]);
    setPlugins(pluginData);
    setRecentScans(resultData);
    if (scan) {
      const matching = resultData.find((item) => item.scan_id === scan.scan_id);
      if (matching) {
        setScan(matching);
      }
    } else if (resultData[0]) {
      setScan(resultData[0]);
      setRepositoryPath(resultData[0].repository_path);
    }
  };

  const selectRepository = async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Select repository to scan",
    });
    if (typeof selected === "string") {
      setRepositoryPath(selected);
    }
  };

  const runScan = async () => {
    if (!repositoryPath) {
      setError("Select a repository before starting a scan.");
      return;
    }
    setLoading(true);
    setError(null);
    setMaintenanceMessage(null);
    try {
      const queued = await createScan(repositoryPath, {
        offline: offlineMode,
        updateAdvisories: refreshAdvisoriesOnScan,
      });
      setScan(queued);
      setActiveView("overview");
      setSeverityFilter("all");
      setFindingQuery("");
      await refreshState();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  };

  const installMissingTool = async (toolName: string) => {
    setLoading(true);
    setError(null);
    setMaintenanceMessage(null);
    try {
      await installTool(toolName);
      setMaintenanceMessage(`${toolName} installed successfully.`);
      await refreshState();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  };

  const installAllMissingTools = async () => {
    const installable = plugins.filter((plugin) => !plugin.available && plugin.metadata.install_strategy !== "system");
    if (!installable.length) {
      setMaintenanceMessage("No installable missing tools remain.");
      return;
    }
    setLoading(true);
    setError(null);
    setMaintenanceMessage(null);
    const failures: string[] = [];
    try {
      for (const plugin of installable) {
        try {
          await installTool(plugin.metadata.name);
        } catch (cause) {
          failures.push(`${plugin.metadata.display_name}: ${cause instanceof Error ? cause.message : String(cause)}`);
        }
      }
      if (failures.length) {
        setError(failures.join("\n"));
      } else {
        setMaintenanceMessage(`Installed ${installable.length} missing tools.`);
      }
      await refreshState();
    } finally {
      setLoading(false);
    }
  };

  const syncAdvisories = async () => {
    setLoading(true);
    setError(null);
    setMaintenanceMessage(null);
    try {
      const summary = await updateAdvisories();
      setMaintenanceMessage(
        `Advisories refreshed: ${summary.github_advisories} GitHub records, ${summary.nvd_advisories} NVD records.`,
      );
      await refreshState();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setLoading(false);
    }
  };

  const openArtifact = async (path: string) => {
    try {
      await invoke("open_path", { path });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  };

  const missingTools = useMemo(() => plugins.filter((plugin) => !plugin.available), [plugins]);
  const installedTools = useMemo(() => plugins.filter((plugin) => plugin.available), [plugins]);
  const runtimeCategories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const plugin of plugins) {
      counts.set(plugin.metadata.category, (counts.get(plugin.metadata.category) || 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [plugins]);
  const filteredPlugins = useMemo(() => {
    if (toolFilter === "missing") {
      return missingTools;
    }
    if (toolFilter === "installed") {
      return installedTools;
    }
    return plugins;
  }, [installedTools, missingTools, plugins, toolFilter]);

  const deferredFindingQuery = useDeferredValue(findingQuery);
  const filteredFindings = useMemo(() => {
    if (!scan) {
      return [];
    }
    const needle = deferredFindingQuery.trim().toLowerCase();
    return [...scan.findings]
      .filter((finding) => {
        if (severityFilter !== "all" && finding.severity !== severityFilter) {
          return false;
        }
        if (!needle) {
          return true;
        }
        const corpus = [
          finding.title,
          finding.description,
          finding.source_tool,
          finding.category,
          finding.rule_id,
          finding.package_name,
          finding.location?.path,
          ...(finding.cve_ids || []),
          ...(finding.cwe_ids || []),
        ]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return corpus.includes(needle);
      })
      .sort((left, right) => {
        const leftRank = severityRank.get(left.severity) ?? severityOrder.length;
        const rightRank = severityRank.get(right.severity) ?? severityOrder.length;
        if (leftRank !== rightRank) {
          return leftRank - rightRank;
        }
        return right.confidence - left.confidence;
      });
  }, [deferredFindingQuery, scan, severityFilter]);

  useEffect(() => {
    if (!filteredFindings.length) {
      setSelectedFindingId(null);
      return;
    }
    if (!selectedFindingId || !filteredFindings.some((finding) => finding.finding_id === selectedFindingId)) {
      setSelectedFindingId(filteredFindings[0].finding_id);
    }
  }, [filteredFindings, selectedFindingId]);

  const selectedFinding = useMemo(
    () => filteredFindings.find((finding) => finding.finding_id === selectedFindingId) || filteredFindings[0] || null,
    [filteredFindings, selectedFindingId],
  );
  const selectedFindingPath = useMemo(() => resolveLocationPath(scan, selectedFinding), [scan, selectedFinding]);
  const ecosystemBreakdown = useMemo(() => {
    if (!scan) {
      return [];
    }
    const counts = new Map<string, number>();
    for (const node of scan.dependency_graph.nodes) {
      counts.set(node.ecosystem, (counts.get(node.ecosystem) || 0) + 1);
    }
    return [...counts.entries()].sort((left, right) => right[1] - left[1]);
  }, [scan]);
  const categoryBreakdown = useMemo(() => {
    if (!scan) {
      return [];
    }
    return Object.entries(scan.summary.by_category).sort((left, right) => right[1] - left[1]);
  }, [scan]);
  const primaryArtifacts = useMemo(
    () => (scan ? scan.artifacts.filter((artifact) => !artifact.kind.endsWith("-raw")) : []),
    [scan],
  );
  const rawArtifacts = useMemo(
    () => (scan ? scan.artifacts.filter((artifact) => artifact.kind.endsWith("-raw")) : []),
    [scan],
  );
  const repositorySignals = useMemo(() => {
    if (!scan) {
      return [];
    }
    return [
      { label: "Languages", value: scan.repository_signal.languages.length, detail: scan.repository_signal.languages.join(", ") || "n/a" },
      { label: "Manifests", value: scan.repository_signal.manifests.length, detail: scan.repository_signal.manifests.join(", ") || "n/a" },
      { label: "CI files", value: scan.repository_signal.ci_files.length, detail: scan.repository_signal.ci_files.join(", ") || "n/a" },
      { label: "Containers", value: scan.repository_signal.docker_files.length, detail: scan.repository_signal.docker_files.join(", ") || "n/a" },
      { label: "Terraform", value: scan.repository_signal.terraform_files.length, detail: scan.repository_signal.terraform_files.join(", ") || "n/a" },
      {
        label: "Kubernetes",
        value: scan.repository_signal.kubernetes_files.length + scan.repository_signal.helm_charts.length,
        detail: [...scan.repository_signal.kubernetes_files, ...scan.repository_signal.helm_charts].join(", ") || "n/a",
      },
    ];
  }, [scan]);
  const runtimeSnapshot = useMemo(() => {
    const installableMissing = missingTools.filter((plugin) => plugin.metadata.install_strategy !== "system").length;
    const systemManagedMissing = missingTools.length - installableMissing;
    return [
      { label: "Registered", value: plugins.length, detail: "scanner adapters loaded" },
      { label: "Installed", value: installedTools.length, detail: "ready for execution" },
      { label: "Installable gaps", value: installableMissing, detail: "can be installed from the app" },
      { label: "System gaps", value: systemManagedMissing, detail: "require host-level setup" },
    ];
  }, [installedTools.length, missingTools, plugins.length]);

  const selectedViewMeta = viewMeta[activeView];
  const selectedRepositoryName = repositoryPath ? compactPath(repositoryPath) : "No repository selected";

  const renderOverview = () => {
    if (!scan) {
      return (
        <section className="panel empty-state">
          <h2>No scan selected</h2>
          <p>Choose a repository, start a scan, and the workspace will populate with findings, artifacts, and runtime telemetry.</p>
        </section>
      );
    }

    return (
      <>
        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Posture</p>
              <h2>Repository Overview</h2>
            </div>
            <span className={`status-pill ${scan.status === "completed" ? "ok" : scan.status === "failed" ? "danger" : "pending"}`}>
              {scan.status}
            </span>
          </div>
          <div className="metric-grid">
            <article className="metric-card metric-card-accent">
              <span className="metric-label">Security score</span>
              <strong>{scan.summary.score}</strong>
              <p>Weighted from severity, dependency exposure, secrets, and remediation confidence.</p>
            </article>
            <article className="metric-card">
              <span className="metric-label">Findings</span>
              <strong>{scan.summary.total_findings}</strong>
              <p>{scan.summary.tools_run.length || scan.tools.length} tools contributed normalized results.</p>
            </article>
            <article className="metric-card">
              <span className="metric-label">Dependencies</span>
              <strong>{scan.dependency_graph.nodes.length}</strong>
              <p>{scan.dependency_graph.edges.length} relationships mapped across manifests and lockfiles.</p>
            </article>
            <article className="metric-card">
              <span className="metric-label">Coverage</span>
              <strong>{scan.repository_signal.languages.length}</strong>
              <p>{scan.repository_signal.languages.join(", ") || "No languages detected"}</p>
            </article>
          </div>
          <div className="severity-strip">
            <button className={`severity-button ${severityFilter === "all" ? "active" : ""}`} onClick={() => setSeverityFilter("all")}>
              <span>All</span>
              <strong>{scan.summary.total_findings}</strong>
            </button>
            {severityOrder.map((severity) => (
              <button
                key={severity}
                className={`severity-button severity-${severity} ${severityFilter === severity ? "active" : ""}`}
                onClick={() => {
                  setSeverityFilter(severity);
                  setActiveView("findings");
                }}
              >
                <span>{severity}</span>
                <strong>{scan.summary.by_severity[severity] || 0}</strong>
              </button>
            ))}
          </div>
        </section>

        <div className="stage-grid">
          <section className="panel panel-spaced">
            <div className="section-head">
              <div>
                <p className="section-label">Execution</p>
                <h2>Live Scan Pressure</h2>
              </div>
              <span className="muted">{scan.completed_tools}/{scan.total_tools} complete</span>
            </div>
            <div className="progress-block">
              <div className="progress-head">
                <span>Progress</span>
                <strong>{scan.progress_percent.toFixed(0)}%</strong>
              </div>
              <div className="progress-bar">
                <div className="progress-fill" style={{ width: `${scan.progress_percent}%` }} />
              </div>
              <p className="micro">
                {scan.active_tools.length ? `Active: ${scan.active_tools.join(", ")}` : "No active tool executions at the moment."}
              </p>
            </div>
            <div className="list-compact">
              {categoryBreakdown.length ? (
                categoryBreakdown.map(([category, count]) => (
                  <div key={category} className="compact-row">
                    <div>
                      <strong>{category}</strong>
                      <span>normalized findings</span>
                    </div>
                    <strong>{count}</strong>
                  </div>
                ))
              ) : (
                <div className="compact-row">
                  <div>
                    <strong>No categories yet</strong>
                    <span>Run or select a completed scan</span>
                  </div>
                  <strong>0</strong>
                </div>
              )}
            </div>
          </section>

          <section className="panel panel-spaced">
            <div className="section-head">
              <div>
                <p className="section-label">Inventory</p>
                <h2>Repository Signals</h2>
              </div>
              <button className="button ghost" onClick={() => void openArtifact(scan.repository_path)}>
                Open repository
              </button>
            </div>
            <div className="signal-grid">
              {repositorySignals.map((signal) => (
                <article key={signal.label} className="signal-card">
                  <span className="signal-label">{signal.label}</span>
                  <strong>{signal.value}</strong>
                  <p className="micro">{signal.detail}</p>
                </article>
              ))}
            </div>
          </section>
        </div>

        <div className="stage-grid">
          <section className="panel panel-spaced">
            <div className="section-head">
              <div>
                <p className="section-label">Packages</p>
                <h2>Dependency Ecosystems</h2>
              </div>
              <span className="muted">{ecosystemBreakdown.length} ecosystems</span>
            </div>
            <div className="list-compact">
              {ecosystemBreakdown.map(([ecosystem, count]) => (
                <div key={ecosystem} className="compact-row">
                  <div>
                    <strong>{ecosystem}</strong>
                    <span>packages detected</span>
                  </div>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          </section>

          <section className="panel panel-spaced">
            <div className="section-head">
              <div>
                <p className="section-label">Reports</p>
                <h2>Ready Artifacts</h2>
              </div>
              <button className="button ghost" onClick={() => setActiveView("artifacts")}>
                Open report center
              </button>
            </div>
            <div className="artifact-grid compact-artifacts">
              {primaryArtifacts.map((artifact) => (
                <button key={`${artifact.kind}:${artifact.path}`} className="artifact-card" onClick={() => void openArtifact(artifact.path)}>
                  <span className="signal-label">{artifact.kind}</span>
                  <strong>{compactPath(artifact.path)}</strong>
                  <p className="micro">{artifact.media_type}</p>
                </button>
              ))}
            </div>
          </section>
        </div>
      </>
    );
  };

  const renderFindings = () => (
    <div className="split-layout">
      <section className="panel panel-spaced">
        <div className="section-head">
          <div>
            <p className="section-label">Explorer</p>
            <h2>Findings</h2>
          </div>
          <span className="muted">{filteredFindings.length} visible</span>
        </div>
        <div className="finding-toolbar">
          <input
            className="search-input"
            type="search"
            value={findingQuery}
            onChange={(event) => setFindingQuery(event.target.value)}
            placeholder="Search by title, path, package, rule, CVE, or tool"
            disabled={!scan}
          />
          <div className="toolbar-pills">
            <button className={`toolbar-pill ${severityFilter === "all" ? "active" : ""}`} onClick={() => setSeverityFilter("all")}>
              all
            </button>
            {severityOrder.map((severity) => (
              <button
                key={severity}
                className={`toolbar-pill severity-${severity} ${severityFilter === severity ? "active" : ""}`}
                onClick={() => setSeverityFilter(severity)}
              >
                {severity}
              </button>
            ))}
          </div>
        </div>
        {scan ? (
          <div className="finding-list">
            {filteredFindings.length ? (
              filteredFindings.map((finding) => (
                <button
                  key={finding.finding_id}
                  className={`finding-row ${selectedFinding?.finding_id === finding.finding_id ? "active" : ""}`}
                  onClick={() => setSelectedFindingId(finding.finding_id)}
                >
                  <div className="finding-row-head">
                    <span className={`status-pill severity-${finding.severity}`}>{finding.severity}</span>
                    <span className="muted">{finding.source_tool}</span>
                  </div>
                  <strong>{finding.title}</strong>
                  <p>{finding.description}</p>
                  <div className="finding-foot">
                    <span>{finding.location?.path || finding.package_name || "no location"}</span>
                    <span>{Math.round(finding.confidence * 100)}% confidence</span>
                  </div>
                </button>
              ))
            ) : (
              <div className="empty-state inset-empty">
                <h3>No findings match</h3>
                <p>Adjust the severity filter or search query to widen the result set.</p>
              </div>
            )}
          </div>
        ) : (
          <div className="empty-state inset-empty">
            <h3>No scan selected</h3>
            <p>Select a completed scan to inspect findings in detail.</p>
          </div>
        )}
      </section>

      <section className="panel panel-spaced">
        <div className="section-head">
          <div>
            <p className="section-label">Detail</p>
            <h2>{selectedFinding ? "Finding Detail" : "Awaiting Selection"}</h2>
          </div>
          {selectedFinding ? <span className={`status-pill severity-${selectedFinding.severity}`}>{selectedFinding.severity}</span> : null}
        </div>
        {selectedFinding ? (
          <div className="detail-stack">
            <div className="headline-block">
              <h3>{selectedFinding.title}</h3>
              <p>{selectedFinding.description}</p>
            </div>

            <div className="detail-section">
              <span className="detail-label">Source</span>
              <div className="meta-row">
                <span className="meta-chip">{selectedFinding.source_tool}</span>
                <span className="meta-chip">{selectedFinding.category}</span>
                {selectedFinding.rule_id ? <span className="meta-chip">{selectedFinding.rule_id}</span> : null}
                {selectedFinding.package_name ? (
                  <span className="meta-chip">
                    {selectedFinding.package_name}@{selectedFinding.package_version || "unknown"}
                  </span>
                ) : null}
              </div>
            </div>

            <div className="detail-section">
              <span className="detail-label">Location</span>
              <div className="detail-actions">
                <div>
                  <strong>{selectedFinding.location?.path || "No concrete file path reported"}</strong>
                  <p className="micro">Line {selectedFinding.location?.line || 1}</p>
                </div>
                {selectedFindingPath ? (
                  <button className="button secondary" onClick={() => void openArtifact(selectedFindingPath)}>
                    Open source
                  </button>
                ) : null}
              </div>
            </div>

            <div className="detail-section">
              <span className="detail-label">Exposure</span>
              <div className="meta-row">
                <span className="meta-chip">{Math.round(selectedFinding.confidence * 100)}% confidence</span>
                {selectedFinding.fixed_version ? <span className="meta-chip">Fix {selectedFinding.fixed_version}</span> : null}
                {selectedFinding.cve_ids.map((cve) => (
                  <span key={cve} className="meta-chip">
                    {cve}
                  </span>
                ))}
                {selectedFinding.cwe_ids.map((cwe) => (
                  <span key={cwe} className="meta-chip">
                    {cwe}
                  </span>
                ))}
              </div>
            </div>

            {selectedFinding.references.length ? (
              <div className="detail-section">
                <span className="detail-label">References</span>
                <div className="detail-link-grid">
                  {selectedFinding.references.map((reference) => (
                    <button key={reference} className="link-tile" onClick={() => void openArtifact(reference)}>
                      <strong>{compactPath(reference)}</strong>
                      <span>{reference}</span>
                    </button>
                  ))}
                </div>
              </div>
            ) : null}

            {selectedFinding.ai_triage ? (
              <div className="detail-section triage-panel">
                <span className="detail-label">AI triage</span>
                <div className="triage-grid">
                  {selectedFinding.ai_triage.priority ? (
                    <div className="triage-cell">
                      <strong>Priority</strong>
                      <span>{String(selectedFinding.ai_triage.priority)}</span>
                    </div>
                  ) : null}
                  {selectedFinding.ai_triage.exploitability ? (
                    <div className="triage-cell">
                      <strong>Exploitability</strong>
                      <span>{String(selectedFinding.ai_triage.exploitability)}</span>
                    </div>
                  ) : null}
                  {selectedFinding.ai_triage.zero_day_candidate ? (
                    <div className="triage-cell">
                      <strong>Zero-day candidate</strong>
                      <span>Flagged for analyst review</span>
                    </div>
                  ) : null}
                </div>
                {selectedFinding.ai_triage.reasoning ? <p>{String(selectedFinding.ai_triage.reasoning)}</p> : null}
                {selectedFinding.ai_triage.remediation ? <p>{String(selectedFinding.ai_triage.remediation)}</p> : null}
              </div>
            ) : null}

            {selectedFinding.remediation ? (
              <div className="detail-section">
                <span className="detail-label">Remediation</span>
                <p>{selectedFinding.remediation}</p>
              </div>
            ) : null}
          </div>
        ) : (
          <div className="empty-state inset-empty">
            <h3>No finding selected</h3>
            <p>Select an item from the findings list to review source, references, and remediation guidance.</p>
          </div>
        )}
      </section>
    </div>
  );

  const renderRuntime = () => (
    <>
      <section className="panel panel-spaced">
        <div className="section-head">
          <div>
            <p className="section-label">Scanner Runtime</p>
            <h2>Toolchain Health</h2>
          </div>
          <div className="toolbar-pills">
            {toolFilters.map((filterValue) => (
              <button
                key={filterValue}
                className={`toolbar-pill ${toolFilter === filterValue ? "active" : ""}`}
                onClick={() => setToolFilter(filterValue)}
              >
                {filterValue}
              </button>
            ))}
          </div>
        </div>
        <div className="metric-grid">
          {runtimeSnapshot.map((item) => (
            <article key={item.label} className="metric-card">
              <span className="metric-label">{item.label}</span>
              <strong>{item.value}</strong>
              <p>{item.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <div className="stage-grid">
        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Coverage</p>
              <h2>Plugin Categories</h2>
            </div>
            <button className="button secondary" onClick={installAllMissingTools} disabled={!missingTools.length || loading}>
              Install all missing
            </button>
          </div>
          <div className="list-compact">
            {runtimeCategories.map(([category, count]) => (
              <div key={category} className="compact-row">
                <div>
                  <strong>{category}</strong>
                  <span>registered adapters</span>
                </div>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </section>

        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Gaps</p>
              <h2>Immediate Actions</h2>
            </div>
            <span className="muted">{missingTools.length} missing tools</span>
          </div>
          <div className="list-compact">
            {missingTools.slice(0, 6).map((plugin) => (
              <div key={plugin.metadata.name} className="compact-row">
                <div>
                  <strong>{plugin.metadata.display_name}</strong>
                  <span>{plugin.metadata.install_strategy || "unknown strategy"}</span>
                </div>
                {plugin.metadata.install_strategy === "system" ? (
                  <span className="status-pill pending">system</span>
                ) : (
                  <button className="button ghost" onClick={() => void installMissingTool(plugin.metadata.name)} disabled={loading}>
                    Install
                  </button>
                )}
              </div>
            ))}
            {!missingTools.length ? (
              <div className="compact-row">
                <div>
                  <strong>Runtime complete</strong>
                  <span>All registered tools are available locally.</span>
                </div>
                <strong>0</strong>
              </div>
            ) : null}
          </div>
        </section>
      </div>

      <section className="panel panel-spaced">
        <div className="section-head">
          <div>
            <p className="section-label">Adapters</p>
            <h2>Installed and Missing Engines</h2>
          </div>
          <span className="muted">{filteredPlugins.length} shown</span>
        </div>
        <div className="tool-grid">
          {filteredPlugins.map((plugin) => (
            <article key={plugin.metadata.name} className="tool-card">
              <div className="tool-card-head">
                <div>
                  <h3>{plugin.metadata.display_name}</h3>
                  <p className="micro">{plugin.metadata.category}</p>
                </div>
                <span className={`status-pill ${plugin.available ? "ok" : "danger"}`}>
                  {plugin.available ? "installed" : "missing"}
                </span>
              </div>
              <p>{plugin.metadata.description || "No description available."}</p>
              <div className="meta-row">
                {(plugin.metadata.supported_languages || []).map((language) => (
                  <span key={language} className="meta-chip">
                    {language}
                  </span>
                ))}
              </div>
              <div className="tool-footer">
                <div>
                  <strong>{plugin.binary_status?.version || plugin.binary_status?.install_hint || "Binary version unavailable"}</strong>
                  {plugin.binary_status?.resolved_path ? <p className="micro">{plugin.binary_status.resolved_path}</p> : null}
                </div>
                {!plugin.available && plugin.metadata.install_strategy !== "system" ? (
                  <button className="button secondary" onClick={() => void installMissingTool(plugin.metadata.name)} disabled={loading}>
                    Install
                  </button>
                ) : null}
              </div>
            </article>
          ))}
        </div>
      </section>
    </>
  );

  const renderArtifacts = () => (
    <>
      <div className="stage-grid">
        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Output</p>
              <h2>Reports and Structured Artifacts</h2>
            </div>
            <span className="muted">{primaryArtifacts.length} reports</span>
          </div>
          {scan ? (
            <div className="artifact-grid">
              {primaryArtifacts.map((artifact) => (
                <button key={`${artifact.kind}:${artifact.path}`} className="artifact-card" onClick={() => void openArtifact(artifact.path)}>
                  <span className="signal-label">{artifact.kind}</span>
                  <strong>{compactPath(artifact.path)}</strong>
                  <p className="micro">{artifact.media_type}</p>
                </button>
              ))}
            </div>
          ) : (
            <div className="empty-state inset-empty">
              <h3>No artifact set loaded</h3>
              <p>Select a scan to review generated reports and exported security data.</p>
            </div>
          )}
        </section>

        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Raw engines</p>
              <h2>Scanner Output Blobs</h2>
            </div>
            <span className="muted">{rawArtifacts.length} raw payloads</span>
          </div>
          {scan ? (
            <div className="artifact-grid">
              {rawArtifacts.map((artifact) => (
                <button key={`${artifact.kind}:${artifact.path}`} className="artifact-card" onClick={() => void openArtifact(artifact.path)}>
                  <span className="signal-label">{artifact.kind}</span>
                  <strong>{compactPath(artifact.path)}</strong>
                  <p className="micro">{artifact.media_type}</p>
                </button>
              ))}
            </div>
          ) : (
            <div className="empty-state inset-empty">
              <h3>No raw outputs</h3>
              <p>Raw scanner output appears once a scan has completed and artifacts have been written to disk.</p>
            </div>
          )}
        </section>
      </div>

      <div className="stage-grid">
        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Telemetry</p>
              <h2>Tool Execution Timeline</h2>
            </div>
            <span className="muted">{scan?.tools.length || 0} tools</span>
          </div>
          {scan ? (
            <div className="telemetry-list">
              {scan.tools.map((tool) => (
                <div key={tool.tool} className="telemetry-row">
                  <div>
                    <strong>{tool.tool}</strong>
                    <span>{tool.category}</span>
                  </div>
                  <div>
                    <strong>{formatDuration(tool.duration_seconds)}</strong>
                    <span>exit {tool.exit_code}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state inset-empty">
              <h3>No telemetry loaded</h3>
              <p>Tool execution timings appear once a scan has run or a persisted result is selected.</p>
            </div>
          )}
        </section>

        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Graph</p>
              <h2>Dependency Breakdown</h2>
            </div>
            <span className="muted">{ecosystemBreakdown.length} ecosystems</span>
          </div>
          {scan ? (
            <div className="list-compact">
              {ecosystemBreakdown.map(([ecosystem, count]) => (
                <div key={ecosystem} className="compact-row">
                  <div>
                    <strong>{ecosystem}</strong>
                    <span>packages in graph</span>
                  </div>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state inset-empty">
              <h3>No dependency graph loaded</h3>
              <p>Select a scan to inspect the package inventory and graph breakdown.</p>
            </div>
          )}
        </section>
      </div>

      {scan?.errors.length ? (
        <section className="panel panel-spaced">
          <div className="section-head">
            <div>
              <p className="section-label">Exceptions</p>
              <h2>Scan Errors</h2>
            </div>
            <span className="status-pill danger">{scan.errors.length}</span>
          </div>
          <div className="banner-stack">
            {scan.errors.map((item) => (
              <div key={item} className="banner banner-danger">
                {item}
              </div>
            ))}
          </div>
        </section>
      ) : null}
    </>
  );

  return (
    <div className="console-shell">
      <aside className="rail">
        <div className="brand-block">
          <div className="brand-icon">CB</div>
          <div>
            <p className="brand-eyebrow">LOCAL-FIRST SECURITY CONSOLE</p>
            <h1>Code Base Scanner</h1>
          </div>
        </div>

        <nav className="nav-list">
          {views.map((view) => (
            <button
              key={view}
              className={`nav-button ${activeView === view ? "active" : ""}`}
              onClick={() => setActiveView(view)}
            >
              <span>{viewMeta[view].eyebrow}</span>
              <strong>{viewMeta[view].label}</strong>
            </button>
          ))}
        </nav>

        <section className="rail-card">
          <div className="rail-card-head">
            <span className={`status-pill ${backendReady ? "ok" : "pending"}`}>{backendReady ? "backend ready" : "starting backend"}</span>
            <strong>{plugins.length}</strong>
          </div>
          <p>{installedTools.length} scanner binaries installed locally across {runtimeCategories.length} categories.</p>
        </section>

        <section className="rail-card">
          <span className="signal-label">Active repository</span>
          <strong>{selectedRepositoryName}</strong>
          <p>{repositoryPath ? summarizePath(repositoryPath) : "Choose a repository to populate the desktop workspace."}</p>
        </section>

        <section className="rail-card">
          <span className="signal-label">Selected scan</span>
          <strong>{scan ? compactPath(scan.repository_path) : "No scan loaded"}</strong>
          <p>{scan ? `${scan.summary.total_findings} findings across ${scan.tools.length} tools` : "Scan results will appear here after execution."}</p>
        </section>
      </aside>

      <div className="workbench">
        <header className="topbar">
          <div>
            <p className="section-label">{selectedViewMeta.eyebrow}</p>
            <h2>{selectedViewMeta.label}</h2>
            <p className="topbar-copy">{selectedViewMeta.description}</p>
          </div>
          <div className="topbar-status">
            <div className="topbar-chip">
              <span>Repo</span>
              <strong>{selectedRepositoryName}</strong>
            </div>
            <div className="topbar-chip">
              <span>Scan state</span>
              <strong>{scan?.status || "idle"}</strong>
            </div>
            <div className="topbar-chip">
              <span>Findings</span>
              <strong>{scan?.summary.total_findings || 0}</strong>
            </div>
          </div>
        </header>

        {(maintenanceMessage || error) && (
          <div className="banner-stack">
            {maintenanceMessage ? <div className="banner banner-info">{maintenanceMessage}</div> : null}
            {error ? <div className="banner banner-danger">{error}</div> : null}
          </div>
        )}

        <div className="workspace-grid">
          <section className="control-stack">
            <section className="panel panel-spaced">
              <div className="section-head">
                <div>
                  <p className="section-label">Command</p>
                  <h2>Repository Scan</h2>
                </div>
                <button className="button secondary" onClick={selectRepository}>
                  Choose repository
                </button>
              </div>
              <div className="path-box">{repositoryPath || "No repository selected"}</div>
              <div className="action-row">
                <button className="button primary" onClick={runScan} disabled={!backendReady || loading}>
                  {loading ? "Working..." : "Start scan"}
                </button>
                <button className="button secondary" onClick={() => void refreshState()} disabled={!backendReady || loading}>
                  Refresh
                </button>
                <button className="button secondary" onClick={syncAdvisories} disabled={!backendReady || loading || offlineMode}>
                  Update databases
                </button>
              </div>
              <div className="option-stack">
                <label className="toggle">
                  <input type="checkbox" checked={offlineMode} onChange={(event) => setOfflineMode(event.target.checked)} />
                  <span>Offline mode</span>
                </label>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={refreshAdvisoriesOnScan}
                    onChange={(event) => setRefreshAdvisoriesOnScan(event.target.checked)}
                    disabled={offlineMode}
                  />
                  <span>Refresh advisories before scan</span>
                </label>
              </div>
              <div className="progress-block">
                <div className="progress-head">
                  <span>Current scan</span>
                  <strong>{scan ? `${scan.progress_percent.toFixed(0)}%` : "idle"}</strong>
                </div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${scan?.progress_percent || 0}%` }} />
                </div>
                <p className="micro">
                  {scan
                    ? `${scan.completed_tools}/${scan.total_tools} tools complete${scan.active_tools.length ? ` | Active: ${scan.active_tools.join(", ")}` : ""}`
                    : "No active scan in progress."}
                </p>
              </div>
            </section>

            <section className="panel panel-spaced">
              <div className="section-head">
                <div>
                  <p className="section-label">History</p>
                  <h2>Recent Runs</h2>
                </div>
                <span className="muted">{recentScans.length}</span>
              </div>
              <div className="history-list">
                {recentScans.map((item) => (
                  <button
                    key={item.scan_id}
                    className={`history-card ${scan?.scan_id === item.scan_id ? "selected" : ""}`}
                    onClick={() => {
                      setScan(item);
                      setRepositoryPath(item.repository_path);
                    }}
                  >
                    <div className="history-head">
                      <strong>{compactPath(item.repository_path)}</strong>
                      <span className={`status-pill ${item.status === "completed" ? "ok" : item.status === "failed" ? "danger" : "pending"}`}>
                        {item.status}
                      </span>
                    </div>
                    <p>{summarizePath(item.repository_path)}</p>
                    <div className="history-foot">
                      <span>{item.summary.total_findings} findings</span>
                      <span>{formatTimestamp(item.started_at)}</span>
                    </div>
                  </button>
                ))}
              </div>
            </section>

            <section className="panel panel-spaced">
              <div className="section-head">
                <div>
                  <p className="section-label">Runtime Snapshot</p>
                  <h2>Installed Tooling</h2>
                </div>
                <button className="button ghost" onClick={() => setActiveView("runtime")}>
                  Manage tools
                </button>
              </div>
              <div className="list-compact">
                {runtimeSnapshot.map((item) => (
                  <div key={item.label} className="compact-row">
                    <div>
                      <strong>{item.label}</strong>
                      <span>{item.detail}</span>
                    </div>
                    <strong>{item.value}</strong>
                  </div>
                ))}
              </div>
            </section>
          </section>

          <section className="stage-stack">
            {activeView === "overview" ? renderOverview() : null}
            {activeView === "findings" ? renderFindings() : null}
            {activeView === "runtime" ? renderRuntime() : null}
            {activeView === "artifacts" ? renderArtifacts() : null}
          </section>
        </div>

        <footer className="statusbar">
          <span>{backendReady ? "Backend connected" : "Backend bootstrapping"}</span>
          <span>{scan ? `Scan ${scan.scan_id}` : "No scan selected"}</span>
          <span>{scan ? `Started ${formatTimestamp(scan.started_at)}` : "Awaiting repository selection"}</span>
          <span>{scan?.completed_at ? `Completed ${formatTimestamp(scan.completed_at)}` : "No completed timestamp yet"}</span>
        </footer>
      </div>
    </div>
  );
}
