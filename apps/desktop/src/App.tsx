import { useEffect, useMemo, useState } from "react";
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
  type PluginDescriptor,
  type ScanResult,
} from "./lib/api";

const severityOrder = ["critical", "high", "medium", "low", "info"] as const;

export default function App() {
  const [backendReady, setBackendReady] = useState(false);
  const [repositoryPath, setRepositoryPath] = useState("");
  const [plugins, setPlugins] = useState<PluginDescriptor[]>([]);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
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
        // Keep the last rendered state if the backend is briefly unavailable.
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [scan]);

  const missingTools = useMemo(() => plugins.filter((plugin) => !plugin.available), [plugins]);
  const filteredFindings = useMemo(() => {
    if (!scan) {
      return [];
    }
    if (severityFilter === "all") {
      return scan.findings;
    }
    return scan.findings.filter((finding) => finding.severity === severityFilter);
  }, [scan, severityFilter]);
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
      setSeverityFilter("all");
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
      await refreshState();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
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
      setMaintenanceMessage(`Advisories refreshed: ${summary.github_advisories} GitHub records, ${summary.nvd_advisories} NVD records.`);
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

  return (
    <div className="shell">
      <header className="hero">
        <div>
          <p className="eyebrow">LOCAL-FIRST CODE SECURITY PLATFORM</p>
          <h1>Code Base Scanner</h1>
          <p className="lede">
            Native desktop orchestration for SAST, SCA, secrets, IaC, SBOM generation, advisory correlation, and
            local report review.
          </p>
        </div>
        <div className="hero-card">
          <span className={`pill ${backendReady ? "online" : "offline"}`}>{backendReady ? "Backend Ready" : "Starting Backend"}</span>
          <div className="hero-metric">
            <strong>{plugins.length}</strong>
            <span>Scanner plugins registered</span>
          </div>
          <div className="hero-metric">
            <strong>{plugins.filter((item) => item.available).length}</strong>
            <span>Installed scanner binaries</span>
          </div>
          <div className="hero-metric">
            <strong>{recentScans.length}</strong>
            <span>Persisted scan runs</span>
          </div>
        </div>
      </header>

      <main className="dashboard">
        <aside className="sidebar">
          <section className="panel control-panel">
            <div className="section-head">
              <h2>Repository Scan</h2>
              <button className="button secondary" onClick={selectRepository}>
                Choose Repository
              </button>
            </div>
            <div className="path-box">{repositoryPath || "No repository selected"}</div>
            <div className="actions">
              <button className="button primary" onClick={runScan} disabled={!backendReady || loading}>
                {loading ? "Working..." : "Start Scan"}
              </button>
              <button className="button secondary" onClick={() => void refreshState()} disabled={!backendReady || loading}>
                Refresh
              </button>
              <button className="button secondary" onClick={syncAdvisories} disabled={!backendReady || loading || offlineMode}>
                Update Databases
              </button>
            </div>
            <div className="scan-options">
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
            {scan ? (
              <div className="progress-panel">
                <div className="progress-top">
                  <span>{scan.status}</span>
                  <strong>{scan.progress_percent.toFixed(0)}%</strong>
                </div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${scan.progress_percent}%` }} />
                </div>
                <p className="micro">
                  {scan.completed_tools}/{scan.total_tools} tools completed
                  {scan.active_tools.length ? ` | Active: ${scan.active_tools.join(", ")}` : ""}
                </p>
              </div>
            ) : null}
            {maintenanceMessage ? <p className="info-box">{maintenanceMessage}</p> : null}
            {error ? <p className="error-box">{error}</p> : null}
          </section>

          <section className="panel">
            <div className="section-head">
              <h2>Recent Scans</h2>
              <span className="muted">{recentScans.length}</span>
            </div>
            <div className="scan-history">
              {recentScans.map((item) => (
                <button
                  key={item.scan_id}
                  className={`history-card ${scan?.scan_id === item.scan_id ? "selected" : ""}`}
                  onClick={() => {
                    setScan(item);
                    setRepositoryPath(item.repository_path);
                  }}
                >
                  <strong>{item.repository_path.split("\\").pop() || item.repository_path}</strong>
                  <span>{item.status}</span>
                  <span>{item.summary.total_findings} findings</span>
                </button>
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="section-head">
              <h2>Scanner Runtime</h2>
              <span className="muted">{missingTools.length} missing</span>
            </div>
            <div className="plugin-grid">
              {plugins.map((plugin) => (
                <article className="plugin-card" key={plugin.metadata.name}>
                  <div className="plugin-top">
                    <div>
                      <h3>{plugin.metadata.display_name}</h3>
                      <p className="muted">{plugin.metadata.category}</p>
                    </div>
                    <span className={`pill ${plugin.available ? "online" : "offline"}`}>{plugin.available ? "Installed" : "Missing"}</span>
                  </div>
                  <p>{plugin.metadata.description}</p>
                  <p className="micro">
                    {plugin.binary_status?.version || plugin.binary_status?.install_hint || "Binary version unavailable"}
                  </p>
                  {plugin.binary_status?.resolved_path ? <p className="micro">Resolved: {plugin.binary_status.resolved_path}</p> : null}
                  {!plugin.available && plugin.metadata.install_strategy !== "system" ? (
                    <button className="button secondary compact" onClick={() => installMissingTool(plugin.metadata.name)} disabled={loading}>
                      Install
                    </button>
                  ) : null}
                  {!plugin.available && plugin.metadata.install_strategy === "system" ? (
                    <p className="micro">Install this tool on the host system, then refresh the runtime state.</p>
                  ) : null}
                </article>
              ))}
            </div>
          </section>
        </aside>

        <section className="workspace">
          <section className="panel">
            <div className="section-head">
              <h2>Result Overview</h2>
              <span className="muted">{scan ? scan.status : "No scan selected"}</span>
            </div>
            {scan ? (
              <>
                <div className="summary-grid">
                  <div className="summary-card accent">
                    <span>Security Score</span>
                    <strong>{scan.summary.score}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Total Findings</span>
                    <strong>{scan.summary.total_findings}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Languages</span>
                    <strong>{scan.repository_signal.languages.join(", ") || "n/a"}</strong>
                  </div>
                  <div className="summary-card">
                    <span>Dependencies</span>
                    <strong>{scan.dependency_graph.nodes.length}</strong>
                  </div>
                </div>

                <div className="severity-row">
                  <button className={`severity-chip clickable ${severityFilter === "all" ? "active" : ""}`} onClick={() => setSeverityFilter("all")}>
                    <span>all</span>
                    <strong>{scan.summary.total_findings}</strong>
                  </button>
                  {severityOrder.map((severity) => (
                    <button
                      key={severity}
                      className={`severity-chip clickable ${severityFilter === severity ? "active" : ""}`}
                      onClick={() => setSeverityFilter(severity)}
                    >
                      <span>{severity}</span>
                      <strong>{scan.summary.by_severity[severity] || 0}</strong>
                    </button>
                  ))}
                </div>

                <div className="detail-grid">
                  <article className="detail-card">
                    <h3>Artifacts</h3>
                    <div className="artifact-list">
                      {scan.artifacts.map((artifact) => (
                        <button key={`${artifact.kind}:${artifact.path}`} className="artifact-button" onClick={() => openArtifact(artifact.path)}>
                          <strong>{artifact.kind}</strong>
                          <span>{artifact.path.split("\\").pop()}</span>
                        </button>
                      ))}
                    </div>
                  </article>

                  <article className="detail-card">
                    <h3>Dependency Graph</h3>
                    <p className="micro">{scan.dependency_graph.edges.length} relationships captured from repository manifests and lockfiles.</p>
                    <div className="artifact-list">
                      {ecosystemBreakdown.map(([ecosystem, count]) => (
                        <div key={ecosystem} className="graph-pill">
                          <strong>{ecosystem}</strong>
                          <span>{count}</span>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="detail-card">
                    <h3>Tool Telemetry</h3>
                    <div className="artifact-list">
                      {scan.tools.map((tool) => (
                        <div key={tool.tool} className="tool-row">
                          <div>
                            <strong>{tool.tool}</strong>
                            <span>{tool.category}</span>
                          </div>
                          <div>
                            <strong>{tool.duration_seconds.toFixed(2)}s</strong>
                            <span>exit {tool.exit_code}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>
                </div>

                {scan.errors.length ? (
                  <div className="error-box">
                    {scan.errors.map((item) => (
                      <div key={item}>{item}</div>
                    ))}
                  </div>
                ) : null}
              </>
            ) : (
              <p className="muted">Run a scan to render findings, dependency intelligence, and generated reports.</p>
            )}
          </section>

          <section className="panel">
            <div className="section-head">
              <h2>Findings</h2>
              <span className="muted">{filteredFindings.length} visible</span>
            </div>
            {scan ? (
              <div className="finding-list">
                {filteredFindings.map((finding) => (
                  <article className="finding-card" key={finding.finding_id}>
                    <div className="finding-head">
                      <span className={`pill severity-${finding.severity}`}>{finding.severity}</span>
                      <span className="muted">{finding.source_tool}</span>
                    </div>
                    <h3>{finding.title}</h3>
                    <p>{finding.description}</p>
                    <div className="finding-meta">
                      <span>{finding.category}</span>
                      <span>{finding.location?.path ? `${finding.location.path}:${finding.location.line || 1}` : "no file location"}</span>
                      <span>{finding.rule_id || "unmapped rule"}</span>
                      {finding.package_name ? <span>{`${finding.package_name}@${finding.package_version || "unknown"}`}</span> : null}
                      {finding.fixed_version ? <span>{`fix ${finding.fixed_version}`}</span> : null}
                      <span>{`${Math.round(finding.confidence * 100)}% confidence`}</span>
                    </div>
                    {finding.cve_ids.length ? <p className="micro">CVE: {finding.cve_ids.join(", ")}</p> : null}
                    {finding.references.length ? (
                      <div className="reference-row">
                        {finding.references.map((reference) => (
                          <button key={reference} className="link-button" onClick={() => openArtifact(reference)}>
                            {reference}
                          </button>
                        ))}
                      </div>
                    ) : null}
                    {finding.ai_triage ? (
                      <div className="triage-box">
                        {finding.ai_triage.priority ? <p className="micro"><strong>AI priority:</strong> {String(finding.ai_triage.priority)}</p> : null}
                        {finding.ai_triage.exploitability ? (
                          <p className="micro"><strong>Exploitability:</strong> {String(finding.ai_triage.exploitability)}</p>
                        ) : null}
                        {finding.ai_triage.reasoning ? <p className="micro">{String(finding.ai_triage.reasoning)}</p> : null}
                        {finding.ai_triage.zero_day_candidate ? <p className="micro">AI flagged this as a zero-day candidate.</p> : null}
                      </div>
                    ) : null}
                    {finding.remediation ? <p className="micro">{finding.remediation}</p> : null}
                  </article>
                ))}
              </div>
            ) : (
              <p className="muted">No findings available yet.</p>
            )}
          </section>
        </section>
      </main>
    </div>
  );
}
