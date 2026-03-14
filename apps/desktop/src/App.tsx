import { useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
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
const workspaceTabs = ["dashboard", "findings", "dependencies", "reports", "plugins"] as const;
const menuIds = ["file", "scan", "view", "tools", "reports", "help"] as const;
const consoleModes = ["events", "timeline"] as const;
const inspectorModes = ["context", "runtime"] as const;

type WorkspaceTabId = (typeof workspaceTabs)[number];
type ToolFilter = (typeof toolFilters)[number];
type MenuId = (typeof menuIds)[number] | null;
type ConsoleMode = (typeof consoleModes)[number];
type InspectorMode = (typeof inspectorModes)[number];
type Artifact = ScanResult["artifacts"][number];
type ToolExecution = ScanResult["tools"][number];
type DependencyNode = ScanResult["dependency_graph"]["nodes"][number];

type MenuItem = {
  label: string;
  hint?: string;
  disabled?: boolean;
  action: () => void;
};

type ConsoleEntry = {
  id: string;
  channel: string;
  message: string;
  detail?: string;
  timestamp?: string;
  tone: "info" | "success" | "warning" | "danger";
};

const workspaceMeta: Record<WorkspaceTabId, { label: string; eyebrow: string; description: string }> = {
  dashboard: {
    label: "Command Deck",
    eyebrow: "Workspace",
    description: "Run scans, watch execution pressure, and review repository posture from a single desktop surface.",
  },
  findings: {
    label: "Finding Explorer",
    eyebrow: "Investigation",
    description: "Filter normalized findings, pivot by severity, and inspect remediation context and evidence.",
  },
  dependencies: {
    label: "Dependency Graph",
    eyebrow: "Intelligence",
    description: "Inspect ecosystem inventory, package surfaces, and graph-connected dependency exposure.",
  },
  reports: {
    label: "Report Explorer",
    eyebrow: "Artifacts",
    description: "Open generated reports, raw scanner payloads, and execution telemetry from the local report store.",
  },
  plugins: {
    label: "Plugin Manager",
    eyebrow: "Runtime",
    description: "Manage scanner engines, verify local binary state, and close runtime coverage gaps.",
  },
};

const menuLabels: Record<Exclude<MenuId, null>, string> = {
  file: "File",
  scan: "Scan",
  view: "View",
  tools: "Tools",
  reports: "Reports",
  help: "Help",
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

function renderSessionInspector({
  scan,
  repositoryPath,
  recentScans,
  openTarget,
}: {
  scan: ScanResult | null;
  repositoryPath: string;
  recentScans: ScanResult[];
  openTarget: (path: string) => Promise<void>;
}) {
  return (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Session</span>
            <h3>Current repository</h3>
          </div>
        </div>
        <div className="path-banner small">{repositoryPath || scan?.repository_path || "No repository selected."}</div>
        {repositoryPath || scan?.repository_path ? (
          <button className="button secondary button-inline" onClick={() => void openTarget(repositoryPath || scan!.repository_path)}>
            Open folder
          </button>
        ) : null}
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Current scan</span>
            <h3>{scan ? scan.scan_id : "No active scan"}</h3>
          </div>
        </div>
        {scan ? (
          <div className="detail-stack">
            <div className="summary-card">
              <span className="detail-label">Status</span>
              <strong>{scan.status}</strong>
              <p>{scan.completed_tools}/{scan.total_tools} tools completed.</p>
            </div>
            <div className="summary-card">
              <span className="detail-label">Artifacts</span>
              <strong>{scan.artifacts.length}</strong>
              <p>{scan.errors.length} errors and {scan.summary.total_findings} findings.</p>
            </div>
            <div className="summary-card">
              <span className="detail-label">Recent scans</span>
              <strong>{recentScans.length}</strong>
              <p>Persisted runs available in the local history timeline.</p>
            </div>
          </div>
        ) : (
          <div className="empty-inline">Start or load a scan to see session detail here.</div>
        )}
      </section>
    </div>
  );
}

function renderFindingInspector({
  finding,
  findingPath,
  openTarget,
}: {
  finding: Finding | null;
  findingPath: string | null;
  openTarget: (path: string) => Promise<void>;
}) {
  if (!finding) {
    return <div className="empty-inline">Select a finding to inspect evidence and remediation detail.</div>;
  }

  const zeroDayCandidate = Boolean(
    finding.ai_triage?.zero_day_candidate ||
      (Array.isArray(finding.ai_triage?.zero_day_candidates) && finding.ai_triage?.zero_day_candidates.length),
  );

  return (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Finding</span>
            <h3>{finding.title}</h3>
          </div>
          <span className={`status-pill severity ${finding.severity}`}>{finding.severity}</span>
        </div>
        <p className="body-copy">{finding.description}</p>
        <div className="pill-row">
          <span className="meta-chip">{finding.source_tool}</span>
          <span className="meta-chip">{finding.category}</span>
          {finding.rule_id ? <span className="meta-chip">{finding.rule_id}</span> : null}
          <span className="meta-chip">{Math.round(finding.confidence * 100)}% confidence</span>
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Location</span>
            <h3>{finding.location?.path || "No path"}</h3>
          </div>
        </div>
        <div className="summary-card">
          <span className="detail-label">Line</span>
          <strong>{finding.location?.line || "n/a"}</strong>
          <p>{finding.location?.column ? `Column ${finding.location.column}` : "Column not provided by the scanner."}</p>
        </div>
        {finding.location?.snippet ? (
          <pre className="code-block">{finding.location.snippet}</pre>
        ) : (
          <div className="empty-inline">No code snippet was attached to this finding.</div>
        )}
        {findingPath ? (
          <button className="button secondary button-inline" onClick={() => void openTarget(findingPath)}>
            Open source file
          </button>
        ) : null}
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Triage</span>
            <h3>AI-assisted context</h3>
          </div>
        </div>
        <div className="summary-grid single-column">
          <article className="summary-card">
            <span className="detail-label">Priority</span>
            <strong>{finding.ai_triage?.priority || "n/a"}</strong>
            <p>{finding.ai_triage?.reasoning || finding.remediation || "No triage reasoning was generated for this finding."}</p>
          </article>
          <article className="summary-card">
            <span className="detail-label">Exploitability</span>
            <strong>{finding.ai_triage?.exploitability || "n/a"}</strong>
            <p>{zeroDayCandidate ? "Flagged as a potential zero-day candidate by the triage layer." : "No zero-day candidate signal attached."}</p>
          </article>
          {finding.ai_triage?.remediation || finding.remediation ? (
            <article className="summary-card">
              <span className="detail-label">Remediation</span>
              <strong>Suggested action</strong>
              <p>{finding.ai_triage?.remediation || finding.remediation}</p>
            </article>
          ) : null}
        </div>
      </section>

      {finding.references.length || finding.cve_ids.length || finding.cwe_ids.length ? (
        <section className="inspector-section">
          <div className="section-heading">
            <div>
              <span className="eyebrow">References</span>
              <h3>Linked identifiers</h3>
            </div>
          </div>
          <div className="pill-row">
            {finding.cve_ids.map((value) => (
              <span key={value} className="meta-chip">{value}</span>
            ))}
            {finding.cwe_ids.map((value) => (
              <span key={value} className="meta-chip">{value}</span>
            ))}
          </div>
          <div className="compact-list">
            {finding.references.map((reference) => (
              <button key={reference} className="link-row" onClick={() => void openTarget(reference)}>
                <strong>{reference}</strong>
                <span>Open reference</span>
              </button>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}

function renderDependencyInspector({
  dependency,
  scan,
}: {
  dependency: DependencyNode | null;
  scan: ScanResult | null;
}) {
  if (!dependency) {
    return <div className="empty-inline">Select a dependency node to inspect graph detail.</div>;
  }

  const relatedFindings = scan
    ? scan.findings.filter((finding) => {
        const packageName = finding.package_name?.toLowerCase();
        return packageName === dependency.id.toLowerCase() || packageName === dependencyName(dependency).toLowerCase();
      })
    : [];

  return (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Dependency</span>
            <h3>{dependencyName(dependency)}</h3>
          </div>
          <span className="meta-chip">{dependency.ecosystem}</span>
        </div>
        <div className="summary-grid single-column">
          <article className="summary-card">
            <span className="detail-label">Version</span>
            <strong>{dependency.version || "unversioned"}</strong>
            <p>{dependency.direct ? "Direct dependency in the manifest graph." : "Transitive dependency discovered through graph resolution."}</p>
          </article>
          <article className="summary-card">
            <span className="detail-label">Downstream edges</span>
            <strong>{dependency.dependencies?.length || 0}</strong>
            <p>Outgoing dependency links from this node.</p>
          </article>
          <article className="summary-card">
            <span className="detail-label">Related findings</span>
            <strong>{relatedFindings.length}</strong>
            <p>Normalized findings linked to this package name.</p>
          </article>
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Graph links</span>
            <h3>Outgoing edges</h3>
          </div>
        </div>
        <div className="compact-list">
          {dependency.dependencies?.length ? (
            dependency.dependencies.map((value) => (
              <div key={value} className="compact-row">
                <div>
                  <strong>{value}</strong>
                  <span>Linked package id</span>
                </div>
              </div>
            ))
          ) : (
            <div className="empty-inline">No outgoing dependency edges were recorded for this node.</div>
          )}
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Finding map</span>
            <h3>Package-linked issues</h3>
          </div>
        </div>
        <div className="compact-list">
          {relatedFindings.length ? (
            relatedFindings.map((finding) => (
              <div key={finding.finding_id} className="compact-row">
                <div>
                  <strong>{finding.title}</strong>
                  <span>{finding.source_tool} · {finding.severity}</span>
                </div>
              </div>
            ))
          ) : (
            <div className="empty-inline">No findings are linked directly to this dependency node.</div>
          )}
        </div>
      </section>
    </div>
  );
}

function renderReportsInspector({
  artifact,
  execution,
  mode,
  openTarget,
}: {
  artifact: Artifact | null;
  execution: ToolExecution | null;
  mode: "artifact" | "execution";
  openTarget: (path: string) => Promise<void>;
}) {
  if (mode === "execution") {
    if (!execution) {
      return <div className="empty-inline">Select a tool execution to inspect command and output.</div>;
    }
    return (
      <div className="inspector-stack">
        <section className="inspector-section">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Execution</span>
              <h3>{execution.tool}</h3>
            </div>
            <span className={`status-pill ${execution.exit_code === 0 ? "ok" : "danger"}`}>exit {execution.exit_code}</span>
          </div>
          <div className="summary-grid single-column">
            <article className="summary-card">
              <span className="detail-label">Category</span>
              <strong>{execution.category}</strong>
              <p>{formatDuration(execution.duration_seconds)} elapsed.</p>
            </article>
            <article className="summary-card">
              <span className="detail-label">Binary</span>
              <strong>{execution.binary_path || "n/a"}</strong>
              <p>{execution.command?.length ? execution.command.join(" ") : "Command line not captured."}</p>
            </article>
          </div>
          {execution.stdout ? <pre className="code-block limited-block">{execution.stdout}</pre> : null}
          {execution.stderr ? <pre className="code-block limited-block">{execution.stderr}</pre> : null}
          {execution.output_files?.length ? (
            <div className="compact-list">
              {execution.output_files.map((path) => (
                <button key={path} className="link-row" onClick={() => void openTarget(path)}>
                  <strong>{compactPath(path)}</strong>
                  <span>{path}</span>
                </button>
              ))}
            </div>
          ) : null}
        </section>
      </div>
    );
  }

  if (!artifact) {
    return <div className="empty-inline">Select an artifact to inspect report detail.</div>;
  }

  return (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Artifact</span>
            <h3>{compactPath(artifact.path)}</h3>
          </div>
          <span className="meta-chip">{artifact.kind}</span>
        </div>
        <div className="summary-grid single-column">
          <article className="summary-card">
            <span className="detail-label">Media type</span>
            <strong>{artifact.media_type}</strong>
            <p>{artifact.path}</p>
          </article>
        </div>
        <button className="button secondary button-inline" onClick={() => void openTarget(artifact.path)}>
          Open artifact
        </button>
      </section>
    </div>
  );
}

function renderPluginInspector({
  plugin,
  install,
  loading,
}: {
  plugin: PluginDescriptor | null;
  install: (toolName: string) => Promise<void>;
  loading: boolean;
}) {
  if (!plugin) {
    return <div className="empty-inline">Select a plugin to inspect runtime metadata.</div>;
  }

  return (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Plugin</span>
            <h3>{plugin.metadata.display_name}</h3>
          </div>
          <span className={`status-pill ${plugin.available ? "ok" : "danger"}`}>
            {plugin.available ? "installed" : "missing"}
          </span>
        </div>
        <div className="summary-grid single-column">
          <article className="summary-card">
            <span className="detail-label">Adapter id</span>
            <strong>{plugin.metadata.name}</strong>
            <p>{plugin.metadata.description || "No plugin description was provided."}</p>
          </article>
          <article className="summary-card">
            <span className="detail-label">Install strategy</span>
            <strong>{plugin.metadata.install_strategy || "system"}</strong>
            <p>{plugin.binary_status?.install_hint || "No installation hint was provided by the runtime."}</p>
          </article>
          <article className="summary-card">
            <span className="detail-label">Binary</span>
            <strong>{plugin.binary_status?.resolved_path || "Not resolved"}</strong>
            <p>Version {plugin.binary_status?.version || "unknown"}.</p>
          </article>
        </div>
        {!plugin.available && plugin.metadata.install_strategy !== "system" ? (
          <button className="button primary button-inline" disabled={loading} onClick={() => void install(plugin.metadata.name)}>
            Install this tool
          </button>
        ) : null}
      </section>
    </div>
  );
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

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }
  return `${size.toFixed(size >= 100 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function compactPath(value: string): string {
  return value.split(/[\\/]/).filter(Boolean).pop() || value;
}

function summarizePath(value: string): string {
  if (value.length <= 64) {
    return value;
  }
  return `${value.slice(0, 28)}...${value.slice(-28)}`;
}

function clipText(value: string | undefined | null, limit = 180): string {
  if (!value) {
    return "";
  }
  return value.length <= limit ? value : `${value.slice(0, limit - 3)}...`;
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

function statusTone(status: string): "ok" | "pending" | "danger" {
  if (status === "completed") {
    return "ok";
  }
  if (status === "failed") {
    return "danger";
  }
  return "pending";
}

function dependencyName(node: DependencyNode): string {
  const [, ...rest] = node.id.split(":");
  return rest.join(":") || node.id;
}

function scanDuration(scan: ScanResult): string {
  if (!scan.completed_at) {
    return scan.status === "running" ? "running" : "n/a";
  }
  const started = new Date(scan.started_at).valueOf();
  const completed = new Date(scan.completed_at).valueOf();
  if (!Number.isFinite(started) || !Number.isFinite(completed) || completed <= started) {
    return "n/a";
  }
  return formatDuration((completed - started) / 1000);
}

export default function App() {
  const [backendReady, setBackendReady] = useState(false);
  const [repositoryPath, setRepositoryPath] = useState("");
  const [plugins, setPlugins] = useState<PluginDescriptor[]>([]);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [activeTab, setActiveTab] = useState<WorkspaceTabId>("dashboard");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [toolFilter, setToolFilter] = useState<ToolFilter>("all");
  const [findingQuery, setFindingQuery] = useState("");
  const [dependencyQuery, setDependencyQuery] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [selectedDependencyId, setSelectedDependencyId] = useState<string | null>(null);
  const [selectedPluginName, setSelectedPluginName] = useState<string | null>(null);
  const [selectedArtifactPath, setSelectedArtifactPath] = useState<string | null>(null);
  const [selectedExecutionTool, setSelectedExecutionTool] = useState<string | null>(null);
  const [reportInspectorMode, setReportInspectorMode] = useState<"artifact" | "execution">("artifact");
  const [offlineMode, setOfflineMode] = useState(false);
  const [refreshAdvisoriesOnScan, setRefreshAdvisoriesOnScan] = useState(false);
  const [maintenanceMessage, setMaintenanceMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openMenu, setOpenMenu] = useState<MenuId>(null);
  const [consoleMode, setConsoleMode] = useState<ConsoleMode>("events");
  const [inspectorMode, setInspectorMode] = useState<InspectorMode>("context");
  const [showTreeDock, setShowTreeDock] = useState(true);
  const [showInspectorDock, setShowInspectorDock] = useState(true);
  const [showConsoleDock, setShowConsoleDock] = useState(true);

  const menuHostRef = useRef<HTMLDivElement | null>(null);

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
        // Keep rendering the last known state when the backend is transiently unavailable.
      }
    }, 2000);
    return () => window.clearInterval(timer);
  }, [scan]);

  useEffect(() => {
    const handlePointerDown = (event: PointerEvent) => {
      if (!menuHostRef.current) {
        return;
      }
      if (menuHostRef.current.contains(event.target as Node)) {
        return;
      }
      setOpenMenu(null);
    };
    window.addEventListener("pointerdown", handlePointerDown);
    return () => window.removeEventListener("pointerdown", handlePointerDown);
  }, []);

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

  const chooseRepository = async () => {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "Select repository to scan",
    });
    if (typeof selected === "string") {
      setRepositoryPath(selected);
      setMaintenanceMessage(`Repository selected: ${selected}`);
      setError(null);
    }
  };

  const loadScan = (nextScan: ScanResult) => {
    setScan(nextScan);
    setRepositoryPath(nextScan.repository_path);
    setMaintenanceMessage(`Loaded persisted scan ${nextScan.scan_id}.`);
    setError(null);
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
      setActiveTab("dashboard");
      setInspectorMode("context");
      setConsoleMode("events");
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

  const openTarget = async (path: string) => {
    try {
      await invoke("open_path", { path });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  };

  const missingTools = useMemo(() => plugins.filter((plugin) => !plugin.available), [plugins]);
  const installedTools = useMemo(() => plugins.filter((plugin) => plugin.available), [plugins]);
  const runtimeSnapshot = useMemo(() => {
    const installableMissing = missingTools.filter((plugin) => plugin.metadata.install_strategy !== "system").length;
    const systemManagedMissing = missingTools.length - installableMissing;
    return [
      { label: "Registered adapters", value: plugins.length, detail: "Scanner plugins loaded into the runtime." },
      { label: "Installed engines", value: installedTools.length, detail: "Local binaries ready for execution." },
      { label: "Installable gaps", value: installableMissing, detail: "Can be provisioned from the plugin manager." },
      { label: "System dependencies", value: systemManagedMissing, detail: "Require host-level installation." },
    ];
  }, [installedTools.length, missingTools, plugins.length]);
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

  const deferredDependencyQuery = useDeferredValue(dependencyQuery);
  const dependencyNodes = useMemo(() => {
    if (!scan) {
      return [];
    }
    const needle = deferredDependencyQuery.trim().toLowerCase();
    return [...scan.dependency_graph.nodes]
      .filter((node) => {
        if (!needle) {
          return true;
        }
        const corpus = `${dependencyName(node)} ${node.ecosystem} ${node.version || ""}`.toLowerCase();
        return corpus.includes(needle);
      })
      .sort((left, right) => {
        if ((left.direct ? 1 : 0) !== (right.direct ? 1 : 0)) {
          return left.direct ? -1 : 1;
        }
        if (left.ecosystem !== right.ecosystem) {
          return left.ecosystem.localeCompare(right.ecosystem);
        }
        return dependencyName(left).localeCompare(dependencyName(right));
      });
  }, [deferredDependencyQuery, scan]);

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

  const selectedFinding = useMemo(
    () => filteredFindings.find((finding) => finding.finding_id === selectedFindingId) || filteredFindings[0] || null,
    [filteredFindings, selectedFindingId],
  );
  const selectedFindingPath = useMemo(() => resolveLocationPath(scan, selectedFinding), [scan, selectedFinding]);
  const selectedDependency =
    dependencyNodes.find((node) => node.id === selectedDependencyId) || dependencyNodes[0] || null;
  const selectedPlugin =
    filteredPlugins.find((plugin) => plugin.metadata.name === selectedPluginName) || filteredPlugins[0] || null;
  const selectedArtifact =
    (scan?.artifacts.find((artifact) => artifact.path === selectedArtifactPath) as Artifact | undefined) ||
    primaryArtifacts[0] ||
    rawArtifacts[0] ||
    null;
  const selectedExecution =
    scan?.tools.find((tool) => tool.tool === selectedExecutionTool) || scan?.tools[0] || null;

  useEffect(() => {
    if (!filteredFindings.length) {
      setSelectedFindingId(null);
      return;
    }
    if (!selectedFindingId || !filteredFindings.some((finding) => finding.finding_id === selectedFindingId)) {
      setSelectedFindingId(filteredFindings[0].finding_id);
    }
  }, [filteredFindings, selectedFindingId]);

  useEffect(() => {
    if (!dependencyNodes.length) {
      setSelectedDependencyId(null);
      return;
    }
    if (!selectedDependencyId || !dependencyNodes.some((node) => node.id === selectedDependencyId)) {
      setSelectedDependencyId(dependencyNodes[0].id);
    }
  }, [dependencyNodes, selectedDependencyId]);

  useEffect(() => {
    if (!filteredPlugins.length) {
      setSelectedPluginName(null);
      return;
    }
    if (!selectedPluginName || !filteredPlugins.some((plugin) => plugin.metadata.name === selectedPluginName)) {
      setSelectedPluginName(filteredPlugins[0].metadata.name);
    }
  }, [filteredPlugins, selectedPluginName]);

  useEffect(() => {
    const nextArtifacts = [...primaryArtifacts, ...rawArtifacts];
    if (!nextArtifacts.length) {
      setSelectedArtifactPath(null);
      return;
    }
    if (!selectedArtifactPath || !nextArtifacts.some((artifact) => artifact.path === selectedArtifactPath)) {
      setSelectedArtifactPath(nextArtifacts[0].path);
    }
  }, [primaryArtifacts, rawArtifacts, selectedArtifactPath]);

  useEffect(() => {
    if (!scan?.tools.length) {
      setSelectedExecutionTool(null);
      return;
    }
    if (!selectedExecutionTool || !scan.tools.some((tool) => tool.tool === selectedExecutionTool)) {
      setSelectedExecutionTool(scan.tools[0].tool);
    }
  }, [scan, selectedExecutionTool]);

  const menuDefinitions: Record<Exclude<MenuId, null>, MenuItem[]> = {
    file: [
      { label: "Open Repository...", hint: "Select a local repository root", action: () => void chooseRepository() },
      {
        label: "Open Repository Folder",
        hint: repositoryPath ? summarizePath(repositoryPath) : "No repository selected",
        disabled: !repositoryPath,
        action: () => {
          if (repositoryPath) {
            void openTarget(repositoryPath);
          }
        },
      },
      {
        label: "Open Active Report",
        hint: selectedArtifact ? compactPath(selectedArtifact.path) : "No report selected",
        disabled: !selectedArtifact,
        action: () => {
          if (selectedArtifact) {
            void openTarget(selectedArtifact.path);
          }
        },
      },
    ],
    scan: [
      { label: "Start Scan", hint: repositoryPath || "Choose a repository first", disabled: !backendReady || !repositoryPath || loading, action: () => void runScan() },
      { label: "Refresh Runtime State", hint: "Reload scans and plugin status", disabled: !backendReady || loading, action: () => void refreshState() },
      { label: offlineMode ? "Disable Offline Mode" : "Enable Offline Mode", hint: "Toggle network-backed updates during scan", action: () => setOfflineMode((value) => !value) },
      {
        label: refreshAdvisoriesOnScan ? "Disable Advisory Refresh" : "Refresh Advisories Before Scan",
        hint: offlineMode ? "Unavailable while offline" : "Sync GitHub/NVD data before launching scans",
        disabled: offlineMode,
        action: () => setRefreshAdvisoriesOnScan((value) => !value),
      },
    ],
    view: [
      { label: "Show Session Tree", hint: showTreeDock ? "Currently visible" : "Reveal left dock", action: () => setShowTreeDock((value) => !value) },
      { label: "Show Inspector", hint: showInspectorDock ? "Currently visible" : "Reveal right dock", action: () => setShowInspectorDock((value) => !value) },
      { label: "Show Event Console", hint: showConsoleDock ? "Currently visible" : "Reveal bottom dock", action: () => setShowConsoleDock((value) => !value) },
      { label: "Open Finding Explorer", hint: "Switch the center workspace to findings", action: () => setActiveTab("findings") },
    ],
    tools: [
      { label: "Install All Missing", hint: `${missingTools.length} missing tools`, disabled: !missingTools.length || loading, action: () => void installAllMissingTools() },
      { label: "Update Advisory Databases", hint: offlineMode ? "Offline mode enabled" : "Sync GitHub/NVD sources", disabled: offlineMode || loading, action: () => void syncAdvisories() },
      { label: "Open Plugin Manager", hint: "Review scanner adapters and binary paths", action: () => setActiveTab("plugins") },
      { label: "Switch Inspector to Runtime", hint: "Show runtime and quick actions in the right dock", action: () => setInspectorMode("runtime") },
    ],
    reports: [
      { label: "Open Report Explorer", hint: "Browse reports and raw payloads", action: () => setActiveTab("reports") },
      {
        label: "Open Latest HTML Report",
        hint: primaryArtifacts.find((artifact) => artifact.kind === "report-html") ? "report.html" : "No HTML report selected",
        disabled: !primaryArtifacts.find((artifact) => artifact.kind === "report-html"),
        action: () => {
          const artifact = primaryArtifacts.find((item) => item.kind === "report-html");
          if (artifact) {
            void openTarget(artifact.path);
          }
        },
      },
      {
        label: "Open Latest JSON Report",
        hint: primaryArtifacts.find((artifact) => artifact.kind === "report-json") ? "report.json" : "No JSON report selected",
        disabled: !primaryArtifacts.find((artifact) => artifact.kind === "report-json"),
        action: () => {
          const artifact = primaryArtifacts.find((item) => item.kind === "report-json");
          if (artifact) {
            void openTarget(artifact.path);
          }
        },
      },
    ],
    help: [
      { label: "Open Command Deck", hint: "Return to the primary workspace", action: () => setActiveTab("dashboard") },
      { label: "Open Dependency Graph", hint: "Inspect package inventory and graph nodes", action: () => setActiveTab("dependencies") },
      { label: "Show Scan Timeline", hint: `${recentScans.length} persisted runs`, action: () => setConsoleMode("timeline") },
    ],
  };

  const getRuntimeToneClass = (tone: "info" | "success" | "warning" | "danger") => {
    if (tone === "success") {
      return "ok";
    }
    if (tone === "warning") {
      return "pending";
    }
    if (tone === "danger") {
      return "danger";
    }
    return "info";
  };

  const dependencyFindingCount = (node: DependencyNode | null) => {
    if (!scan || !node) {
      return 0;
    }
    const byId = node.id.toLowerCase();
    const byName = dependencyName(node).toLowerCase();
    return scan.findings.filter((finding) => {
      const packageName = finding.package_name?.toLowerCase();
      return packageName === byId || packageName === byName;
    }).length;
  };

  const pluginVersion = (plugin: PluginDescriptor) => plugin.binary_status?.version || "unknown";

  const workspaceMetrics = useMemo(() => {
    if (!scan) {
      return [
        { label: "Adapters", value: String(plugins.length), detail: "Scanner plugins registered", accent: false },
        { label: "Installed", value: String(installedTools.length), detail: "Ready to execute locally", accent: false },
        { label: "Scans", value: String(recentScans.length), detail: "Persisted runs in local storage", accent: false },
        { label: "Status", value: backendReady ? "Online" : "Booting", detail: "Desktop runtime availability", accent: true },
      ];
    }
    return [
      { label: "Score", value: scan.summary.score.toFixed(2), detail: "Repository security score", accent: true },
      { label: "Findings", value: String(scan.summary.total_findings), detail: "Normalized findings in this run", accent: false },
      { label: "Tools", value: `${scan.completed_tools}/${scan.total_tools}`, detail: "Scanner engines completed", accent: false },
      { label: "Duration", value: scanDuration(scan), detail: "Elapsed runtime for this scan", accent: false },
    ];
  }, [backendReady, installedTools.length, plugins.length, recentScans.length, scan]);

  const consoleEntries = useMemo<ConsoleEntry[]>(() => {
    const entries: ConsoleEntry[] = [];
    if (maintenanceMessage) {
      entries.push({
        id: "maintenance",
        channel: "workspace",
        message: maintenanceMessage,
        tone: "info",
      });
    }
    if (error) {
      entries.push({
        id: "error",
        channel: "runtime",
        message: error,
        tone: "danger",
      });
    }
    if (scan) {
      if (scan.status === "running") {
        entries.push({
          id: `scan-running-${scan.scan_id}`,
          channel: "orchestrator",
          message: `Scan ${scan.scan_id} is running at ${scan.progress_percent.toFixed(0)} percent.`,
          detail: scan.active_tools.length ? `Active: ${scan.active_tools.join(", ")}` : "Waiting for active tool updates.",
          timestamp: scan.started_at,
          tone: "warning",
        });
      }
      if (scan.status === "completed") {
        entries.push({
          id: `scan-complete-${scan.scan_id}`,
          channel: "reporting",
          message: `Scan ${scan.scan_id} completed with ${scan.summary.total_findings} findings.`,
          detail: `${scan.completed_tools}/${scan.total_tools} tools completed, score ${scan.summary.score.toFixed(2)}`,
          timestamp: scan.completed_at || scan.started_at,
          tone: "success",
        });
      }
      if (scan.status === "failed") {
        entries.push({
          id: `scan-failed-${scan.scan_id}`,
          channel: "orchestrator",
          message: `Scan ${scan.scan_id} failed.`,
          detail: scan.errors[0] || "Review tool output and logs for details.",
          timestamp: scan.completed_at || scan.started_at,
          tone: "danger",
        });
      }
      for (const entry of scan.errors) {
        entries.push({
          id: `scan-error-${entry}`,
          channel: "scanner",
          message: entry,
          tone: "danger",
        });
      }
      for (const tool of scan.tools) {
        entries.push({
          id: `tool-${tool.tool}`,
          channel: tool.category,
          message: `${tool.tool} finished with exit code ${tool.exit_code}.`,
          detail: `${formatDuration(tool.duration_seconds)} via ${tool.binary_path || "resolved runtime path"}`,
          tone: tool.exit_code === 0 ? "success" : "warning",
        });
      }
    }
    return entries.slice(0, 40);
  }, [error, maintenanceMessage, scan]);

  const selectedRepositoryName = compactPath(repositoryPath || scan?.repository_path || "No repository selected");
  const currentTabMeta = workspaceMeta[activeTab];

  const executeMenuItem = (item: MenuItem) => {
    if (item.disabled) {
      return;
    }
    item.action();
    setOpenMenu(null);
  };

  const renderDashboard = () => {
    const progressValue = scan ? scan.progress_percent : 0;
    const languages = scan?.repository_signal.languages || [];
    const manifests = scan?.repository_signal.manifests || [];
    const stageCards = [
      {
        label: "Repository signal",
        value: scan ? String(scan.repository_signal.total_files) : repositoryPath ? "Ready" : "Idle",
        description: scan ? `${formatBytes(scan.repository_signal.total_bytes)} indexed from the repo root.` : "Select a local repository to populate repository telemetry.",
      },
      {
        label: "Scanner execution",
        value: scan ? `${scan.completed_tools}/${scan.total_tools}` : "0/0",
        description: scan ? `${scan.active_tools.length} active tools, ${scan.summary.tools_run.length} finished.` : "No scan active. Start a scan to launch the local scanner pipeline.",
      },
      {
        label: "Correlation",
        value: scan ? String(scan.summary.total_findings) : "0",
        description: scan ? `${categoryBreakdown.length} finding categories normalized into the result set.` : "Correlation starts after tool results are available.",
      },
      {
        label: "Reporting",
        value: scan ? String(primaryArtifacts.length) : "0",
        description: scan ? `${rawArtifacts.length} raw artifacts and ${primaryArtifacts.length} published reports.` : "Reports appear here once the reporting engine finishes.",
      },
    ];

    return (
      <div className="workspace-scroll">
        <section className="panel work-card command-card">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Repository Command</span>
              <h3>{selectedRepositoryName}</h3>
            </div>
            <span className={`status-pill ${scan ? statusTone(scan.status) : "pending"}`}>
              {scan ? scan.status : backendReady ? "ready" : "starting"}
            </span>
          </div>
          <div className="path-banner">{repositoryPath || "Choose a repository to enable the scan command deck."}</div>
          <div className="toolbar-actions">
            <button className="button primary" disabled={!backendReady || !repositoryPath || loading} onClick={() => void runScan()}>
              {scan?.status === "running" ? "Scan Running" : "Start Scan"}
            </button>
            <button className="button secondary" disabled={loading} onClick={() => void chooseRepository()}>
              Choose Repository
            </button>
            <button className="button secondary" disabled={!backendReady || loading} onClick={() => void refreshState()}>
              Refresh
            </button>
            <button className="button secondary" disabled={offlineMode || loading} onClick={() => void syncAdvisories()}>
              Update Databases
            </button>
          </div>
          <div className="toggle-row">
            <label className="toggle">
              <input type="checkbox" checked={offlineMode} onChange={() => setOfflineMode((value) => !value)} />
              <span>Offline mode</span>
            </label>
            <label className="toggle">
              <input
                type="checkbox"
                checked={refreshAdvisoriesOnScan}
                disabled={offlineMode}
                onChange={() => setRefreshAdvisoriesOnScan((value) => !value)}
              />
              <span>Refresh advisories before scan</span>
            </label>
          </div>
          <div className="progress-module">
            <div className="progress-header">
              <strong>Scan progress</strong>
              <span>{scan ? `${scan.progress_percent.toFixed(0)}%` : "0%"}</span>
            </div>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${progressValue}%` }} />
            </div>
            <p className="muted">
              {scan
                ? `${scan.completed_tools} of ${scan.total_tools} tools completed.`
                : "No active scan. Once a scan starts, the command deck will stream execution progress here."}
            </p>
          </div>
        </section>

        <section className="metric-grid">
          {workspaceMetrics.map((metric) => (
            <article key={metric.label} className={`panel metric-card ${metric.accent ? "metric-card-accent" : ""}`}>
              <span className="metric-label">{metric.label}</span>
              <strong>{metric.value}</strong>
              <p>{metric.detail}</p>
            </article>
          ))}
        </section>

        <section className="panel work-card">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Execution Pipeline</span>
              <h3>Scan orchestration stages</h3>
            </div>
          </div>
          <div className="stage-grid">
            {stageCards.map((stage) => (
              <article key={stage.label} className="stage-card">
                <span className="detail-label">{stage.label}</span>
                <strong>{stage.value}</strong>
                <p>{stage.description}</p>
              </article>
            ))}
          </div>
        </section>

        <div className="dual-grid">
          <section className="panel work-card">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Repository Signal</span>
                <h3>Language and manifest coverage</h3>
              </div>
            </div>
            <div className="summary-grid">
              <article className="summary-card">
                <span className="detail-label">Languages</span>
                <strong>{languages.length || 0}</strong>
                <p>{languages.length ? languages.join(", ") : "No language signal recorded yet."}</p>
              </article>
              <article className="summary-card">
                <span className="detail-label">Manifests</span>
                <strong>{manifests.length || 0}</strong>
                <p>{manifests.length ? manifests.slice(0, 6).map(compactPath).join(", ") : "Dependency manifests will appear here."}</p>
              </article>
              <article className="summary-card">
                <span className="detail-label">CI files</span>
                <strong>{scan?.repository_signal.ci_files.length || 0}</strong>
                <p>
                  {scan?.repository_signal.ci_files.length
                    ? scan.repository_signal.ci_files.slice(0, 5).map(compactPath).join(", ")
                    : "No CI configuration discovered in the current repository signal."}
                </p>
              </article>
            </div>
          </section>

          <section className="panel work-card">
            <div className="section-heading">
              <div>
                <span className="eyebrow">Result Mix</span>
                <h3>Finding categories</h3>
              </div>
            </div>
            <div className="compact-list">
              {categoryBreakdown.length ? (
                categoryBreakdown.map(([category, count]) => (
                  <div key={category} className="compact-row">
                    <div>
                      <strong>{category}</strong>
                      <span>{count} findings</span>
                    </div>
                    <span className="meta-chip">{Math.round((count / Math.max(scan?.summary.total_findings || 1, 1)) * 100)}%</span>
                  </div>
                ))
              ) : (
                <div className="empty-inline">Run a scan to populate category distribution.</div>
              )}
            </div>
          </section>
        </div>
      </div>
    );
  };

  const renderFindings = () => (
    <div className="workspace-scroll">
      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Finding Filters</span>
            <h3>Investigation workspace</h3>
          </div>
          <span className="meta-chip">{filteredFindings.length} visible</span>
        </div>
        <div className="filters-bar">
          <input
            className="search-input"
            value={findingQuery}
            onChange={(event) => setFindingQuery(event.target.value)}
            placeholder="Search title, rule, package, path, CVE, CWE, or tool"
          />
          <div className="pill-row">
            <button
              className={`filter-pill ${severityFilter === "all" ? "active" : ""}`}
              onClick={() => setSeverityFilter("all")}
            >
              All severities
            </button>
            {severityOrder.map((severity) => (
              <button
                key={severity}
                className={`filter-pill ${severityFilter === severity ? "active" : ""}`}
                onClick={() => setSeverityFilter(severity)}
              >
                {severity} ({scan?.summary.by_severity[severity] || 0})
              </button>
            ))}
          </div>
        </div>
      </section>

      <section className="panel work-card findings-table-card">
        <div className="finding-table">
          <div className="finding-table-head">
            <span>Severity</span>
            <span>Title</span>
            <span>Tool</span>
            <span>Location</span>
            <span>Confidence</span>
          </div>
          <div className="finding-table-body">
            {filteredFindings.length ? (
              filteredFindings.map((finding) => (
                <button
                  key={finding.finding_id}
                  className={`finding-table-row ${selectedFinding?.finding_id === finding.finding_id ? "active" : ""}`}
                  onClick={() => {
                    setSelectedFindingId(finding.finding_id);
                    setInspectorMode("context");
                  }}
                >
                  <span className={`status-pill severity ${finding.severity}`}>{finding.severity}</span>
                  <div className="table-primary">
                    <strong>{finding.title}</strong>
                    <p>{clipText(finding.description, 130)}</p>
                  </div>
                  <span>{finding.source_tool}</span>
                  <span>{finding.location?.path ? summarizePath(finding.location.path) : "n/a"}</span>
                  <span>{Math.round(finding.confidence * 100)}%</span>
                </button>
              ))
            ) : (
              <div className="empty-inline">No findings match the current filters.</div>
            )}
          </div>
        </div>
      </section>
    </div>
  );

  const renderDependencies = () => (
    <div className="workspace-scroll">
      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Dependency Intelligence</span>
            <h3>Graph inventory</h3>
          </div>
          <span className="meta-chip">{dependencyNodes.length} nodes</span>
        </div>
        <div className="filters-bar">
          <input
            className="search-input"
            value={dependencyQuery}
            onChange={(event) => setDependencyQuery(event.target.value)}
            placeholder="Search package name, ecosystem, or version"
          />
        </div>
        <div className="summary-grid">
          {ecosystemBreakdown.length ? (
            ecosystemBreakdown.map(([ecosystem, count]) => (
              <article key={ecosystem} className="summary-card">
                <span className="detail-label">{ecosystem}</span>
                <strong>{count}</strong>
                <p>Packages discovered in this ecosystem.</p>
              </article>
            ))
          ) : (
            <div className="empty-inline">Run a scan to populate dependency intelligence.</div>
          )}
        </div>
      </section>

      <section className="panel work-card">
        <div className="dependency-list">
          {dependencyNodes.length ? (
            dependencyNodes.map((node) => (
              <button
                key={node.id}
                className={`dependency-row ${selectedDependency?.id === node.id ? "active" : ""}`}
                onClick={() => {
                  setSelectedDependencyId(node.id);
                  setInspectorMode("context");
                }}
              >
                <div>
                  <strong>{dependencyName(node)}</strong>
                  <p>{node.version || "unversioned"} in {node.ecosystem}</p>
                </div>
                <div className="dependency-meta">
                  {node.direct ? <span className="meta-chip">direct</span> : <span className="meta-chip">transitive</span>}
                  <span className="meta-chip">{dependencyFindingCount(node)} findings</span>
                </div>
              </button>
            ))
          ) : (
            <div className="empty-inline">No dependency graph nodes are available for the selected scan.</div>
          )}
        </div>
      </section>
    </div>
  );

  const renderReports = () => (
    <div className="workspace-scroll">
      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Artifacts and Raw Output</span>
            <h3>Report explorer</h3>
          </div>
          <div className="pill-row">
            <button
              className={`filter-pill ${reportInspectorMode === "artifact" ? "active" : ""}`}
              onClick={() => setReportInspectorMode("artifact")}
            >
              Artifact view
            </button>
            <button
              className={`filter-pill ${reportInspectorMode === "execution" ? "active" : ""}`}
              onClick={() => setReportInspectorMode("execution")}
            >
              Execution view
            </button>
          </div>
        </div>
        <div className="dual-grid">
          <div className="artifact-grid">
            <h4 className="subsection-title">Published reports</h4>
            {primaryArtifacts.length ? (
              primaryArtifacts.map((artifact) => (
                <button
                  key={artifact.path}
                  className={`tile-card ${selectedArtifact?.path === artifact.path ? "active" : ""}`}
                  onClick={() => {
                    setSelectedArtifactPath(artifact.path);
                    setReportInspectorMode("artifact");
                    setInspectorMode("context");
                  }}
                >
                  <span className="detail-label">{artifact.kind}</span>
                  <strong>{compactPath(artifact.path)}</strong>
                  <p>{artifact.media_type}</p>
                </button>
              ))
            ) : (
              <div className="empty-inline">No published reports are available for the active scan.</div>
            )}
          </div>
          <div className="artifact-grid">
            <h4 className="subsection-title">Raw scanner payloads</h4>
            {rawArtifacts.length ? (
              rawArtifacts.map((artifact) => (
                <button
                  key={artifact.path}
                  className={`tile-card ${selectedArtifact?.path === artifact.path ? "active" : ""}`}
                  onClick={() => {
                    setSelectedArtifactPath(artifact.path);
                    setReportInspectorMode("artifact");
                    setInspectorMode("context");
                  }}
                >
                  <span className="detail-label">{artifact.kind}</span>
                  <strong>{compactPath(artifact.path)}</strong>
                  <p>{artifact.media_type}</p>
                </button>
              ))
            ) : (
              <div className="empty-inline">No raw payloads were captured for this run.</div>
            )}
          </div>
        </div>
      </section>

      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Tool Execution</span>
            <h3>Scanner runs</h3>
          </div>
          <span className="meta-chip">{scan?.tools.length || 0} tools</span>
        </div>
        <div className="execution-list">
          {scan?.tools.length ? (
            scan.tools.map((tool) => (
              <button
                key={tool.tool}
                className={`execution-row ${selectedExecution?.tool === tool.tool ? "active" : ""}`}
                onClick={() => {
                  setSelectedExecutionTool(tool.tool);
                  setReportInspectorMode("execution");
                  setInspectorMode("context");
                }}
              >
                <div>
                  <strong>{tool.tool}</strong>
                  <p>{tool.category}</p>
                </div>
                <div className="execution-meta">
                  <span className={`status-pill ${tool.exit_code === 0 ? "ok" : "danger"}`}>exit {tool.exit_code}</span>
                  <span className="meta-chip">{formatDuration(tool.duration_seconds)}</span>
                </div>
              </button>
            ))
          ) : (
            <div className="empty-inline">No execution telemetry is available yet.</div>
          )}
        </div>
      </section>
    </div>
  );

  const renderPlugins = () => (
    <div className="workspace-scroll">
      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Plugin Lifecycle</span>
            <h3>Scanner runtime manager</h3>
          </div>
          <div className="pill-row">
            {toolFilters.map((filterValue) => (
              <button
                key={filterValue}
                className={`filter-pill ${toolFilter === filterValue ? "active" : ""}`}
                onClick={() => setToolFilter(filterValue)}
              >
                {filterValue}
              </button>
            ))}
          </div>
        </div>
        <div className="summary-grid">
          {runtimeSnapshot.map((metric) => (
            <article key={metric.label} className="summary-card">
              <span className="detail-label">{metric.label}</span>
              <strong>{metric.value}</strong>
              <p>{metric.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="panel work-card">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Adapters</span>
            <h3>Installed and missing tools</h3>
          </div>
          <button
            className="button secondary"
            disabled={!missingTools.length || loading}
            onClick={() => void installAllMissingTools()}
          >
            Install all missing
          </button>
        </div>
        <div className="plugin-grid">
          {filteredPlugins.length ? (
            filteredPlugins.map((plugin) => (
              <article
                key={plugin.metadata.name}
                className={`plugin-card ${selectedPlugin?.metadata.name === plugin.metadata.name ? "active" : ""}`}
              >
                <button
                  className="plugin-card-body"
                  onClick={() => {
                    setSelectedPluginName(plugin.metadata.name);
                    setInspectorMode("context");
                  }}
                >
                  <div className="plugin-card-head">
                    <div>
                      <h4>{plugin.metadata.display_name}</h4>
                      <p>{plugin.metadata.category}</p>
                    </div>
                    <span className={`status-pill ${plugin.available ? "ok" : "danger"}`}>
                      {plugin.available ? "installed" : "missing"}
                    </span>
                  </div>
                  <p>{plugin.metadata.description || "No description published for this adapter."}</p>
                  <div className="plugin-card-foot">
                    <span className="meta-chip">{plugin.metadata.install_strategy || "system"}</span>
                    <span className="meta-chip">v {pluginVersion(plugin)}</span>
                  </div>
                </button>
                {!plugin.available && plugin.metadata.install_strategy !== "system" ? (
                  <button
                    className="button primary button-inline"
                    disabled={loading}
                    onClick={() => void installMissingTool(plugin.metadata.name)}
                  >
                    Install
                  </button>
                ) : null}
              </article>
            ))
          ) : (
            <div className="empty-inline">No plugins match the current filter.</div>
          )}
        </div>
      </section>
    </div>
  );

  const renderContextInspector = () => {
    if (activeTab === "findings") {
      return renderFindingInspector({
        finding: selectedFinding,
        findingPath: selectedFindingPath,
        openTarget,
      });
    }
    if (activeTab === "dependencies") {
      return renderDependencyInspector({
        dependency: selectedDependency,
        scan,
      });
    }
    if (activeTab === "reports") {
      return renderReportsInspector({
        artifact: selectedArtifact,
        execution: selectedExecution,
        mode: reportInspectorMode,
        openTarget,
      });
    }
    if (activeTab === "plugins") {
      return renderPluginInspector({
        plugin: selectedPlugin,
        install: installMissingTool,
        loading,
      });
    }
    return renderSessionInspector({
      scan,
      repositoryPath,
      recentScans,
      openTarget,
    });
  };

  const renderRuntimeInspector = () => (
    <div className="inspector-stack">
      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Runtime</span>
            <h3>Execution readiness</h3>
          </div>
        </div>
        <div className="inspector-metrics">
          {runtimeSnapshot.map((metric) => (
            <article key={metric.label} className="summary-card">
              <span className="detail-label">{metric.label}</span>
              <strong>{metric.value}</strong>
              <p>{metric.detail}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Categories</span>
            <h3>Scanner coverage</h3>
          </div>
        </div>
        <div className="compact-list">
          {runtimeCategories.length ? (
            runtimeCategories.map(([category, count]) => (
              <div key={category} className="compact-row">
                <div>
                  <strong>{category}</strong>
                  <span>{count} adapters</span>
                </div>
                <span className="meta-chip">{count}</span>
              </div>
            ))
          ) : (
            <div className="empty-inline">No scanner categories loaded yet.</div>
          )}
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Quick Actions</span>
            <h3>Runtime operations</h3>
          </div>
        </div>
        <div className="action-column">
          <button className="button secondary" disabled={loading} onClick={() => void refreshState()}>
            Refresh runtime
          </button>
          <button className="button secondary" disabled={offlineMode || loading} onClick={() => void syncAdvisories()}>
            Sync advisories
          </button>
          <button className="button secondary" disabled={!missingTools.length || loading} onClick={() => void installAllMissingTools()}>
            Install missing tools
          </button>
        </div>
      </section>

      <section className="inspector-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Active tools</span>
            <h3>Current executions</h3>
          </div>
        </div>
        <div className="compact-list">
          {scan?.tools.length ? (
            scan.tools.slice(0, 8).map((tool) => (
              <div key={tool.tool} className="compact-row">
                <div>
                  <strong>{tool.tool}</strong>
                  <span>{tool.category}</span>
                </div>
                <span className={`status-pill ${tool.exit_code === 0 ? "ok" : "danger"}`}>exit {tool.exit_code}</span>
              </div>
            ))
          ) : (
            <div className="empty-inline">No tool execution records are loaded.</div>
          )}
        </div>
      </section>
    </div>
  );

  const renderBottomConsole = () => (
    <section className="console-dock">
      <div className="console-header">
        <div>
          <span className="eyebrow">Bottom Dock</span>
          <h3>Event and progress console</h3>
        </div>
        <div className="console-controls">
          {consoleModes.map((mode) => (
            <button
              key={mode}
              className={`filter-pill ${consoleMode === mode ? "active" : ""}`}
              onClick={() => setConsoleMode(mode)}
            >
              {mode}
            </button>
          ))}
          <button className="button ghost button-inline" onClick={() => setShowConsoleDock(false)}>
            Hide dock
          </button>
        </div>
      </div>

      {consoleMode === "events" ? (
        <div className="console-list">
          {consoleEntries.length ? (
            consoleEntries.map((entry) => (
              <article key={entry.id} className={`console-entry ${getRuntimeToneClass(entry.tone)}`}>
                <div className="console-entry-head">
                  <span className="meta-chip">{entry.channel}</span>
                  <span className="muted">{entry.timestamp ? formatTimestamp(entry.timestamp) : "live"}</span>
                </div>
                <strong>{entry.message}</strong>
                {entry.detail ? <p>{entry.detail}</p> : null}
              </article>
            ))
          ) : (
            <div className="empty-inline">No console events are available yet.</div>
          )}
        </div>
      ) : (
        <div className="timeline-list">
          {recentScans.length ? (
            recentScans.map((item) => (
              <button key={item.scan_id} className="timeline-card" onClick={() => loadScan(item)}>
                <div className="timeline-head">
                  <strong>{compactPath(item.repository_path)}</strong>
                  <span className={`status-pill ${statusTone(item.status)}`}>{item.status}</span>
                </div>
                <p>{item.scan_id}</p>
                <div className="timeline-foot">
                  <span>{formatTimestamp(item.started_at)}</span>
                  <span>{item.summary.total_findings} findings</span>
                  <span>score {item.summary.score.toFixed(2)}</span>
                </div>
              </button>
            ))
          ) : (
            <div className="empty-inline">No scan history is available in the local database.</div>
          )}
        </div>
      )}
    </section>
  );

  return (
    <div className="desktop-shell">
      <header className="menu-bar" ref={menuHostRef}>
        <div className="menu-bar-left">
          <div className="brand-mark">
            <span className="brand-badge">CB</span>
            <div>
              <div className="brand-title">Code Base Scanner</div>
              <div className="brand-subtitle">Local-first security workbench</div>
            </div>
          </div>
          <nav className="menu-strip">
            {menuIds.map((menuId) => (
              <div key={menuId} className="menu-host">
                <button
                  className={`menu-trigger ${openMenu === menuId ? "active" : ""}`}
                  onClick={() => setOpenMenu((value) => (value === menuId ? null : menuId))}
                >
                  {menuLabels[menuId]}
                </button>
                {openMenu === menuId ? (
                  <div className="menu-dropdown">
                    {menuDefinitions[menuId].map((item) => (
                      <button
                        key={item.label}
                        className="menu-item"
                        disabled={item.disabled}
                        onClick={() => executeMenuItem(item)}
                      >
                        <strong>{item.label}</strong>
                        {item.hint ? <span>{item.hint}</span> : null}
                      </button>
                    ))}
                  </div>
                ) : null}
              </div>
            ))}
          </nav>
        </div>
        <div className="menu-bar-right">
          <span className={`status-pill ${backendReady ? "ok" : "pending"}`}>{backendReady ? "backend ready" : "starting backend"}</span>
          <span className="meta-chip">{installedTools.length}/{plugins.length} installed</span>
          <span className="meta-chip">{recentScans.length} scans</span>
        </div>
      </header>

      <section className="toolbar">
        <div className="toolbar-group">
          <button className="button primary button-inline" disabled={!backendReady || !repositoryPath || loading} onClick={() => void runScan()}>
            Start Scan
          </button>
          <button className="button secondary button-inline" disabled={loading} onClick={() => void chooseRepository()}>
            Open Repo
          </button>
          <button className="button secondary button-inline" disabled={!backendReady || loading} onClick={() => void refreshState()}>
            Refresh
          </button>
          <button className="button secondary button-inline" disabled={offlineMode || loading} onClick={() => void syncAdvisories()}>
            Update Feeds
          </button>
        </div>
        <div className="toolbar-group">
          <button className={`toolbar-toggle ${showTreeDock ? "active" : ""}`} onClick={() => setShowTreeDock((value) => !value)}>
            Tree
          </button>
          <button className={`toolbar-toggle ${showInspectorDock ? "active" : ""}`} onClick={() => setShowInspectorDock((value) => !value)}>
            Inspector
          </button>
          <button className={`toolbar-toggle ${showConsoleDock ? "active" : ""}`} onClick={() => setShowConsoleDock((value) => !value)}>
            Console
          </button>
          <button className={`toolbar-toggle ${inspectorMode === "runtime" ? "active" : ""}`} onClick={() => setInspectorMode((value) => (value === "runtime" ? "context" : "runtime"))}>
            {inspectorMode === "runtime" ? "Runtime Inspector" : "Context Inspector"}
          </button>
        </div>
      </section>

      <main className={`workbench ${showTreeDock ? "with-tree" : ""} ${showInspectorDock ? "with-inspector" : ""}`}>
        {showTreeDock ? (
          <aside className="dock dock-left">
            <section className="dock-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Session Tree</span>
                  <h3>Workspace</h3>
                </div>
              </div>
              <div className="tree-group">
                <button className={`tree-node ${activeTab === "dashboard" ? "active" : ""}`} onClick={() => setActiveTab("dashboard")}>
                  <span>Overview</span>
                  <strong>Command Deck</strong>
                </button>
                <button className={`tree-node ${activeTab === "findings" ? "active" : ""}`} onClick={() => setActiveTab("findings")}>
                  <span>Investigation</span>
                  <strong>Finding Explorer</strong>
                </button>
                <button className={`tree-node ${activeTab === "dependencies" ? "active" : ""}`} onClick={() => setActiveTab("dependencies")}>
                  <span>Intelligence</span>
                  <strong>Dependency Graph</strong>
                </button>
                <button className={`tree-node ${activeTab === "reports" ? "active" : ""}`} onClick={() => setActiveTab("reports")}>
                  <span>Artifacts</span>
                  <strong>Report Explorer</strong>
                </button>
                <button className={`tree-node ${activeTab === "plugins" ? "active" : ""}`} onClick={() => setActiveTab("plugins")}>
                  <span>Runtime</span>
                  <strong>Plugin Manager</strong>
                </button>
              </div>
            </section>

            <section className="dock-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Repository</span>
                  <h3>{selectedRepositoryName}</h3>
                </div>
              </div>
              <div className="path-banner small">{repositoryPath || "No repository selected."}</div>
              <div className="summary-grid single-column">
                <article className="summary-card">
                  <span className="detail-label">Files</span>
                  <strong>{scan?.repository_signal.total_files || 0}</strong>
                  <p>Indexed files in the current repository signal.</p>
                </article>
                <article className="summary-card">
                  <span className="detail-label">Languages</span>
                  <strong>{scan?.repository_signal.languages.length || 0}</strong>
                  <p>{scan?.repository_signal.languages.join(", ") || "No repository scan loaded."}</p>
                </article>
              </div>
            </section>

            <section className="dock-section">
              <div className="section-heading">
                <div>
                  <span className="eyebrow">Scan Timeline</span>
                  <h3>Recent runs</h3>
                </div>
              </div>
              <div className="history-list">
                {recentScans.length ? (
                  recentScans.map((item) => (
                    <button
                      key={item.scan_id}
                      className={`history-card ${scan?.scan_id === item.scan_id ? "selected" : ""}`}
                      onClick={() => loadScan(item)}
                    >
                      <div className="history-head">
                        <strong>{compactPath(item.repository_path)}</strong>
                        <span className={`status-pill ${statusTone(item.status)}`}>{item.status}</span>
                      </div>
                      <p>{item.scan_id}</p>
                      <div className="history-foot">
                        <span>{formatTimestamp(item.started_at)}</span>
                        <span>{item.summary.total_findings} findings</span>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="empty-inline">No persisted scans are available yet.</div>
                )}
              </div>
            </section>
          </aside>
        ) : null}

        <section className="workspace-panel">
          <div className="workspace-header">
            <div>
              <span className="eyebrow">{currentTabMeta.eyebrow}</span>
              <h1>{currentTabMeta.label}</h1>
              <p>{currentTabMeta.description}</p>
            </div>
            <div className="workspace-header-metrics">
              {workspaceMetrics.map((metric) => (
                <div key={metric.label} className="header-metric">
                  <span>{metric.label}</span>
                  <strong>{metric.value}</strong>
                </div>
              ))}
            </div>
          </div>

          <div className="tab-strip">
            {workspaceTabs.map((tab) => (
              <button
                key={tab}
                className={`tab-button ${activeTab === tab ? "active" : ""}`}
                onClick={() => setActiveTab(tab)}
              >
                <span>{workspaceMeta[tab].eyebrow}</span>
                <strong>{workspaceMeta[tab].label}</strong>
              </button>
            ))}
          </div>

          <div className="workspace-body">
            {activeTab === "dashboard" ? renderDashboard() : null}
            {activeTab === "findings" ? renderFindings() : null}
            {activeTab === "dependencies" ? renderDependencies() : null}
            {activeTab === "reports" ? renderReports() : null}
            {activeTab === "plugins" ? renderPlugins() : null}
          </div>
        </section>

        {showInspectorDock ? (
          <aside className="dock dock-right">
            <div className="inspector-header">
              <div>
                <span className="eyebrow">Inspector</span>
                <h3>{inspectorMode === "context" ? "Selection detail" : "Runtime detail"}</h3>
              </div>
              <div className="pill-row">
                {inspectorModes.map((mode) => (
                  <button
                    key={mode}
                    className={`filter-pill ${inspectorMode === mode ? "active" : ""}`}
                    onClick={() => setInspectorMode(mode)}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>
            <div className="inspector-body">{inspectorMode === "context" ? renderContextInspector() : renderRuntimeInspector()}</div>
          </aside>
        ) : null}
      </main>

      {showConsoleDock ? renderBottomConsole() : null}

      <footer className="status-bar">
        <span>Backend: {backendReady ? "ready" : "starting"}</span>
        <span>Repository: {repositoryPath ? summarizePath(repositoryPath) : "not selected"}</span>
        <span>Active scan: {scan ? scan.scan_id : "none"}</span>
        <span>Findings: {scan ? scan.summary.total_findings : 0}</span>
        <span>Missing tools: {missingTools.length}</span>
      </footer>
    </div>
  );
}
