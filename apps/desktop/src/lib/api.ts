export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Finding {
  finding_id: string;
  source_tool: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  rule_id?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  fixed_version?: string | null;
  cve_ids: string[];
  cwe_ids: string[];
  references: string[];
  confidence: number;
  location?: {
    path?: string | null;
    line?: number | null;
  } | null;
  remediation?: string | null;
  ai_triage?: {
    priority?: string;
    reasoning?: string;
    remediation?: string;
    exploitability?: string;
    zero_day_candidate?: boolean;
    zero_day_candidates?: Array<Record<string, unknown>>;
    [key: string]: unknown;
  };
}

export interface ScanResult {
  scan_id: string;
  status: string;
  repository_path: string;
  started_at: string;
  completed_at?: string | null;
  total_tools: number;
  completed_tools: number;
  progress_percent: number;
  active_tools: string[];
  findings: Finding[];
  artifacts: { kind: string; path: string; media_type: string }[];
  errors: string[];
  summary: {
    total_findings: number;
    by_severity: Record<string, number>;
    by_category: Record<string, number>;
    tools_run: string[];
    score: number;
  };
  repository_signal: {
    languages: string[];
    manifests: string[];
    ci_files: string[];
    docker_files: string[];
    helm_charts: string[];
    kubernetes_files: string[];
    terraform_files: string[];
  };
  tools: {
    tool: string;
    category: string;
    duration_seconds: number;
    exit_code: number;
    stderr?: string;
    binary_path?: string | null;
  }[];
  dependency_graph: {
    nodes: { id: string; ecosystem: string; version?: string | null }[];
    edges: [string, string][];
  };
}

export interface PluginDescriptor {
  metadata: {
    name: string;
    display_name: string;
    category: string;
    supported_languages: string[];
    install_strategy?: string | null;
    description?: string | null;
  };
  available: boolean;
  binary_status?: {
    resolved_path?: string | null;
    version?: string | null;
    install_hint?: string | null;
  } | null;
}

export interface ScanOptions {
  offline?: boolean;
  updateAdvisories?: boolean;
}

const API_ROOT = "http://127.0.0.1:8686";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers ?? {});
  const hasBody = init?.body !== undefined && init?.body !== null;
  if (hasBody && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const response = await fetch(`${API_ROOT}${path}`, {
    headers,
    ...init,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return (await response.json()) as T;
}

export async function health(): Promise<boolean> {
  try {
    await request("/health");
    return true;
  } catch {
    return false;
  }
}

export async function getPlugins(): Promise<PluginDescriptor[]> {
  return request("/plugins");
}

export async function installTool(toolName: string): Promise<void> {
  await request(`/plugins/${toolName}/install`, { method: "POST" });
}

export async function updateAdvisories(): Promise<{ github_advisories: number; nvd_advisories: number }> {
  return request("/updates/advisories", { method: "POST" });
}

export async function createScan(repositoryPath: string, options: ScanOptions = {}): Promise<ScanResult> {
  return request("/scan", {
    method: "POST",
    body: JSON.stringify({
      repository_path: repositoryPath,
      report_formats: ["json", "sarif", "html", "md", "pdf"],
      update_advisories: options.updateAdvisories ?? false,
      offline: options.offline ?? false,
      include_git_history: true,
    }),
  });
}

export async function getScan(scanId: string): Promise<ScanResult> {
  return request(`/results/${scanId}`);
}

export async function listResults(): Promise<ScanResult[]> {
  return request("/results?limit=20");
}
