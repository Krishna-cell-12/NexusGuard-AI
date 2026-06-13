const BASE_URL = process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:3000";

export const api = {
  async get<T>(path: string): Promise<T> {
    const res = await fetch(`${BASE_URL}${path}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`API ${res.status}`);
    return res.json();
  },
  async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`API ${res.status}`);
    return res.json();
  },
};

export type PipelineState =
  | "STARTED" | "SCANNING" | "SCAN_COMPLETE" | "NO_VULNS_FOUND"
  | "REQUESTING_PATCH" | "PATCH_RECEIVED" | "SUBMITTING_PATCH" | "PATCH_SUBMITTED"
  | "TRIGGERING_BOUNTY" | "BOUNTY_RELEASED" | "NOTIFYING_UI" | "COMPLETED" | "FAILED";

export interface Run {
  runId: string;
  repoName: string;
  commitSha: string;
  senderLogin: string;
  state: PipelineState;
  startedAt: string;
  updatedAt: string;
  scanReport?: {
    vulnerabilities: Array<{ ruleId?: string; message?: string; severity: string; path?: string; line?: number }>;
    secrets: Array<{ type?: string; file?: string }>;
    summary?: { vulnBySeverity?: Record<string, number> };
    scannedAt?: string;
  };
  patchResult?: { prUrl?: string; prNumber?: number };
  blockchainResult?: { txHash?: string; explorerUrl?: string };
  error?: string;
}

export interface ScoreEntry {
  repoName: string;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  totalVulnerabilities: number;
  totalSecrets: number;
  vulnBySeverity: Record<string, number>;
  lastScannedAt: string;
  commitSha?: string;
}

export interface PatchEntry {
  runId: string; repoName: string; commitSha: string; state: PipelineState;
  prUrl?: string; prNumber?: number; patchedAt: string;
  txHash?: string; explorerUrl?: string;
}

export interface ThreatEntry {
  id: string;
  source: string;
  indicator: string;
  severity: string;
  timestamp: string;
  status: string;
}

export interface HealthResponse { status: string; service: string; uptime: number; timestamp: string; }

export const fetchers = {
  health:  ()            => api.get<HealthResponse>("/health"),
  runs:    (n = 20)      => api.get<{ total: number; count: number; runs: Run[] }>(`/api/runs?limit=${n}`),
  scores:  ()            => api.get<{ count: number; scores: ScoreEntry[] }>("/api/scores"),
  patches: (n = 20)      => api.get<{ count: number; patches: PatchEntry[] }>(`/api/patches?limit=${n}`),
  threats: ()            => api.get<{ count: number; threats: ThreatEntry[] }>("/api/threats"),
  scanManual: (cloneUrl: string, repoName?: string, commitSha?: string) =>
    api.post("/api/scan/manual", { cloneUrl, repoName, commitSha }),
};
