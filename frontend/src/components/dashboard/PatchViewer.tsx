"use client";
import { useRuns } from "@/hooks/useBackendData";
import { Code2, AlertCircle, Eye } from "lucide-react";

const SEV_BADGE: Record<string, string> = {
  ERROR:   "badge-red",
  WARNING: "badge-yellow",
  INFO:    "badge-cyan",
};

export default function PatchViewer() {
  const { data } = useRuns(20);
  const runs = (data?.runs ?? []).filter(r => r.scanReport?.vulnerabilities?.length);

  return (
    <div className="card card-glow-cyan animate-in">
      <div className="card-header">
        <div className="card-title"><Code2 size={14} />Vulnerability Findings</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
          Latest scan results
        </span>
      </div>
      <div style={{ maxHeight: 340, overflowY: "auto" }}>
        {runs.length === 0 ? (
          <div className="empty" style={{ padding: "32px" }}>
            <AlertCircle size={32} />
            <span>No vulnerability findings yet.</span>
          </div>
        ) : (
          runs.slice(0, 3).map(run => (
            <div key={run.runId} style={{ borderBottom: "1px solid var(--border)", padding: "14px 20px" }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
                <span style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: "0.8rem" }}>
                  {run.repoName}
                </span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--fg-dim)" }}>
                  #{run.commitSha?.slice(0, 7)}
                </span>
              </div>
              {run.scanReport?.vulnerabilities.slice(0, 4).map((v, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "flex-start", gap: 10,
                  padding: "6px 0", borderBottom: "1px solid #1e293b"
                }}>
                  <span className={`badge ${SEV_BADGE[v.severity] ?? "badge-muted"}`} style={{ flexShrink: 0 }}>
                    {v.severity}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--fg)", wordBreak: "break-word" }}>
                      {v.message ?? v.ruleId ?? "Unknown finding"}
                    </div>
                    {v.path && (
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.65rem", color: "var(--fg-dim)", marginTop: 2 }}>
                        {v.path}{v.line ? `:${v.line}` : ""}
                      </div>
                    )}
                  </div>
                </div>
              ))}
              {(run.scanReport?.vulnerabilities.length ?? 0) > 4 && (
                <div style={{ padding: "6px 0", fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
                  +{(run.scanReport?.vulnerabilities.length ?? 0) - 4} more findings...
                </div>
              )}
              {run.patchResult?.prUrl && (
                <a
                  href={run.patchResult.prUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-primary"
                  style={{ marginTop: 10, display: "inline-flex", fontSize: "0.7rem", padding: "6px 14px" }}
                >
                  <Eye size={12} />
                  View PR #{run.patchResult.prNumber}
                </a>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
