"use client";
import { useState } from "react";
import { useRuns } from "@/hooks/useBackendData";
import { Code2, AlertCircle, Eye, X, Terminal, ShieldAlert, FileCode2 } from "lucide-react";

const SEV_BADGE: Record<string, string> = {
  ERROR:   "badge-red",
  WARNING: "badge-yellow",
  INFO:    "badge-cyan",
};

interface SelectedVuln {
  repoName: string;
  commitSha: string;
  vuln: {
    ruleId?: string;
    message?: string;
    severity: string;
    path?: string;
    line?: number;
  };
  patchCode?: string;
  explanation?: string;
  prUrl?: string;
  prNumber?: number;
}

export default function PatchViewer() {
  const { data } = useRuns(20);
  const runs = (data?.runs ?? []).filter(r => r.scanReport?.vulnerabilities?.length);
  const [selected, setSelected] = useState<SelectedVuln | null>(null);

  return (
    <div className="card card-glow-cyan animate-in">
      <div className="card-header">
        <div className="card-title"><Code2 size={14} />Vulnerability Findings</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
          Click findings for AI Reports & PoCs
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
                <div
                  key={i}
                  onClick={() => setSelected({
                    repoName: run.repoName,
                    commitSha: run.commitSha,
                    vuln: v,
                    patchCode: run.patchResult?.patchCode,
                    explanation: run.patchResult?.explanation,
                    prUrl: run.patchResult?.prUrl,
                    prNumber: run.patchResult?.prNumber,
                  })}
                  className="vuln-item"
                  style={{
                    display: "flex", alignItems: "flex-start", gap: 10,
                    padding: "8px 10px", borderBottom: "1px solid #1e293b",
                    cursor: "pointer", borderRadius: "var(--radius)",
                    transition: "background var(--t-fast)"
                  }}
                >
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
                <div style={{ padding: "6px 10px", fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
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

      {/* Detail Modal Overlay */}
      {selected && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(2, 6, 23, 0.85)", backdropFilter: "blur(8px)",
          display: "flex", alignItems: "center", justifyContent: "center",
          zIndex: 1000, padding: 20
        }}>
          <div className="card card-glow-cyan animate-in" style={{
            maxWidth: 800, width: "100%", maxHeight: "90vh", display: "flex", flexDirection: "column"
          }}>
            {/* Modal Header */}
            <div className="card-header" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div className="card-title">
                <Terminal size={14} />
                AI SECURITY REPORT & POC
              </div>
              <button
                onClick={() => setSelected(null)}
                style={{ background: "transparent", border: "none", color: "var(--fg-muted)", cursor: "pointer" }}
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ overflowY: "auto", padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
              
              {/* Finding Summary */}
              <div style={{ background: "var(--bg-surface)", padding: 16, borderRadius: "var(--radius)", border: "1px solid var(--border)" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <span className={`badge ${SEV_BADGE[selected.vuln.severity] ?? "badge-muted"}`}>
                    {selected.vuln.severity}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--accent)" }}>
                    {selected.repoName}
                  </span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
                    #{selected.commitSha.slice(0, 7)}
                  </span>
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.95rem", color: "var(--fg)", marginBottom: 8 }}>
                  {selected.vuln.message ?? selected.vuln.ruleId}
                </div>
                {selected.vuln.path && (
                  <div style={{ fontFamily: "var(--font-code)", fontSize: "0.75rem", color: "var(--fg-dim)" }}>
                    Target: {selected.vuln.path}:{selected.vuln.line}
                  </div>
                )}
              </div>

              {/* Exploit PoC */}
              <div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--fg-dim)", letterSpacing: 1, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                  <ShieldAlert size={12} color="var(--red)" />
                  EXPLOIT PROOF OF CONCEPT (POC)
                </div>
                <div style={{
                  fontFamily: "var(--font-code)", fontSize: "0.78rem", background: "#0c0d14",
                  border: "1px solid var(--red-glow)", color: "var(--fg-muted)", padding: 14, borderRadius: "var(--radius)", lineHeight: 1.5
                }}>
                  {selected.explanation ? (
                    selected.explanation
                  ) : (
                    <div>
                      <span className="text-red">[VULNERABILITY DETECTED]</span> The scanner identified a code pattern matching ruleset <span className="text-accent">{selected.vuln.ruleId ?? "ruleset-main"}</span>.<br />
                      <span className="text-cyan">[POTENTIAL ATTACK]</span> An attacker could leverage inputs passing directly to this block to bypass security filters, execute arbitrary commands, or leak internal variables.<br />
                      <span className="text-muted">[STATUS]</span> Automated AI patch proposal generated and dispatched to repository pull requests.
                    </div>
                  )}
                </div>
              </div>

              {/* AI Proposed Patch */}
              <div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--fg-dim)", letterSpacing: 1, marginBottom: 8, display: "flex", alignItems: "center", gap: 6 }}>
                  <FileCode2 size={12} color="var(--accent)" />
                  AI PROPOSED PATCH CODE
                </div>
                <div style={{
                  fontFamily: "var(--font-code)", fontSize: "0.78rem", background: "#010b14",
                  border: "1px solid var(--border)", color: "var(--accent)", padding: 14, borderRadius: "var(--radius)",
                  overflowX: "auto", maxHeight: 240
                }}>
                  {selected.patchCode ? (
                    <pre style={{ margin: 0 }}><code>{selected.patchCode}</code></pre>
                  ) : (
                    <span style={{ color: "var(--fg-dim)" }}>No patch code generated for this vulnerability finding.</span>
                  )}
                </div>
              </div>

            </div>

            {/* Modal Footer */}
            <div className="card-header" style={{ display: "flex", justifyContent: "flex-end", gap: 12, borderTop: "1px solid var(--border)" }}>
              {selected.prUrl && (
                <a
                  href={selected.prUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-primary"
                  style={{ fontSize: "0.75rem", padding: "8px 16px" }}
                >
                  <Eye size={12} />
                  View GitHub PR #{selected.prNumber}
                </a>
              )}
              <button
                className="btn btn-ghost"
                onClick={() => setSelected(null)}
                style={{ fontSize: "0.75rem", padding: "8px 16px" }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
