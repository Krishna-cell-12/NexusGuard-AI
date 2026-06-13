"use client";
import { useState } from "react";
import Sidebar from "@/components/layout/Sidebar";
import TopBar from "@/components/layout/TopBar";
import LiveFeed from "@/components/dashboard/LiveFeed";
import { fetchers } from "@/lib/api";
import { Terminal, GitBranch, Play, CheckCircle2, AlertCircle, Loader2, Shield } from "lucide-react";

interface ScanResult { message: string; repoName: string; cloneUrl: string; commitSha: string; }

const EXAMPLE_REPOS = [
  "https://github.com/nextlevelbuilder/ui-ux-pro-max-skill.git",
  "https://github.com/Krishna-cell-12/NexusGuard-AI.git",
];

export default function ScanPage() {
  const [cloneUrl,  setClone]  = useState("");
  const [repoName,  setRepo]   = useState("");
  const [commitSha, setCommit] = useState("");
  const [loading,   setLoad]   = useState(false);
  const [result,    setResult] = useState<ScanResult | null>(null);
  const [error,     setError]  = useState<string | null>(null);

  const handleScan = async () => {
    if (!cloneUrl.trim()) { setError("Clone URL is required."); return; }
    setLoad(true); setError(null); setResult(null);
    try {
      const r = await fetchers.scanManual(
        cloneUrl.trim(),
        repoName.trim() || undefined,
        commitSha.trim() || undefined,
      ) as ScanResult;
      setResult(r);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Scan failed. Is the backend running?");
    } finally {
      setLoad(false);
    }
  };

  return (
    <div className="shell">
      <Sidebar />
      <TopBar />
      <main className="main">

        {/* Header */}
        <div className="card card-glow-green animate-in">
          <div className="card-body" style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{
              width: 56, height: 56, borderRadius: "50%",
              background: "var(--accent-glow)", border: "2px solid var(--accent)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "var(--glow-green)", flexShrink: 0
            }}>
              <Terminal size={24} color="var(--accent)" />
            </div>
            <div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "1.1rem", color: "var(--fg)", letterSpacing: 2 }}>
                MANUAL SCAN
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--fg-dim)", marginTop: 4 }}>
                Trigger a full NexusGuard pipeline: Semgrep + TruffleHog → AI Patch → Blockchain Bounty
              </div>
            </div>
          </div>
        </div>

        <div className="two-col">
          {/* Scan Form */}
          <div className="card animate-in">
            <div className="card-header">
              <div className="card-title"><GitBranch size={14} />Repository Target</div>
            </div>
            <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 16 }}>

              {/* Clone URL */}
              <div className="input-group">
                <label className="input-label">Clone URL *</label>
                <input
                  className="input"
                  type="url"
                  placeholder="https://github.com/org/repo.git"
                  value={cloneUrl}
                  onChange={e => setClone(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && handleScan()}
                />
              </div>

              {/* Quick fill */}
              <div>
                <div className="input-label" style={{ marginBottom: 6 }}>Quick Fill</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {EXAMPLE_REPOS.map(url => (
                    <button
                      key={url}
                      className="btn btn-ghost"
                      style={{ fontSize: "0.65rem", padding: "4px 10px" }}
                      onClick={() => setClone(url)}
                    >
                      {url.split("/").slice(-2).join("/")}
                    </button>
                  ))}
                </div>
              </div>

              {/* Repo Name */}
              <div className="input-group">
                <label className="input-label">Repo Name (optional)</label>
                <input
                  className="input"
                  placeholder="my-repo (auto-detected if empty)"
                  value={repoName}
                  onChange={e => setRepo(e.target.value)}
                />
              </div>

              {/* Commit SHA */}
              <div className="input-group">
                <label className="input-label">Commit SHA (optional)</label>
                <input
                  className="input"
                  placeholder="HEAD (default)"
                  value={commitSha}
                  onChange={e => setCommit(e.target.value)}
                />
              </div>

              {/* Error */}
              {error && (
                <div style={{
                  display: "flex", alignItems: "center", gap: 8,
                  padding: "10px 14px", background: "var(--red-glow)",
                  border: "1px solid var(--red)", borderRadius: "var(--radius)",
                  fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--red)"
                }}>
                  <AlertCircle size={14} />{error}
                </div>
              )}

              {/* Success */}
              {result && (
                <div style={{
                  display: "flex", alignItems: "flex-start", gap: 8,
                  padding: "12px 14px", background: "var(--accent-glow)",
                  border: "1px solid var(--accent)", borderRadius: "var(--radius)",
                  fontFamily: "var(--font-mono)", fontSize: "0.78rem", color: "var(--accent)"
                }}>
                  <CheckCircle2 size={14} style={{ marginTop: 2, flexShrink: 0 }} />
                  <div>
                    <div style={{ fontWeight: 700 }}>Scan Queued!</div>
                    <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
                      Repo: {result.repoName} — watch the Live Feed for real-time progress.
                    </div>
                  </div>
                </div>
              )}

              {/* Submit */}
              <button
                className="btn btn-primary w-full"
                onClick={handleScan}
                disabled={loading || !cloneUrl.trim()}
                style={{ marginTop: 4, padding: "12px 20px", fontSize: "0.85rem" }}
              >
                {loading
                  ? <><Loader2 size={16} style={{ animation: "spin 1s linear infinite" }} />Queuing Scan...</>
                  : <><Play size={16} />Launch Security Scan</>
                }
              </button>
            </div>
          </div>

          {/* Live Feed */}
          <LiveFeed />
        </div>

        {/* Pipeline Info */}
        <div className="card animate-in">
          <div className="card-header">
            <div className="card-title"><Shield size={14} />What Happens Next</div>
          </div>
          <div className="card-body">
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
              {[
                { num: "01", title: "Clone & Scan", desc: "Semgrep static analysis + TruffleHog secret detection run in parallel on your repo.", color: "var(--cyan)" },
                { num: "02", title: "AI Patch", desc: "Findings routed to the AI microservice (port 8000) which generates a code patch.", color: "var(--purple)" },
                { num: "03", title: "Auto PR", desc: "The patch is submitted as a Pull Request to your repository automatically.", color: "var(--accent)" },
                { num: "04", title: "Bounty Release", desc: "Web3 oracle (port 8001) releases an on-chain bounty on Polygon Amoy.", color: "var(--orange)" },
              ].map(step => (
                <div key={step.num} style={{
                  padding: "16px", background: "var(--bg-surface)",
                  borderRadius: "var(--radius)", border: "1px solid var(--border)"
                }}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "1.5rem", color: step.color, opacity: 0.6, marginBottom: 8 }}>
                    {step.num}
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", color: "var(--fg)", marginBottom: 6 }}>
                    {step.title}
                  </div>
                  <div style={{ fontFamily: "var(--font-code)", fontSize: "0.75rem", color: "var(--fg-dim)", lineHeight: 1.5 }}>
                    {step.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

      </main>
    </div>
  );
}
