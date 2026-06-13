"use client";
import { usePatches } from "@/hooks/useBackendData";
import { Coins, ExternalLink, CheckCircle2 } from "lucide-react";

const STATE_BADGE: Record<string, string> = {
  PATCH_RECEIVED: "badge-purple", SUBMITTING_PATCH: "badge-purple",
  PATCH_SUBMITTED: "badge-purple", TRIGGERING_BOUNTY: "badge-orange",
  BOUNTY_RELEASED: "badge-green", COMPLETED: "badge-green",
};

export default function BountyBoard() {
  const { data, loading } = usePatches(20);
  const patches = data?.patches ?? [];

  return (
    <div className="card card-glow-green animate-in">
      <div className="card-header">
        <div className="card-title"><Coins size={14} />Bounty Board</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
          Polygon Amoy — On-chain rewards
        </span>
      </div>
      <div style={{ overflowX: "auto" }}>
        {loading ? (
          <div style={{ padding: 20 }}>
            {[1,2,3].map(i => <div key={i} className="skeleton" style={{ height: 40, marginBottom: 8 }} />)}
          </div>
        ) : patches.length === 0 ? (
          <div className="empty" style={{ padding: "32px" }}>
            <Coins size={32} /><span>No bounty transactions yet.</span>
          </div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Repo</th><th>State</th><th>PR</th><th>Tx Hash</th><th>Patched At</th>
              </tr>
            </thead>
            <tbody>
              {patches.map((p) => (
                <tr key={p.runId}>
                  <td style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{p.repoName}</td>
                  <td>
                    <span className={`badge ${STATE_BADGE[p.state] ?? "badge-muted"}`}>
                      {p.state.replace(/_/g, " ")}
                    </span>
                  </td>
                  <td>
                    {p.prUrl
                      ? <a href={p.prUrl} target="_blank" rel="noopener noreferrer">
                          #{p.prNumber} <ExternalLink size={10} style={{ display: "inline", verticalAlign: "middle" }} />
                        </a>
                      : <span className="mono">—</span>
                    }
                  </td>
                  <td>
                    {p.explorerUrl
                      ? <a href={p.explorerUrl} target="_blank" rel="noopener noreferrer" className="mono">
                          {p.txHash?.slice(0, 10)}… <ExternalLink size={10} style={{ display: "inline", verticalAlign: "middle" }} />
                        </a>
                      : <span className="mono text-dim">{p.txHash?.slice(0, 10) ?? "—"}</span>
                    }
                  </td>
                  <td className="mono">{new Date(p.patchedAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
