"use client";
import { useScores } from "@/hooks/useBackendData";
import { Shield } from "lucide-react";

const GRADE_CLASS: Record<string, string> = {
  A: "score-A", B: "score-B", C: "score-C", D: "score-D", F: "score-F",
};

export default function SecurityScore() {
  const { data, loading } = useScores();
  const scores = data?.scores ?? [];

  return (
    <div className="card card-glow-purple animate-in">
      <div className="card-header">
        <div className="card-title"><Shield size={14} />Security Scores</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
          {scores.length} repo{scores.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div className="card-body">
        {loading && (
          <div className="score-grid">
            {[1,2,3].map(i => (
              <div key={i} className="skeleton" style={{ height: 72 }} />
            ))}
          </div>
        )}
        {!loading && scores.length === 0 && (
          <div className="empty"><Shield size={32} /><span>No scores yet. Run a scan first.</span></div>
        )}
        {!loading && scores.length > 0 && (
          <div className="score-grid">
            {scores.map(s => (
              <div key={s.repoName} className="score-item">
                <div className={`score-circle ${GRADE_CLASS[s.grade] ?? "score-F"}`}>
                  {s.grade}<br />
                  <span style={{ fontSize: "0.55rem", fontWeight: 400 }}>{s.score}</span>
                </div>
                <div className="score-info">
                  <div className="score-name" title={s.repoName}>{s.repoName}</div>
                  <div className="score-meta">
                    {s.totalVulnerabilities} vuln · {s.totalSecrets} secret
                  </div>
                  <div className="score-meta" style={{ marginTop: 2 }}>
                    {new Date(s.lastScannedAt).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
