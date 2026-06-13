"use client";
import { useState, useEffect } from "react";
import { useScores } from "@/hooks/useBackendData";
import { Shield, BarChart3 } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

const GRADE_CLASS: Record<string, string> = {
  A: "score-A", B: "score-B", C: "score-C", D: "score-D", F: "score-F",
};

export default function SecurityScore() {
  const { data, loading } = useScores();
  const scores = data?.scores ?? [];
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  // Aggregate vulnerabilities
  let totalError = 0;
  let totalWarning = 0;
  let totalInfo = 0;

  scores.forEach(s => {
    totalError += s.vulnBySeverity?.ERROR ?? 0;
    totalWarning += s.vulnBySeverity?.WARNING ?? 0;
    totalInfo += s.vulnBySeverity?.INFO ?? 0;
  });

  const chartData = [
    { name: "Critical", value: totalError, color: "#ef4444" },
    { name: "Medium", value: totalWarning, color: "#f97316" },
    { name: "Low", value: totalInfo, color: "#06b6d4" },
  ];

  return (
    <div className="card card-glow-purple animate-in">
      <div className="card-header">
        <div className="card-title"><Shield size={14} />Security Scores</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
          {scores.length} repo{scores.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div className="card-body" style={{ display: "flex", flexDirection: "column", gap: 20 }}>
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
          <>
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

            {/* Severity Distribution Chart */}
            {mounted && (totalError + totalWarning + totalInfo > 0) && (
              <div style={{ marginTop: 10, borderTop: "1px solid var(--border)", paddingTop: 16 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)", marginBottom: 12, display: "flex", alignItems: "center", gap: 6, letterSpacing: 1 }}>
                  <BarChart3 size={12} color="var(--purple)" />
                  VULNERABILITY DISTRIBUTION BY SEVERITY
                </div>
                <div style={{ width: "100%", height: 160 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                      <XAxis dataKey="name" stroke="var(--fg-dim)" tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }} />
                      <YAxis stroke="var(--fg-dim)" tick={{ fontSize: 10, fontFamily: "var(--font-mono)" }} allowDecimals={false} />
                      <Tooltip
                        contentStyle={{
                          background: "var(--bg-card)",
                          border: "1px solid var(--border)",
                          borderRadius: "var(--radius)",
                          fontSize: "0.75rem",
                          fontFamily: "var(--font-mono)"
                        }}
                      />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
