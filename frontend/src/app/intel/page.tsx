"use client";
import Sidebar from "@/components/layout/Sidebar";
import TopBar from "@/components/layout/TopBar";
import { useThreats } from "@/hooks/useBackendData";
import { ShieldAlert, Globe, Server, Database, Activity } from "lucide-react";

export default function ThreatIntelPage() {
  const { data, loading } = useThreats();
  const threats = data?.threats ?? [];

  const sevBadge = (sev: string) => {
    if (sev === "CRITICAL") return "badge-red";
    if (sev === "HIGH") return "badge-orange";
    return "badge-yellow";
  };

  return (
    <div className="shell">
      <Sidebar />
      <TopBar />
      <main className="main">
        
        {/* Page Header */}
        <div className="card card-glow-purple animate-in">
          <div className="card-body" style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{
              width: 56, height: 56, borderRadius: "50%",
              background: "var(--purple-glow)", border: "2px solid var(--purple)",
              display: "flex", alignItems: "center", justifyCentering: "center",
              boxShadow: "var(--glow-purple)", flexShrink: 0,
              alignItems: "center", justifyContent: "center"
            }}>
              <Globe size={24} color="var(--purple)" />
            </div>
            <div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "1.1rem", color: "var(--fg)", letterSpacing: 2 }}>
                THREAT INTELLIGENCE & OSINT FEEDS
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--fg-dim)", marginTop: 4 }}>
                Active dark web crawlers, Exploit DB scrapers, and automated signature feeds mapping zero-days.
              </div>
            </div>
          </div>
        </div>

        {/* Info Grid */}
        <div className="stats-grid">
          {[
            { label: "OSINT Crawlers", value: "Active", icon: Globe, color: "green", sub: "Dark Web + RSS" },
            { label: "Signature DB", value: "Verified", icon: Database, color: "cyan", sub: "Vulnerability signatures" },
            { label: "Intelligence Feed", value: `${threats.length} Signals`, icon: ShieldAlert, color: "purple", sub: "Crawled indicators" },
            { label: "AI Engine", value: "Online", icon: Activity, color: "green", sub: "Continuous analysis" },
          ].map((stat, i) => (
            <div key={i} className={`stat-card ${stat.color} animate-in`}>
              <div className={`stat-icon ${stat.color}`}>
                <stat.icon size={18} />
              </div>
              <div className="stat-label">{stat.label}</div>
              <div className="stat-value">{stat.value}</div>
              <div className="stat-sub">{stat.sub}</div>
            </div>
          ))}
        </div>

        {/* Live Threat signals */}
        <div className="card card-glow-purple animate-in">
          <div className="card-header">
            <div className="card-title">
              <ShieldAlert size={14} />
              Live Threat intelligence signals
            </div>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.7rem", color: "var(--fg-dim)" }}>
              Updates every 15 seconds
            </span>
          </div>
          <div className="card-body" style={{ padding: 0 }}>
            {loading && (
              <div style={{ padding: 20 }}>
                {[1, 2, 3].map(i => (
                  <div key={i} className="skeleton" style={{ height: 48, marginBottom: 8 }} />
                ))}
              </div>
            )}
            {!loading && threats.length === 0 && (
              <div className="empty" style={{ padding: 40 }}>
                <Server size={32} />
                <span>Crawling OSINT feeds... waiting for initial signals.</span>
              </div>
            )}
            {!loading && threats.length > 0 && (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Signal ID</th>
                    <th>Source</th>
                    <th>Indicator / Vulnerability Target</th>
                    <th>Severity</th>
                    <th>Crawled At</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((t) => (
                    <tr key={t.id}>
                      <td style={{ color: "var(--purple)", fontFamily: "var(--font-mono)" }}>{t.id}</td>
                      <td style={{ color: "var(--fg)" }}>{t.source}</td>
                      <td className="mono" style={{ color: "var(--fg-muted)" }}>{t.indicator}</td>
                      <td>
                        <span className={`badge ${sevBadge(t.severity)}`}>
                          {t.severity}
                        </span>
                      </td>
                      <td className="mono">{new Date(t.timestamp).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

      </main>
    </div>
  );
}
