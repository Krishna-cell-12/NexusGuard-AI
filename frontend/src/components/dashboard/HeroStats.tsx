"use client";
import { useRuns, useScores, usePatches } from "@/hooks/useBackendData";
import { Activity, ShieldAlert, GitPullRequest, Coins } from "lucide-react";

export default function HeroStats() {
  const { data: runsData }    = useRuns(100);
  const { data: scoresData }  = useScores();
  const { data: patchesData } = usePatches(100);

  const totalScans  = runsData?.total ?? 0;
  const allRuns     = runsData?.runs ?? [];
  const critVulns   = allRuns.reduce((s, r) =>
    s + (r.scanReport?.vulnerabilities.filter(v => v.severity === "ERROR").length ?? 0), 0);
  const patchCount  = patchesData?.count ?? 0;
  const bountyCount = patchesData?.patches.filter(p => p.txHash).length ?? 0;

  const stats = [
    { label: "Total Scans",    value: totalScans,  icon: Activity,     color: "green",  sub: "Pipeline runs" },
    { label: "Critical Vulns", value: critVulns,   icon: ShieldAlert,  color: "red",    sub: "ERROR severity" },
    { label: "AI Patches",     value: patchCount,  icon: GitPullRequest, color: "cyan", sub: "Generated PRs" },
    { label: "Bounties Released", value: bountyCount, icon: Coins,     color: "purple", sub: "On-chain rewards" },
  ];

  return (
    <div className="stats-grid">
      {stats.map(({ label, value, icon: Icon, color, sub }) => (
        <div key={label} className={`stat-card ${color} animate-in`}>
          <div className={`stat-icon ${color}`}>
            <Icon size={18} />
          </div>
          <div className="stat-label">{label}</div>
          <div className="stat-value">{value}</div>
          <div className="stat-sub">{sub}</div>
        </div>
      ))}
    </div>
  );
}
