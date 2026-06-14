"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Activity, GitBranch, Cpu, Box, Zap, Terminal, BarChart2
} from "lucide-react";

const NAV = [
  { href: "/", icon: BarChart2, label: "Command Center" },
  { href: "/scan", icon: Terminal, label: "Manual Scan" },
];

export default function Sidebar() {
  const path = usePathname();
  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <Terminal size={18} style={{ marginRight: 8, color: "var(--accent)", filter: "drop-shadow(0 0 3px var(--accent))" }} />
        <span style={{ fontWeight: 700, letterSpacing: "1px", fontFamily: "var(--font-mono)" }}>NexusGuard AI</span>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="sidebar-section">Navigation</div>
        {NAV.map(({ href, icon: Icon, label }) => (
          <Link
            key={href}
            href={href}
            className={`sidebar-link${path === href ? " active" : ""}`}
          >
            <Icon size={15} />
            {label}
          </Link>
        ))}

        <div className="sidebar-section" style={{ marginTop: 16 }}>Services</div>
        <div className="sidebar-link" style={{ cursor: "default" }}>
          <Activity size={15} />
          Backend :3000
        </div>
        <div className="sidebar-link" style={{ cursor: "default" }}>
          <Cpu size={15} />
          AI Patch :8000
        </div>
        <div className="sidebar-link" style={{ cursor: "default" }}>
          <Box size={15} />
          Web3 Oracle :8001
        </div>
        <div className="sidebar-link" style={{ cursor: "default" }}>
          <GitBranch size={15} />
          GitHub Webhook
        </div>
        <div className="sidebar-link" style={{ cursor: "default" }}>
          <Zap size={15} />
          Polygon Amoy
        </div>
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div style={{ marginBottom: 8, fontStyle: "italic", fontSize: "0.58rem", color: "var(--fg-dim)", lineHeight: "1.3" }}>
          "ALL YOUR BASE ARE BELONG TO US."
        </div>
        <div style={{ marginBottom: 4 }}>[SYSTEM STATUS: ESCALATED]</div>
        <div style={{ color: "var(--accent)", fontSize: "0.65rem" }}>
          ● EXPLOIT ORACLE ONLINE
        </div>
      </div>
    </aside>
  );
}
