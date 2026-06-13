"use client";
import { useHealth } from "@/hooks/useBackendData";
import { useWebSocket } from "@/hooks/useWebSocket";
import { Wifi, WifiOff, Clock } from "lucide-react";

export default function TopBar() {
  const { data: health } = useHealth();
  const { connected }    = useWebSocket();

  const now = new Date().toLocaleTimeString("en-US", { hour12: false });

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title">NEXUSGUARD AI // SECURITY COMMAND CENTER</span>
      </div>
      <div className="topbar-right">
        {/* WebSocket status */}
        <div className="flex gap-2" style={{ alignItems: "center", gap: 6 }}>
          {connected
            ? <><div className="status-dot online" /><span>WS Live</span></>
            : <><div className="status-dot offline" /><span>WS Offline</span></>
          }
        </div>

        {/* Backend health */}
        <div className="flex gap-2" style={{ alignItems: "center", gap: 6 }}>
          {health?.status === "ok"
            ? <><div className="status-dot online" /><span>Backend OK</span></>
            : <><div className="status-dot offline" /><span>Backend Down</span></>
          }
        </div>

        {health && (
          <span style={{ color: "var(--fg-dim)", fontSize: "0.7rem" }}>
            uptime {health.uptime}s
          </span>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--fg-dim)" }}>
          <Clock size={12} />
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{now}</span>
        </div>
      </div>
    </header>
  );
}
