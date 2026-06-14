"use client";
import { useHealth } from "@/hooks/useBackendData";
import { useWebSocket } from "@/hooks/useWebSocket";
import { Clock } from "lucide-react";
import { useState, useEffect } from "react";

export default function TopBar() {
  const { data: health } = useHealth();
  const { connected }    = useWebSocket();
  const [time, setTime]  = useState("");

  // Only render time on client to avoid SSR hydration mismatch
  useEffect(() => {
    const tick = () => setTime(new Date().toLocaleTimeString("en-US", { hour12: false }));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="topbar">
      <div className="topbar-left">
        <span className="topbar-title" style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 700, letterSpacing: "1px" }}>
          <span style={{ color: "var(--accent)" }}>[NEXUSGUARD // EXPLOIT ORACLE]</span> COMMAND CENTER
        </span>
      </div>
      <div className="topbar-right">
        <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
          {connected
            ? <><div className="status-dot online" /><span>WS Live</span></>
            : <><div className="status-dot offline" /><span>WS Offline</span></>
          }
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>
          {health?.status === "ok"
            ? <><div className="status-dot online" /><span>Backend OK</span></>
            : <><div className="status-dot offline" /><span>Backend Down</span></>
          }
        </div>
        {health && (
          <span style={{ color: "var(--fg-dim)", fontSize: "0.7rem", fontFamily: "var(--font-mono)" }}>
            uptime {health.uptime}s
          </span>
        )}
        {time && (
          <div style={{ display: "flex", alignItems: "center", gap: 4, color: "var(--fg-dim)" }}>
            <Clock size={12} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{time}</span>
          </div>
        )}
      </div>
    </header>
  );
}
