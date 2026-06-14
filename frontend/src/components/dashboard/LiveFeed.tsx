"use client";
import { useWebSocket, type WsEvent } from "@/hooks/useWebSocket";
import { Activity, CheckCircle2, AlertTriangle, Wifi } from "lucide-react";

function eventColor(ev: WsEvent): string {
  if (ev.event === "PIPELINE_FAILED") return "error";
  if (ev.event === "SCAN_COMPLETE")   return "success";
  return "info";
}

function stateColor(state?: string): string {
  if (!state) return "muted";
  if (state.includes("FAILED") || state.includes("ERROR")) return "red";
  if (state === "COMPLETED" || state === "BOUNTY_RELEASED") return "green";
  if (state === "SCANNING" || state === "REQUESTING_PATCH") return "cyan";
  if (state === "VULNS_DETECTED") return "orange";
  return "muted";
}

const STATE_BADGE_MAP: Record<string, string> = {
  STARTED:           "badge-cyan",   SCANNING:          "badge-cyan",
  SCAN_COMPLETE:     "badge-yellow", NO_VULNS_FOUND:    "badge-green",
  VULNS_DETECTED:    "badge-orange",
  REQUESTING_PATCH:  "badge-cyan",   PATCH_RECEIVED:    "badge-purple",
  SUBMITTING_PATCH:  "badge-purple", PATCH_SUBMITTED:   "badge-purple",
  TRIGGERING_BOUNTY: "badge-orange", BOUNTY_RELEASED:   "badge-green",
  NOTIFYING_UI:      "badge-cyan",   COMPLETED:         "badge-green",
  FAILED:            "badge-red",
};

export default function LiveFeed() {
  const { events, connected } = useWebSocket();

  return (
    <div className="card card-glow-cyan animate-in">
      <div className="card-header">
        <div className="card-title">
          <Activity size={14} />
          Live Event Feed
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: "0.7rem", fontFamily: "var(--font-mono)" }}>
          <div className={`status-dot ${connected ? "online" : "offline"}`} />
          {connected ? "Connected" : "Reconnecting..."}
          <span style={{ color: "var(--fg-dim)" }}>({events.length} events)</span>
        </div>
      </div>

      <div className="terminal">
        {events.length === 0 ? (
          <div style={{ color: "var(--fg-dim)", textAlign: "center", padding: "20px 0" }}>
            <span className="terminal-cursor">Waiting for pipeline events</span>
          </div>
        ) : (
          events.map((ev, i) => (
            <div key={i} className="terminal-line" style={{ marginBottom: 4 }}>
              <span className="terminal-ts">
                {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString("en-US", { hour12: false }) : "--:--:--"}
              </span>
              <span>
                <span className={`badge ${STATE_BADGE_MAP[ev.state ?? ""] ?? "badge-muted"}`} style={{ marginRight: 8 }}>
                  {ev.state ?? ev.event}
                </span>
                <span className={`terminal-msg ${eventColor(ev)}`}>
                  {ev.repoName && <span style={{ color: "var(--accent)" }}>[{ev.repoName}] </span>}
                  {ev.message ?? ev.event}
                  {ev.commitSha && (
                    <span style={{ color: "var(--fg-dim)", marginLeft: 8 }}>
                      #{ev.commitSha.slice(0, 7)}
                    </span>
                  )}
                </span>
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
