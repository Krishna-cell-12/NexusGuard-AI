"use client";
import { useRuns } from "@/hooks/useBackendData";
import { useWebSocket } from "@/hooks/useWebSocket";
import { GitBranch, CheckCircle2, XCircle, Loader2 } from "lucide-react";

type PState = string;

const STEPS = [
  { key: "STARTED",          label: "Started" },
  { key: "SCANNING",         label: "Scanning" },
  { key: "REQUESTING_PATCH", label: "AI Patch" },
  { key: "PATCH_RECEIVED",   label: "Patched" },
  { key: "TRIGGERING_BOUNTY",label: "Bounty" },
  { key: "COMPLETED",        label: "Done" },
];

const ORDER: Record<string, number> = {
  STARTED: 0, SCANNING: 1, SCAN_COMPLETE: 1, NO_VULNS_FOUND: 5,
  REQUESTING_PATCH: 2, PATCH_RECEIVED: 3, SUBMITTING_PATCH: 3, PATCH_SUBMITTED: 3,
  TRIGGERING_BOUNTY: 4, BOUNTY_RELEASED: 4, NOTIFYING_UI: 5, COMPLETED: 5, FAILED: -1,
};

function nodeStatus(stepIdx: number, currentIdx: number, failed: boolean) {
  if (failed) return stepIdx <= currentIdx ? "failed" : "pending";
  if (stepIdx < currentIdx) return "done";
  if (stepIdx === currentIdx) return "active";
  return "pending";
}

const STATE_BADGE: Record<string, string> = {
  STARTED: "badge-cyan", SCANNING: "badge-cyan", SCAN_COMPLETE: "badge-yellow",
  NO_VULNS_FOUND: "badge-green", REQUESTING_PATCH: "badge-cyan", PATCH_RECEIVED: "badge-purple",
  SUBMITTING_PATCH: "badge-purple", PATCH_SUBMITTED: "badge-purple",
  TRIGGERING_BOUNTY: "badge-orange", BOUNTY_RELEASED: "badge-green",
  NOTIFYING_UI: "badge-cyan", COMPLETED: "badge-green", FAILED: "badge-red",
};

export default function PipelineTracker() {
  const { data }      = useRuns(10);
  const { lastEvent } = useWebSocket();

  const runs = data?.runs ?? [];
  const latest = runs[0];

  // Merge live WebSocket state
  const liveState: PState | undefined = lastEvent?.state ?? latest?.state;
  const failed  = liveState === "FAILED";
  const curIdx  = ORDER[liveState ?? ""] ?? 0;

  return (
    <div className="card card-glow-green animate-in">
      <div className="card-header">
        <div className="card-title">
          <GitBranch size={14} />
          Pipeline Tracker
        </div>
        {liveState && (
          <span className={`badge ${STATE_BADGE[liveState] ?? "badge-muted"}`}>
            {liveState.replace(/_/g, " ")}
          </span>
        )}
      </div>

      {/* Pipeline Steps */}
      <div className="pipeline">
        {STEPS.map((step, i) => {
          const status = nodeStatus(i, curIdx, failed);
          const isLast = i === STEPS.length - 1;
          return (
            <div key={step.key} style={{ display: "flex", alignItems: "center" }}>
              <div className="pipeline-step">
                <div className={`pipeline-node ${status}`}>
                  {status === "done"   && <CheckCircle2 size={14} />}
                  {status === "active" && <Loader2 size={14} style={{ animation: "spin 1s linear infinite" }} />}
                  {status === "failed" && <XCircle size={14} />}
                  {status === "pending" && <span style={{ fontSize: "0.6rem" }}>{i + 1}</span>}
                </div>
                <span className="pipeline-label">{step.label}</span>
              </div>
              {!isLast && (
                <div className={`pipeline-connector ${status === "done" || (status === "active" && i < curIdx) ? "done" : ""}`} />
              )}
            </div>
          );
        })}
      </div>

      {/* Recent runs table */}
      <div style={{ padding: "0 20px 20px" }}>
        <div style={{ fontSize: "0.7rem", color: "var(--fg-dim)", fontFamily: "var(--font-mono)", marginBottom: 10, letterSpacing: 1 }}>
          RECENT RUNS
        </div>
        {runs.length === 0 ? (
          <div className="empty" style={{ padding: "16px 0" }}>No pipeline runs yet. Trigger a scan to start.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Repo</th><th>State</th><th>Commit</th><th>Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.slice(0, 6).map((r) => (
                <tr key={r.runId}>
                  <td style={{ color: "var(--accent)" }}>{r.repoName}</td>
                  <td><span className={`badge ${STATE_BADGE[r.state] ?? "badge-muted"}`}>{r.state.replace(/_/g, " ")}</span></td>
                  <td className="mono">{r.commitSha?.slice(0, 7) ?? "—"}</td>
                  <td className="mono">{new Date(r.startedAt).toLocaleTimeString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
