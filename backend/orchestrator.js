/**
 * NexusGuard AI — Orchestration Controller
 *
 * processVulnerabilityWorkflow() is the central pipeline that sequences:
 *   1. Security scanning       (scanner.js)
 *   2. AI patch generation     (AI microservice  → POST :8000)
 *   3. Web3 bounty release     (Web3 microservice → POST :8001)
 *   4. Frontend notification   (WebSocket broadcast + HTTP webhook fallback)
 *
 * Every state transition is logged as a structured JSON line so you can
 * pinpoint exactly which step fails during the live demo.
 *
 * Env vars consumed (all optional — defaults shown):
 *   AI_SERVICE_URL      http://localhost:8000/api/ai/generate-patch
 *   WEB3_SERVICE_URL    http://localhost:8001/api/web3/trigger-bounty
 *   FRONTEND_WEBHOOK_URL  (optional HTTP fallback when no WS clients connected)
 *   HTTP_TIMEOUT_MS     10000
 */

import axios from "axios";
import { rm } from "fs/promises";
import { cloneRepository, runSemgrep, runTruffleHog } from "./scanner.js";
import { runDynamicAnalysis } from "./sandbox.js";
import { runStore } from "./store.js";

// ─── Config ───────────────────────────────────────────────────────────────────

const AI_SERVICE_URL =
  process.env.AI_SERVICE_URL ?? "http://localhost:8000/api/ai/generate-patch";

const WEB3_SERVICE_URL =
  process.env.WEB3_SERVICE_URL ?? "http://localhost:3000/api/web3/trigger-bounty";

const FRONTEND_WEBHOOK_URL = process.env.FRONTEND_WEBHOOK_URL ?? null;

const HTTP_TIMEOUT_MS = Number(process.env.HTTP_TIMEOUT_MS ?? 10_000);

// ─── Pipeline State Enum ─────────────────────────────────────────────────────

/**
 * Canonical state labels emitted in every log line.
 * Lets you grep a log stream with `grep '"state"' server.log` during a demo.
 */
export const PipelineState = Object.freeze({
  STARTED:          "STARTED",
  SCANNING:         "SCANNING",
  SCAN_COMPLETE:    "SCAN_COMPLETE",
  NO_VULNS_FOUND:   "NO_VULNS_FOUND",
  REQUESTING_PATCH: "REQUESTING_PATCH",
  PATCH_RECEIVED:   "PATCH_RECEIVED",
  TRIGGERING_BOUNTY:"TRIGGERING_BOUNTY",
  BOUNTY_RELEASED:  "BOUNTY_RELEASED",
  NOTIFYING_UI:     "NOTIFYING_UI",
  COMPLETED:        "COMPLETED",
  FAILED:           "FAILED",
});

// ─── WebSocket Registry ───────────────────────────────────────────────────────

/**
 * Set of active WebSocket client connections, populated by registerWsServer().
 * The orchestrator pushes pipeline events to all connected clients.
 */
const wsClients = new Set();

/**
 * Attach a `ws.WebSocketServer` instance so the orchestrator can broadcast
 * events to the frontend in real time.
 *
 * Call this once from server.js after creating the WS server:
 *   import { registerWsServer } from './orchestrator.js';
 *   registerWsServer(wss);
 *
 * @param {import('ws').WebSocketServer} wss
 */
export function registerWsServer(wss) {
  wss.on("connection", (ws) => {
    wsClients.add(ws);
    ws.on("close", () => wsClients.delete(ws));
    ws.on("error", ()  => wsClients.delete(ws));
  });
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/**
 * Structured logger — every line includes a pipeline `runId` so you can
 * filter a single workflow's logs even when multiple scans run concurrently.
 */
function makeLogger(runId) {
  const base = { runId };

  return {
    info:  (state, message, meta = {}) =>
      console.log(JSON.stringify({  level: "info",  timestamp: new Date().toISOString(), state, message, ...base, ...meta })),
    warn:  (state, message, meta = {}) =>
      console.warn(JSON.stringify({ level: "warn",  timestamp: new Date().toISOString(), state, message, ...base, ...meta })),
    error: (state, message, meta = {}) =>
      console.error(JSON.stringify({ level: "error", timestamp: new Date().toISOString(), state, message, ...base, ...meta })),
  };
}

/**
 * Broadcasts a JSON event to every connected WebSocket client.
 * Silently skips clients whose socket is not in OPEN state.
 *
 * @param {object} payload
 */
function broadcastToClients(payload) {
  const message = JSON.stringify(payload);
  for (const client of wsClients) {
    // ws.OPEN === 1
    if (client.readyState === 1) {
      client.send(message, (err) => {
        if (err) wsClients.delete(client); // prune dead sockets
      });
    }
  }
}

/**
 * Creates a pre-configured axios instance with a timeout and JSON headers.
 *
 * @param {string} serviceLabel - Used in error messages for clarity.
 */
function httpClient(serviceLabel) {
  const instance = axios.create({
    timeout: HTTP_TIMEOUT_MS,
    headers: { "Content-Type": "application/json" },
  });

  // Attach an interceptor that enriches axios errors with the service name.
  instance.interceptors.response.use(
    (res) => res,
    (err) => {
      const status  = err.response?.status;
      const detail  = err.response?.data ?? err.message;
      const enriched = new Error(
        `[${serviceLabel}] HTTP ${status ?? "network error"}: ${JSON.stringify(detail)}`
      );
      enriched.status      = status;
      enriched.serviceLabel = serviceLabel;
      enriched.upstream    = detail;
      return Promise.reject(enriched);
    }
  );

  return instance;
}

/**
 * Clones the repository once and fans out to three scanners in parallel:
 *   - Semgrep        (static code analysis)
 *   - TruffleHog     (secret detection)
 *   - Docker sandbox (dynamic analysis — runtime behaviour)
 *
 * All three share the same cloned directory and the directory is always
 * cleaned up in a finally block, regardless of individual scanner failures.
 *
 * @param {{ cloneUrl: string, commitSha: string, repoName: string }} repoDetails
 * @returns {Promise<object>} vulnerabilityReport
 */
async function runScanners(repoDetails) {
  const { cloneUrl, commitSha, repoName } = repoDetails;
  const scannedAt = new Date().toISOString();
  let tempDir = null;

  try {
    // ── Single clone shared by all three scanners ───────────────────────────
    tempDir = await cloneRepository(cloneUrl, commitSha);

    // ── Fan out — all three run concurrently on the same directory ──────────
    const [semgrepResult, truffleHogResult, dynamicResult] = await Promise.allSettled([
      runSemgrep(tempDir),
      runTruffleHog(tempDir),
      runDynamicAnalysis(tempDir),   // Docker sandbox — network-disabled container
    ]);

    // Tolerate individual scanner failures — partial results are still useful.
    const vulnerabilities = semgrepResult.status    === "fulfilled" ? semgrepResult.value    : [];
    const secrets         = truffleHogResult.status === "fulfilled" ? truffleHogResult.value : [];
    const dynamic         = dynamicResult.status    === "fulfilled" ? dynamicResult.value    : null;

    const scanErrors = [
      semgrepResult.status    === "rejected" ? `Semgrep: ${semgrepResult.reason?.message}`    : null,
      truffleHogResult.status === "rejected" ? `TruffleHog: ${truffleHogResult.reason?.message}` : null,
      dynamicResult.status    === "rejected" ? `Sandbox: ${dynamicResult.reason?.message}`    : null,
    ].filter(Boolean);

    // ── Build summary ───────────────────────────────────────────────────────
    const vulnBySeverity = vulnerabilities.reduce((acc, v) => {
      const key = (v.severity ?? "UNKNOWN").toUpperCase();
      acc[key] = (acc[key] ?? 0) + 1;
      return acc;
    }, {});

    return {
      repoName,
      commitSha,
      scannedAt,
      vulnerabilities,          // Semgrep static findings
      secrets,                  // TruffleHog secret findings
      dynamic,                  // Docker sandbox output (runtime behaviour)
      summary: {
        totalVulnerabilities: vulnerabilities.length,
        totalSecrets:         secrets.length,
        verifiedSecrets:      secrets.filter((s) => s.verified).length,
        vulnBySeverity,
        dynamicAnalysis: dynamic
          ? { runtime: dynamic.runtime, exitCode: dynamic.exitCode, timedOut: dynamic.timedOut }
          : null,
        scanErrors: scanErrors.length ? scanErrors : null,
      },
      hasFindings: vulnerabilities.length > 0 || secrets.length > 0,
    };
  } finally {
    // Always remove the cloned directory — even if all three scanners threw.
    if (tempDir) {
      await rm(tempDir, { recursive: true, force: true }).catch((e) =>
        console.error(JSON.stringify({
          level: "warn", message: "Failed to delete scanner temp dir",
          tempDir, error: e.message,
        }))
      );
    }
  }
}

// ─── Main Orchestrator ────────────────────────────────────────────────────────

/**
 * @typedef {Object} RepoDetails
 * @property {string} cloneUrl   - HTTPS git clone URL.
 * @property {string} commitSha  - Exact commit to scan.
 * @property {string} repoName   - Human-readable repo name.
 * @property {string} senderLogin - GitHub user who triggered the event.
 */

/**
 * @typedef {Object} WorkflowResult
 * @property {boolean}     success          - Whether the pipeline completed.
 * @property {string}      runId            - Unique ID for this workflow run.
 * @property {string}      finalState       - Last PipelineState value reached.
 * @property {object}      vulnerabilityReport
 * @property {string|null} patchCode        - AI-generated patch (if any).
 * @property {string|null} patchExplanation
 * @property {object|null} bountyReceipt    - Web3 transaction receipt (if any).
 * @property {string|null} error            - Error message on failure.
 */

/**
 * Central orchestration pipeline for NexusGuard AI.
 *
 * Runs sequentially:
 *   scan → AI patch → Web3 bounty → frontend notification
 *
 * @param {RepoDetails} repoDetails
 * @returns {Promise<WorkflowResult>}
 */
export async function processVulnerabilityWorkflow(repoDetails) {
  // Every run gets a unique ID so concurrent pipeline logs don't interleave.
  const runId = `run_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
  const log   = makeLogger(runId);
  const http  = httpClient;

  // Accumulated result — built up incrementally so partial results survive errors.
  const result = {
    success:             false,
    runId,
    finalState:          PipelineState.STARTED,
    vulnerabilityReport: null,
    patchCode:           null,
    patchExplanation:    null,
    bountyReceipt:       null,
    error:               null,
  };

  // Helper: update state, log it, persist to runStore, and broadcast to WS clients.
  const transition = (state, message, meta = {}) => {
    result.finalState = state;
    log.info(state, message, meta);
    // Persist to in-memory store so GET /api/status/:runId returns live state.
    runStore.set(runId, {
      runId,
      state,
      message,
      updatedAt: new Date().toISOString(),
      startedAt: result.startedAt ?? (result.startedAt = new Date().toISOString()),
      repoName: repoDetails.repoName,
      commitSha: repoDetails.commitSha,
      ...meta,
    });
    broadcastToClients({ event: "PIPELINE_STATE", runId, state, message, ...meta });
  };

  try {
    transition(PipelineState.STARTED, "Vulnerability workflow initiated.", {
      repoName:    repoDetails.repoName,
      commitSha:   repoDetails.commitSha,
      senderLogin: repoDetails.senderLogin,
    });

    // ── Step 1: Run Scanners ────────────────────────────────────────────────

    transition(PipelineState.SCANNING, "Cloning repository and running Semgrep + TruffleHog...", {
      cloneUrl: repoDetails.cloneUrl,
    });

    const vulnerabilityReport = await runScanners(repoDetails);
    result.vulnerabilityReport = vulnerabilityReport;

    transition(PipelineState.SCAN_COMPLETE, "Scan finished.", {
      totalVulnerabilities: vulnerabilityReport.summary.totalVulnerabilities,
      totalSecrets:         vulnerabilityReport.summary.totalSecrets,
      verifiedSecrets:      vulnerabilityReport.summary.verifiedSecrets,
      vulnBySeverity:       vulnerabilityReport.summary.vulnBySeverity,
      dynamicAnalysis:      vulnerabilityReport.summary.dynamicAnalysis,
      scanErrors:           vulnerabilityReport.summary.scanErrors,
      hasFindings:          vulnerabilityReport.hasFindings,
    });

    // ── Step 2: Short-circuit if nothing found ──────────────────────────────

    if (!vulnerabilityReport.hasFindings) {
      transition(PipelineState.NO_VULNS_FOUND,
        "No vulnerabilities or secrets detected. Pipeline complete — no patch required.",
        { repoName: repoDetails.repoName }
      );
      result.success = true;
      return result;
    }

    // ── Step 3: Request AI Patch ────────────────────────────────────────────

    transition(PipelineState.REQUESTING_PATCH,
      "Findings detected — requesting AI patch generation.", {
        endpoint: AI_SERVICE_URL,
        findingCount: vulnerabilityReport.summary.totalVulnerabilities +
                      vulnerabilityReport.summary.totalSecrets,
      }
    );

    const aiResponse = await http("AI Patch Service").post(AI_SERVICE_URL, {
      vulnerabilityReport,
    });

    const { patchCode, explanation: patchExplanation } = aiResponse.data;

    if (!patchCode) {
      throw new Error("AI service returned a response but 'patchCode' field is missing.");
    }

    result.patchCode        = patchCode;
    result.patchExplanation = patchExplanation ?? null;

    transition(PipelineState.PATCH_RECEIVED, "AI patch received.", {
      patchLength:  patchCode.length,
      hasExplanation: Boolean(patchExplanation),
    });

    // ── Step 4: Trigger Web3 Bounty ─────────────────────────────────────────

    transition(PipelineState.TRIGGERING_BOUNTY,
      "Triggering Web3 bounty release...", {
        endpoint: WEB3_SERVICE_URL,
        repoName: repoDetails.repoName,
      }
    );

    const web3Response = await http("Web3 Bounty Service").post(WEB3_SERVICE_URL, {
      repoName:    repoDetails.repoName,
      commitSha:   repoDetails.commitSha,
      senderLogin: repoDetails.senderLogin,
      patchCode,
      report:      vulnerabilityReport.summary,
    });

    const bountyReceipt = web3Response.data;
    result.bountyReceipt = bountyReceipt;

    transition(PipelineState.BOUNTY_RELEASED, "Bounty transaction submitted.", {
      txHash:   bountyReceipt?.txHash   ?? "unknown",
      amount:   bountyReceipt?.amount   ?? "unknown",
      currency: bountyReceipt?.currency ?? "unknown",
    });

    // ── Step 5: Notify Frontend ─────────────────────────────────────────────

    transition(PipelineState.NOTIFYING_UI, "Broadcasting results to frontend.");

    const uiPayload = {
      event:       "SCAN_COMPLETE",
      runId,
      repoName:    repoDetails.repoName,
      commitSha:   repoDetails.commitSha,
      summary:     vulnerabilityReport.summary,
      patchCode,
      patchExplanation,
      bountyReceipt,
    };

    // Primary: WebSocket broadcast to all connected dashboard clients.
    const wsClientCount = wsClients.size;
    broadcastToClients(uiPayload);

    // Secondary: HTTP webhook POST to frontend URL (useful when WS not available,
    // e.g. during SSR or when the frontend hasn't connected to the WS yet).
    if (FRONTEND_WEBHOOK_URL) {
      try {
        await http("Frontend Webhook").post(FRONTEND_WEBHOOK_URL, uiPayload);
        log.info(PipelineState.NOTIFYING_UI, "Frontend webhook delivered.", {
          url: FRONTEND_WEBHOOK_URL,
        });
      } catch (webhookErr) {
        // Non-fatal — the WS broadcast already went out.
        log.warn(PipelineState.NOTIFYING_UI,
          "Frontend webhook POST failed (non-fatal).", {
            url:   FRONTEND_WEBHOOK_URL,
            error: webhookErr.message,
          }
        );
      }
    }

    // ── Step 6: Complete ────────────────────────────────────────────────────

    result.success = true;

    transition(PipelineState.COMPLETED, "Vulnerability workflow completed successfully.", {
      wsClientsBroadcasted: wsClientCount,
      webhookSent: Boolean(FRONTEND_WEBHOOK_URL),
    });

    return result;

  } catch (err) {
    // ── Error Path ────────────────────────────────────────────────────────
    result.error = err.message;

    log.error(PipelineState.FAILED, "Pipeline failed.", {
      failedAtState: result.finalState,
      error:         err.message,
      // Include upstream service response body if available.
      upstream:      err.upstream ?? null,
      httpStatus:    err.status   ?? null,
      serviceLabel:  err.serviceLabel ?? null,
    });

    // Broadcast failure to frontend so the dashboard updates immediately.
    broadcastToClients({
      event:        "PIPELINE_FAILED",
      runId,
      failedAtState: result.finalState,
      error:         err.message,
    });

    result.finalState = PipelineState.FAILED;
    return result; // Always return — never re-throw (caller decides on HTTP status)
  }
}
