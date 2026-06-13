/**
 * NexusGuard AI — Express Server
 * GitHub Webhook Receiver with HMAC-SHA256 signature verification.
 *
 * Env vars required:
 *   PORT                  — TCP port to listen on            (default: 3000)
 *   GITHUB_WEBHOOK_SECRET — Shared secret set in GitHub repo settings
 */

import express from "express";
import crypto from "crypto";
import { createServer } from "http";
import { WebSocketServer } from "ws";
import { runStore, scoreStore, computeScore } from "./store.js";
import { processVulnerabilityWorkflow, registerWsServer } from "./orchestrator.js";
import bountyRoutes from "./web3/routes/bountyRoutes.js";

// ─── Constants ───────────────────────────────────────────────────────────────

const PORT = process.env.PORT ?? 3000;
const GITHUB_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET;

// Supported GitHub event types this server cares about.
const SUPPORTED_EVENTS = new Set(["push", "pull_request"]);

// ─── Logging Helpers ─────────────────────────────────────────────────────────

/**
 * Minimal structured logger that emits JSON lines to stdout/stderr.
 * Replace with winston/pino in production.
 */
const log = {
  info: (message, meta = {}) =>
    console.log(JSON.stringify({ level: "info", timestamp: new Date().toISOString(), message, ...meta })),

  warn: (message, meta = {}) =>
    console.warn(JSON.stringify({ level: "warn", timestamp: new Date().toISOString(), message, ...meta })),

  error: (message, meta = {}) =>
    console.error(JSON.stringify({ level: "error", timestamp: new Date().toISOString(), message, ...meta })),
};

// ─── Startup Validation ───────────────────────────────────────────────────────

if (!GITHUB_WEBHOOK_SECRET) {
  log.error("GITHUB_WEBHOOK_SECRET is not set. Server cannot start securely.");
  process.exit(1);
}

// ─── App Initialisation ───────────────────────────────────────────────────────

const app = express();

/**
 * We need the raw request body Buffer to verify GitHub's HMAC signature.
 * `express.json()` alone discards it, so we use `express.raw()` with a
 * custom verify callback that stashes the raw bytes on `req`.
 */
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// ─── CORS ─────────────────────────────────────────────────────────────────────
// Allow the Next.js frontend (port 3001) and any configured origin to call APIs.
const ALLOWED_ORIGINS = [
  "http://localhost:3001",
  "http://localhost:3000",
  process.env.FRONTEND_ORIGIN ?? "",
].filter(Boolean);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin ?? "*");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization,X-NexusGuard-Signature");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ─── In-Memory Run Store ──────────────────────────────────────────────────────
// Imported from store.js (shared with orchestrator.js) to avoid circular imports.
// runStore: Map<runId, pipelineStateSnapshot>

// ─── Routes: Liveness & Status ───────────────────────────────────────────────

/**
 * GET /health
 * Liveness probe for Docker / Kubernetes / load balancers.
 * Also used by the GitHub Actions workflow to confirm the server is reachable.
 */
app.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "nexusguard-ai",
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

/**
 * GET /api/status/:runId
 * Returns the current pipeline state for a given run.
 * The orchestrator updates runStore at each state transition.
 */
app.get("/api/status/:runId", (req, res) => {
  const entry = runStore.get(req.params.runId);
  if (!entry) {
    return res.status(404).json({ error: `Run '${req.params.runId}' not found.` });
  }
  return res.status(200).json(entry);
});

// ─── Dashboard API: Security Command Center ───────────────────────────────────

/**
 * GET /api/runs
 * Live vulnerability feed — returns the last N pipeline runs.
 * Used by the dashboard's "Live Vulnerability Feeds" panel.
 *
 * Query params:
 *   ?limit=20     — max runs to return (default 20)
 *   ?repo=name    — filter by repo name
 *   ?state=FAILED — filter by pipeline state
 */
app.get("/api/runs", (req, res) => {
  const limit  = Math.min(parseInt(req.query.limit ?? "20", 10), 100);
  const repo   = req.query.repo ?? null;
  const state  = req.query.state ?? null;

  let runs = [...runStore.values()]
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));

  if (repo)  runs = runs.filter(r => r.repoName === repo);
  if (state) runs = runs.filter(r => r.state === state);

  runs = runs.slice(0, limit);

  return res.status(200).json({
    total:   runStore.size,
    count:   runs.length,
    runs,
  });
});

/**
 * GET /api/score/:repoName
 * Project Security Score for the dashboard's score panel.
 * Returns score 0-100, grade, and breakdown.
 */
app.get("/api/score/:repoName", (req, res) => {
  const name  = req.params.repoName;
  const entry = scoreStore.get(name);

  if (!entry) {
    // No scan yet — return a neutral score
    return res.status(200).json({
      repoName: name,
      score:    null,
      grade:    null,
      message:  "No scan data available yet. Trigger a scan to get a score.",
    });
  }

  return res.status(200).json(entry);
});

/**
 * GET /api/scores
 * Returns security scores for all repos that have been scanned.
 */
app.get("/api/scores", (_req, res) => {
  const scores = [...scoreStore.values()]
    .sort((a, b) => a.score - b.score); // worst first
  return res.status(200).json({ count: scores.length, scores });
});

/**
 * GET /api/patches
 * Patch Status Tracking — all runs that reached PATCH_RECEIVED or beyond.
 */
app.get("/api/patches", (req, res) => {
  const limit = Math.min(parseInt(req.query.limit ?? "20", 10), 100);

  const PATCH_STATES = new Set([
    "PATCH_RECEIVED", "SUBMITTING_PATCH", "PATCH_SUBMITTED",
    "TRIGGERING_BOUNTY", "BOUNTY_RELEASED", "COMPLETED",
  ]);

  const patches = [...runStore.values()]
    .filter(r => PATCH_STATES.has(r.state) || r.patchResult)
    .sort((a, b) => new Date(b.updatedAt ?? b.startedAt) - new Date(a.updatedAt ?? a.startedAt))
    .slice(0, limit)
    .map(r => ({
      runId:      r.runId,
      repoName:   r.repoName,
      commitSha:  r.commitSha,
      state:      r.state,
      prUrl:      r.patchResult?.prUrl ?? null,
      prNumber:   r.patchResult?.prNumber ?? null,
      patchedAt:  r.updatedAt,
      txHash:     r.blockchainResult?.txHash ?? null,
      explorerUrl: r.blockchainResult?.explorerUrl ?? null,
    }));

  return res.status(200).json({ count: patches.length, patches });
});

/**
 * POST /api/scan/manual
 * Trigger a manual scan from the dashboard (no GitHub webhook needed).
 *
 * Body: { cloneUrl, commitSha?, repoName?, senderLogin? }
 */
app.post("/api/scan/manual", (req, res) => {
  const { cloneUrl, commitSha = "HEAD", repoName, senderLogin = "dashboard" } = req.body ?? {};

  if (!cloneUrl) {
    return res.status(400).json({ error: "'cloneUrl' is required." });
  }

  const resolvedRepo = repoName ?? cloneUrl.split("/").pop()?.replace(".git", "") ?? "unknown";

  log.info("Manual scan triggered.", { cloneUrl, commitSha, repoName: resolvedRepo, senderLogin });

  // Non-blocking — same as GitHub webhook path
  processVulnerabilityWorkflow({
    cloneUrl,
    commitSha,
    repoName:    resolvedRepo,
    senderLogin,
  })
    .then((result) => {
      // Compute score after scan completes
      const run = runStore.get(result.runId);
      if (run?.scanReport) {
        computeScore(resolvedRepo, run.scanReport);
      }
      log.info("Manual scan completed.", { runId: result.runId, state: result.finalState });
    })
    .catch((err) => {
      log.error("Manual scan failed.", { error: err.message });
    });

  return res.status(202).json({
    message:  "Manual scan queued.",
    cloneUrl,
    repoName: resolvedRepo,
    commitSha,
  });
});


// ─── Middleware: HMAC-SHA256 Signature Verification ───────────────────────────

/**
 * Validates the `X-Hub-Signature-256` header sent by GitHub.
 *
 * GitHub computes:
 *   HMAC-SHA256(secret, rawRequestBody) → hex digest
 * and sends it as `sha256=<digest>`.
 *
 * We replicate the computation and use `timingSafeEqual` to prevent
 * timing-based side-channel attacks.
 */
const verifyGitHubSignature = (req, res, next) => {
  const signatureHeader = req.headers["x-hub-signature-256"];

  if (!signatureHeader) {
    log.warn("Webhook rejected — missing X-Hub-Signature-256 header", {
      ip: req.ip,
    });
    return res.status(401).json({ error: "Missing signature header." });
  }

  if (!req.rawBody) {
    log.error("Raw body unavailable — cannot verify signature.");
    return res.status(500).json({ error: "Internal signature verification error." });
  }

  const expectedSignature = `sha256=${crypto
    .createHmac("sha256", GITHUB_WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex")}`;

  // Convert both strings to Buffers of equal length to prevent length leaks.
  const sigBuf = Buffer.from(signatureHeader, "utf8");
  const expectedBuf = Buffer.from(expectedSignature, "utf8");

  const signaturesMatch =
    sigBuf.byteLength === expectedBuf.byteLength &&
    crypto.timingSafeEqual(sigBuf, expectedBuf);

  if (!signaturesMatch) {
    log.warn("Webhook rejected — invalid signature.", {
      ip: req.ip,
      received: signatureHeader,
    });
    return res.status(401).json({ error: "Invalid signature." });
  }

  next();
};

// ─── Route: POST /api/webhook/github ─────────────────────────────────────────

app.post("/api/webhook/github", verifyGitHubSignature, (req, res) => {
  const eventType = req.headers["x-github-event"];
  const deliveryId = req.headers["x-github-delivery"] ?? "unknown";
  const payload = req.body;

  // ── Validate event type ──────────────────────────────────────────────────

  if (!eventType) {
    log.warn("Webhook received with no X-GitHub-Event header.", { deliveryId });
    return res.status(400).json({ error: "Missing X-GitHub-Event header." });
  }

  if (!SUPPORTED_EVENTS.has(eventType)) {
    log.info(`Ignoring unsupported event type: '${eventType}'.`, { deliveryId });
    // Return 200 — GitHub expects a success ACK even for ignored events.
    return res.status(200).json({ message: `Event '${eventType}' received but not processed.` });
  }

  // ── Extract common fields ────────────────────────────────────────────────

  const repository = payload?.repository;
  const sender = payload?.sender;

  if (!repository) {
    log.error("Malformed payload — 'repository' object is missing.", { deliveryId, eventType });
    return res.status(422).json({ error: "Malformed payload: missing 'repository' object." });
  }

  const cloneUrl = repository.clone_url;
  const repoName = repository.name;
  const senderLogin = sender?.login ?? "unknown";

  // ── Extract event-specific SHA ───────────────────────────────────────────

  let commitSha;

  if (eventType === "push") {
    commitSha = payload.after;

    if (!commitSha || commitSha === "0000000000000000000000000000000000000000") {
      // The all-zeros SHA means the branch was deleted — nothing to scan.
      log.info("Push event is a branch deletion. Skipping scan.", {
        deliveryId,
        repoName,
        senderLogin,
      });
      return res.status(200).json({ message: "Branch deletion event ignored." });
    }
  } else if (eventType === "pull_request") {
    // For PRs we scan the head commit of the incoming branch.
    commitSha = payload.pull_request?.head?.sha;

    const prAction = payload.action;
    const prNumber = payload.pull_request?.number;

    // Only trigger a scan on actionable PR lifecycle events.
    const SCAN_TRIGGERING_ACTIONS = new Set(["opened", "synchronize", "reopened"]);
    if (!SCAN_TRIGGERING_ACTIONS.has(prAction)) {
      log.info(`PR action '${prAction}' does not trigger a scan.`, {
        deliveryId,
        repoName,
        prNumber,
        senderLogin,
      });
      return res.status(200).json({ message: `PR action '${prAction}' acknowledged but not scanned.` });
    }

    log.info("Pull request scan triggered.", { deliveryId, repoName, prNumber, prAction, senderLogin });
  }

  if (!commitSha) {
    log.error("Could not extract commit SHA from payload.", { deliveryId, eventType });
    return res.status(422).json({ error: "Malformed payload: could not determine commit SHA." });
  }

  // ── Structured event log ─────────────────────────────────────────────────

  const scanContext = {
    deliveryId,
    eventType,
    repoName,
    cloneUrl,
    commitSha,
    senderLogin,
  };

  log.info("Scan context extracted — dispatching to orchestrator.", scanContext);

  // ── Trigger full pipeline (non-blocking — GitHub needs < 10 s response) ──
  // processVulnerabilityWorkflow never throws; it always returns a result object.
  processVulnerabilityWorkflow({
    cloneUrl:    cloneUrl,
    commitSha:   commitSha,
    repoName:    repoName,
    senderLogin: senderLogin,
  })
    .then((result) => {
      if (result.success) {
        log.info("Pipeline completed.", {
          runId:      result.runId,
          finalState: result.finalState,
          repoName,
          commitSha,
        });
      } else {
        log.error("Pipeline returned failure.", {
          runId:      result.runId,
          finalState: result.finalState,
          error:      result.error,
          repoName,
          commitSha,
        });
      }
    })
    .catch((err) => {
      // Should never reach here — orchestrator catches internally.
      log.error("Unexpected orchestrator rejection.", { error: err.message, repoName, commitSha });
    });

  return res.status(202).json({
    message: "Webhook received. Security scan queued.",
    ...scanContext,
  });
});

// ─── Web3 / Blockchain Oracle Routes ────────────────────────────────────────

/**
 * All Yadnesh's blockchain routes are mounted here.
 * The existing express.json() verify callback above already populates
 * req.rawBody (Buffer) which bountyController uses for HMAC verification.
 *
 * Routes exposed:
 *   GET  /api/web3/health          — Oracle wallet liveness probe
 *   GET  /api/web3/bounty/:bugId   — On-chain bounty state (public)
 *   POST /api/web3/trigger-bounty  — Internal loopback from orchestrator
 *   POST /api/web3/webhook/merge   — External HMAC-authenticated release
 */
app.use("/api/web3", bountyRoutes);

// ─── Global Error Handler ─────────────────────────────────────────────────────

// Catches JSON parse errors (malformed body) and any other unhandled errors.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err.type === "entity.parse.failed") {
    log.warn("Received malformed JSON body.", { ip: req.ip, error: err.message });
    return res.status(400).json({ error: "Invalid JSON body." });
  }

  log.error("Unhandled server error.", { error: err.message, stack: err.stack });
  return res.status(500).json({ error: "Internal server error." });
});

// ─── HTTP + WebSocket Server ──────────────────────────────────────────────────

// Wrap Express in a raw http.Server so the WebSocket server can share the
// same port via HTTP 'upgrade' — no second port needed.
const httpServer = createServer(app);

const wss = new WebSocketServer({ server: httpServer });
registerWsServer(wss);

httpServer.listen(PORT, () => {
  log.info("NexusGuard AI server listening.", {
    port: PORT,
    env: process.env.NODE_ENV ?? "development",
    wsEndpoint: `ws://localhost:${PORT}`,
  });
});

export default app;
