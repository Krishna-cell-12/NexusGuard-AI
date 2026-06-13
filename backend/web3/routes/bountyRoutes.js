/**
 * NexusGuard AI — Web3 / Oracle Routes  (ESM)
 * backend/web3/routes/bountyRoutes.js
 *
 * Mounted in server.js as:
 *   app.use('/api/web3', bountyRoutes);
 *
 * Resulting public routes:
 *   GET  /api/web3/health              — Oracle liveness probe
 *   GET  /api/web3/bounty/:bugId       — On-chain bounty status (public read)
 *   POST /api/web3/submit-patch        — Internal: transition bounty OPEN → SUBMITTED
 *   POST /api/web3/trigger-bounty      — Internal loopback (orchestrator → bounty release, no HMAC)
 *   POST /api/web3/webhook/merge       — External HMAC-authenticated bounty release
 */

import { Router } from "express";
import {
  healthCheck,
  getBountyStatus,
  submitPatchController,
  triggerBounty,
  handleMergeWebhook,
} from "../controllers/bountyController.js";

const router = Router();

// ── Liveness probe ───────────────────────────────────────────────────────────
router.get("/health", healthCheck);

// ── On-chain bounty query ────────────────────────────────────────────────────
router.get("/bounty/:bugId", getBountyStatus);

// ── Internal: submit patch (OPEN → SUBMITTED) ───────────────────────────────
// Called by the orchestrator after the AI service generates and creates a patch PR.
router.post("/submit-patch", submitPatchController);

// ── Internal loopback route (called by orchestrator — NO HMAC) ───────────────
// This is intentionally not HMAC-gated: it is only reachable on localhost:3000
// from within the same Node.js process (the orchestrator).
router.post("/trigger-bounty", triggerBounty);

// ── External HMAC-authenticated webhook ─────────────────────────────────────
// Called by external CI/CD systems with X-NexusGuard-Signature header.
router.post("/webhook/merge", handleMergeWebhook);

export default router;
