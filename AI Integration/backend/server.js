// ============================================================
//  NexusGuard AI — Express Backend Server
//  backend/server.js
//
//  Entry point for the Oracle API backend.
//  Mounts all routes and starts listening.
// ============================================================

"use strict";

const express  = require("express");
const cors     = require("cors");
const helmet   = require("helmet");
const morgan   = require("morgan");
require("dotenv").config();

const bountyController = require("./controllers/bountyController");

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Middleware ────────────────────────────────────────────────
app.use(helmet());        // Security headers
app.use(cors());          // CORS (tighten in production)
app.use(morgan("combined")); // Request logging

// ⚠️  express.json() MUST come before route mounting.
// The raw body string is reconstructed as JSON.stringify(req.body)
// inside bountyController for HMAC verification.
app.use(express.json({ limit: "10kb" })); // Cap payload to prevent DoS

// ── Routes ────────────────────────────────────────────────────

/**
 * @route   GET /api/health
 * @desc    Liveness probe — returns Oracle wallet status & current block.
 * @access  Public
 */
app.get("/api/health", bountyController.healthCheck);

/**
 * @route   GET /api/bounty/:bugId
 * @desc    Fetch the on-chain state of a specific bounty.
 * @access  Public
 */
app.get("/api/bounty/:bugId", bountyController.getBountyStatus);

/**
 * @route   POST /api/webhooks/github/merge
 * @desc    Called by NexusGuard AI when a verified patch PR is merged.
 *          Authenticates via HMAC-SHA256 header, then triggers releaseBounty().
 * @access  Protected (HMAC webhook signature required)
 */
app.post("/api/webhooks/github/merge", bountyController.handleMergeWebhook);

// ── 404 Handler ───────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, error: "Route not found" });
});

// ── Global Error Handler ──────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("[NexusGuard] Unhandled error:", err);
  res.status(500).json({
    success: false,
    error:   "Internal server error",
    detail:  process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

// ── Start Server ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🛡️  NexusGuard Oracle Backend running on port ${PORT}`);
  console.log(`   Health  : http://localhost:${PORT}/api/health`);
  console.log(`   Webhook : POST http://localhost:${PORT}/api/webhooks/github/merge\n`);
});

module.exports = app;
