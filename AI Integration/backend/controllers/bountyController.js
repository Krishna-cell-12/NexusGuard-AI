// ============================================================
//  NexusGuard AI — Bounty Controller
//  backend/controllers/bountyController.js
//
//  This Express controller is the secure Oracle bridge between
//  the GitHub/NexusGuard webhook system and the on-chain
//  NexusGuardBounty smart contract.
//
//  Flow:
//    1. NexusGuard AI verifies a PR is merged & patch is valid.
//    2. It fires a POST to /api/webhooks/github/merge.
//    3. This controller authenticates the request, calls
//       releaseBounty() on-chain, and returns the tx hash.
//
//  Required .env variables:
//    ORACLE_PRIVATE_KEY     — The authorized Oracle wallet private key
//    CONTRACT_ADDRESS       — Deployed NexusGuardBounty address
//    POLYGON_AMOY_RPC_URL   — Polygon Amoy JSON-RPC endpoint
//    WEBHOOK_SECRET         — HMAC secret to authenticate incoming webhooks
//
//  Install dependencies:
//    npm install ethers express dotenv crypto
// ============================================================

"use strict";

const { ethers }    = require("ethers");
const crypto        = require("crypto");
require("dotenv").config();

// ─────────────────────────────────────────────────────────────
//  CONTRACT ABI (minimal — only the functions we call + events)
//  Copy the full ABI from artifacts/contracts/NexusGuardBounty.sol/
//  NexusGuardBounty.json after running `npx hardhat compile`.
// ─────────────────────────────────────────────────────────────
const NEXUSGUARD_ABI = [
  // ── Write Functions ──────────────────────────────────────
  "function releaseBounty(string memory bugId, address payable contributor) external",
  "function submitPatch(string memory bugId, address contributor) external",

  // ── Read Functions ───────────────────────────────────────
  "function getBounty(string memory bugId) external view returns (tuple(address sponsor, address tokenAddress, uint256 amount, address contributor, uint8 status, uint256 createdAt, uint256 paidAt))",
  "function getBountyStatus(string memory bugId) external view returns (uint8)",

  // ── Events ───────────────────────────────────────────────
  "event BountyPaid(string indexed bugId, address indexed contributor, uint256 amount, address tokenAddress, uint256 timestamp)",
  "event PatchSubmitted(string indexed bugId, address indexed contributor, uint256 timestamp)",
  "event VulnerabilityFound(string indexed bugId, address indexed sponsor, address tokenAddress, uint256 amount, uint256 timestamp)",
];

// ─────────────────────────────────────────────────────────────
//  ENVIRONMENT VALIDATION
// ─────────────────────────────────────────────────────────────

const REQUIRED_ENV_VARS = [
  "ORACLE_PRIVATE_KEY",
  "CONTRACT_ADDRESS",
  "POLYGON_AMOY_RPC_URL",
  "WEBHOOK_SECRET",
];

for (const key of REQUIRED_ENV_VARS) {
  if (!process.env[key]) {
    throw new Error(`[NexusGuard] Missing required environment variable: ${key}`);
  }
}

// ─────────────────────────────────────────────────────────────
//  ETHERS.JS PROVIDER & WALLET SETUP (initialized once on startup)
// ─────────────────────────────────────────────────────────────

/**
 * JsonRpcProvider connecting to Polygon Amoy.
 * For production: use a dedicated node service (Alchemy, Infura, QuickNode)
 * rather than a public RPC to avoid rate limits.
 */
const provider = new ethers.JsonRpcProvider(process.env.POLYGON_AMOY_RPC_URL);

/**
 * The Oracle wallet — the sole account authorized to call releaseBounty.
 * The private key lives in .env and is NEVER committed to source control.
 */
const oracleWallet = new ethers.Wallet(process.env.ORACLE_PRIVATE_KEY, provider);

/**
 * Read/write contract instance connected to the Oracle signer.
 */
const bountyContract = new ethers.Contract(
  process.env.CONTRACT_ADDRESS,
  NEXUSGUARD_ABI,
  oracleWallet
);

console.log(`[NexusGuard] Oracle wallet : ${oracleWallet.address}`);
console.log(`[NexusGuard] Contract      : ${process.env.CONTRACT_ADDRESS}`);
console.log(`[NexusGuard] Network       : Polygon Amoy`);

// ─────────────────────────────────────────────────────────────
//  SECURITY: WEBHOOK SIGNATURE VERIFICATION
// ─────────────────────────────────────────────────────────────

/**
 * Verifies the X-NexusGuard-Signature header on incoming webhooks.
 *
 * The sending service computes:
 *   signature = HMAC-SHA256(WEBHOOK_SECRET, rawBody).hexdigest()
 * and sends it as:
 *   X-NexusGuard-Signature: sha256=<hex>
 *
 * We recompute the signature and do a timing-safe comparison to
 * prevent replay and forgery attacks.
 *
 * @param {string} rawBody   The raw request body string.
 * @param {string} signature The signature header value.
 * @returns {boolean}
 */
function verifyWebhookSignature(rawBody, signature) {
  if (!signature || !signature.startsWith("sha256=")) return false;

  const expected = "sha256=" + crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(rawBody)
    .digest("hex");

  // timingSafeEqual prevents timing-based side-channel attacks.
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, "utf8"),
      Buffer.from(expected,  "utf8")
    );
  } catch {
    return false;
  }
}

// ─────────────────────────────────────────────────────────────
//  BOUNTY STATUS ENUM (mirrors Solidity BountyStatus)
// ─────────────────────────────────────────────────────────────

const BountyStatus = Object.freeze({
  0: "OPEN",
  1: "SUBMITTED",
  2: "PAID",
  3: "CANCELLED",
});

// ─────────────────────────────────────────────────────────────
//  CONTROLLERS
// ─────────────────────────────────────────────────────────────

/**
 * POST /api/webhooks/github/merge
 *
 * Triggered by the NexusGuard backend when a verified security patch
 * PR is merged. Calls `releaseBounty` on the smart contract and
 * returns the transaction hash.
 *
 * Expected JSON body:
 * {
 *   "bugId":                  "CVE-2025-12345",          // Must match on-chain bounty
 *   "contributorWalletAddress": "0xABCD...1234",         // Recipient of the bounty
 *   "prNumber":               42,                        // GitHub PR number (for audit)
 *   "repositoryFullName":     "acme/my-open-source-lib" // For logging / audit trail
 * }
 *
 * Success response (200):
 * {
 *   "success":     true,
 *   "txHash":      "0x...",
 *   "blockNumber": 12345678,
 *   "netPayout":   "49.00",         // USDC or MATIC, post-fee
 *   "bugId":       "CVE-2025-12345",
 *   "contributor": "0xABCD...1234"
 * }
 */
async function handleMergeWebhook(req, res) {
  // ── 1. Authenticate Request ────────────────────────────────
  const signature = req.headers["x-nexusguard-signature"];
  const rawBody   = JSON.stringify(req.body); // Works if express.json() is used.

  if (!verifyWebhookSignature(rawBody, signature)) {
    console.warn("[NexusGuard] ⚠️  Rejected webhook — invalid signature");
    return res.status(401).json({
      success: false,
      error:   "Unauthorized: invalid webhook signature",
    });
  }

  // ── 2. Validate Payload ─────────────────────────────────────
  const { bugId, contributorWalletAddress, prNumber, repositoryFullName } = req.body;

  const validationErrors = [];
  if (!bugId || typeof bugId !== "string" || bugId.trim() === "") {
    validationErrors.push("bugId is required and must be a non-empty string");
  }
  if (!ethers.isAddress(contributorWalletAddress)) {
    validationErrors.push("contributorWalletAddress must be a valid Ethereum address");
  }

  if (validationErrors.length > 0) {
    return res.status(400).json({
      success: false,
      error:   "Invalid request payload",
      details: validationErrors,
    });
  }

  const sanitizedBugId = bugId.trim();
  console.log(`[NexusGuard] 🔔 Merge webhook received`);
  console.log(`             BugID        : ${sanitizedBugId}`);
  console.log(`             Contributor  : ${contributorWalletAddress}`);
  console.log(`             PR           : #${prNumber} @ ${repositoryFullName}`);

  // ── 3. Pre-flight: Read On-Chain State ─────────────────────
  // We verify the on-chain state BEFORE sending a transaction
  // to give a clear error message without wasting gas.
  let onChainBounty;
  try {
    onChainBounty = await bountyContract.getBounty(sanitizedBugId);
  } catch (err) {
    console.error(`[NexusGuard] ❌  getBounty failed for "${sanitizedBugId}":`, err.message);
    return res.status(404).json({
      success: false,
      error:   `Bounty "${sanitizedBugId}" not found on-chain`,
    });
  }

  const statusLabel = BountyStatus[Number(onChainBounty.status)] ?? "UNKNOWN";
  console.log(`[NexusGuard] 📋 On-chain bounty status: ${statusLabel}`);

  if (statusLabel !== "SUBMITTED") {
    return res.status(409).json({
      success: false,
      error:   `Bounty is in "${statusLabel}" state. releaseBounty requires "SUBMITTED".`,
      currentStatus: statusLabel,
    });
  }

  // Confirm the contributor matches what was registered on-chain.
  if (onChainBounty.contributor.toLowerCase() !== contributorWalletAddress.toLowerCase()) {
    console.warn(
      `[NexusGuard] ⚠️  Contributor mismatch. On-chain: ${onChainBounty.contributor} | Payload: ${contributorWalletAddress}`
    );
    return res.status(400).json({
      success: false,
      error:   "Contributor address does not match the registered patch author on-chain",
    });
  }

  // ── 4. Send Transaction ─────────────────────────────────────
  let tx;
  try {
    console.log(`[NexusGuard] 📡 Sending releaseBounty() transaction...`);

    // ethers v6: gasLimit can be estimated or set manually.
    tx = await bountyContract.releaseBounty(sanitizedBugId, contributorWalletAddress, {
      // Optional: override gas limit for predictability. Remove to let ethers estimate.
      // gasLimit: 200_000,
    });

    console.log(`[NexusGuard] ⏳ Tx submitted: ${tx.hash}`);
    console.log(`             Explorer: https://amoy.polygonscan.com/tx/${tx.hash}`);
  } catch (err) {
    console.error("[NexusGuard] ❌  releaseBounty() transaction failed:", err.message);

    // Parse common revert reasons for a helpful error message.
    const errMsg = err.message || "";
    let userMessage = "Transaction failed. Check the contract state and Oracle permissions.";

    if (errMsg.includes("caller is not the Oracle")) {
      userMessage = "Oracle wallet is not authorized. Check CONTRACT_ADDRESS and ORACLE_PRIVATE_KEY.";
    } else if (errMsg.includes("contributor address mismatch")) {
      userMessage = "The contributor address does not match the registered patch author.";
    } else if (errMsg.includes("SUBMITTED")) {
      userMessage = "Bounty must be in SUBMITTED state to be released.";
    }

    return res.status(500).json({
      success: false,
      error:   userMessage,
      rawError: process.env.NODE_ENV === "development" ? errMsg : undefined,
    });
  }

  // ── 5. Wait for Confirmation ────────────────────────────────
  let receipt;
  try {
    console.log(`[NexusGuard] ⌛ Waiting for block confirmation...`);
    // Wait for 2 confirmations for safety (Polygon finalizes quickly).
    receipt = await tx.wait(2);
    console.log(`[NexusGuard] ✅ Confirmed in block #${receipt.blockNumber}`);
  } catch (err) {
    console.error("[NexusGuard] ❌  Transaction reverted on-chain:", err.message);
    return res.status(500).json({
      success:  false,
      error:    "Transaction was mined but reverted",
      txHash:   tx.hash,
      rawError: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }

  // ── 6. Parse BountyPaid Event from Receipt ──────────────────
  let parsedEvent = null;
  for (const log of receipt.logs) {
    try {
      const parsed = bountyContract.interface.parseLog(log);
      if (parsed && parsed.name === "BountyPaid") {
        parsedEvent = parsed.args;
        break;
      }
    } catch {
      // Non-matching logs will throw — ignore them.
    }
  }

  const netPayout = parsedEvent
    ? ethers.formatUnits(parsedEvent.amount, 6) // Assumes USDC (6 decimals); adjust for MATIC.
    : "unknown";

  console.log(`[NexusGuard] 💸 Bounty paid!`);
  console.log(`             Net payout  : ${netPayout}`);
  console.log(`             Tx hash     : ${receipt.hash}`);

  // ── 7. Return Success Response ──────────────────────────────
  return res.status(200).json({
    success:     true,
    message:     "Bounty successfully released on-chain 🎉",
    txHash:      receipt.hash,
    blockNumber: receipt.blockNumber,
    netPayout,
    explorerUrl: `https://amoy.polygonscan.com/tx/${receipt.hash}`,
    bugId:       sanitizedBugId,
    contributor: contributorWalletAddress,
    prNumber:    prNumber    ?? null,
    repository:  repositoryFullName ?? null,
  });
}

/**
 * GET /api/bounty/:bugId
 *
 * Public read endpoint to fetch the on-chain state of a bounty.
 * Used by the frontend live-feed to populate bounty cards.
 */
async function getBountyStatus(req, res) {
  const { bugId } = req.params;

  if (!bugId || bugId.trim() === "") {
    return res.status(400).json({ success: false, error: "bugId is required" });
  }

  try {
    const bounty = await bountyContract.getBounty(bugId.trim());

    return res.status(200).json({
      success: true,
      bounty: {
        sponsor:      bounty.sponsor,
        tokenAddress: bounty.tokenAddress,
        amount:       bounty.amount.toString(),
        contributor:  bounty.contributor,
        status:       BountyStatus[Number(bounty.status)] ?? "UNKNOWN",
        createdAt:    new Date(Number(bounty.createdAt) * 1000).toISOString(),
        paidAt:       bounty.paidAt > 0n
          ? new Date(Number(bounty.paidAt) * 1000).toISOString()
          : null,
      },
    });
  } catch (err) {
    return res.status(404).json({
      success: false,
      error:   `Bounty "${bugId}" not found on-chain`,
    });
  }
}

/**
 * GET /api/health
 *
 * Liveness probe for the Oracle backend.
 * Returns the Oracle wallet address and current block for quick debugging.
 */
async function healthCheck(req, res) {
  try {
    const blockNumber   = await provider.getBlockNumber();
    const oracleBalance = await provider.getBalance(oracleWallet.address);

    return res.status(200).json({
      status:        "healthy",
      oracleAddress: oracleWallet.address,
      oracleBalance: ethers.formatEther(oracleBalance) + " MATIC",
      contractAddress: process.env.CONTRACT_ADDRESS,
      network:       "Polygon Amoy",
      currentBlock:  blockNumber,
      timestamp:     new Date().toISOString(),
    });
  } catch (err) {
    return res.status(503).json({
      status: "degraded",
      error:  err.message,
    });
  }
}

// ─────────────────────────────────────────────────────────────
//  EXPRESS ROUTER SETUP
// ─────────────────────────────────────────────────────────────
//
//  In your main app.js / server.js, mount these routes like:
//
//    const express            = require("express");
//    const bountyController   = require("./controllers/bountyController");
//    const app                = express();
//
//    app.use(express.json()); // ⚠️  Must be before mounting these routes
//
//    app.post("/api/webhooks/github/merge", bountyController.handleMergeWebhook);
//    app.get("/api/bounty/:bugId",          bountyController.getBountyStatus);
//    app.get("/api/health",                 bountyController.healthCheck);
//

module.exports = {
  handleMergeWebhook,
  getBountyStatus,
  healthCheck,
};
