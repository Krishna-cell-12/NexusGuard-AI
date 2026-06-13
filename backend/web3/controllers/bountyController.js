// ============================================================
//  NexusGuard AI — Bounty Controller  (ESM edition)
//  backend/web3/controllers/bountyController.js
//
//  This Express controller is the secure Oracle bridge between
//  the GitHub/NexusGuard webhook system and the on-chain
//  NexusGuardBounty smart contract.
//
//  Flow (external, HMAC-authenticated):
//    1. NexusGuard AI verifies a PR is merged & patch is valid.
//    2. It fires POST /api/web3/webhook/merge with X-NexusGuard-Signature.
//    3. This controller authenticates, calls releaseBounty() on-chain,
//       and returns the tx hash.
//
//  Flow (internal, loopback):
//    - The orchestrator calls POST /api/web3/trigger-bounty directly.
//    - No HMAC required — route is only reachable on localhost.
//
//  Required .env variables (loaded via node --env-file=.env):
//    ORACLE_PRIVATE_KEY     — The authorized Oracle wallet private key
//    CONTRACT_ADDRESS       — Deployed NexusGuardBounty address
//    POLYGON_AMOY_RPC_URL   — Polygon Amoy JSON-RPC endpoint
//    WEBHOOK_SECRET         — HMAC secret for external webhook auth
// ============================================================

import { ethers } from "ethers";
import crypto     from "crypto";

// ─────────────────────────────────────────────────────────────
//  CONTRACT ABI (minimal — only the functions we call + events)
//  Full ABI is in contracts-hardhat/artifacts after `hardhat compile`.
// ─────────────────────────────────────────────────────────────
const NEXUSGUARD_ABI = [
  // ── Write Functions ──────────────────────────────────────
  "function createBounty(string memory bugId, address tokenAddress, uint256 amount) external payable",
  "function submitPatch(string memory bugId, address contributor) external",
  "function releaseBounty(string memory bugId, address payable contributor) external",
  "function cancelBounty(string memory bugId) external",

  // ── Read Functions ───────────────────────────────────────
  "function getBounty(string memory bugId) external view returns (tuple(address sponsor, address tokenAddress, uint256 amount, address contributor, uint8 status, uint256 createdAt, uint256 paidAt))",
  "function getBountyStatus(string memory bugId) external view returns (uint8)",
  "function getSponsorBounties(address sponsor) external view returns (string[] memory)",

  // ── Events ───────────────────────────────────────────────
  "event VulnerabilityFound(string indexed bugIdHash, address indexed sponsor, string bugId, address tokenAddress, uint256 amount, uint256 timestamp)",
  "event PatchSubmitted(string indexed bugIdHash, address indexed contributor, string bugId, uint256 timestamp)",
  "event BountyPaid(string indexed bugIdHash, address indexed contributor, string bugId, uint256 amount, address tokenAddress, uint256 timestamp)",
  "event BountyCancelled(string indexed bugIdHash, address indexed sponsor, string bugId, uint256 amount, uint256 timestamp)",
];

// ─────────────────────────────────────────────────────────────
//  ENVIRONMENT VALIDATION (at module load — fails fast)
// ─────────────────────────────────────────────────────────────

const REQUIRED_ENV_VARS = [
  "ORACLE_PRIVATE_KEY",
  "CONTRACT_ADDRESS",
  "POLYGON_AMOY_RPC_URL",
  "WEBHOOK_SECRET",
];

for (const key of REQUIRED_ENV_VARS) {
  if (!process.env[key]) {
    throw new Error(`[NexusGuard/bountyController] Missing required env var: ${key}`);
  }
}

// ─────────────────────────────────────────────────────────────
//  ETHERS.JS PROVIDER & WALLET SETUP (initialized once on startup)
// ─────────────────────────────────────────────────────────────

const provider = new ethers.JsonRpcProvider(process.env.POLYGON_AMOY_RPC_URL);

const oracleWallet = new ethers.Wallet(process.env.ORACLE_PRIVATE_KEY, provider);

const bountyContract = new ethers.Contract(
  process.env.CONTRACT_ADDRESS,
  NEXUSGUARD_ABI,
  oracleWallet
);

console.log(`[NexusGuard] Oracle wallet : ${oracleWallet.address}`);
console.log(`[NexusGuard] Contract      : ${process.env.CONTRACT_ADDRESS}`);
console.log(`[NexusGuard] Network       : Polygon Amoy`);

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
//  SECURITY: WEBHOOK SIGNATURE VERIFICATION
// ─────────────────────────────────────────────────────────────

/**
 * Verifies the X-NexusGuard-Signature header on incoming external webhooks.
 *
 * The sending service computes:
 *   signature = HMAC-SHA256(WEBHOOK_SECRET, rawBody).hexdigest()
 * and sends it as:
 *   X-NexusGuard-Signature: sha256=<hex>
 *
 * @param {string|Buffer} rawBody   - The raw request body.
 * @param {string}        signature - The X-NexusGuard-Signature header value.
 * @returns {boolean}
 */
function verifyWebhookSignature(rawBody, signature) {
  if (!signature || !signature.startsWith("sha256=")) return false;

  // rawBody may be a Buffer (from Yug's express.json verify callback) or string.
  const bodyStr = Buffer.isBuffer(rawBody) ? rawBody.toString("utf8") : rawBody;

  const expected = "sha256=" + crypto
    .createHmac("sha256", process.env.WEBHOOK_SECRET)
    .update(bodyStr)
    .digest("hex");

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
//  SHARED BOUNTY RELEASE LOGIC
// ─────────────────────────────────────────────────────────────

/**
 * Core logic to validate payload, check on-chain state, send the
 * releaseBounty() transaction, and return a structured response.
 *
 * Used by both the external HMAC-authenticated route and the internal
 * loopback /trigger-bounty route.
 *
 * @param {object} body   - Parsed request body.
 * @param {object} res    - Express response object.
 */
async function executeReleaseBounty(body, res) {
  const { bugId, contributorWalletAddress, prNumber, repositoryFullName } = body;

  // ── Validate Payload ─────────────────────────────────────────
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
  console.log(`[NexusGuard] 🔔 Bounty release triggered`);
  console.log(`             BugID        : ${sanitizedBugId}`);
  console.log(`             Contributor  : ${contributorWalletAddress}`);
  console.log(`             PR           : #${prNumber} @ ${repositoryFullName}`);

  // ── Pre-flight: Read On-Chain State ────────────────────────
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

  if (onChainBounty.contributor.toLowerCase() !== contributorWalletAddress.toLowerCase()) {
    console.warn(
      `[NexusGuard] ⚠️  Contributor mismatch. On-chain: ${onChainBounty.contributor} | Payload: ${contributorWalletAddress}`
    );
    return res.status(400).json({
      success: false,
      error:   "Contributor address does not match the registered patch author on-chain",
    });
  }

  // ── Send Transaction ─────────────────────────────────────────
  let tx;
  try {
    console.log(`[NexusGuard] 📡 Sending releaseBounty() transaction...`);
    tx = await bountyContract.releaseBounty(sanitizedBugId, contributorWalletAddress);
    console.log(`[NexusGuard] ⏳ Tx submitted: ${tx.hash}`);
    console.log(`             Explorer: https://amoy.polygonscan.com/tx/${tx.hash}`);
  } catch (err) {
    console.error("[NexusGuard] ❌  releaseBounty() transaction failed:", err.message);

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

  // ── Wait for Confirmation ────────────────────────────────────
  let receipt;
  try {
    console.log(`[NexusGuard] ⌛ Waiting for block confirmation...`);
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

  // ── Parse BountyPaid Event from Receipt ─────────────────────
  let parsedEvent = null;
  for (const log of receipt.logs) {
    try {
      const parsed = bountyContract.interface.parseLog(log);
      if (parsed && parsed.name === "BountyPaid") {
        parsedEvent = parsed.args;
        break;
      }
    } catch {
      // Non-matching logs — ignore.
    }
  }

  let netPayout = "unknown";
  if (parsedEvent) {
    const tokenAddr = parsedEvent.tokenAddress;
    const decimals  = (tokenAddr === ethers.ZeroAddress) ? 18 : 6;
    netPayout       = ethers.formatUnits(parsedEvent.amount, decimals);
  }

  console.log(`[NexusGuard] 💸 Bounty paid! Net payout: ${netPayout}`);

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

// ─────────────────────────────────────────────────────────────
//  CONTROLLERS
// ─────────────────────────────────────────────────────────────

/**
 * POST /api/web3/webhook/merge
 *
 * External, HMAC-authenticated entry point.
 * Called by external systems with X-NexusGuard-Signature header.
 *
 * Expected JSON body:
 * {
 *   "bugId":                    "CVE-2025-12345",
 *   "contributorWalletAddress": "0xABCD...1234",
 *   "prNumber":                 42,
 *   "repositoryFullName":       "acme/my-open-source-lib"
 * }
 */
export async function handleMergeWebhook(req, res) {
  // ── Authenticate Request ─────────────────────────────────────
  const signature = req.headers["x-nexusguard-signature"];
  // rawBody is a Buffer captured by Yug's express.json() verify callback.
  const rawBody   = req.rawBody || JSON.stringify(req.body);

  if (!verifyWebhookSignature(rawBody, signature)) {
    console.warn("[NexusGuard] ⚠️  Rejected webhook — invalid signature");
    return res.status(401).json({
      success: false,
      error:   "Unauthorized: invalid webhook signature",
    });
  }

  return executeReleaseBounty(req.body, res);
}

/**
 * POST /api/web3/trigger-bounty
 *
 * Internal loopback entry point called by the orchestrator.
 * Skips HMAC — this route is only accessible on localhost:3000.
 *
 * The orchestrator sends:
 * {
 *   "repoName":    "my-repo",
 *   "commitSha":   "abc123",
 *   "senderLogin": "github-user",
 *   "patchCode":   "...",
 *   "report":      { summary object }
 * }
 *
 * We synthesize a minimal bounty payload from these fields.
 * The orchestrator does not know the bugId / contributor wallet —
 * those must be resolvable or set to a default for the hackathon demo.
 *
 * For a production system: the orchestrator should pass bugId and
 * contributorWalletAddress from the scan result.
 */
export async function triggerBounty(req, res) {
  const {
    bugId,
    contributorWalletAddress,
    repoName,
    commitSha,
    senderLogin,
    prNumber,
    repositoryFullName,
    patchCode,
    report,
  } = req.body;

  // Allow the orchestrator to send its native fields and still work.
  const resolvedBugId      = bugId      ?? `${repoName ?? "repo"}-${(commitSha ?? "").slice(0, 8)}`;
  const resolvedContributor = contributorWalletAddress ?? process.env.ORACLE_ADDRESS;
  const resolvedRepo        = repositoryFullName ?? repoName ?? "unknown";

  console.log(`[NexusGuard] ⚡ Internal trigger-bounty received`);
  console.log(`             Resolved bugId      : ${resolvedBugId}`);
  console.log(`             Resolved contributor: ${resolvedContributor}`);
  console.log(`             Commit SHA          : ${commitSha ?? "n/a"}`);
  console.log(`             Patch length        : ${patchCode?.length ?? 0} chars`);

  return executeReleaseBounty(
    {
      bugId:                    resolvedBugId,
      contributorWalletAddress: resolvedContributor,
      prNumber:                 prNumber ?? null,
      repositoryFullName:       resolvedRepo,
    },
    res
  );
}

/**
 * GET /api/web3/bounty/:bugId
 *
 * Public read endpoint — fetches the on-chain state of a bounty.
 */
export async function getBountyStatus(req, res) {
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
 * GET /api/web3/health
 *
 * Oracle liveness probe — returns wallet address, balance, and current block.
 */
export async function healthCheck(req, res) {
  try {
    const blockNumber   = await provider.getBlockNumber();
    const oracleBalance = await provider.getBalance(oracleWallet.address);

    return res.status(200).json({
      status:          "healthy",
      oracleAddress:   oracleWallet.address,
      oracleBalance:   ethers.formatEther(oracleBalance) + " MATIC",
      contractAddress: process.env.CONTRACT_ADDRESS,
      network:         "Polygon Amoy",
      currentBlock:    blockNumber,
      timestamp:       new Date().toISOString(),
    });
  } catch (err) {
    return res.status(503).json({
      status: "degraded",
      error:  err.message,
    });
  }
}
