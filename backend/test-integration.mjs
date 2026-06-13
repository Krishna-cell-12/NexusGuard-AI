/**
 * NexusGuard AI — Full Integration Test Suite
 * backend/test-integration.mjs
 *
 * Tests every route on the unified server (port 3000).
 * Run with: node --env-file=.env test-integration.mjs
 *
 * Uses Node's built-in `http` module — no external test framework needed.
 */

import http    from "http";
import crypto  from "crypto";

// ─── Config ──────────────────────────────────────────────────────────────────
const BASE = { host: "localhost", port: 3000 };
const GITHUB_WEBHOOK_SECRET  = process.env.GITHUB_WEBHOOK_SECRET;
const WEBHOOK_SECRET         = process.env.WEBHOOK_SECRET;
const ORACLE_ADDRESS         = process.env.ORACLE_ADDRESS;

// ─── Helpers ─────────────────────────────────────────────────────────────────
let passed = 0, failed = 0;
const results = [];

function assert(label, condition, detail = "") {
  if (condition) {
    passed++;
    results.push({ status: "PASS", label, detail });
    console.log(`  ✅  PASS  ${label}${detail ? " — " + detail : ""}`);
  } else {
    failed++;
    results.push({ status: "FAIL", label, detail });
    console.error(`  ❌  FAIL  ${label}${detail ? " — " + detail : ""}`);
  }
}

function request(method, path, body = null, headers = {}) {
  return new Promise((resolve) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      ...BASE, path, method,
      headers: {
        "Content-Type": "application/json",
        ...(data ? { "Content-Length": Buffer.byteLength(data) } : {}),
        ...headers,
      },
      timeout: 8000,
    };
    const req = http.request(opts, (res) => {
      let raw = "";
      res.on("data", d => raw += d);
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(raw); } catch { /* non-JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, body: raw, json });
      });
    });
    req.on("error",   e => resolve({ status: 0,         body: e.message, json: null }));
    req.on("timeout", () => { req.destroy(); resolve({ status: "TIMEOUT", body: "", json: null }); });
    if (data) req.write(data);
    req.end();
  });
}

function makeGitHubHmac(body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return "sha256=" + crypto.createHmac("sha256", GITHUB_WEBHOOK_SECRET).update(raw).digest("hex");
}

function makeWeb3Hmac(body) {
  const raw = typeof body === "string" ? body : JSON.stringify(body);
  return "sha256=" + crypto.createHmac("sha256", WEBHOOK_SECRET).update(raw).digest("hex");
}

// ─── Test Suites ─────────────────────────────────────────────────────────────

async function testCoreHealth() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 1 — Core Server Health");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const r = await request("GET", "/health");
  assert("GET /health → 200",              r.status === 200);
  assert("GET /health → status:ok",        r.json?.status === "ok");
  assert("GET /health → service field",    r.json?.service === "nexusguard-ai");
  assert("GET /health → uptime is number", typeof r.json?.uptime === "number");
}

async function testStatusRoute() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 2 — Run Status Route");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const r = await request("GET", "/api/status/nonexistent-run-id");
  assert("GET /api/status/:id → 404 for unknown", r.status === 404);
  assert("GET /api/status/:id → error field",      r.json?.error?.includes("not found"));
}

async function testGitHubWebhook() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 3 — GitHub Webhook (Yug's Layer)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // 3a — No signature header → 401
  const r1 = await request("POST", "/api/webhook/github", { test: "payload" });
  assert("POST /api/webhook/github no sig → 401",  r1.status === 401);
  assert("POST /api/webhook/github → error field",  r1.json?.error?.includes("signature"));

  // 3b — Wrong signature → 401
  const r2 = await request("POST", "/api/webhook/github",
    { test: "payload" },
    { "x-hub-signature-256": "sha256=badhash", "x-github-event": "push" }
  );
  assert("POST /api/webhook/github bad sig → 401",  r2.status === 401);

  // 3c — Valid HMAC + unsupported event → 200 (ignored gracefully)
  const unsupportedPayload = { test: "ping" };
  const r3 = await request("POST", "/api/webhook/github",
    unsupportedPayload,
    {
      "x-hub-signature-256": makeGitHubHmac(unsupportedPayload),
      "x-github-event":      "ping",
      "x-github-delivery":   "test-delivery-001",
    }
  );
  assert("POST /api/webhook/github valid sig + ping event → 200", r3.status === 200);
  assert("POST /api/webhook/github ping → 'not processed' msg",   r3.json?.message?.includes("not processed"));

  // 3d — Valid HMAC + push event with branch deletion SHA → 200 (ignored)
  const pushDeletePayload = {
    repository: { name: "test-repo", clone_url: "https://github.com/test/repo.git" },
    sender: { login: "test-user" },
    after: "0000000000000000000000000000000000000000",
  };
  const r4 = await request("POST", "/api/webhook/github",
    pushDeletePayload,
    {
      "x-hub-signature-256": makeGitHubHmac(pushDeletePayload),
      "x-github-event":      "push",
      "x-github-delivery":   "test-delivery-002",
    }
  );
  assert("POST /api/webhook/github push branch-delete → 200", r4.status === 200);
  assert("POST /api/webhook/github branch-delete → ignored",  r4.json?.message?.includes("ignored"));
}

async function testWeb3Health() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 4 — Web3 Oracle Health (Yadnesh's Layer)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const r = await request("GET", "/api/web3/health");
  // Network call to Polygon Amoy — may be healthy or degraded (no control)
  assert("GET /api/web3/health → 200 or 503",       r.status === 200 || r.status === 503,
         `HTTP ${r.status}`);
  assert("GET /api/web3/health → has status field",  r.json?.status !== undefined,
         `status="${r.json?.status}"`);
  assert("GET /api/web3/health → has oracleAddress", r.json?.oracleAddress !== undefined ||
         r.json?.error !== undefined);

  if (r.status === 200) {
    assert("GET /api/web3/health → wallet matches .env",
      r.json?.oracleAddress?.toLowerCase() === ORACLE_ADDRESS?.toLowerCase(),
      `got ${r.json?.oracleAddress}`);
  }
}

async function testBountyStatus() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 5 — Bounty Status Read (Public Route)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // With zero CONTRACT_ADDRESS, expect 404 (bounty not found on-chain)
  const r1 = await request("GET", "/api/web3/bounty/CVE-2025-test-001");
  assert("GET /api/web3/bounty/:bugId → 404 (not deployed)",
    r1.status === 404,
    `HTTP ${r1.status}: ${r1.body?.slice(0, 100)}`);
  assert("GET /api/web3/bounty/:bugId → success:false",
    r1.json?.success === false);

  // Empty bugId-like path that hits 404 handler
  const r2 = await request("GET", "/api/web3/bounty/%20%20%20");
  // Spaces may be interpreted differently — just check it responds
  assert("GET /api/web3/bounty/whitespace-id → responds",
    r2.status !== undefined && r2.status !== "TIMEOUT");
}

async function testTriggerBounty() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 6 — Internal Trigger-Bounty (Orchestrator Route)");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // With zero contract address — expect 404 from on-chain lookup
  const payload = {
    repoName:    "nexusguard-test",
    commitSha:   "deadbeef1234",
    senderLogin: "testuser",
    patchCode:   "diff --git a/fix.js b/fix.js\n+console.log('fixed');",
    report:      { totalVulnerabilities: 2, totalSecrets: 0 },
  };
  const r1 = await request("POST", "/api/web3/trigger-bounty", payload);
  assert("POST /api/web3/trigger-bounty → responds (no HMAC needed)", r1.status !== "TIMEOUT");
  assert("POST /api/web3/trigger-bounty → 404 (contract not deployed)",
    r1.status === 404,
    `HTTP ${r1.status}: ${r1.body?.slice(0, 150)}`);
  assert("POST /api/web3/trigger-bounty → success:false",   r1.json?.success === false);
  assert("POST /api/web3/trigger-bounty → error mentions bounty", r1.json?.error?.toLowerCase().includes("bounty") ||
    r1.json?.error?.toLowerCase().includes("not found"));

  // Invalid payload — missing required fields
  const r2 = await request("POST", "/api/web3/trigger-bounty", {});
  assert("POST /api/web3/trigger-bounty empty body → 400 or 404",
    r2.status === 400 || r2.status === 404,
    `HTTP ${r2.status}`);
}

async function testExternalWebhookMerge() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 7 — External HMAC Webhook /api/web3/webhook/merge");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  // 7a — No signature → 401
  const r1 = await request("POST", "/api/web3/webhook/merge",
    { bugId: "CVE-test", contributorWalletAddress: ORACLE_ADDRESS });
  assert("POST /api/web3/webhook/merge no sig → 401", r1.status === 401);
  assert("POST /api/web3/webhook/merge → error: unauthorized", r1.json?.error?.toLowerCase().includes("unauthorized"));

  // 7b — Bad signature → 401
  const r2 = await request("POST", "/api/web3/webhook/merge",
    { bugId: "CVE-test", contributorWalletAddress: ORACLE_ADDRESS },
    { "x-nexusguard-signature": "sha256=badhashvalue" }
  );
  assert("POST /api/web3/webhook/merge bad sig → 401", r2.status === 401);

  // 7c — Valid HMAC + valid body → 404 (contract not deployed — expected)
  const mergePayload = {
    bugId:                    "CVE-2025-nexusguard-001",
    contributorWalletAddress: ORACLE_ADDRESS,
    prNumber:                 42,
    repositoryFullName:       "nexusguard/test-repo",
  };
  const bodyStr = JSON.stringify(mergePayload);
  const sig     = makeWeb3Hmac(bodyStr);
  const r3 = await request("POST", "/api/web3/webhook/merge",
    mergePayload,
    { "x-nexusguard-signature": sig }
  );
  assert("POST /api/web3/webhook/merge valid HMAC → not 401",   r3.status !== 401,
    `HTTP ${r3.status}`);
  assert("POST /api/web3/webhook/merge valid HMAC → 404 (not deployed)", r3.status === 404,
    `HTTP ${r3.status}: ${r3.body?.slice(0, 120)}`);
  assert("POST /api/web3/webhook/merge → success:false",         r3.json?.success === false);
}

async function testNotFound() {
  console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
  console.log("  SUITE 8 — Unknown Routes");
  console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

  const r = await request("GET", "/api/does-not-exist");
  assert("GET /api/does-not-exist → 404", r.status === 404);
}

// ─── Runner ──────────────────────────────────────────────────────────────────

async function main() {
  console.log("\n╔════════════════════════════════════════════════════╗");
  console.log("║  NexusGuard AI — Full Integration Test Suite       ║");
  console.log("║  Target: http://localhost:3000                      ║");
  console.log("╚════════════════════════════════════════════════════╝");

  // Connectivity check
  const ping = await request("GET", "/health");
  if (ping.status !== 200) {
    console.error(`\n❌  Server not reachable on port 3000 (got: ${ping.status} / ${ping.body})`);
    console.error("    Start it with: npm run dev");
    process.exit(1);
  }
  console.log("\n  🟢  Server is up — running all suites...");

  await testCoreHealth();
  await testStatusRoute();
  await testGitHubWebhook();
  await testWeb3Health();
  await testBountyStatus();
  await testTriggerBounty();
  await testExternalWebhookMerge();
  await testNotFound();

  // ─── Final Report ───────────────────────────────────────────
  console.log("\n╔════════════════════════════════════════════════════╗");
  console.log("║  RESULTS                                            ║");
  console.log("╠════════════════════════════════════════════════════╣");
  console.log(`║  ✅  PASSED : ${String(passed).padEnd(36)}║`);
  console.log(`║  ❌  FAILED : ${String(failed).padEnd(36)}║`);
  console.log(`║  📊  TOTAL  : ${String(passed + failed).padEnd(36)}║`);
  console.log("╚════════════════════════════════════════════════════╝");

  if (failed > 0) {
    console.log("\nFailed tests:");
    results.filter(r => r.status === "FAIL").forEach(r =>
      console.error(`  ❌  ${r.label}${r.detail ? " — " + r.detail : ""}`)
    );
    process.exit(1);
  } else {
    console.log("\n🎉  All tests passed! Integration is complete.\n");
  }
}

main().catch(err => {
  console.error("Test runner crashed:", err);
  process.exit(1);
});
