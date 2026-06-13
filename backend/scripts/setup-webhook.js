#!/usr/bin/env node
/**
 * NexusGuard AI — GitHub Webhook Auto-Configurator
 *
 * Usage:
 *   GITHUB_TOKEN=ghp_xxx node scripts/setup-webhook.js [ngrok-url]
 *
 * What it does:
 *   1. Reads GITHUB_WEBHOOK_SECRET from .env
 *   2. Calls the GitHub REST API to create (or update) the NexusGuard webhook
 *   3. Configures it to fire on push + pull_request events
 *
 * Requires:
 *   GITHUB_TOKEN env var — a Personal Access Token with `admin:repo_hook` scope
 *   Get one at: https://github.com/settings/tokens/new?scopes=admin:repo_hook
 */

import { readFileSync } from "fs";
import { resolve } from "path";

// ─── Config ───────────────────────────────────────────────────────────────────

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER   = "Krishna-cell-12";
const REPO_NAME    = "NexusGuard-AI";
const NGROK_URL    = process.argv[2] || process.env.NGROK_URL || "https://stays-enjoyable-tweak.ngrok-free.app";

// Read GITHUB_WEBHOOK_SECRET from .env
let webhookSecret = process.env.GITHUB_WEBHOOK_SECRET;
if (!webhookSecret) {
  try {
    const envFile = readFileSync(resolve(process.cwd(), ".env"), "utf8");
    const match = envFile.match(/^GITHUB_WEBHOOK_SECRET=(.+)$/m);
    webhookSecret = match?.[1]?.trim();
  } catch { /* no .env file */ }
}

// ─── Validation ───────────────────────────────────────────────────────────────

if (!GITHUB_TOKEN) {
  console.error(`
ERROR: GITHUB_TOKEN is not set.

1. Go to: https://github.com/settings/tokens/new?scopes=admin:repo_hook
2. Generate a token with the 'admin:repo_hook' scope
3. Run:  GITHUB_TOKEN=ghp_xxx node scripts/setup-webhook.js

Or, set it up manually in GitHub:
  Repo → Settings → Webhooks → Add webhook
  URL:     ${NGROK_URL}/api/webhook/github
  Secret:  ${webhookSecret ?? "<your GITHUB_WEBHOOK_SECRET>"}
  Events:  push, pull_request
`);
  process.exit(1);
}

if (!webhookSecret) {
  console.error("ERROR: GITHUB_WEBHOOK_SECRET not found in .env");
  process.exit(1);
}

// ─── GitHub API Helpers ───────────────────────────────────────────────────────

const API_BASE = "https://api.github.com";
const HEADERS  = {
  "Authorization": `Bearer ${GITHUB_TOKEN}`,
  "Accept":        "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
  "Content-Type":  "application/json",
  "User-Agent":    "nexusguard-ai-setup",
};

async function ghFetch(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers: HEADERS });
  const body = await res.json();
  return { status: res.status, body };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

(async () => {
  const webhookUrl = `${NGROK_URL}/api/webhook/github`;
  console.log(`\nNexusGuard AI — Webhook Configurator`);
  console.log(`Repo   : ${REPO_OWNER}/${REPO_NAME}`);
  console.log(`URL    : ${webhookUrl}`);
  console.log(`Secret : ${webhookSecret.slice(0, 8)}...`);
  console.log("");

  // Check for existing webhooks
  const { status: listStatus, body: hooks } = await ghFetch(
    `/repos/${REPO_OWNER}/${REPO_NAME}/hooks`
  );

  if (listStatus === 403 || listStatus === 401) {
    console.error(`GitHub API returned ${listStatus}. Check your token has 'admin:repo_hook' scope.`);
    process.exit(1);
  }

  // Find any existing hook pointing at ngrok or our URL
  const existing = Array.isArray(hooks)
    ? hooks.find((h) => h.config?.url?.includes("api/webhook/github"))
    : null;

  const hookPayload = {
    name: "web",
    active: true,
    events: ["push", "pull_request"],
    config: {
      url:          webhookUrl,
      content_type: "json",
      secret:       webhookSecret,
      insecure_ssl: "0",
    },
  };

  let result;

  if (existing) {
    console.log(`Updating existing webhook ID ${existing.id}...`);
    result = await ghFetch(
      `/repos/${REPO_OWNER}/${REPO_NAME}/hooks/${existing.id}`,
      { method: "PATCH", body: JSON.stringify(hookPayload) }
    );
  } else {
    console.log("Creating new webhook...");
    result = await ghFetch(
      `/repos/${REPO_OWNER}/${REPO_NAME}/hooks`,
      { method: "POST", body: JSON.stringify(hookPayload) }
    );
  }

  if (result.status === 201 || result.status === 200) {
    const hook = result.body;
    console.log(`✅ Webhook ${existing ? "updated" : "created"} successfully!`);
    console.log(`   ID     : ${hook.id}`);
    console.log(`   URL    : ${hook.config?.url}`);
    console.log(`   Events : ${hook.events?.join(", ")}`);
    console.log(`   Active : ${hook.active}`);
    console.log("");
    console.log("Next steps:");
    console.log("  1. Push a commit or open a PR on the repo");
    console.log("  2. Watch the server logs for pipeline state transitions");
    console.log("  3. Visit GET /api/status/<runId> to poll run state");
  } else {
    console.error(`❌ Webhook setup failed (HTTP ${result.status}):`);
    console.error(JSON.stringify(result.body, null, 2));
    process.exit(1);
  }
})();
