# NexusGuard AI — Backend Engine

Autonomous security scanner that listens for GitHub push/PR events, runs static and dynamic analysis, routes findings to an AI patch service, and triggers a Web3 bounty release.

---

## Architecture

```
GitHub Event (push / PR)
        │
        ▼
┌───────────────────────┐
│   server.js           │  Express + WebSocket server
│   POST /api/webhook   │  Verifies HMAC-SHA256 signature
└──────────┬────────────┘
           │
           ▼
┌───────────────────────────────────────────┐
│   orchestrator.js                         │
│   processVulnerabilityWorkflow()          │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │ runScanners() — single git clone    │  │
│  │  ├─ Semgrep  (static analysis)      │  │  All three
│  │  ├─ TruffleHog (secret detection)   │  │  run in
│  │  └─ sandbox.js (Docker, no network) │  │  parallel
│  └─────────────────────────────────────┘  │
│           │                               │
│           ▼  (findings exist?)            │
│  POST :8000  AI Microservice              │
│           │  (patchCode + explanation)     │
│           ▼                               │
│  POST :8001  Web3 Microservice            │
│           │  (bounty tx receipt)           │
│           ▼                               │
│  WebSocket broadcast → Frontend dashboard │
└───────────────────────────────────────────┘

GitHub Actions CI (on every push / PR):
  ├─ Semgrep scan   → SARIF upload to GitHub Security tab
  ├─ TruffleHog     → verified secrets only
  └─ Signed webhook → triggers NexusGuard full pipeline
```

---

## Project Structure

```
NexusGuard-AI/
├── .github/
│   └── workflows/
│       └── nexusguard-ci.yml          # GitHub Actions: Semgrep + TruffleHog + webhook
├── backend/
│   ├── server.js                      # Express server, webhook receiver, WebSocket, /health
│   ├── orchestrator.js                # Pipeline: scan → AI → Web3 → notify frontend
│   ├── scanner.js                     # Semgrep + TruffleHog + git clone helpers
│   ├── sandbox.js                     # Docker dynamic analysis sandbox
│   ├── store.js                       # Shared in-memory run store
│   ├── scripts/
│   │   └── setup-webhook.js           # Auto-configure GitHub webhook via REST API
│   ├── package.json
│   ├── .env.example
│   └── .env                           # Your local config (git-ignored)
├── README.md
└── .gitignore
```

---

## Prerequisites

| Tool | Install |
|---|---|
| Node.js ≥ 20.6 | [nvm](https://github.com/nvm-sh/nvm): `nvm install 22` |
| Docker | `sudo apt install docker.io && sudo usermod -aG docker $USER` |
| Semgrep | `pip install --user semgrep` |
| TruffleHog | [GitHub releases](https://github.com/trufflesecurity/trufflehog/releases) or `pip install trufflehog` |
| git | `sudo apt install git` |

---

## Setup

### 1. Clone and install

```bash
git clone https://github.com/Krishna-cell-12/NexusGuard-AI.git
cd NexusGuard-AI/backend
npm install

# On WSL2 (Windows PATH issue): use nvm's npm explicitly
node ~/.nvm/versions/node/$(node --version)/lib/node_modules/npm/bin/npm-cli.js install
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env — all variables documented inside
```

| Variable | Required | Description |
|---|---|---|
| `GITHUB_WEBHOOK_SECRET` | ✅ | Shared secret set in GitHub → Settings → Webhooks |
| `PORT` | optional | Server port (default: `3000`) |
| `AI_SERVICE_URL` | optional | AI patch endpoint (default: `http://localhost:8000/api/ai/generate-patch`) |
| `WEB3_SERVICE_URL` | optional | Web3 bounty endpoint (default: `http://localhost:8001/api/web3/trigger-bounty`) |
| `FRONTEND_WEBHOOK_URL` | optional | HTTP fallback when no WS clients connected |
| `HTTP_TIMEOUT_MS` | optional | Upstream service timeout ms (default: `10000`) |

### 3. Start the server

```bash
cd backend
npm run dev       # hot-reload via node --watch
npm start         # production
```

Server starts on `http://localhost:3000`. WebSocket endpoint: `ws://localhost:3000`.

### 4. Expose with ngrok (for GitHub webhooks during development)

```bash
ngrok http 3000
```

Copy the `https://<id>.ngrok-free.app` URL — use it as the webhook URL.

### 5. Register a GitHub Webhook

**Option A — Automated (recommended):**
```bash
cd backend
GITHUB_TOKEN=ghp_xxx npm run webhook:setup
# or with a custom ngrok URL:
GITHUB_TOKEN=ghp_xxx node scripts/setup-webhook.js https://your-url.ngrok-free.app
```

**Option B — Manual:**
1. Go to your repo → **Settings → Webhooks → Add webhook**
2. **Payload URL**: `https://<your-ngrok-url>/api/webhook/github`
3. **Content type**: `application/json`
4. **Secret**: paste the value of `GITHUB_WEBHOOK_SECRET` from your `.env`
5. **Events**: Select `Push` and `Pull requests`
6. Click **Add webhook**

### 6. Configure GitHub Actions secrets

In your repo → **Settings → Secrets and variables → Actions**:

| Secret / Variable | Value |
|---|---|
| `NEXUSGUARD_WEBHOOK_SECRET` (Secret) | Same value as `GITHUB_WEBHOOK_SECRET` in `.env` |
| `NEXUSGUARD_API_URL` (Variable) | Your ngrok URL or production server URL |
| `SEMGREP_APP_TOKEN` (Secret) | Optional — from [semgrep.dev](https://semgrep.dev) for managed rules |

---

## API Reference

### `POST /api/webhook/github`
GitHub webhook receiver. Verifies `X-Hub-Signature-256` and dispatches the scan pipeline.

**Headers required:**
- `X-Hub-Signature-256: sha256=<hmac>`
- `X-GitHub-Event: push` or `pull_request`
- `X-GitHub-Delivery: <uuid>`

**Response:** `202 Accepted` with `{ message, runId, repoName, commitSha, ... }`

---

### `GET /health`
Liveness probe. Returns `200 OK` when the server is up.

```json
{ "status": "ok", "service": "nexusguard-ai", "uptime": 42, "timestamp": "..." }
```

---

### `GET /api/status/:runId`
Returns the current pipeline state for a given `runId` (returned by the webhook endpoint).

```json
{
  "runId": "run_1718264400000_a8xqz",
  "state": "PATCH_RECEIVED",
  "message": "AI patch received.",
  "repoName": "my-repo",
  "commitSha": "abc123",
  "updatedAt": "2026-06-13T07:45:00.000Z"
}
```

---

### WebSocket Events

Connect to `ws://localhost:3000`. All events are JSON.

| Event | When |
|---|---|
| `PIPELINE_STATE` | Every state transition — real-time progress |
| `SCAN_COMPLETE` | Full results payload (summary + patch + bounty receipt) |
| `PIPELINE_FAILED` | On any unrecoverable error |

**Frontend example:**
```js
const ws = new WebSocket("ws://localhost:3000");
ws.onmessage = ({ data }) => {
  const { event, state, ...payload } = JSON.parse(data);
  if (event === "PIPELINE_STATE")  updateBadge(state);
  if (event === "SCAN_COMPLETE")   renderReport(payload);
  if (event === "PIPELINE_FAILED") showError(payload);
};
```

---

## Pipeline States

```
STARTED → SCANNING → SCAN_COMPLETE
                          │
                    no findings → NO_VULNS_FOUND → (done)
                          │
                    findings  → REQUESTING_PATCH → PATCH_RECEIVED
                                                        │
                                              TRIGGERING_BOUNTY → BOUNTY_RELEASED
                                                                        │
                                                               NOTIFYING_UI → COMPLETED
                          │ (any step)
                        FAILED
```

**Demo tip — tail logs in real-time:**
```bash
cd backend && npm run dev 2>&1 | grep '"state"'
```

---

## WSL2 note — Windows npm in PATH

If `npm install` fails with `UNC paths are not supported`, your shell is picking up the Windows npm. Use nvm's npm directly:

```bash
node ~/.nvm/versions/node/$(node --version)/lib/node_modules/npm/bin/npm-cli.js install
```
