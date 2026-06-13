# 🔌 NexusGuard AI — Layer 3 & 4 Integration Guide
## Full API Reference for the Blockchain Layer

---

## Overview: How Layers 3, 4, and 5 Connect

```
┌──────────────────────────────────────────────────────────────────┐
│                     NexusGuard AI Pipeline                       │
│                                                                  │
│  Layer 3 (YOU)              Layer 4 (YOU)         Layer 5 (US)  │
│  ─────────────              ────────────           ──────────── │
│  AI finds vuln     →    AI generates patch   →   Smart contract  │
│  Generates PoC          Creates PR on GitHub      releases bounty│
│  Writes report          Calls our webhook          to contributor │
│                                                                  │
│  YOUR TRIGGER                YOUR TRIGGER          AUTO by us   │
│  submitPatch()  ─────────→  /github/merge  ──────→ BountyPaid   │
└──────────────────────────────────────────────────────────────────┘
```

---

## The Bounty Lifecycle (What You Need to Know)

```
State 1: OPEN       → Sponsor deposited funds (already done by frontend)
State 2: SUBMITTED  → YOU call submitPatch() when AI patch PR is created  ← Layer 4
State 3: PAID       → WE call releaseBounty() when PR is merged           ← Layer 5 auto
State 4: CANCELLED  → Sponsor withdrew (you don't need to handle)
```

**Your trigger points:**
- **Layer 3 output** → Report generated → Sponsor notified → They create bounty
- **Layer 4 output** → Patch PR created → Call `submitPatch` → State becomes SUBMITTED
- **Layer 4 output** → Patch PR merged → Call our webhook → State becomes PAID

---

## API Endpoints

### Base URL
```
http://localhost:3001   (development)
https://your-backend.com  (production)
```

---

### 1. `POST /api/webhooks/github/merge`
**Trigger this when your AI patch PR is merged.**

Releases the bounty payout to the contributor. Calls the blockchain.

#### Authentication
Every request needs an HMAC-SHA256 signature header:
```
X-NexusGuard-Signature: sha256=<computed_hmac>
```

Computing the signature:

**Python:**
```python
import hmac, hashlib, json

def sign_payload(payload_dict: dict, secret: str) -> str:
    body = json.dumps(payload_dict, separators=(',', ':'))
    mac  = hmac.new(secret.encode(), body.encode(), hashlib.sha256)
    return "sha256=" + mac.hexdigest()
```

**Node.js:**
```javascript
const crypto = require('crypto');

function signPayload(payloadObj, secret) {
  const body = JSON.stringify(payloadObj);
  const mac  = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return `sha256=${mac}`;
}
```

#### Request Body
```json
{
  "bugId":                    "CVE-2025-12345",
  "contributorWalletAddress": "0xABCD...1234",
  "prNumber":                 42,
  "repositoryFullName":       "acme/open-source-lib"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bugId` | string | ✅ | Must EXACTLY match the ID used when creating the bounty |
| `contributorWalletAddress` | string | ✅ | Ethereum address of the developer who wrote the patch |
| `prNumber` | number | Optional | GitHub PR number (for audit trail) |
| `repositoryFullName` | string | Optional | `"owner/repo"` format |

#### Success Response (200)
```json
{
  "success":     true,
  "message":     "Bounty successfully released on-chain 🎉",
  "txHash":      "0x3a8f...bc91",
  "blockNumber": 40069500,
  "netPayout":   "490.00",
  "explorerUrl": "https://amoy.polygonscan.com/tx/0x3a8f...bc91",
  "bugId":       "CVE-2025-12345",
  "contributor": "0xABCD...1234"
}
```

#### Error Responses
```json
{ "success": false, "error": "Bounty must be in SUBMITTED state" }
{ "success": false, "error": "Unauthorized: invalid webhook signature" }
{ "success": false, "error": "Bounty \"CVE-2025-12345\" not found on-chain" }
```

#### Full Python Example
```python
import requests, hmac, hashlib, json

BACKEND_URL    = "http://localhost:3001"
WEBHOOK_SECRET = "ASK_LAYER5_TEAM_FOR_THIS"

def release_bounty(bug_id: str, contributor_wallet: str, pr_number: int, repo: str):
    payload = {
        "bugId":                    bug_id,
        "contributorWalletAddress": contributor_wallet,
        "prNumber":                 pr_number,
        "repositoryFullName":       repo
    }
    body = json.dumps(payload, separators=(',', ':'))
    sig  = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body.encode(), hashlib.sha256
    ).hexdigest()

    resp = requests.post(
        f"{BACKEND_URL}/api/webhooks/github/merge",
        data=body,
        headers={
            "Content-Type":            "application/json",
            "X-NexusGuard-Signature":  sig
        },
        timeout=60  # blockchain tx can take up to 30s
    )
    
    data = resp.json()
    if data.get("success"):
        print(f"✅ Bounty paid! Tx: {data['explorerUrl']}")
        return data["txHash"]
    else:
        raise Exception(f"Bounty release failed: {data['error']}")

# Example call from your Layer 4 PR merge handler:
release_bounty(
    bug_id="CVE-2025-SQL-INJECTION-001",
    contributor_wallet="0xContributorWalletAddress",
    pr_number=42,
    repo="acme/vulnerable-app"
)
```

#### Full Node.js Example
```javascript
const axios  = require('axios');
const crypto = require('crypto');

const BACKEND_URL    = 'http://localhost:3001';
const WEBHOOK_SECRET = 'ASK_LAYER5_TEAM_FOR_THIS';

async function releaseBounty({ bugId, contributorWalletAddress, prNumber, repositoryFullName }) {
  const payload = { bugId, contributorWalletAddress, prNumber, repositoryFullName };
  const body    = JSON.stringify(payload);
  const sig     = 'sha256=' + crypto
    .createHmac('sha256', WEBHOOK_SECRET)
    .update(body)
    .digest('hex');

  const { data } = await axios.post(
    `${BACKEND_URL}/api/webhooks/github/merge`,
    body,
    { headers: { 'Content-Type': 'application/json', 'X-NexusGuard-Signature': sig } }
  );

  if (!data.success) throw new Error(data.error);
  console.log('✅ Tx Hash:', data.txHash);
  console.log('🔗 Explorer:', data.explorerUrl);
  return data;
}
```

---

### 2. `GET /api/bounty/:bugId`
**Check the current on-chain state of any bounty.**

No authentication needed — public read endpoint.

```bash
curl http://localhost:3001/api/bounty/CVE-2025-12345
```

Response:
```json
{
  "success": true,
  "bounty": {
    "sponsor":      "0xSponsorAddress",
    "tokenAddress": "0x0000000000000000000000000000000000000000",
    "amount":       "1000000000000000000",
    "contributor":  "0xContributorAddress",
    "status":       "SUBMITTED",
    "createdAt":    "2025-06-13T06:00:00.000Z",
    "paidAt":       null
  }
}
```

Status values: `"OPEN"` | `"SUBMITTED"` | `"PAID"` | `"CANCELLED"`

**Python:**
```python
import requests

def get_bounty_status(bug_id: str) -> dict:
    resp = requests.get(f"http://localhost:3001/api/bounty/{bug_id}")
    return resp.json()

bounty = get_bounty_status("CVE-2025-12345")
print(f"Status: {bounty['bounty']['status']}")
```

---

### 3. `GET /api/health`
Check if the backend Oracle is online.

```bash
curl http://localhost:3001/api/health
```

```json
{
  "status":          "healthy",
  "oracleAddress":   "0x552D2D307672fe47506dB8A29C0CC086a6f7a2eb",
  "oracleBalance":   "0.45 MATIC",
  "contractAddress": "0x...",
  "currentBlock":    40069453
}
```

---

## Direct Smart Contract Integration (Advanced)

If you want to call the contract directly (bypassing the backend), use `ethers.js`:

```javascript
const { ethers } = require('ethers');
const ABI = require('./abi/NexusGuardBounty.json'); // in this package

const CONTRACT_ADDRESS = 'ASK_LAYER5_TEAM'; // after deployment
const RPC_URL = 'https://rpc-amoy.polygon.technology/';

const provider = new ethers.JsonRpcProvider(RPC_URL);
const contract  = new ethers.Contract(CONTRACT_ADDRESS, ABI.abi, provider);

// Read bounty state
const bounty = await contract.getBounty('CVE-2025-12345');
console.log('Status:', ['OPEN','SUBMITTED','PAID','CANCELLED'][bounty.status]);
console.log('Amount:', ethers.formatEther(bounty.amount), 'MATIC');

// Listen to live on-chain events
contract.on('PatchSubmitted', (bugId, contributor, timestamp) => {
  console.log(`Patch submitted for ${bugId} by ${contributor}`);
  // Trigger your Layer 4 AI patch review pipeline here
});

contract.on('BountyPaid', (bugId, contributor, amount, token, timestamp) => {
  console.log(`Bounty paid for ${bugId}! Net: ${ethers.formatEther(amount)} MATIC`);
  // Update your dashboard / notify the contributor
});
```

---

## On-Chain Events Reference

Your Layer 3/4 code can subscribe to these events to react to blockchain activity:

| Event | When | Parameters |
|-------|------|------------|
| `VulnerabilityFound` | Sponsor creates bounty | `bugId`, `sponsor`, `tokenAddress`, `amount`, `timestamp` |
| `PatchSubmitted` | Patch PR registered | `bugId`, `contributor`, `timestamp` |
| `BountyPaid` | Bounty released | `bugId`, `contributor`, `netAmount`, `tokenAddress`, `timestamp` |
| `BountyCancelled` | Sponsor refunded | `bugId`, `sponsor`, `amount`, `timestamp` |

---

## The `bugId` Convention

The `bugId` is the key that links everything together. Agree on a format with the whole team:

```
Recommended format: "CVE-YYYY-REPONAME-NNNN"
Examples:
  - "CVE-2025-ACME-0001"
  - "NEXUS-2025-SQL-INJECTION-01"
  - "GH-ISSUE-acme/repo-123"
```

> ⚠️ The `bugId` used in `createBounty()` (by the frontend/sponsor) **must exactly match** what you pass in the webhook. Case-sensitive string comparison.

---

## Environment Variables You Need

Create a `.env` file in your project with:

```bash
# Backend URL (where the Layer 5 Oracle is running)
NEXUSGUARD_BACKEND_URL=http://localhost:3001

# The HMAC secret to sign webhook requests (get from Layer 5 team)
WEBHOOK_SECRET=ASK_LAYER5_TEAM_FOR_THIS

# Contract address (get from Layer 5 team after deployment)
CONTRACT_ADDRESS=ASK_LAYER5_TEAM_AFTER_DEPLOY

# RPC for reading contract events directly
POLYGON_AMOY_RPC_URL=https://rpc-amoy.polygon.technology/
```

---

## Contact Layer 5 Team For:
1. `WEBHOOK_SECRET` — needed to sign your webhook calls
2. `CONTRACT_ADDRESS` — available once deployed to Amoy
3. The confirmed `bugId` format for the project

---

*NexusGuard AI — HackPrix 2025*
