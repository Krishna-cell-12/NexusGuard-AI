# 🛡️ NexusGuard AI — Layer 5: Blockchain & Bounty Layer

> **Autonomous Security Engineer for Open Source**  
> *Detect. Explain. Fix. Reward — all on-chain.*

[![Polygon](https://img.shields.io/badge/Network-Polygon%20Amoy-8247e5?logo=polygon)](https://amoy.polygonscan.com/)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-363636?logo=solidity)](https://docs.soliditylang.org/)
[![OpenZeppelin](https://img.shields.io/badge/OpenZeppelin-5.x-4e5ee4?logo=openzeppelin)](https://openzeppelin.com/)
[![Hardhat](https://img.shields.io/badge/Hardhat-2.22-f7dc6f)](https://hardhat.org/)
[![Ethers.js](https://img.shields.io/badge/Ethers.js-6.x-2535a0)](https://docs.ethers.org/v6/)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     NexusGuard AI System                        │
│                                                                 │
│  GitHub PR  ──→  NexusGuard AI  ──→  Webhook  ──→  Oracle API  │
│    Merged         (AI Verified)      (HMAC)      (Express.js)   │
│                                            │                    │
│                                            ▼                    │
│                              ┌─────────────────────────┐       │
│                              │   NexusGuardBounty.sol  │       │
│                              │   (Polygon Amoy/Mainnet) │       │
│                              │  Escrow ──→ Contributor  │       │
│                              │  MATIC / USDC payout     │       │
│                              └─────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

---

## How the Escrow Flow Works (For Judges)

This is a **three-actor, four-stage** lifecycle. Every state transition is recorded on-chain — giving full transparency to anyone with a block explorer.

### The Four Actors

| Actor | Role |
|-------|------|
| **Sponsor** | Deposits funds for a known vulnerability |
| **Contributor** | Developer who submits the security patch PR |
| **Oracle** | Authorized backend wallet — only address that can trigger payouts |
| **NexusGuard AI** | Verifies the patch, then signals the Oracle |

---

### Stage 1 — Vulnerability Found → `createBounty()`

```
Sponsor → createBounty("CVE-2025-12345", USDC_ADDRESS, 500_000000)
         Funds locked in contract (500 USDC)
         emit VulnerabilityFound("CVE-2025-12345", sponsor, USDC, 500, timestamp)
```

> Supports both USDC (ERC-20) and native MATIC. For MATIC, pass `address(0)` as the token.

---

### Stage 2 — Patch Submitted → `submitPatch()`

```
NexusGuard Backend → submitPatch("CVE-2025-12345", "0xContributor...")
         Bounty status: OPEN → SUBMITTED
         emit PatchSubmitted("CVE-2025-12345", contributor, timestamp)
```

---

### Stage 3 — PR Merged → Oracle Webhook Fires

```
GitHub Webhook → POST /api/webhooks/github/merge
                 { bugId: "CVE-2025-12345", contributorWalletAddress: "0x..." }
         bountyController.js authenticates (HMAC-SHA256) + validates
         Oracle wallet calls releaseBounty() on-chain
```

---

### Stage 4 — Bounty Paid → `releaseBounty()`

The Oracle calls `releaseBounty()`. The contract:
1. Verifies the caller is the Oracle (access control)
2. Verifies the contributor address matches (TOCTOU prevention)
3. Deducts the platform fee (2%)
4. Transfers the net payout to the contributor
5. Emits `BountyPaid` for frontends to read

```
Oracle → releaseBounty("CVE-2025-12345", "0xContributor...")
         Fee (2%) → platform treasury
         Net (98%) → contributor wallet (instant)
         emit BountyPaid("CVE-2025-12345", contributor, 490 USDC, timestamp)
```

---

## Project Structure

```
NexusGuard/
├── contracts/
│   └── NexusGuardBounty.sol      ← Core escrow contract
├── scripts/
│   └── deploy.js                 ← Hardhat deployment + auto-verify
├── test/
│   └── NexusGuardBounty.test.js  ← Full test suite
├── backend/
│   ├── server.js                 ← Express app entry point
│   └── controllers/
│       └── bountyController.js   ← Oracle webhook bridge (ethers.js)
├── deployments/                  ← Auto-generated after deploy
│   └── polygonAmoy.json
├── hardhat.config.js
├── package.json
└── .env.example
```

---

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

```bash
cp .env.example .env
# Fill in ORACLE_PRIVATE_KEY, POLYGONSCAN_API_KEY, etc.
```

Get testnet MATIC from the [Polygon Faucet](https://faucet.polygon.technology/).

### 3. Compile

```bash
npx hardhat compile
```

### 4. Run Tests

```bash
npx hardhat test
# With gas report:
REPORT_GAS=true npx hardhat test
```

### 5. Deploy to Polygon Amoy

```bash
npx hardhat run scripts/deploy.js --network polygonAmoy
```

The script automatically:
- Validates your balance
- Deploys the contract
- Saves `deployments/polygonAmoy.json`
- Waits 30s and verifies on Polygonscan

### 6. Manual Verification (if auto-verify failed)

```bash
npx hardhat verify --network polygonAmoy \
  <CONTRACT_ADDRESS> \
  "<ORACLE_ADDRESS>" \
  200
```

### 7. Run the Oracle Backend

```bash
# Copy the contract address from deployments/polygonAmoy.json into .env
npm run backend:dev
```

---

## Security Design Notes

### Access Control
- **`releaseBounty`** is restricted to the Oracle address via `onlyOracle` modifier.
- **`setOracle`** is restricted to the contract owner, allowing key rotation without redeployment.
- **Sponsor self-dealing prevention**: `submitPatch` rejects transactions where `contributor == sponsor`.

### Re-entrancy Protection
All state-mutating functions use OpenZeppelin's `ReentrancyGuard`. The contract also follows **Checks-Effects-Interactions**: bounty status is set to `PAID` *before* the transfer is made.

### Safe Token Transfers
All ERC-20 transfers use OpenZeppelin's `SafeERC20`, which handles non-standard tokens gracefully.

### Webhook Authentication
The backend uses **HMAC-SHA256** with a shared secret to verify incoming webhook requests. `crypto.timingSafeEqual` prevents timing-based side-channel attacks.

---

## The Oracle Problem — Judge Q&A

> *"How does the contract know the GitHub PR was actually merged?"*

**For the hackathon:** Our backend acts as a **centralized trusted Oracle**. The backend wallet is the sole authorized signer — it queries the GitHub API to confirm the PR is merged before calling `releaseBounty`. This is secure because:
- Only one private key can call `releaseBounty`
- All payouts are publicly verifiable on Polygonscan
- HMAC authentication prevents spoofed webhook requests

**For production mainnet:** We would replace the centralized backend with:
- **[Chainlink Functions](https://docs.chain.link/chainlink-functions)** — Makes HTTP calls to the GitHub API from the smart contract itself via a Decentralized Oracle Network.
- **[UMA Optimistic Oracle](https://uma.xyz/)** — Allows anyone to assert "PR #42 was merged" with a dispute window, requiring no off-chain trusted party.
- **[Gelato Relay](https://www.gelato.network/)** — Gasless meta-transactions so contributors don't need MATIC to interact.

---

## API Reference (Oracle Backend)

### `GET /api/health`
Returns Oracle wallet status and current block number.

### `GET /api/bounty/:bugId`
Returns the full on-chain state of a bounty.

```json
{
  "success": true,
  "bounty": {
    "sponsor": "0x...",
    "tokenAddress": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
    "amount": "500000000",
    "contributor": "0x...",
    "status": "SUBMITTED",
    "createdAt": "2025-06-13T06:00:00.000Z",
    "paidAt": null
  }
}
```

### `POST /api/webhooks/github/merge`
Triggers an on-chain bounty payout.

**Headers:**
```
Content-Type: application/json
X-NexusGuard-Signature: sha256=<hmac_hex>
```

**Body:**
```json
{
  "bugId": "CVE-2025-12345",
  "contributorWalletAddress": "0xContributorAddress...",
  "prNumber": 42,
  "repositoryFullName": "acme/open-source-lib"
}
```

**Success Response:**
```json
{
  "success": true,
  "txHash": "0x...",
  "blockNumber": 15234567,
  "netPayout": "490.00",
  "explorerUrl": "https://amoy.polygonscan.com/tx/0x..."
}
```

---

## On-Chain Events (for Frontend Live Feed)

| Event | When Emitted | Data |
|-------|-------------|------|
| `VulnerabilityFound` | Bounty created | bugId, sponsor, token, amount, timestamp |
| `PatchSubmitted` | Patch registered | bugId, contributor, timestamp |
| `BountyPaid` | Bounty released | bugId, contributor, netAmount, token, timestamp |
| `BountyCancelled` | Sponsor cancels | bugId, sponsor, refundAmount, timestamp |

```javascript
// Example: Frontend live event subscription (ethers.js v6)
const contract = new ethers.Contract(CONTRACT_ADDRESS, ABI, provider);

contract.on("BountyPaid", (bugId, contributor, amount, token, timestamp) => {
  console.log(`Bounty paid for ${bugId}: ${ethers.formatUnits(amount, 6)} USDC → ${contributor}`);
  // Update React state / Chart.js graph here
});
```

---

## Why This Wins

1. **Real on-chain escrow** — not a mock. Funds are genuinely locked and released by a smart contract.
2. **Dual-currency** — supports both native MATIC and any ERC-20 (USDC preconfigured).
3. **Production-grade security** — ReentrancyGuard, SafeERC20, access control, HMAC webhook auth.
4. **Full transparency** — every lifecycle event is on-chain and readable by anyone.
5. **Verified on Polygonscan** — judges can inspect the source code with a green checkmark.
6. **Extensible oracle design** — clear upgrade path to Chainlink Functions for trustless GitHub verification.

---

*Built for HackPrix 2025 — NexusGuard AI Team*
