# 🤝 NexusGuard AI — Layer 3 & 4 Integration Package
## From the Layer 5 (Blockchain) Team

Hey! This package is everything you need to connect your **AI Exploit Reproduction (Layer 3)** and **AI Patch Generator (Layer 4)** work to our live smart contract on Polygon Amoy.

---

## 📦 What's in This Package

```
NexusGuard_L3L4_Integration/
├── abi/
│   └── NexusGuardBounty.json      ← Full contract ABI (use this in your code)
├── backend/
│   └── controllers/
│       └── bountyController.js    ← Our Oracle API bridge (reference)
│   └── server.js                  ← Our Express server (reference)
├── contracts/
│   └── NexusGuardBounty.sol       ← The smart contract source (for understanding)
├── INTEGRATION_GUIDE.md           ← ⭐ START HERE — your API reference
├── .env.example                   ← The env vars you need to set
└── README.md                      ← Full project overview
```

---

## ⚡ Quick Start for You

### Your Layer 3 Job (AI Exploit Reproduction)
When your AI finds + reproduces a vulnerability, call our backend:

```bash
# Tell our contract a vulnerability was found (sponsor creates bounty separately)
# Your job: trigger submitPatch() once the AI generates the patch PR

POST http://localhost:3001/api/webhooks/github/merge
```

### Your Layer 4 Job (AI Patch Generator)  
When the AI patch PR is merged and verified, fire this webhook:

```python
import requests, hmac, hashlib, json

payload = {
    "bugId": "CVE-2025-YOUR-ID",           # Same ID used when bounty was created
    "contributorWalletAddress": "0x...",   # Developer's wallet who wrote the patch
    "prNumber": 42,                        # GitHub PR number
    "repositoryFullName": "org/repo"
}

body = json.dumps(payload)
secret = "YOUR_WEBHOOK_SECRET"             # Get this from the Layer 5 team
sig = "sha256=" + hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()

response = requests.post(
    "http://localhost:3001/api/webhooks/github/merge",
    data=body,
    headers={
        "Content-Type": "application/json",
        "X-NexusGuard-Signature": sig
    }
)
print(response.json())  # Returns txHash + explorerUrl
```

---

## 🔗 Key Info from Layer 5 Team

| Item | Value |
|------|-------|
| **Oracle Wallet** | `0x552D2D307672fe47506dB8A29C0CC086a6f7a2eb` |
| **Network** | Polygon Amoy Testnet (Chain ID: 80002) |
| **Explorer** | https://amoy.polygonscan.com/ |
| **Backend Port** | 3001 |
| **Contract Address** | *(will be shared after live deployment)* |

> Ask the Layer 5 team for: `CONTRACT_ADDRESS` and `WEBHOOK_SECRET`

---

See `INTEGRATION_GUIDE.md` for the full API reference and code examples in Node.js, Python, and JavaScript.
