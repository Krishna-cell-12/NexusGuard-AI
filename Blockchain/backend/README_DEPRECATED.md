# ⚠️ DEPRECATED — This standalone server is superseded

## Why This Exists

This `Blockchain/backend/` directory was a standalone Oracle backend
written in CommonJS (CJS) that ran on port 3001. It duplicated the blockchain
oracle functionality already present in `backend/web3/` (the main service).

## What Replaced It

The main unified service at **`../../backend/`** now provides all Oracle routes:

| Old Route (port 3001)             | New Route (port 3000)                  |
|-----------------------------------|----------------------------------------|
| `GET  /api/health`                | `GET  /api/web3/health`                |
| `GET  /api/bounty/:bugId`         | `GET  /api/web3/bounty/:bugId`         |
| `POST /api/webhooks/github/merge` | `POST /api/web3/webhook/merge`         |

## How to Run the Unified Backend

```bash
cd ../../backend
npm install
node --env-file=.env server.js
```

## Hardhat (Contract Deployment)

All contract work lives in `../../contracts-hardhat/`:

```bash
cd ../../contracts-hardhat
npm install
npm run deploy:amoy
```
