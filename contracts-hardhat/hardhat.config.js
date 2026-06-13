// ============================================================
//  NexusGuard AI — Hardhat Configuration
//  hardhat.config.js
//
//  Configured for:
//    • Local Hardhat Network (testing)
//    • Polygon Amoy Testnet (deployment + Polygonscan verification)
//    • Polygon Mainnet (production — use with caution!)
//
//  Prerequisites:
//    npm install --save-dev hardhat \
//      @nomicfoundation/hardhat-toolbox \
//      @nomicfoundation/hardhat-verify \
//      @openzeppelin/contracts \
//      dotenv
// ============================================================

require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-verify");   // Polygonscan verification
require("dotenv").config();

// ── Environment Variable Guards ───────────────────────────────
// These are validated at config-load time so you get a clear error
// message rather than a cryptic runtime failure mid-deployment.
const {
  PRIVATE_KEY,
  POLYGON_AMOY_RPC_URL,
  POLYGON_MAINNET_RPC_URL,
  POLYGONSCAN_API_KEY,
} = process.env;

// A valid private key must be a 32-byte hex string (64 hex chars, optionally 0x-prefixed).
// If PRIVATE_KEY is a placeholder or missing, fall back to a dummy so `compile` / `test`
// still work without needing a real wallet configured.
const HEX_RE = /^(0x)?[0-9a-fA-F]{64}$/;
const FALLBACK_KEY = "0x" + "a".repeat(64);
const DEPLOY_KEY   = HEX_RE.test(PRIVATE_KEY || "") ? PRIVATE_KEY : FALLBACK_KEY;

/** @type {import('hardhat/config').HardhatUserConfig} */
module.exports = {
  // ─── Solidity Compiler ─────────────────────────────────────
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,          // Optimise for average call frequency (deploy + read heavy).
      },
      viaIR: false,         // Set true only if you hit "stack too deep" errors.
    },
  },

  // ─── Named Networks ────────────────────────────────────────
  networks: {
    // Local hardhat node — used by `npx hardhat test`
    hardhat: {
      chainId: 31337,
    },

    // ── Polygon Amoy Testnet ────────────────────────────────
    // Chain ID : 80002
    // Faucet   : https://faucet.polygon.technology/
    // Explorer : https://amoy.polygonscan.com/
    polygonAmoy: {
      url:      POLYGON_AMOY_RPC_URL || "https://rpc-amoy.polygon.technology/",
      accounts: [DEPLOY_KEY],
      chainId:  80002,
      gasPrice: "auto",   // Let Hardhat negotiate EIP-1559 fees automatically.
      // Optional: set a hard gas limit to avoid accidental runaway txs.
      // gas: 3_000_000,
    },

    // ── Polygon Mainnet ─────────────────────────────────────
    // ⚠️  Real funds — only use after thorough testing on Amoy.
    polygon: {
      url:      POLYGON_MAINNET_RPC_URL || "https://polygon-rpc.com/",
      accounts: [DEPLOY_KEY],
      chainId:  137,
      gasPrice: "auto",
    },
  },

  // ─── Etherscan / Polygonscan Verification ──────────────────
  // After deploying, run:
  //   npx hardhat verify --network polygonAmoy <CONTRACT_ADDRESS> <CONSTRUCTOR_ARGS>
  etherscan: {
    apiKey: {
      // Polygonscan uses the same API key for Amoy + Mainnet.
      polygonAmoy: POLYGONSCAN_API_KEY || "",
      polygon:     POLYGONSCAN_API_KEY || "",
    },
    customChains: [
      {
        // Polygon Amoy is not in Hardhat's built-in chain list yet — add it manually.
        network:   "polygonAmoy",
        chainId:   80002,
        urls: {
          apiURL:     "https://api-amoy.polygonscan.com/api",
          browserURL: "https://amoy.polygonscan.com",
        },
      },
    ],
  },

  // ─── Gas Reporter (optional but useful for hackathon demos) ─
  gasReporter: {
    enabled:      process.env.REPORT_GAS === "true",
    currency:     "USD",
    coinmarketcap: process.env.COINMARKETCAP_API_KEY,
    outputFile:   "gas-report.txt",
    noColors:     true,
  },

  // ─── Source Paths ───────────────────────────────────────────
  paths: {
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },
};
