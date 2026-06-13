// ============================================================
//  NexusGuard AI — Hardhat Deployment Script
//  scripts/deploy.js
//
//  Deploys NexusGuardBounty to the configured network and
//  optionally verifies the source on Polygonscan.
//
//  Usage:
//    npx hardhat run scripts/deploy.js --network polygonAmoy
//
//  Then verify:
//    npx hardhat verify --network polygonAmoy <ADDRESS> <ORACLE> <FEE>
// ============================================================

const { ethers, network, run } = require("hardhat");
require("dotenv").config();

// ─────────────────────────────────────────────────────────────
//  DEPLOYMENT CONFIGURATION
//  Tweak these before deploying.
// ─────────────────────────────────────────────────────────────

const CONFIG = {
  /**
   * The Oracle wallet address — this will be the ONLY address allowed
   * to call `releaseBounty`.
   *
   * For the hackathon demo this is our backend webhook wallet.
   * In production, replace with a Chainlink Functions consumer or
   * a UMA Optimistic Oracle for fully trustless GitHub verification.
   *
   * Falls back to ORACLE_ADDRESS in .env, then to the deployer wallet.
   */
  oracleAddress: process.env.ORACLE_ADDRESS || null,

  /**
   * Platform fee in basis points.
   * 200 = 2 %   (default)
   * 0   = waive fees for the hackathon demo
   */
  feeBasisPoints: 200,

  /**
   * Set to true to automatically verify on Polygonscan after deploy.
   * Requires POLYGONSCAN_API_KEY in .env.
   */
  autoVerify: true,

  /**
   * Seconds to wait after deployment before attempting verification.
   * Polygonscan indexers need a moment to pick up the new contract.
   */
  verifyDelay: 30,
};

// ─────────────────────────────────────────────────────────────
//  HELPER UTILITIES
// ─────────────────────────────────────────────────────────────

/**
 * Sleep for `ms` milliseconds.  Used to give Polygonscan time
 * to index the contract before we call `verify`.
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Pretty-print a separator line with an optional label.
 */
function banner(label = "") {
  const line = "─".repeat(60);
  console.log(label ? `\n${line}\n  ${label}\n${line}` : `\n${line}`);
}

// ─────────────────────────────────────────────────────────────
//  MAIN DEPLOYMENT FUNCTION
// ─────────────────────────────────────────────────────────────

async function main() {
  banner("NexusGuard AI — Bounty Contract Deployment");

  // ── Signers & Network Info ───────────────────────────────
  const [deployer] = await ethers.getSigners();
  const networkInfo = await ethers.provider.getNetwork();

  console.log(`  Network  : ${network.name} (Chain ID: ${networkInfo.chainId})`);
  console.log(`  Deployer : ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`  Balance  : ${ethers.formatEther(balance)} MATIC`);

  if (balance === 0n) {
    throw new Error(
      "Deployer has 0 MATIC. Fund the account via https://faucet.polygon.technology/ first."
    );
  }

  // ── Resolve Constructor Arguments ────────────────────────
  const oracleAddress = CONFIG.oracleAddress || deployer.address;
  const feeBasisPoints = CONFIG.feeBasisPoints;

  console.log(`\n  Oracle   : ${oracleAddress}`);
  console.log(`  Fee      : ${feeBasisPoints} bps (${feeBasisPoints / 100}%)`);

  if (oracleAddress === deployer.address) {
    console.log(
      "\n  ⚠️  Oracle == Deployer. This is fine for testing but rotate keys before mainnet!"
    );
  }

  // ── Compile & Get Factory ────────────────────────────────
  banner("Deploying Contract");

  const NexusGuardBounty = await ethers.getContractFactory("NexusGuardBounty");

  console.log("  Estimating deployment gas...");
  const deployTx = await NexusGuardBounty.getDeployTransaction(oracleAddress, feeBasisPoints);
  const estimatedGas = await ethers.provider.estimateGas(deployTx);
  console.log(`  Estimated gas : ${estimatedGas.toString()} units`);

  // ── Deploy ───────────────────────────────────────────────
  console.log("\n  Broadcasting deployment transaction...");
  const contract = await NexusGuardBounty.deploy(oracleAddress, feeBasisPoints);

  const deploymentTx = contract.deploymentTransaction();
  console.log(`  Tx Hash  : ${deploymentTx.hash}`);
  console.log("  Waiting for confirmation...");

  // Wait for 2 block confirmations for reliability on Polygon.
  await contract.waitForDeployment();
  const contractAddress = await contract.getAddress();

  banner("Deployment Successful! 🎉");
  console.log(`  Contract Address : ${contractAddress}`);
  console.log(`  Block Explorer   : https://amoy.polygonscan.com/address/${contractAddress}`);

  // ── Write Deployment Artefact ────────────────────────────
  // Saves contract address and ABI reference for use by the backend.
  const fs = require("fs");
  const path = require("path");

  const deploymentData = {
    network:         network.name,
    chainId:         networkInfo.chainId.toString(),
    contractAddress,
    deployerAddress: deployer.address,
    oracleAddress,
    feeBasisPoints,
    txHash:          deploymentTx.hash,
    deployedAt:      new Date().toISOString(),
  };

  const outputDir = path.join(__dirname, "../deployments");
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const outputPath = path.join(outputDir, `${network.name}.json`);
  fs.writeFileSync(outputPath, JSON.stringify(deploymentData, null, 2));
  console.log(`\n  Deployment record saved → ${outputPath}`);

  // ── Polygonscan Verification ─────────────────────────────
  if (CONFIG.autoVerify && network.name !== "hardhat" && network.name !== "localhost") {
    banner("Polygonscan Verification");

    console.log(`  Waiting ${CONFIG.verifyDelay}s for Polygonscan to index the contract...`);
    await sleep(CONFIG.verifyDelay * 1000);

    try {
      await run("verify:verify", {
        address:              contractAddress,
        constructorArguments: [oracleAddress, feeBasisPoints],
        contract:             "contracts/NexusGuardBounty.sol:NexusGuardBounty",
      });

      console.log("  ✅  Contract verified successfully on Polygonscan!");
      console.log(
        `  🔗  https://amoy.polygonscan.com/address/${contractAddress}#code`
      );
    } catch (err) {
      if (err.message.toLowerCase().includes("already verified")) {
        console.log("  ℹ️   Contract is already verified.");
      } else {
        console.error("  ⚠️   Verification failed:", err.message);
        console.log("  Manual verification command:");
        console.log(
          `  npx hardhat verify --network ${network.name} ${contractAddress} "${oracleAddress}" ${feeBasisPoints}`
        );
      }
    }
  }

  banner("Done");
  console.log("\n  Next steps:");
  console.log("  1. Copy contractAddress into your backend .env as CONTRACT_ADDRESS");
  console.log("  2. Fund the Oracle wallet with MATIC for gas");
  console.log("  3. Call createBounty() via the frontend or Polygonscan UI");
  console.log("  4. Merge a patch PR → webhook fires → releaseBounty() pays out!\n");

  return contractAddress;
}

// ─────────────────────────────────────────────────────────────
//  ENTRY POINT
// ─────────────────────────────────────────────────────────────

main()
  .then((addr) => {
    console.log(`✅  NexusGuardBounty deployed at: ${addr}`);
    process.exit(0);
  })
  .catch((error) => {
    console.error("\n❌  Deployment failed:");
    console.error(error);
    process.exit(1);
  });
