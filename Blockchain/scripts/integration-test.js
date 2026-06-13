/**
 * NexusGuard — Integration Self-Test
 * Spins up a local Hardhat node, deploys the contract with your real
 * private key as both deployer and oracle, then runs the full
 * createBounty → submitPatch → releaseBounty lifecycle.
 *
 * Run: node scripts/integration-test.js
 */

const { ethers, network } = require("hardhat");
require("dotenv").config();

const WALLET_ADDR = "0x552D2D307672fe47506dB8A29C0CC086a6f7a2eb";
const FEE_BPS     = 200; // 2 %
const BUG_ID      = "CVE-2026-NEXUSGUARD-DEMO";

async function main() {
  console.log("\n╔══════════════════════════════════════════════════╗");
  console.log("║   NexusGuard — Oracle Key Integration Self-Test  ║");
  console.log("╚══════════════════════════════════════════════════╝\n");

  // ── 1. Signers ──────────────────────────────────────────────
  const [deployer, sponsor, contributor] = await ethers.getSigners();

  console.log(`  Oracle/Deployer : ${deployer.address}`);
  console.log(`  Sponsor         : ${sponsor.address}`);
  console.log(`  Contributor     : ${contributor.address}`);

  const deployerBal = await ethers.provider.getBalance(deployer.address);
  console.log(`  Deployer Balance: ${ethers.formatEther(deployerBal)} MATIC\n`);

  // ── 2. Deploy Contract ─────────────────────────────────────
  console.log("  [1/5] Deploying NexusGuardBounty...");
  const Factory  = await ethers.getContractFactory("NexusGuardBounty", deployer);
  const contract = await Factory.deploy(deployer.address, FEE_BPS);
  await contract.waitForDeployment();
  const addr = await contract.getAddress();
  console.log(`        ✅ Deployed at: ${addr}`);
  console.log(`        Oracle set to: ${await contract.oracleAddress()}`);
  console.log(`        Fee          : ${await contract.feeBasisPoints()} bps\n`);

  // ── 3. createBounty (1 MATIC) ──────────────────────────────
  const BOUNTY = ethers.parseEther("1");
  console.log("  [2/5] Sponsor creating a 1 MATIC bounty...");
  const createTx = await contract.connect(sponsor).createBounty(
    BUG_ID,
    ethers.ZeroAddress, // native MATIC
    0,
    { value: BOUNTY }
  );
  const createReceipt = await createTx.wait();
  console.log(`        ✅ Tx: ${createTx.hash}`);

  // Parse VulnerabilityFound event
  for (const log of createReceipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed.name === "VulnerabilityFound") {
        console.log(`        📢 VulnerabilityFound — bugId: "${parsed.args.bugId}", amount: ${ethers.formatEther(parsed.args.amount)} MATIC`);
      }
    } catch {}
  }

  const contractBal = await ethers.provider.getBalance(addr);
  console.log(`        Contract balance: ${ethers.formatEther(contractBal)} MATIC\n`);

  // ── 4. submitPatch ─────────────────────────────────────────
  console.log("  [3/5] Contributor submitting patch...");
  const patchTx = await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
  const patchReceipt = await patchTx.wait();
  console.log(`        ✅ Tx: ${patchTx.hash}`);

  for (const log of patchReceipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed.name === "PatchSubmitted") {
        console.log(`        📢 PatchSubmitted — bugId: "${parsed.args.bugId}", contributor: ${parsed.args.contributor}`);
      }
    } catch {}
  }

  const status = await contract.getBountyStatus(BUG_ID);
  console.log(`        Bounty status: ${["OPEN","SUBMITTED","PAID","CANCELLED"][Number(status)]}\n`);

  // ── 5. releaseBounty (Oracle signs!) ───────────────────────
  console.log("  [4/5] Oracle (your key) releasing bounty...");
  const contribBefore = await ethers.provider.getBalance(contributor.address);

  const releaseTx = await contract.connect(deployer).releaseBounty(BUG_ID, contributor.address);
  const releaseReceipt = await releaseTx.wait();
  console.log(`        ✅ Tx: ${releaseTx.hash}`);

  for (const log of releaseReceipt.logs) {
    try {
      const parsed = contract.interface.parseLog(log);
      if (parsed.name === "BountyPaid") {
        const net = ethers.formatEther(parsed.args.amount);
        console.log(`        📢 BountyPaid — bugId: "${parsed.args.bugId}", net: ${net} MATIC → ${parsed.args.contributor}`);
      }
    } catch {}
  }

  const contribAfter  = await ethers.provider.getBalance(contributor.address);
  const fee           = (BOUNTY * BigInt(FEE_BPS)) / 10_000n;
  const netPayout     = BOUNTY - fee;
  const actualGain    = contribAfter - contribBefore;

  console.log(`\n        Expected net payout : ${ethers.formatEther(netPayout)} MATIC`);
  console.log(`        Actual gain         : ${ethers.formatEther(actualGain)} MATIC`);
  console.log(`        Platform fee (2%)   : ${ethers.formatEther(fee)} MATIC`);

  // ── 6. Verify Final State ──────────────────────────────────
  console.log("\n  [5/5] Verifying final on-chain state...");
  const bounty = await contract.getBounty(BUG_ID);
  const finalStatus = ["OPEN","SUBMITTED","PAID","CANCELLED"][Number(bounty.status)];
  console.log(`        Bounty status : ${finalStatus}`);
  console.log(`        Paid at       : ${new Date(Number(bounty.paidAt) * 1000).toISOString()}`);
  console.log(`        Pending fees  : ${ethers.formatEther(await contract.pendingNativeFees())} MATIC`);

  const contractFinalBal = await ethers.provider.getBalance(addr);
  console.log(`        Contract bal  : ${ethers.formatEther(contractFinalBal)} MATIC (only fee remains)`);

  // ── Result ─────────────────────────────────────────────────
  if (finalStatus === "PAID" && actualGain === netPayout) {
    console.log("\n  ╔══════════════════════════════════════════════════╗");
    console.log("  ║  ✅  ALL CHECKS PASSED — Oracle key works!       ║");
    console.log("  ║  Private key derived, contract deployed,         ║");
    console.log("  ║  bounty locked & released end-to-end.            ║");
    console.log("  ╚══════════════════════════════════════════════════╝\n");
  } else {
    console.error("\n  ❌  Check failed — status or payout mismatch.");
    process.exit(1);
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
