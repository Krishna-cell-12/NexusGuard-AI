// ============================================================
//  NexusGuard AI — Hardhat Test Suite
//  test/NexusGuardBounty.test.js
//
//  Run with:  npx hardhat test
//  Coverage:  npx hardhat coverage
// ============================================================

const { expect }        = require("chai");
const { ethers }        = require("hardhat");
const { loadFixture }   = require("@nomicfoundation/hardhat-toolbox/network-helpers");

// ─────────────────────────────────────────────────────────────
//  CONSTANTS
// ─────────────────────────────────────────────────────────────

const NATIVE_TOKEN    = ethers.ZeroAddress;
const FEE_BASIS_POINTS = 200n; // 2 %
const ONE_MATIC        = ethers.parseEther("1");
const BUG_ID           = "CVE-2025-99999";

// ─────────────────────────────────────────────────────────────
//  FIXTURE — deployed fresh before each test group
// ─────────────────────────────────────────────────────────────

async function deployFixture() {
  const [owner, oracle, sponsor, contributor, attacker] = await ethers.getSigners();

  const NexusGuardBounty = await ethers.getContractFactory("NexusGuardBounty");
  const contract = await NexusGuardBounty.deploy(oracle.address, FEE_BASIS_POINTS);
  await contract.waitForDeployment();

  // Deploy a mock ERC-20 (uses OpenZeppelin ERC20 mock from toolbox)
  const MockERC20 = await ethers.getContractFactory("MockERC20");
  const token = await MockERC20.deploy("USD Coin", "USDC", 6);
  await token.waitForDeployment();

  // Mint 1000 USDC (6 decimals) to the sponsor
  const USDC_AMOUNT = 1000n * 10n ** 6n;
  await token.mint(sponsor.address, USDC_AMOUNT);

  return { contract, token, owner, oracle, sponsor, contributor, attacker, USDC_AMOUNT };
}

// ─────────────────────────────────────────────────────────────
//  TEST SUITES
// ─────────────────────────────────────────────────────────────

describe("NexusGuardBounty", function () {

  // ── Deployment ──────────────────────────────────────────────
  describe("Deployment", function () {
    it("Should set the correct oracle address", async function () {
      const { contract, oracle } = await loadFixture(deployFixture);
      expect(await contract.oracleAddress()).to.equal(oracle.address);
    });

    it("Should set the correct fee", async function () {
      const { contract } = await loadFixture(deployFixture);
      expect(await contract.feeBasisPoints()).to.equal(FEE_BASIS_POINTS);
    });

    it("Should set the deployer as owner", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      expect(await contract.owner()).to.equal(owner.address);
    });

    it("Should reject plain MATIC sends via receive()", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);
      await expect(
        sponsor.sendTransaction({ to: await contract.getAddress(), value: ONE_MATIC })
      ).to.be.revertedWith("NexusGuard: use createBounty() to fund escrow");
    });
  });

  // ── createBounty — Native MATIC ─────────────────────────────
  describe("createBounty() — Native MATIC", function () {
    it("Should create a native bounty and emit VulnerabilityFound", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);

      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC })
      )
        .to.emit(contract, "VulnerabilityFound")
        // Event args: (bugIdHash, sponsor, bugId, tokenAddress, amount, timestamp)
        .withArgs(BUG_ID, sponsor.address, BUG_ID, NATIVE_TOKEN, ONE_MATIC, (ts) => ts > 0n);
    });

    it("Should hold MATIC in the contract", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });

      const contractBalance = await ethers.provider.getBalance(await contract.getAddress());
      expect(contractBalance).to.equal(ONE_MATIC);
    });

    it("Should revert if msg.value is 0", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);
      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: 0 })
      ).to.be.revertedWith("NexusGuard: must send MATIC to create a native bounty");
    });

    it("Should revert if the same bugId is used twice", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC })
      ).to.be.revertedWith("NexusGuard: bounty already exists for this bugId");
    });
  });

  // ── createBounty — ERC-20 ───────────────────────────────────
  describe("createBounty() — ERC-20 (USDC)", function () {
    it("Should create an ERC-20 bounty and pull tokens into escrow", async function () {
      const { contract, token, sponsor, USDC_AMOUNT } = await loadFixture(deployFixture);
      await token.connect(sponsor).approve(await contract.getAddress(), USDC_AMOUNT);

      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, await token.getAddress(), USDC_AMOUNT)
      ).to.emit(contract, "VulnerabilityFound");

      expect(await token.balanceOf(await contract.getAddress())).to.equal(USDC_AMOUNT);
    });

    it("Should revert if amount is 0", async function () {
      const { contract, token, sponsor } = await loadFixture(deployFixture);
      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, await token.getAddress(), 0)
      ).to.be.revertedWith("NexusGuard: amount must be > 0");
    });

    it("Should revert if MATIC is also sent with an ERC-20 bounty", async function () {
      const { contract, token, sponsor, USDC_AMOUNT } = await loadFixture(deployFixture);
      await token.connect(sponsor).approve(await contract.getAddress(), USDC_AMOUNT);
      await expect(
        contract.connect(sponsor).createBounty(BUG_ID, await token.getAddress(), USDC_AMOUNT, { value: ONE_MATIC })
      ).to.be.revertedWith("NexusGuard: do not send MATIC for an ERC-20 bounty");
    });
  });

  // ── submitPatch ─────────────────────────────────────────────
  describe("submitPatch()", function () {
    async function withOpenBounty() {
      const f = await loadFixture(deployFixture);
      await f.contract.connect(f.sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      return f;
    }

    it("Should record the contributor and emit PatchSubmitted", async function () {
      const { contract, contributor } = await withOpenBounty();
      // Event args: (bugIdHash, contributor, bugId, timestamp)
      await expect(contract.connect(contributor).submitPatch(BUG_ID, contributor.address))
        .to.emit(contract, "PatchSubmitted")
        .withArgs(BUG_ID, contributor.address, BUG_ID, (ts) => ts > 0n);
    });

    it("Should set bounty status to SUBMITTED (1)", async function () {
      const { contract, contributor } = await withOpenBounty();
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
      expect(await contract.getBountyStatus(BUG_ID)).to.equal(1);
    });

    it("Should revert if the sponsor tries to be the contributor", async function () {
      const { contract, sponsor } = await withOpenBounty();
      await expect(
        contract.connect(sponsor).submitPatch(BUG_ID, sponsor.address)
      ).to.be.revertedWith("NexusGuard: sponsor cannot be the contributor");
    });

    it("Should revert if patch is submitted twice", async function () {
      const { contract, contributor, attacker } = await withOpenBounty();
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
      await expect(
        contract.connect(attacker).submitPatch(BUG_ID, attacker.address)
      ).to.be.revertedWith("NexusGuard: bounty is not open for patch submission");
    });
  });

  // ── releaseBounty ───────────────────────────────────────────
  describe("releaseBounty()", function () {
    async function withSubmittedBounty() {
      const f = await loadFixture(deployFixture);
      await f.contract.connect(f.sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      await f.contract.connect(f.contributor).submitPatch(BUG_ID, f.contributor.address);
      return f;
    }

    it("Should release MATIC and emit BountyPaid", async function () {
      const { contract, oracle, contributor } = await withSubmittedBounty();
      const fee       = (ONE_MATIC * FEE_BASIS_POINTS) / 10_000n;
      const netPayout = ONE_MATIC - fee;

      await expect(
        contract.connect(oracle).releaseBounty(BUG_ID, contributor.address)
      )
        .to.emit(contract, "BountyPaid")
        // Event args: (bugIdHash, contributor, bugId, amount, tokenAddress, timestamp)
        .withArgs(BUG_ID, contributor.address, BUG_ID, netPayout, NATIVE_TOKEN, (ts) => ts > 0n);
    });

    it("Should transfer correct net MATIC to contributor", async function () {
      const { contract, oracle, contributor } = await withSubmittedBounty();
      const fee         = (ONE_MATIC * FEE_BASIS_POINTS) / 10_000n;
      const netPayout   = ONE_MATIC - fee;

      await expect(
        contract.connect(oracle).releaseBounty(BUG_ID, contributor.address)
      ).to.changeEtherBalance(contributor, netPayout);
    });

    it("Should accumulate the platform fee as pendingNativeFees", async function () {
      const { contract, oracle, contributor } = await withSubmittedBounty();
      const fee = (ONE_MATIC * FEE_BASIS_POINTS) / 10_000n;
      await contract.connect(oracle).releaseBounty(BUG_ID, contributor.address);
      expect(await contract.pendingNativeFees()).to.equal(fee);
    });

    it("Should revert if called by a non-Oracle address", async function () {
      const { contract, attacker, contributor } = await withSubmittedBounty();
      await expect(
        contract.connect(attacker).releaseBounty(BUG_ID, contributor.address)
      ).to.be.revertedWith("NexusGuard: caller is not the Oracle");
    });

    it("Should revert if contributor address mismatches", async function () {
      const { contract, oracle, attacker } = await withSubmittedBounty();
      await expect(
        contract.connect(oracle).releaseBounty(BUG_ID, attacker.address)
      ).to.be.revertedWith("NexusGuard: contributor address mismatch");
    });

    it("Should revert if released a second time (PAID state)", async function () {
      const { contract, oracle, contributor } = await withSubmittedBounty();
      await contract.connect(oracle).releaseBounty(BUG_ID, contributor.address);
      await expect(
        contract.connect(oracle).releaseBounty(BUG_ID, contributor.address)
      ).to.be.revertedWith("NexusGuard: bounty must be in SUBMITTED state");
    });
  });

  // ── cancelBounty ────────────────────────────────────────────
  describe("cancelBounty()", function () {
    it("Should refund sponsor and emit BountyCancelled", async function () {
      const { contract, sponsor } = await loadFixture(deployFixture);
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });

      // Cannot chain emit + changeEtherBalance — test them separately.
      const tx = contract.connect(sponsor).cancelBounty(BUG_ID);
      await expect(tx).to.emit(contract, "BountyCancelled");
      await expect(tx).to.changeEtherBalance(sponsor, ONE_MATIC);
    });

    it("Should revert if non-sponsor tries to cancel", async function () {
      const { contract, sponsor, attacker } = await loadFixture(deployFixture);
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      await expect(
        contract.connect(attacker).cancelBounty(BUG_ID)
      ).to.be.revertedWith("NexusGuard: only the sponsor can cancel");
    });

    it("Should revert if patch already submitted", async function () {
      const { contract, sponsor, contributor } = await loadFixture(deployFixture);
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
      await expect(
        contract.connect(sponsor).cancelBounty(BUG_ID)
      ).to.be.revertedWith("NexusGuard: can only cancel an open bounty");
    });
  });

  // ── Admin Functions ─────────────────────────────────────────
  describe("Admin Functions", function () {
    it("Should allow owner to rotate oracle", async function () {
      const { contract, owner, attacker } = await loadFixture(deployFixture);
      await expect(contract.connect(owner).setOracle(attacker.address))
        .to.emit(contract, "OracleUpdated");
      expect(await contract.oracleAddress()).to.equal(attacker.address);
    });

    it("Should prevent non-owner from rotating oracle", async function () {
      const { contract, attacker } = await loadFixture(deployFixture);
      await expect(
        contract.connect(attacker).setOracle(attacker.address)
      ).to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
    });

    it("Should cap fee at 10% (1000 bps)", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(contract.connect(owner).setFee(1001))
        .to.be.revertedWith("NexusGuard: fee cannot exceed 10%");
    });
  });

  // ── ERC-20 Full Lifecycle ──────────────────────────────────
  describe("ERC-20 Full Lifecycle (create → submit → release)", function () {
    it("Should escrow, submit patch, release payout, and accumulate fee for ERC-20", async function () {
      const { contract, token, oracle, sponsor, contributor, USDC_AMOUNT } = await loadFixture(deployFixture);

      // 1. Approve and create ERC-20 bounty
      const tokenAddr = await token.getAddress();
      await token.connect(sponsor).approve(await contract.getAddress(), USDC_AMOUNT);
      await contract.connect(sponsor).createBounty(BUG_ID, tokenAddr, USDC_AMOUNT);

      // 2. Submit patch
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);

      // 3. Oracle releases bounty
      const fee       = (USDC_AMOUNT * FEE_BASIS_POINTS) / 10_000n;
      const netPayout = USDC_AMOUNT - fee;

      await expect(
        contract.connect(oracle).releaseBounty(BUG_ID, contributor.address)
      )
        .to.emit(contract, "BountyPaid")
        .withArgs(BUG_ID, contributor.address, BUG_ID, netPayout, tokenAddr, (ts) => ts > 0n);

      // 4. Verify contributor received net payout
      expect(await token.balanceOf(contributor.address)).to.equal(netPayout);

      // 5. Verify fee accumulated in contract
      expect(await contract.pendingTokenFees(tokenAddr)).to.equal(fee);

      // 6. Verify bounty status is PAID (2)
      expect(await contract.getBountyStatus(BUG_ID)).to.equal(2);
    });
  });

  // ── Fee Withdrawal ─────────────────────────────────────────
  describe("Fee Withdrawal", function () {
    it("Should let owner withdraw accumulated native MATIC fees", async function () {
      const { contract, oracle, sponsor, contributor, owner } = await loadFixture(deployFixture);

      // Create → submit → release a MATIC bounty to accumulate fees
      await contract.connect(sponsor).createBounty(BUG_ID, NATIVE_TOKEN, 0, { value: ONE_MATIC });
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
      await contract.connect(oracle).releaseBounty(BUG_ID, contributor.address);

      const fee = (ONE_MATIC * FEE_BASIS_POINTS) / 10_000n;
      expect(await contract.pendingNativeFees()).to.equal(fee);

      // Owner withdraws fees
      await expect(
        contract.connect(owner).withdrawNativeFees()
      ).to.changeEtherBalance(owner, fee);

      expect(await contract.pendingNativeFees()).to.equal(0);
    });

    it("Should let owner withdraw accumulated ERC-20 fees", async function () {
      const { contract, token, oracle, sponsor, contributor, owner, USDC_AMOUNT } = await loadFixture(deployFixture);

      const tokenAddr = await token.getAddress();
      await token.connect(sponsor).approve(await contract.getAddress(), USDC_AMOUNT);
      await contract.connect(sponsor).createBounty(BUG_ID, tokenAddr, USDC_AMOUNT);
      await contract.connect(contributor).submitPatch(BUG_ID, contributor.address);
      await contract.connect(oracle).releaseBounty(BUG_ID, contributor.address);

      const fee = (USDC_AMOUNT * FEE_BASIS_POINTS) / 10_000n;
      expect(await contract.pendingTokenFees(tokenAddr)).to.equal(fee);

      // Owner withdraws ERC-20 fees
      await contract.connect(owner).withdrawTokenFees(tokenAddr);
      expect(await contract.pendingTokenFees(tokenAddr)).to.equal(0);
      expect(await token.balanceOf(owner.address)).to.equal(fee);
    });

    it("Should revert fee withdrawal when no fees accumulated", async function () {
      const { contract, owner } = await loadFixture(deployFixture);
      await expect(
        contract.connect(owner).withdrawNativeFees()
      ).to.be.revertedWith("NexusGuard: no native fees to withdraw");
    });
  });
});

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────

async function latestTimestamp() {
  const block = await ethers.provider.getBlock("latest");
  return block.timestamp;
}
