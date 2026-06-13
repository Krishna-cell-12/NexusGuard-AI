// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================================================
//  NexusGuard AI — Autonomous Security Engineer for Open Source
//  Layer 5: Blockchain & Bounty Layer
//
//  NexusGuardBounty.sol
//
//  This contract acts as the immutable, trustless escrow engine
//  for the NexusGuard bug-bounty system. Sponsors lock funds
//  here; the authorized Oracle (our backend) releases them the
//  moment a verified patch lands on-chain.
//
//  Network : Polygon (Amoy Testnet / Mainnet)
//  Compiler: solc ^0.8.24  (optimizer: 200 runs)
//  Author  : NexusGuard AI Team — HackPrix 2025
// ============================================================

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract NexusGuardBounty is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // ─────────────────────────────────────────────────────────
    //  CONSTANTS & SENTINEL VALUES
    // ─────────────────────────────────────────────────────────

    /// @dev Sentinel address used to represent native MATIC bounties
    ///      (instead of an ERC-20 token address).
    address public constant NATIVE_TOKEN = address(0);

    // ─────────────────────────────────────────────────────────
    //  ENUMS
    // ─────────────────────────────────────────────────────────

    /**
     * @dev Lifecycle states a bounty can move through.
     *
     *  OPEN       → Funds deposited, no patch submitted yet.
     *  SUBMITTED  → A contributor has submitted a patch (under review).
     *  PAID       → Funds released to the contributor — terminal state.
     *  CANCELLED  → Sponsor withdrew funds — terminal state.
     */
    enum BountyStatus {
        OPEN,
        SUBMITTED,
        PAID,
        CANCELLED
    }

    // ─────────────────────────────────────────────────────────
    //  STORAGE STRUCTS
    // ─────────────────────────────────────────────────────────

    /**
     * @dev Complete on-chain record for a single vulnerability bounty.
     * @param sponsor         Address that funded the bounty.
     * @param tokenAddress    ERC-20 token used, or NATIVE_TOKEN for MATIC.
     * @param amount          Escrowed amount (wei / token's smallest unit).
     * @param contributor     Address of the patch author (set on submitPatch).
     * @param status          Current lifecycle phase.
     * @param createdAt       Block timestamp when the bounty was created.
     * @param paidAt          Block timestamp when the bounty was released (0 if not yet).
     */
    struct Bounty {
        address sponsor;
        address tokenAddress;
        uint256 amount;
        address contributor;
        BountyStatus status;
        uint256 createdAt;
        uint256 paidAt;
    }

    // ─────────────────────────────────────────────────────────
    //  STATE VARIABLES
    // ─────────────────────────────────────────────────────────

    /**
     * @notice The Oracle address — the only account authorised to
     *         call `releaseBounty`.  This is our secure webhook backend
     *         wallet that verifies GitHub PR merges off-chain.
     *
     * @dev  For production: replace with a Chainlink Functions consumer
     *       or a UMA Optimistic Oracle for fully trustless verification.
     */
    address public oracleAddress;

    /**
     * @notice Primary storage: bugId (off-chain identifier string)
     *         → on-chain Bounty record.
     */
    mapping(string => Bounty) private bounties;

    /**
     * @notice Quick look-up: all bounty IDs created by a given sponsor.
     */
    mapping(address => string[]) private sponsorBounties;

    /**
     * @notice Platform fee in basis points (100 = 1 %).
     *         Fee is taken only at payout time, preventing sponsor lock-in.
     *         Default: 200 bps = 2 %.
     */
    uint256 public feeBasisPoints;

    /**
     * @notice Accumulated native MATIC fees claimable by the owner.
     */
    uint256 public pendingNativeFees;

    /**
     * @notice Accumulated ERC-20 fees claimable by the owner.
     *         token → amount
     */
    mapping(address => uint256) public pendingTokenFees;

    // ─────────────────────────────────────────────────────────
    //  EVENTS
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Emitted when a new vulnerability bounty escrow is created.
     * @param bugIdHash     Keccak256 hash of the bugId (indexed for filtering).
     * @param sponsor       Address that funded the escrow.
     * @param bugId         Off-chain identifier (e.g., GitHub issue #) — readable on-chain.
     * @param tokenAddress  ERC-20 address or NATIVE_TOKEN (address(0)).
     * @param amount        Amount escrowed.
     * @param timestamp     Block timestamp.
     */
    event VulnerabilityFound(
        string indexed bugIdHash,
        address indexed sponsor,
        string bugId,
        address tokenAddress,
        uint256 amount,
        uint256 timestamp
    );

    /**
     * @notice Emitted when a contributor submits a patch for review.
     * @param bugIdHash   Keccak256 hash of the bugId (indexed for filtering).
     * @param contributor Address of the developer who submitted the fix.
     * @param bugId       Off-chain identifier — readable on-chain.
     * @param timestamp   Block timestamp.
     */
    event PatchSubmitted(
        string indexed bugIdHash,
        address indexed contributor,
        string bugId,
        uint256 timestamp
    );

    /**
     * @notice Emitted when the Oracle releases a bounty payout.
     * @param bugIdHash    Keccak256 hash of the bugId (indexed for filtering).
     * @param contributor  Address that received the bounty.
     * @param bugId        Off-chain identifier — readable on-chain.
     * @param amount       Net amount transferred (after fee deduction).
     * @param tokenAddress ERC-20 address or NATIVE_TOKEN (address(0)).
     * @param timestamp    Block timestamp.
     */
    event BountyPaid(
        string indexed bugIdHash,
        address indexed contributor,
        string bugId,
        uint256 amount,
        address tokenAddress,
        uint256 timestamp
    );

    /**
     * @notice Emitted when a sponsor cancels and reclaims an unpaid bounty.
     * @param bugIdHash    Keccak256 hash of the bugId (indexed for filtering).
     * @param sponsor      Address that funded the escrow.
     * @param bugId        Off-chain identifier — readable on-chain.
     * @param amount       Refunded amount.
     * @param timestamp    Block timestamp.
     */
    event BountyCancelled(
        string indexed bugIdHash,
        address indexed sponsor,
        string bugId,
        uint256 amount,
        uint256 timestamp
    );

    /**
     * @notice Emitted when the Oracle address is rotated.
     */
    event OracleUpdated(address indexed oldOracle, address indexed newOracle);

    /**
     * @notice Emitted when the platform fee rate is changed.
     */
    event FeeUpdated(uint256 oldFee, uint256 newFee);

    // ─────────────────────────────────────────────────────────
    //  MODIFIERS
    // ─────────────────────────────────────────────────────────

    /**
     * @dev Restricts a function to the authorised Oracle address only.
     */
    modifier onlyOracle() {
        require(msg.sender == oracleAddress, "NexusGuard: caller is not the Oracle");
        _;
    }

    /**
     * @dev Ensures a bounty with the given ID exists (has been created).
     */
    modifier bountyExists(string memory bugId) {
        require(bounties[bugId].sponsor != address(0), "NexusGuard: bounty does not exist");
        _;
    }

    // ─────────────────────────────────────────────────────────
    //  CONSTRUCTOR
    // ─────────────────────────────────────────────────────────

    /**
     * @param _oracleAddress  Initial Oracle wallet (our webhook backend).
     * @param _feeBasisPoints Platform fee in bps (e.g., 200 = 2 %).
     */
    constructor(address _oracleAddress, uint256 _feeBasisPoints) Ownable(msg.sender) {
        require(_oracleAddress != address(0), "NexusGuard: zero oracle address");
        require(_feeBasisPoints <= 1000, "NexusGuard: fee cannot exceed 10%");

        oracleAddress    = _oracleAddress;
        feeBasisPoints   = _feeBasisPoints;
    }

    // ─────────────────────────────────────────────────────────
    //  CORE PUBLIC FUNCTIONS
    // ─────────────────────────────────────────────────────────

    /**
     * @notice  Creates a new bounty escrow for a detected vulnerability.
     *
     * @dev     For native MATIC bounties: pass `tokenAddress = address(0)`
     *          and send the MATIC amount as `msg.value`.
     *          For ERC-20 bounties: pass the token contract address and
     *          `amount`; make sure this contract has `allowance >= amount`
     *          before calling.
     *
     * @param bugId        Unique off-chain vulnerability identifier.
     * @param tokenAddress ERC-20 token, or address(0) for MATIC.
     * @param amount       For ERC-20 bounties only; ignored for MATIC.
     */
    function createBounty(
        string memory bugId,
        address tokenAddress,
        uint256 amount
    ) external payable nonReentrant {
        // Each bugId maps to exactly one bounty — no overwrites allowed.
        require(bounties[bugId].sponsor == address(0), "NexusGuard: bounty already exists for this bugId");

        uint256 escrowed;

        if (tokenAddress == NATIVE_TOKEN) {
            // ── NATIVE MATIC PATH ──────────────────────────
            require(msg.value > 0, "NexusGuard: must send MATIC to create a native bounty");
            escrowed = msg.value;
        } else {
            // ── ERC-20 PATH ────────────────────────────────
            require(amount > 0,        "NexusGuard: amount must be > 0");
            require(msg.value == 0,    "NexusGuard: do not send MATIC for an ERC-20 bounty");

            // Pull tokens from the sponsor into escrow.
            // SafeERC20 reverts if the transfer fails (e.g., insufficient allowance).
            IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
            escrowed = amount;
        }

        // Persist the bounty record.
        bounties[bugId] = Bounty({
            sponsor:      msg.sender,
            tokenAddress: tokenAddress,
            amount:       escrowed,
            contributor:  address(0),
            status:       BountyStatus.OPEN,
            createdAt:    block.timestamp,
            paidAt:       0
        });

        sponsorBounties[msg.sender].push(bugId);

        emit VulnerabilityFound(bugId, msg.sender, bugId, tokenAddress, escrowed, block.timestamp);
    }

    /**
     * @notice  Records that a patch has been submitted for review.
     *
     * @dev     Can be called by anyone (the contributor themselves, or our
     *          backend acting on their behalf).  The `contributor` field is
     *          set here so the Oracle can later release funds without
     *          re-specifying the recipient — reducing TOCTOU risk.
     *
     * @param bugId       Identifies the bounty being patched.
     * @param contributor Wallet address of the patch author.
     */
    function submitPatch(
        string memory bugId,
        address contributor
    ) external nonReentrant bountyExists(bugId) {
        Bounty storage b = bounties[bugId];

        require(b.status == BountyStatus.OPEN, "NexusGuard: bounty is not open for patch submission");
        require(contributor != address(0),     "NexusGuard: zero contributor address");
        // A contributor cannot be the sponsor (prevents self-dealing).
        require(contributor != b.sponsor,      "NexusGuard: sponsor cannot be the contributor");

        b.contributor = contributor;
        b.status      = BountyStatus.SUBMITTED;

        emit PatchSubmitted(bugId, contributor, bugId, block.timestamp);
    }

    /**
     * @notice  Releases the escrowed funds to the verified patch contributor.
     *
     * @dev     🔒 ORACLE ONLY — called exclusively by our authorized backend
     *          wallet after it has confirmed the PR is merged on GitHub.
     *
     *          Fee deduction:
     *            platformFee = amount * feeBasisPoints / 10_000
     *            netPayout   = amount - platformFee
     *
     *          The platform fee accumulates in this contract and is claimed
     *          separately by the owner via `withdrawFees`.
     *
     * @param bugId       Identifies the bounty to release.
     * @param contributor The final recipient (must match the stored value).
     */
    function releaseBounty(
        string memory bugId,
        address payable contributor
    ) external nonReentrant onlyOracle bountyExists(bugId) {
        Bounty storage b = bounties[bugId];

        // Require the bounty is in SUBMITTED state — patch must exist.
        require(b.status == BountyStatus.SUBMITTED, "NexusGuard: bounty must be in SUBMITTED state");
        // Extra safety: confirm the contributor matches what was registered.
        require(b.contributor == contributor,        "NexusGuard: contributor address mismatch");

        // ── Fee Calculation ────────────────────────────────
        uint256 fee       = (b.amount * feeBasisPoints) / 10_000;
        uint256 netPayout = b.amount - fee;

        // Mark PAID before external calls (checks-effects-interactions pattern).
        b.status = BountyStatus.PAID;
        b.paidAt = block.timestamp;

        // ── Payout ────────────────────────────────────────
        if (b.tokenAddress == NATIVE_TOKEN) {
            // Accumulate native fee for owner withdrawal.
            pendingNativeFees += fee;

            // Transfer net MATIC to the contributor.
            (bool success, ) = contributor.call{value: netPayout}("");
            require(success, "NexusGuard: MATIC transfer to contributor failed");
        } else {
            // Accumulate ERC-20 fee for owner withdrawal.
            pendingTokenFees[b.tokenAddress] += fee;

            // Transfer net ERC-20 tokens to the contributor.
            IERC20(b.tokenAddress).safeTransfer(contributor, netPayout);
        }

        emit BountyPaid(bugId, contributor, bugId, netPayout, b.tokenAddress, block.timestamp);
    }

    /**
     * @notice  Allows a sponsor to cancel their bounty and reclaim funds,
     *          but ONLY if no patch has been submitted yet.
     *
     * @param bugId Identifies the bounty to cancel.
     */
    function cancelBounty(
        string memory bugId
    ) external nonReentrant bountyExists(bugId) {
        Bounty storage b = bounties[bugId];

        require(b.sponsor == msg.sender,          "NexusGuard: only the sponsor can cancel");
        require(b.status == BountyStatus.OPEN,    "NexusGuard: can only cancel an open bounty");

        uint256 refund = b.amount;
        b.status       = BountyStatus.CANCELLED;
        b.amount       = 0; // Zero out before transfer (re-entrancy safety).

        if (b.tokenAddress == NATIVE_TOKEN) {
            (bool success, ) = payable(msg.sender).call{value: refund}("");
            require(success, "NexusGuard: MATIC refund failed");
        } else {
            IERC20(b.tokenAddress).safeTransfer(msg.sender, refund);
        }

        emit BountyCancelled(bugId, msg.sender, bugId, refund, block.timestamp);
    }

    // ─────────────────────────────────────────────────────────
    //  ADMIN FUNCTIONS (Owner only)
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Rotates the Oracle address. Use when rotating backend wallets.
     * @param newOracle The replacement Oracle wallet address.
     */
    function setOracle(address newOracle) external onlyOwner {
        require(newOracle != address(0), "NexusGuard: zero oracle address");
        emit OracleUpdated(oracleAddress, newOracle);
        oracleAddress = newOracle;
    }

    /**
     * @notice Updates the platform fee. Capped at 10 % to protect sponsors.
     * @param newFeeBasisPoints New fee in basis points (e.g., 150 = 1.5 %).
     */
    function setFee(uint256 newFeeBasisPoints) external onlyOwner {
        require(newFeeBasisPoints <= 1000, "NexusGuard: fee cannot exceed 10%");
        emit FeeUpdated(feeBasisPoints, newFeeBasisPoints);
        feeBasisPoints = newFeeBasisPoints;
    }

    /**
     * @notice Withdraws accumulated native MATIC fees to the owner wallet.
     */
    function withdrawNativeFees() external onlyOwner nonReentrant {
        uint256 amount    = pendingNativeFees;
        pendingNativeFees = 0;
        require(amount > 0, "NexusGuard: no native fees to withdraw");
        (bool success, ) = payable(owner()).call{value: amount}("");
        require(success, "NexusGuard: fee withdrawal failed");
    }

    /**
     * @notice Withdraws accumulated ERC-20 fees for a given token.
     * @param tokenAddress The ERC-20 token to withdraw fees for.
     */
    function withdrawTokenFees(address tokenAddress) external onlyOwner nonReentrant {
        uint256 amount = pendingTokenFees[tokenAddress];
        pendingTokenFees[tokenAddress] = 0;
        require(amount > 0, "NexusGuard: no token fees to withdraw");
        IERC20(tokenAddress).safeTransfer(owner(), amount);
    }

    // ─────────────────────────────────────────────────────────
    //  VIEW / QUERY FUNCTIONS
    // ─────────────────────────────────────────────────────────

    /**
     * @notice Returns the full on-chain record for a given bounty.
     * @param bugId Off-chain vulnerability identifier.
     */
    function getBounty(string memory bugId)
        external
        view
        bountyExists(bugId)
        returns (Bounty memory)
    {
        return bounties[bugId];
    }

    /**
     * @notice Returns all bounty IDs created by a given sponsor.
     * @param sponsor Sponsor wallet address.
     */
    function getSponsorBounties(address sponsor)
        external
        view
        returns (string[] memory)
    {
        return sponsorBounties[sponsor];
    }

    /**
     * @notice Returns the current lifecycle status of a bounty.
     */
    function getBountyStatus(string memory bugId)
        external
        view
        bountyExists(bugId)
        returns (BountyStatus)
    {
        return bounties[bugId].status;
    }

    // ─────────────────────────────────────────────────────────
    //  FALLBACK — reject accidental ETH/MATIC sends
    // ─────────────────────────────────────────────────────────

    /**
     * @dev Revert any plain MATIC sent outside of `createBounty`.
     *      Forces sponsors to use the proper flow.
     */
    receive() external payable {
        revert("NexusGuard: use createBounty() to fund escrow");
    }

    /**
     * @dev Revert any calls with non-empty calldata that don't match a function.
     */
    fallback() external payable {
        revert("NexusGuard: use createBounty() to fund escrow");
    }
}
