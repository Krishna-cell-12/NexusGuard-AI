// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title BountyEscrow
 * @dev Autonomous escrow smart contract to hold sponsor funds and distribute
 *      bounties to security contributors upon verification by the Oracle.
 */
contract BountyEscrow {
    enum BountyStatus { OPEN, SUBMITTED, PAID, CANCELLED }

    struct Bounty {
        address sponsor;
        address tokenAddress; // Address of token (e.g. USDC), or address(0) for native MATIC/ETH
        uint256 amount;
        address contributor;
        BountyStatus status;
        uint256 createdAt;
        uint256 paidAt;
    }

    address public oracle;
    mapping(string => Bounty) public bounties;
    mapping(address => string[]) private sponsorBounties;

    event BountyCreated(string indexed bugId, address indexed sponsor, address tokenAddress, uint256 amount, uint256 timestamp);
    event PatchSubmitted(string indexed bugId, address indexed contributor, uint256 timestamp);
    event BountyPaid(string indexed bugId, address indexed contributor, uint256 amount, address tokenAddress, uint256 timestamp);
    event BountyCancelled(string indexed bugId, address indexed sponsor, uint256 amount, uint256 timestamp);

    modifier onlyOracle() {
        require(msg.sender == oracle, "BountyEscrow: caller is not the Oracle");
        _;
    }

    modifier onlySponsor(string memory bugId) {
        require(bounties[bugId].sponsor == msg.sender, "BountyEscrow: caller is not the sponsor");
        _;
    }

    constructor(address _oracle) {
        require(_oracle != address(0), "BountyEscrow: Oracle address cannot be zero");
        oracle = _oracle;
    }

    /**
     * @dev Creates a bounty for a vulnerability.
     */
    function createBounty(string calldata bugId, address tokenAddress, uint256 amount) external payable {
        require(bounties[bugId].sponsor == address(0), "BountyEscrow: bounty already exists");
        
        if (tokenAddress == address(0)) {
            require(msg.value == amount, "BountyEscrow: incorrect native payment amount");
        } else {
            require(msg.value == 0, "BountyEscrow: native value sent with ERC20 request");
            // In a production system, transfer token from msg.sender here
            // SafeERC20.safeTransferFrom(IERC20(tokenAddress), msg.sender, address(this), amount);
        }

        bounties[bugId] = Bounty({
            sponsor: msg.sender,
            tokenAddress: tokenAddress,
            amount: amount,
            contributor: address(0),
            status: BountyStatus.OPEN,
            createdAt: block.timestamp,
            paidAt: 0
        });

        sponsorBounties[msg.sender].push(bugId);

        emit BountyCreated(bugId, msg.sender, tokenAddress, amount, block.timestamp);
    }

    /**
     * @dev Registers that a patch has been submitted by a contributor.
     */
    function submitPatch(string calldata bugId, address contributor) external onlyOracle {
        Bounty storage bounty = bounties[bugId];
        require(bounty.sponsor != address(0), "BountyEscrow: bounty does not exist");
        require(bounty.status == BountyStatus.OPEN, "BountyEscrow: bounty is not open");
        require(contributor != address(0), "BountyEscrow: invalid contributor address");

        bounty.contributor = contributor;
        bounty.status = BountyStatus.SUBMITTED;

        emit PatchSubmitted(bugId, contributor, block.timestamp);
    }

    /**
     * @dev Releases the escrowed funds to the contributor.
     */
    function releaseBounty(string calldata bugId, address payable contributor) external onlyOracle {
        Bounty storage bounty = bounties[bugId];
        require(bounty.sponsor != address(0), "BountyEscrow: bounty does not exist");
        require(bounty.status == BountyStatus.SUBMITTED, "BountyEscrow: bounty must be submitted");
        require(bounty.contributor == contributor, "BountyEscrow: contributor address mismatch");

        bounty.status = BountyStatus.PAID;
        bounty.paidAt = block.timestamp;

        uint256 amount = bounty.amount;
        address token = bounty.tokenAddress;

        if (token == address(0)) {
            contributor.transfer(amount);
        } else {
            // Production deployment: SafeERC20.safeTransfer(IERC20(token), contributor, amount);
        }

        emit BountyPaid(bugId, contributor, amount, token, block.timestamp);
    }

    /**
     * @dev Sponsor can cancel an open bounty.
     */
    function cancelBounty(string calldata bugId) external onlySponsor(bugId) {
        Bounty storage bounty = bounties[bugId];
        require(bounty.status == BountyStatus.OPEN, "BountyEscrow: bounty is not open");

        bounty.status = BountyStatus.CANCELLED;
        uint256 amount = bounty.amount;
        address token = bounty.tokenAddress;

        if (token == address(0)) {
            payable(msg.sender).transfer(amount);
        } else {
            // Production deployment: SafeERC20.safeTransfer(IERC20(token), msg.sender, amount);
        }

        emit BountyCancelled(bugId, msg.sender, amount, token, block.timestamp);
    }

    function getBounty(string calldata bugId) external view returns (
        address sponsor,
        address tokenAddress,
        uint256 amount,
        address contributor,
        uint8 status,
        uint256 createdAt,
        uint256 paidAt
    ) {
        Bounty memory b = bounties[bugId];
        return (b.sponsor, b.tokenAddress, b.amount, b.contributor, uint8(b.status), b.createdAt, b.paidAt);
    }

    function getSponsorBounties(address sponsor) external view returns (string[] memory) {
        return sponsorBounties[sponsor];
    }
}
