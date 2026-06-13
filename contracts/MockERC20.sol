// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// ============================================================
//  MockERC20 — Only used in tests, NOT deployed to mainnet.
//  Provides a mintable ERC-20 token to simulate USDC in the
//  NexusGuardBounty test suite.
// ============================================================

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    uint8 private _decimals;

    constructor(
        string memory name,
        string memory symbol,
        uint8 decimalsValue
    ) ERC20(name, symbol) {
        _decimals = decimalsValue;
    }

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    /// @notice Mint tokens to any address — test helper only.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
