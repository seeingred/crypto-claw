// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title CclawToken - Test ERC-20 token for crypto-claw integration tests.
contract CclawToken is ERC20 {
    address public owner;

    constructor() ERC20("Crypto Claw", "CCLAW") {
        owner = msg.sender;
    }

    /// @notice Mint tokens to an address (test only, no access control beyond owner).
    function mint(address to, uint256 amount) external {
        require(msg.sender == owner, "only owner");
        _mint(to, amount);
    }
}
