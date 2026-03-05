// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @title CclawStaking - Simple staking contract for integration tests.
/// Users deposit CCLAW tokens and can claim them back at any time.
contract CclawStaking {
    IERC20 public token;
    mapping(address => uint256) public balances;

    event Deposited(address indexed user, uint256 amount);
    event Claimed(address indexed user, uint256 amount);

    constructor(address _token) {
        token = IERC20(_token);
    }

    /// @notice Deposit CCLAW tokens into the staking contract.
    function deposit(uint256 amount) external {
        require(amount > 0, "amount must be > 0");
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        balances[msg.sender] += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @notice Claim all staked CCLAW tokens back.
    function claim() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to claim");
        balances[msg.sender] = 0;
        require(token.transfer(msg.sender, amount), "transfer failed");
        emit Claimed(msg.sender, amount);
    }

    /// @notice Claim a specific amount of staked CCLAW tokens.
    function claimAmount(uint256 amount) external {
        require(amount > 0, "amount must be > 0");
        require(balances[msg.sender] >= amount, "insufficient balance");
        balances[msg.sender] -= amount;
        require(token.transfer(msg.sender, amount), "transfer failed");
        emit Claimed(msg.sender, amount);
    }
}
