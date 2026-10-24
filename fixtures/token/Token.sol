// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Minimal ERC-20 with a PLANTED BUG for the fuzzer to find.
/// @dev `transfer` caches both balances before writing them back, so a
///      transfer to yourself credits the cached (pre-debit) balance and
///      mints `amount` out of thin air. Invariant broken:
///      totalSupply == sum of balances.
contract Token {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        balanceOf[msg.sender] = initialSupply;
        totalSupply = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "allowance");
        allowance[from][msg.sender] = allowed - amount;
        _move(from, to, amount);
        return true;
    }

    function burn(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
    }

    function _move(address from, address to, uint256 amount) internal {
        uint256 fromBalance = balanceOf[from];
        uint256 toBalance = balanceOf[to];
        require(fromBalance >= amount, "balance");
        balanceOf[from] = fromBalance - amount;
        balanceOf[to] = toBalance + amount; // BUG: stale when from == to
        emit Transfer(from, to, amount);
    }
}
