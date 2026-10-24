// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Ether vault with per-user accounting and a PLANTED BUG.
/// @dev `emergencyExit` is meant to be an operator-only escape hatch but
///      is guarded only by a 64-bit magic code. It pays the caller their
///      deposit twice over without updating `totalDeposits`, so the vault
///      becomes insolvent. Invariant broken:
///      address(this).balance >= totalDeposits.
///      Uniform random 64-bit guessing has a 2^-64 chance per call; the
///      fuzzer's comparison-operand dictionary sees the magic in the EQ.
contract Vault {
    mapping(address => uint256) public deposits;
    uint256 public totalDeposits;

    function deposit() external payable {
        require(msg.value > 0, "zero");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "balance");
        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
    }

    function emergencyExit(uint64 code) external {
        require(code == 0x5eedc0defeedbeef, "code");
        uint256 owed = deposits[msg.sender];
        require(owed > 0 && address(this).balance >= 2 * owed, "empty");
        (bool ok, ) = msg.sender.call{value: 2 * owed}(""); // BUG: no accounting update
        require(ok, "send");
    }
}
