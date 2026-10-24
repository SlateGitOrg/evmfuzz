// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice A four-stage unlock state machine with a PLANTED BUG reachable
///         only through a specific call sequence.
/// @dev Stage 3's `payout` forgets to set `paid`, so it can be claimed
///      repeatedly. Reaching stage 3 needs: unlock1(42) -> unlock2(y) with
///      1000 < y < 1010 -> unlock3() from the same caller as unlock1, and
///      the overpayment needs payout() twice. Invariant broken:
///      paidOut <= cap.
contract Staged {
    uint8 public stage;
    address public opener;
    uint256 public paidOut;
    uint256 public constant cap = 100;
    bool public paid;

    function unlock1(uint8 x) external {
        require(stage == 0 && x == 42, "s1");
        opener = msg.sender;
        stage = 1;
    }

    function unlock2(uint256 y) external {
        require(stage == 1 && y > 1000 && y < 1010, "s2");
        stage = 2;
    }

    function unlock3() external {
        require(stage == 2 && msg.sender == opener, "s3");
        stage = 3;
    }

    function payout() external {
        require(stage == 3 && !paid, "s4");
        paidOut += 60; // BUG: `paid = true;` missing
    }

    function reset() external {
        require(msg.sender == opener, "opener");
        stage = 0;
    }
}
