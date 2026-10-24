// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Packed record registry with an assertion-guarded codec and a
///         PLANTED BUG for the fuzzer's assertion oracle.
/// @dev `amountOf` masks with 0x7fffffff instead of 0xffffffff, dropping
///      the top bit. The self-check `assert` fires (Panic 0x01) when a
///      record for the configured special id stores an amount >= 2^31.
///      Needs a prior `configure(id)` by the owner and a later `store`
///      that reuses the same 32-bit id.
contract Registry {
    address public immutable owner;
    uint32 public specialId;
    bool public configured;
    mapping(uint32 => uint64) public packed;

    constructor() {
        owner = msg.sender;
    }

    function configure(uint32 id) external {
        require(msg.sender == owner, "owner");
        specialId = id;
        configured = true;
    }

    function store(uint32 id, uint32 amount) external {
        uint64 word = (uint64(id) << 32) | uint64(amount);
        packed[id] = word;
        if (configured && id == specialId) {
            assert(amountOf(word) == amount); // fails for amount >= 2^31
        }
    }

    function amountOf(uint64 word) public pure returns (uint32) {
        return uint32(word & 0x7fffffff); // BUG: should be 0xffffffff
    }
}
