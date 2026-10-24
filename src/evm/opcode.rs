//! Opcode byte values, mnemonics and static gas costs for the Shanghai fork.

#![allow(missing_docs)]

pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
pub const DIV: u8 = 0x04;
pub const SDIV: u8 = 0x05;
pub const MOD: u8 = 0x06;
pub const SMOD: u8 = 0x07;
pub const ADDMOD: u8 = 0x08;
pub const MULMOD: u8 = 0x09;
pub const EXP: u8 = 0x0a;
pub const SIGNEXTEND: u8 = 0x0b;
pub const LT: u8 = 0x10;
pub const GT: u8 = 0x11;
pub const SLT: u8 = 0x12;
pub const SGT: u8 = 0x13;
pub const EQ: u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND: u8 = 0x16;
pub const OR: u8 = 0x17;
pub const XOR: u8 = 0x18;
pub const NOT: u8 = 0x19;
pub const BYTE: u8 = 0x1a;
pub const SHL: u8 = 0x1b;
pub const SHR: u8 = 0x1c;
pub const SAR: u8 = 0x1d;
pub const KECCAK256: u8 = 0x20;
pub const ADDRESS: u8 = 0x30;
pub const BALANCE: u8 = 0x31;
pub const ORIGIN: u8 = 0x32;
pub const CALLER: u8 = 0x33;
pub const CALLVALUE: u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
pub const GASPRICE: u8 = 0x3a;
pub const EXTCODESIZE: u8 = 0x3b;
pub const EXTCODECOPY: u8 = 0x3c;
pub const RETURNDATASIZE: u8 = 0x3d;
pub const RETURNDATACOPY: u8 = 0x3e;
pub const EXTCODEHASH: u8 = 0x3f;
pub const BLOCKHASH: u8 = 0x40;
pub const COINBASE: u8 = 0x41;
pub const TIMESTAMP: u8 = 0x42;
pub const NUMBER: u8 = 0x43;
pub const PREVRANDAO: u8 = 0x44;
pub const GASLIMIT: u8 = 0x45;
pub const CHAINID: u8 = 0x46;
pub const SELFBALANCE: u8 = 0x47;
pub const BASEFEE: u8 = 0x48;
pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const PC: u8 = 0x58;
pub const MSIZE: u8 = 0x59;
pub const GAS: u8 = 0x5a;
pub const JUMPDEST: u8 = 0x5b;
pub const PUSH0: u8 = 0x5f;
pub const PUSH1: u8 = 0x60;
pub const PUSH32: u8 = 0x7f;
pub const DUP1: u8 = 0x80;
pub const DUP16: u8 = 0x8f;
pub const SWAP1: u8 = 0x90;
pub const SWAP16: u8 = 0x9f;
pub const LOG0: u8 = 0xa0;
pub const LOG4: u8 = 0xa4;
pub const CREATE: u8 = 0xf0;
pub const CALL: u8 = 0xf1;
pub const CALLCODE: u8 = 0xf2;
pub const RETURN: u8 = 0xf3;
pub const DELEGATECALL: u8 = 0xf4;
pub const CREATE2: u8 = 0xf5;
pub const STATICCALL: u8 = 0xfa;
pub const REVERT: u8 = 0xfd;
pub const INVALID: u8 = 0xfe;
pub const SELFDESTRUCT: u8 = 0xff;

/// Static description of an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpInfo {
    /// Mnemonic, e.g. `"ADD"`.
    pub name: &'static str,
    /// Constant gas charged before any dynamic component.
    pub static_gas: u64,
    /// Whether the opcode exists in Shanghai.
    pub defined: bool,
}

const UNDEFINED: OpInfo = OpInfo { name: "UNDEFINED", static_gas: 0, defined: false };

const fn op(name: &'static str, static_gas: u64) -> OpInfo {
    OpInfo { name, static_gas, defined: true }
}

const PUSH_NAMES: [&str; 32] = [
    "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5", "PUSH6", "PUSH7", "PUSH8", "PUSH9", "PUSH10", "PUSH11", "PUSH12",
    "PUSH13", "PUSH14", "PUSH15", "PUSH16", "PUSH17", "PUSH18", "PUSH19", "PUSH20", "PUSH21", "PUSH22", "PUSH23",
    "PUSH24", "PUSH25", "PUSH26", "PUSH27", "PUSH28", "PUSH29", "PUSH30", "PUSH31", "PUSH32",
];
const DUP_NAMES: [&str; 16] = [
    "DUP1", "DUP2", "DUP3", "DUP4", "DUP5", "DUP6", "DUP7", "DUP8", "DUP9", "DUP10", "DUP11", "DUP12", "DUP13",
    "DUP14", "DUP15", "DUP16",
];
const SWAP_NAMES: [&str; 16] = [
    "SWAP1", "SWAP2", "SWAP3", "SWAP4", "SWAP5", "SWAP6", "SWAP7", "SWAP8", "SWAP9", "SWAP10", "SWAP11", "SWAP12",
    "SWAP13", "SWAP14", "SWAP15", "SWAP16",
];
const LOG_NAMES: [&str; 5] = ["LOG0", "LOG1", "LOG2", "LOG3", "LOG4"];

const fn build_table() -> [OpInfo; 256] {
    let mut t = [UNDEFINED; 256];
    t[STOP as usize] = op("STOP", 0);
    t[ADD as usize] = op("ADD", 3);
    t[MUL as usize] = op("MUL", 5);
    t[SUB as usize] = op("SUB", 3);
    t[DIV as usize] = op("DIV", 5);
    t[SDIV as usize] = op("SDIV", 5);
    t[MOD as usize] = op("MOD", 5);
    t[SMOD as usize] = op("SMOD", 5);
    t[ADDMOD as usize] = op("ADDMOD", 8);
    t[MULMOD as usize] = op("MULMOD", 8);
    t[EXP as usize] = op("EXP", 10);
    t[SIGNEXTEND as usize] = op("SIGNEXTEND", 5);
    t[LT as usize] = op("LT", 3);
    t[GT as usize] = op("GT", 3);
    t[SLT as usize] = op("SLT", 3);
    t[SGT as usize] = op("SGT", 3);
    t[EQ as usize] = op("EQ", 3);
    t[ISZERO as usize] = op("ISZERO", 3);
    t[AND as usize] = op("AND", 3);
    t[OR as usize] = op("OR", 3);
    t[XOR as usize] = op("XOR", 3);
    t[NOT as usize] = op("NOT", 3);
    t[BYTE as usize] = op("BYTE", 3);
    t[SHL as usize] = op("SHL", 3);
    t[SHR as usize] = op("SHR", 3);
    t[SAR as usize] = op("SAR", 3);
    t[KECCAK256 as usize] = op("KECCAK256", 30);
    t[ADDRESS as usize] = op("ADDRESS", 2);
    t[BALANCE as usize] = op("BALANCE", 0);
    t[ORIGIN as usize] = op("ORIGIN", 2);
    t[CALLER as usize] = op("CALLER", 2);
    t[CALLVALUE as usize] = op("CALLVALUE", 2);
    t[CALLDATALOAD as usize] = op("CALLDATALOAD", 3);
    t[CALLDATASIZE as usize] = op("CALLDATASIZE", 2);
    t[CALLDATACOPY as usize] = op("CALLDATACOPY", 3);
    t[CODESIZE as usize] = op("CODESIZE", 2);
    t[CODECOPY as usize] = op("CODECOPY", 3);
    t[GASPRICE as usize] = op("GASPRICE", 2);
    t[EXTCODESIZE as usize] = op("EXTCODESIZE", 0);
    t[EXTCODECOPY as usize] = op("EXTCODECOPY", 0);
    t[RETURNDATASIZE as usize] = op("RETURNDATASIZE", 2);
    t[RETURNDATACOPY as usize] = op("RETURNDATACOPY", 3);
    t[EXTCODEHASH as usize] = op("EXTCODEHASH", 0);
    t[BLOCKHASH as usize] = op("BLOCKHASH", 20);
    t[COINBASE as usize] = op("COINBASE", 2);
    t[TIMESTAMP as usize] = op("TIMESTAMP", 2);
    t[NUMBER as usize] = op("NUMBER", 2);
    t[PREVRANDAO as usize] = op("PREVRANDAO", 2);
    t[GASLIMIT as usize] = op("GASLIMIT", 2);
    t[CHAINID as usize] = op("CHAINID", 2);
    t[SELFBALANCE as usize] = op("SELFBALANCE", 5);
    t[BASEFEE as usize] = op("BASEFEE", 2);
    t[POP as usize] = op("POP", 2);
    t[MLOAD as usize] = op("MLOAD", 3);
    t[MSTORE as usize] = op("MSTORE", 3);
    t[MSTORE8 as usize] = op("MSTORE8", 3);
    t[SLOAD as usize] = op("SLOAD", 0);
    t[SSTORE as usize] = op("SSTORE", 0);
    t[JUMP as usize] = op("JUMP", 8);
    t[JUMPI as usize] = op("JUMPI", 10);
    t[PC as usize] = op("PC", 2);
    t[MSIZE as usize] = op("MSIZE", 2);
    t[GAS as usize] = op("GAS", 2);
    t[JUMPDEST as usize] = op("JUMPDEST", 1);
    t[PUSH0 as usize] = op("PUSH0", 2);
    let mut i = 0;
    while i < 32 {
        t[PUSH1 as usize + i] = op(PUSH_NAMES[i], 3);
        i += 1;
    }
    i = 0;
    while i < 16 {
        t[DUP1 as usize + i] = op(DUP_NAMES[i], 3);
        t[SWAP1 as usize + i] = op(SWAP_NAMES[i], 3);
        i += 1;
    }
    i = 0;
    while i < 5 {
        t[LOG0 as usize + i] = op(LOG_NAMES[i], 375 * (i as u64 + 1));
        i += 1;
    }
    t[CREATE as usize] = op("CREATE", 32000);
    t[CALL as usize] = op("CALL", 0);
    t[CALLCODE as usize] = op("CALLCODE", 0);
    t[RETURN as usize] = op("RETURN", 0);
    t[DELEGATECALL as usize] = op("DELEGATECALL", 0);
    t[CREATE2 as usize] = op("CREATE2", 32000);
    t[STATICCALL as usize] = op("STATICCALL", 0);
    t[REVERT as usize] = op("REVERT", 0);
    t[INVALID as usize] = OpInfo { name: "INVALID", static_gas: 0, defined: false };
    t[SELFDESTRUCT as usize] = op("SELFDESTRUCT", 5000);
    t
}

/// Opcode table indexed by byte value.
pub static OPCODES: [OpInfo; 256] = build_table();

/// Returns the number of immediate bytes following `op` (PUSH1..PUSH32).
#[inline]
pub fn immediate_len(op: u8) -> usize {
    if (PUSH1..=PUSH32).contains(&op) {
        (op - PUSH1 + 1) as usize
    } else {
        0
    }
}

/// Disassembles bytecode into `(pc, mnemonic, immediate)` triples.
pub fn disassemble(code: &[u8]) -> Vec<(usize, &'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < code.len() {
        let op = code[pc];
        let n = immediate_len(op);
        let end = (pc + 1 + n).min(code.len());
        out.push((pc, OPCODES[op as usize].name, code[pc + 1..end].to_vec()));
        pc += 1 + n;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_consistent() {
        assert_eq!(OPCODES[PUSH32 as usize].name, "PUSH32");
        assert_eq!(OPCODES[DUP16 as usize].name, "DUP16");
        assert_eq!(OPCODES[SWAP16 as usize].name, "SWAP16");
        assert_eq!(OPCODES[LOG4 as usize].static_gas, 1875);
        assert!(!OPCODES[0x0c].defined);
        assert!(!OPCODES[INVALID as usize].defined);
        assert_eq!(immediate_len(0x61), 2);
        assert_eq!(immediate_len(ADD), 0);
    }

    #[test]
    fn disassembly_handles_truncated_push() {
        let d = disassemble(&[0x60, 0x01, 0x61, 0xff]);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0], (0, "PUSH1", vec![1]));
        assert_eq!(d[1], (2, "PUSH2", vec![0xff]));
    }
}
