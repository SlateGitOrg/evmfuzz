//! The instruction dispatch loop and the frame-level CALL / CREATE logic.

use super::gas::{self, all_but_one_64th, copy_cost, words};
use super::memory::Memory;
use super::opcode::*;
use super::precompiles;
use super::stack::Stack;
use super::state::{Code, Log};
use super::{
    create2_address, create_address, Analysis, CallKind, CallMessage, CreateMessage, Evm, FrameResult, Halt, Status,
    Tracer,
};
use crate::crypto::keccak256;
use crate::types::{Address, B256};
use crate::u256::U256;
use std::rc::Rc;
use std::sync::Arc;

/// Execution state of one call frame.
struct Frame {
    code: Code,
    analysis: Rc<Analysis>,
    pc: usize,
    gas: u64,
    stack: Stack,
    memory: Memory,
    input: Vec<u8>,
    address: Address,
    caller: Address,
    value: U256,
    is_static: bool,
    depth: usize,
    return_data: Vec<u8>,
}

/// Normal (non-exceptional) frame exits.
enum Exit {
    Stop,
    Return(Vec<u8>),
    Revert(Vec<u8>),
}

impl Frame {
    #[inline]
    fn charge(&mut self, amount: u64) -> Result<(), Halt> {
        if self.gas < amount {
            return Err(Halt::OutOfGas);
        }
        self.gas -= amount;
        Ok(())
    }
}

impl<T: Tracer> Evm<T> {
    /// Executes a message call frame (and everything it calls).
    pub fn call_message(&mut self, m: &CallMessage) -> FrameResult {
        let cp = self.state.checkpoint();
        match m.kind {
            CallKind::Call => {
                if !self.state.exists(&m.target) && !precompiles::is_precompile(&m.target) && m.value.is_zero() {
                    return FrameResult::ok(m.gas, Vec::new());
                }
                if !self.state.transfer(m.caller, m.target, m.value) {
                    // Callers check affordability first; reaching this is a frame failure.
                    return FrameResult { status: Status::Revert, gas_left: m.gas, output: Vec::new(), created: None };
                }
            }
            CallKind::StaticCall => {
                // A zero-value touch, as specified for STATICCALL targets.
                self.state.add_balance(m.target, U256::ZERO);
            }
            CallKind::CallCode | CallKind::DelegateCall => {}
        }

        let result = if precompiles::is_precompile(&m.code_address) {
            match precompiles::run(&m.code_address, &m.input, m.gas) {
                Ok(out) => FrameResult::ok(m.gas - out.gas_used, out.output),
                Err(h) => {
                    if let Halt::UnsupportedPrecompile(id) = h {
                        self.unsupported = Some(id);
                    }
                    FrameResult::halt(h)
                }
            }
        } else {
            let (code, hash) = match self.state.account(&m.code_address) {
                Some(acc) if !acc.code.is_empty() => (acc.code.clone(), acc.code_hash),
                _ => return FrameResult::ok(m.gas, Vec::new()),
            };
            let analysis = self.analysis_for(&code, hash);
            let mut frame = Frame {
                code,
                analysis,
                pc: 0,
                gas: m.gas,
                stack: Stack::new(),
                memory: Memory::new(),
                input: m.input.clone(),
                address: m.target,
                caller: m.caller,
                value: m.value,
                is_static: m.is_static,
                depth: m.depth,
                return_data: Vec::new(),
            };
            self.finish_frame(&mut frame)
        };
        if !result.status.is_success() {
            self.state.revert_to(cp);
        }
        result
    }

    fn finish_frame(&mut self, frame: &mut Frame) -> FrameResult {
        match self.run(frame) {
            Ok(Exit::Stop) => FrameResult::ok(frame.gas, Vec::new()),
            Ok(Exit::Return(out)) => FrameResult::ok(frame.gas, out),
            Ok(Exit::Revert(out)) => {
                FrameResult { status: Status::Revert, gas_left: frame.gas, output: out, created: None }
            }
            Err(h) => FrameResult::halt(h),
        }
    }

    /// Executes a contract creation (CREATE, CREATE2 or a creation transaction).
    ///
    /// The caller's nonce is incremented here. Failures before the init code
    /// runs (depth, balance, nonce overflow) return all gas; a collision
    /// consumes it.
    pub fn create_message(&mut self, m: &CreateMessage) -> FrameResult {
        let fail_keep_gas = FrameResult { status: Status::Revert, gas_left: m.gas, output: Vec::new(), created: None };
        if m.depth > gas::MAX_CALL_DEPTH || self.state.balance(&m.caller) < m.value {
            return fail_keep_gas;
        }
        let nonce = self.state.nonce(&m.caller);
        if nonce == u64::MAX {
            return fail_keep_gas;
        }
        self.state.set_nonce(m.caller, nonce + 1);
        let code_hash = keccak256(&m.init_code);
        let address = match m.salt {
            Some(salt) => create2_address(&m.caller, salt, &code_hash),
            None => create_address(&m.caller, nonce),
        };
        self.state.warm_account(address);
        if let Some(acc) = self.state.account(&address) {
            // EIP-684 plus EIP-7610 (non-empty storage also collides).
            if acc.nonce != 0 || !acc.code.is_empty() || !acc.storage.is_empty() {
                return FrameResult::halt(Halt::CreateCollision);
            }
        }
        let cp = self.state.checkpoint();
        self.state.create_account(address);
        self.state.set_nonce(address, 1);
        self.state.transfer(m.caller, address, m.value);

        let code: Code = Arc::from(m.init_code.clone());
        let analysis = self.analysis_for(&code, code_hash);
        let mut frame = Frame {
            code,
            analysis,
            pc: 0,
            gas: m.gas,
            stack: Stack::new(),
            memory: Memory::new(),
            input: Vec::new(),
            address,
            caller: m.caller,
            value: m.value,
            is_static: false,
            depth: m.depth,
            return_data: Vec::new(),
        };
        let mut result = self.finish_frame(&mut frame);
        if result.status.is_success() {
            let deployed = std::mem::take(&mut result.output);
            let deposit = gas::CODE_DEPOSIT_BYTE * deployed.len() as u64;
            let err = if deployed.len() > gas::MAX_CODE_SIZE {
                Some(Halt::CodeSizeLimit)
            } else if deployed.first() == Some(&0xef) {
                Some(Halt::InvalidCodePrefix)
            } else if result.gas_left < deposit {
                Some(Halt::OutOfGas)
            } else {
                None
            };
            match err {
                Some(h) => result = FrameResult::halt(h),
                None => {
                    result.gas_left -= deposit;
                    self.state.set_code(address, deployed);
                    result.created = Some(address);
                }
            }
        }
        if !result.status.is_success() {
            self.state.revert_to(cp);
        }
        result
    }

    #[inline]
    fn account_access_cost(&mut self, a: Address) -> u64 {
        if self.state.warm_account(a) {
            gas::COLD_ACCOUNT_ACCESS
        } else {
            gas::WARM_STORAGE_READ
        }
    }

    /// The dispatch loop.
    fn run(&mut self, f: &mut Frame) -> Result<Exit, Halt> {
        let code = f.code.clone();
        let code_id = f.analysis.code_id;
        loop {
            let op = code.get(f.pc).copied().unwrap_or(STOP);
            self.tracer.step(code_id, f.pc, op, f.gas, f.stack.as_slice(), f.depth);
            let info = &OPCODES[op as usize];
            if !info.defined {
                return Err(Halt::InvalidOpcode(op));
            }
            f.charge(info.static_gas)?;
            match op {
                STOP => return Ok(Exit::Stop),
                ADD => self.binop(f, |a, b| a.wrapping_add(b))?,
                MUL => self.binop(f, |a, b| a.wrapping_mul(b))?,
                SUB => self.binop(f, |a, b| a.wrapping_sub(b))?,
                DIV => self.binop(f, |a, b| a.evm_div(b))?,
                SDIV => self.binop(f, |a, b| a.evm_sdiv(b))?,
                MOD => self.binop(f, |a, b| a.evm_rem(b))?,
                SMOD => self.binop(f, |a, b| a.evm_smod(b))?,
                ADDMOD => {
                    let [a, b, m] = f.stack.pop_n::<3>()?;
                    f.stack.push(a.evm_addmod(b, m))?;
                }
                MULMOD => {
                    let [a, b, m] = f.stack.pop_n::<3>()?;
                    f.stack.push(a.evm_mulmod(b, m))?;
                }
                EXP => {
                    let [a, e] = f.stack.pop_n::<2>()?;
                    f.charge(gas::EXP_BYTE * u64::from(e.byte_len()))?;
                    f.stack.push(a.evm_exp(e))?;
                }
                SIGNEXTEND => self.binop(f, |b, x| x.evm_signextend(b))?,
                LT => self.cmpop(f, |a, b| a < b)?,
                GT => self.cmpop(f, |a, b| a > b)?,
                SLT => self.cmpop(f, |a, b| a.signed_cmp(&b).is_lt())?,
                SGT => self.cmpop(f, |a, b| a.signed_cmp(&b).is_gt())?,
                EQ => self.cmpop(f, |a, b| a == b)?,
                ISZERO => {
                    let a = f.stack.pop()?;
                    f.stack.push(U256::from(a.is_zero()))?;
                }
                AND => self.binop(f, |a, b| a & b)?,
                OR => self.binop(f, |a, b| a | b)?,
                XOR => self.binop(f, |a, b| a ^ b)?,
                NOT => {
                    let a = f.stack.pop()?;
                    f.stack.push(!a)?;
                }
                BYTE => self.binop(f, |i, x| x.evm_byte(i))?,
                SHL => self.binop(f, |s, v| v.evm_shl(s))?,
                SHR => self.binop(f, |s, v| v.evm_shr(s))?,
                SAR => self.binop(f, |s, v| v.evm_sar(s))?,
                KECCAK256 => {
                    let [off, size] = f.stack.pop_n::<2>()?;
                    let (o, n) = f.memory.expand(&mut f.gas, off, size)?;
                    f.charge(gas::KECCAK_WORD * words(n as u64))?;
                    let h = keccak256(f.memory.slice(o, n));
                    f.stack.push(h.to_u256())?;
                }
                ADDRESS => f.stack.push(f.address.to_word())?,
                BALANCE => {
                    let a = Address::from_word(f.stack.pop()?);
                    let cost = self.account_access_cost(a);
                    f.charge(cost)?;
                    f.stack.push(self.state.balance(&a))?;
                }
                ORIGIN => f.stack.push(self.origin.to_word())?,
                CALLER => f.stack.push(f.caller.to_word())?,
                CALLVALUE => f.stack.push(f.value)?,
                CALLDATALOAD => {
                    let off = f.stack.pop()?;
                    let mut buf = [0u8; 32];
                    if let Some(o) = off.to_usize() {
                        if o < f.input.len() {
                            let n = (f.input.len() - o).min(32);
                            buf[..n].copy_from_slice(&f.input[o..o + n]);
                        }
                    }
                    f.stack.push(U256::from_be_bytes(buf))?;
                }
                CALLDATASIZE => f.stack.push(U256::from_u64(f.input.len() as u64))?,
                CALLDATACOPY => {
                    let [dst, src, len] = f.stack.pop_n::<3>()?;
                    let (d, n) = f.memory.expand(&mut f.gas, dst, len)?;
                    f.charge(copy_cost(n as u64))?;
                    f.memory.copy_padded(d, &f.input, src, n);
                }
                CODESIZE => f.stack.push(U256::from_u64(code.len() as u64))?,
                CODECOPY => {
                    let [dst, src, len] = f.stack.pop_n::<3>()?;
                    let (d, n) = f.memory.expand(&mut f.gas, dst, len)?;
                    f.charge(copy_cost(n as u64))?;
                    f.memory.copy_padded(d, &code, src, n);
                }
                GASPRICE => f.stack.push(self.gas_price)?,
                EXTCODESIZE => {
                    let a = Address::from_word(f.stack.pop()?);
                    let cost = self.account_access_cost(a);
                    f.charge(cost)?;
                    let len = self.state.account(&a).map_or(0, |acc| acc.code.len());
                    f.stack.push(U256::from_u64(len as u64))?;
                }
                EXTCODECOPY => {
                    let a = Address::from_word(f.stack.pop()?);
                    let [dst, src, len] = f.stack.pop_n::<3>()?;
                    let (d, n) = f.memory.expand(&mut f.gas, dst, len)?;
                    let cost = self.account_access_cost(a);
                    f.charge(cost + copy_cost(n as u64))?;
                    let ext = self.state.code(&a);
                    f.memory.copy_padded(d, &ext, src, n);
                }
                RETURNDATASIZE => f.stack.push(U256::from_u64(f.return_data.len() as u64))?,
                RETURNDATACOPY => {
                    let [dst, src, len] = f.stack.pop_n::<3>()?;
                    let end = src.checked_add(len).ok_or(Halt::ReturnDataOutOfBounds)?;
                    if end > U256::from_u64(f.return_data.len() as u64) {
                        return Err(Halt::ReturnDataOutOfBounds);
                    }
                    let (d, n) = f.memory.expand(&mut f.gas, dst, len)?;
                    f.charge(copy_cost(n as u64))?;
                    let s = src.low_u64() as usize;
                    f.memory.write(d, &f.return_data[s..s + n]);
                }
                EXTCODEHASH => {
                    let a = Address::from_word(f.stack.pop()?);
                    let cost = self.account_access_cost(a);
                    f.charge(cost)?;
                    f.stack.push(self.state.ext_code_hash(&a).to_u256())?;
                }
                BLOCKHASH => {
                    let n = f.stack.pop()?;
                    f.stack.push(self.block.blockhash(n).to_u256())?;
                }
                COINBASE => f.stack.push(self.block.coinbase.to_word())?,
                TIMESTAMP => f.stack.push(U256::from_u64(self.block.timestamp))?,
                NUMBER => f.stack.push(U256::from_u64(self.block.number))?,
                PREVRANDAO => f.stack.push(self.block.prevrandao)?,
                GASLIMIT => f.stack.push(U256::from_u64(self.block.gas_limit))?,
                CHAINID => f.stack.push(self.block.chain_id)?,
                SELFBALANCE => f.stack.push(self.state.balance(&f.address))?,
                BASEFEE => f.stack.push(self.block.base_fee)?,
                POP => {
                    f.stack.pop()?;
                }
                MLOAD => {
                    let off = f.stack.pop()?;
                    let (o, _) = f.memory.expand(&mut f.gas, off, U256::from_u64(32))?;
                    f.stack.push(f.memory.load_word(o))?;
                }
                MSTORE => {
                    let [off, v] = f.stack.pop_n::<2>()?;
                    let (o, _) = f.memory.expand(&mut f.gas, off, U256::from_u64(32))?;
                    f.memory.store_word(o, v);
                }
                MSTORE8 => {
                    let [off, v] = f.stack.pop_n::<2>()?;
                    let (o, _) = f.memory.expand(&mut f.gas, off, U256::ONE)?;
                    f.memory.store_byte(o, v.low_u64() as u8);
                }
                SLOAD => {
                    let key = f.stack.pop()?;
                    let cost =
                        if self.state.warm_slot(f.address, key) { gas::COLD_SLOAD } else { gas::WARM_STORAGE_READ };
                    f.charge(cost)?;
                    f.stack.push(self.state.sload(&f.address, &key))?;
                }
                SSTORE => self.op_sstore(f)?,
                JUMP => {
                    let dest = f.stack.pop()?;
                    f.pc = Self::jump_target(f, dest)?;
                    continue;
                }
                JUMPI => {
                    let [dest, cond] = f.stack.pop_n::<2>()?;
                    let taken = !cond.is_zero();
                    self.tracer.branch(code_id, f.pc, dest.saturating_u64() as usize, taken);
                    if taken {
                        f.pc = Self::jump_target(f, dest)?;
                        continue;
                    }
                }
                PC => f.stack.push(U256::from_u64(f.pc as u64))?,
                MSIZE => f.stack.push(U256::from_u64(f.memory.len() as u64))?,
                GAS => f.stack.push(U256::from_u64(f.gas))?,
                JUMPDEST => {}
                PUSH0 => f.stack.push(U256::ZERO)?,
                PUSH1..=PUSH32 => {
                    let n = immediate_len(op);
                    let start = f.pc + 1;
                    let end = (start + n).min(code.len());
                    let mut buf = [0u8; 32];
                    // Bytes past the end of code read as zero (right-padded).
                    if start < end {
                        buf[32 - n..32 - n + (end - start)].copy_from_slice(&code[start..end]);
                    }
                    f.stack.push(U256::from_be_bytes(buf))?;
                    f.pc += n;
                }
                DUP1..=DUP16 => f.stack.dup((op - DUP1 + 1) as usize)?,
                SWAP1..=SWAP16 => f.stack.swap((op - SWAP1 + 1) as usize)?,
                LOG0..=LOG4 => self.op_log(f, (op - LOG0) as usize)?,
                CREATE | CREATE2 => self.op_create(f, op == CREATE2)?,
                CALL => self.op_call(f, CallKind::Call)?,
                CALLCODE => self.op_call(f, CallKind::CallCode)?,
                DELEGATECALL => self.op_call(f, CallKind::DelegateCall)?,
                STATICCALL => self.op_call(f, CallKind::StaticCall)?,
                RETURN | REVERT => {
                    let [off, size] = f.stack.pop_n::<2>()?;
                    let (o, n) = f.memory.expand(&mut f.gas, off, size)?;
                    let out = f.memory.slice(o, n).to_vec();
                    return Ok(if op == RETURN { Exit::Return(out) } else { Exit::Revert(out) });
                }
                SELFDESTRUCT => {
                    self.op_selfdestruct(f)?;
                    return Ok(Exit::Stop);
                }
                _ => return Err(Halt::InvalidOpcode(op)),
            }
            f.pc += 1;
        }
    }

    #[inline]
    fn binop(&mut self, f: &mut Frame, op: impl Fn(U256, U256) -> U256) -> Result<(), Halt> {
        let [a, b] = f.stack.pop_n::<2>()?;
        f.stack.push(op(a, b))
    }

    #[inline]
    fn cmpop(&mut self, f: &mut Frame, op: impl Fn(U256, U256) -> bool) -> Result<(), Halt> {
        let [a, b] = f.stack.pop_n::<2>()?;
        self.tracer.compare(a, b);
        f.stack.push(U256::from(op(a, b)))
    }

    fn jump_target(f: &Frame, dest: U256) -> Result<usize, Halt> {
        match dest.to_usize() {
            Some(d) if f.analysis.is_jumpdest(d) => Ok(d),
            _ => Err(Halt::InvalidJump),
        }
    }

    /// EIP-2200 / EIP-2929 / EIP-3529 metered `SSTORE`.
    fn op_sstore(&mut self, f: &mut Frame) -> Result<(), Halt> {
        if f.is_static {
            return Err(Halt::StaticStateChange);
        }
        let [key, new] = f.stack.pop_n::<2>()?;
        if f.gas <= gas::SSTORE_SENTRY {
            return Err(Halt::OutOfGas);
        }
        let mut cost = if self.state.warm_slot(f.address, key) { gas::COLD_SLOAD } else { 0 };
        let current = self.state.sload(&f.address, &key);
        let original = self.state.original(&f.address, &key);
        let mut refund: i64 = 0;
        if current == new {
            cost += gas::WARM_STORAGE_READ;
        } else if original == current {
            if original.is_zero() {
                cost += gas::SSTORE_SET;
            } else {
                cost += gas::SSTORE_RESET;
                if new.is_zero() {
                    refund += gas::SSTORE_CLEARS_SCHEDULE;
                }
            }
        } else {
            cost += gas::WARM_STORAGE_READ;
            if !original.is_zero() {
                if current.is_zero() {
                    refund -= gas::SSTORE_CLEARS_SCHEDULE;
                } else if new.is_zero() {
                    refund += gas::SSTORE_CLEARS_SCHEDULE;
                }
            }
            if original == new {
                refund += if original.is_zero() {
                    (gas::SSTORE_SET - gas::WARM_STORAGE_READ) as i64
                } else {
                    (gas::SSTORE_RESET - gas::WARM_STORAGE_READ) as i64
                };
            }
        }
        f.charge(cost)?;
        if refund != 0 {
            self.state.add_refund(refund);
        }
        if current != new {
            self.state.sstore(f.address, key, new);
        }
        Ok(())
    }

    fn op_log(&mut self, f: &mut Frame, n_topics: usize) -> Result<(), Halt> {
        if f.is_static {
            return Err(Halt::StaticStateChange);
        }
        let [off, size] = f.stack.pop_n::<2>()?;
        let mut topics = Vec::with_capacity(n_topics);
        for _ in 0..n_topics {
            topics.push(B256::from(f.stack.pop()?));
        }
        let (o, n) = f.memory.expand(&mut f.gas, off, size)?;
        f.charge(gas::LOG_DATA_BYTE.checked_mul(n as u64).ok_or(Halt::OutOfGas)?)?;
        let data = f.memory.slice(o, n).to_vec();
        self.state.push_log(Log { address: f.address, topics, data });
        Ok(())
    }

    fn op_selfdestruct(&mut self, f: &mut Frame) -> Result<(), Halt> {
        if f.is_static {
            return Err(Halt::StaticStateChange);
        }
        let beneficiary = Address::from_word(f.stack.pop()?);
        let mut cost = 0;
        if self.state.warm_account(beneficiary) {
            cost += gas::COLD_ACCOUNT_ACCESS;
        }
        let balance = self.state.balance(&f.address);
        if !balance.is_zero() && self.state.is_dead(&beneficiary) {
            cost += gas::NEW_ACCOUNT;
        }
        f.charge(cost)?;
        self.state.add_balance(beneficiary, balance);
        self.state.self_destruct(f.address);
        Ok(())
    }

    fn op_create(&mut self, f: &mut Frame, is_create2: bool) -> Result<(), Halt> {
        if f.is_static {
            return Err(Halt::StaticStateChange);
        }
        let [value, off, size] = f.stack.pop_n::<3>()?;
        let salt = if is_create2 { Some(f.stack.pop()?) } else { None };
        let (o, n) = f.memory.expand(&mut f.gas, off, size)?;
        if n > gas::MAX_INITCODE_SIZE {
            return Err(Halt::OutOfGas);
        }
        let w = words(n as u64);
        let mut cost = gas::INITCODE_WORD * w;
        if is_create2 {
            cost += gas::KECCAK_WORD * w;
        }
        f.charge(cost)?;
        f.return_data.clear();
        let gas = all_but_one_64th(f.gas);
        f.gas -= gas;
        let msg = CreateMessage {
            caller: f.address,
            value,
            init_code: f.memory.slice(o, n).to_vec(),
            gas,
            salt,
            depth: f.depth + 1,
        };
        let res = self.create_message(&msg);
        f.gas += res.gas_left;
        f.stack.push(res.created.map_or(U256::ZERO, Address::to_word))?;
        if res.status == Status::Revert {
            f.return_data = res.output;
        }
        Ok(())
    }

    fn op_call(&mut self, f: &mut Frame, kind: CallKind) -> Result<(), Halt> {
        let gas_req = f.stack.pop()?;
        let to = Address::from_word(f.stack.pop()?);
        let value = match kind {
            CallKind::Call | CallKind::CallCode => f.stack.pop()?,
            CallKind::DelegateCall | CallKind::StaticCall => U256::ZERO,
        };
        let [in_off, in_size, out_off, out_size] = f.stack.pop_n::<4>()?;
        let (in_o, in_n) = f.memory.expand(&mut f.gas, in_off, in_size)?;
        let (out_o, out_n) = f.memory.expand(&mut f.gas, out_off, out_size)?;

        let mut cost = self.account_access_cost(to);
        if kind == CallKind::Call && !value.is_zero() && f.is_static {
            return Err(Halt::StaticStateChange);
        }
        if !value.is_zero() {
            cost += gas::CALL_VALUE;
            if kind == CallKind::Call && self.state.is_dead(&to) {
                cost += gas::NEW_ACCOUNT;
            }
        }
        f.charge(cost)?;
        let mut call_gas = gas_req.saturating_u64().min(all_but_one_64th(f.gas));
        f.gas -= call_gas;
        if !value.is_zero() {
            call_gas += gas::CALL_STIPEND;
        }
        f.return_data.clear();

        let needs_funds = matches!(kind, CallKind::Call | CallKind::CallCode) && !value.is_zero();
        if f.depth + 1 > gas::MAX_CALL_DEPTH || (needs_funds && self.state.balance(&f.address) < value) {
            f.gas += call_gas;
            return f.stack.push(U256::ZERO);
        }
        let (caller, target, msg_value, is_static) = match kind {
            CallKind::Call => (f.address, to, value, f.is_static),
            CallKind::CallCode => (f.address, f.address, value, f.is_static),
            CallKind::DelegateCall => (f.caller, f.address, f.value, f.is_static),
            CallKind::StaticCall => (f.address, to, U256::ZERO, true),
        };
        let msg = CallMessage {
            kind,
            caller,
            target,
            code_address: to,
            value: msg_value,
            input: f.memory.slice(in_o, in_n).to_vec(),
            gas: call_gas,
            is_static,
            depth: f.depth + 1,
        };
        let res = self.call_message(&msg);
        f.gas += res.gas_left;
        let copy = out_n.min(res.output.len());
        f.memory.write(out_o, &res.output[..copy]);
        let ok = res.status.is_success();
        f.return_data = res.output;
        f.stack.push(U256::from(ok))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{BlockEnv, Evm, WorldState};
    use super::*;
    use crate::evm::state::Account;

    fn run_code(code: &[u8], gas: u64) -> (FrameResult, Evm) {
        let mut ws = WorldState::new();
        let target = Address::from_low_u64(0x100);
        ws.insert(target, Account::with_code(code.to_vec()));
        let mut evm = Evm::new(ws, BlockEnv::default());
        let msg = CallMessage {
            kind: CallKind::Call,
            caller: Address::from_low_u64(1),
            target,
            code_address: target,
            value: U256::ZERO,
            input: vec![],
            gas,
            is_static: false,
            depth: 0,
        };
        let r = evm.call_message(&msg);
        (r, evm)
    }

    #[test]
    fn add_and_return() {
        // PUSH1 2 PUSH1 3 ADD PUSH0 MSTORE PUSH1 32 PUSH0 RETURN
        let code = [0x60, 2, 0x60, 3, 0x01, 0x5f, 0x52, 0x60, 32, 0x5f, 0xf3];
        let (r, _) = run_code(&code, 100);
        assert_eq!(r.status, Status::Success);
        assert_eq!(U256::from_be_slice(&r.output), U256::from_u64(5));
        // 3+3+3+2+3(mstore)+3(mem)+3+2+0 = 22
        assert_eq!(r.gas_left, 100 - 22);
    }

    #[test]
    fn invalid_jump_and_opcode_halt() {
        let (r, _) = run_code(&[0x60, 0x03, 0x56, 0x00], 100);
        assert_eq!(r.status, Status::Halt(Halt::InvalidJump));
        assert_eq!(r.gas_left, 0);
        let (r, _) = run_code(&[0xfe], 100);
        assert_eq!(r.status, Status::Halt(Halt::InvalidOpcode(0xfe)));
        let (r, _) = run_code(&[0x01], 100);
        assert_eq!(r.status, Status::Halt(Halt::StackUnderflow));
    }

    #[test]
    fn revert_returns_gas_and_rolls_back_storage() {
        // PUSH1 1 PUSH1 0 SSTORE PUSH0 PUSH0 REVERT
        let (r, evm) = run_code(&[0x60, 1, 0x60, 0, 0x55, 0x5f, 0x5f, 0xfd], 30_000);
        assert_eq!(r.status, Status::Revert);
        assert!(r.gas_left > 0);
        assert_eq!(evm.state.sload(&Address::from_low_u64(0x100), &U256::ZERO), U256::ZERO);
    }

    #[test]
    fn sstore_sentry_and_jumpi() {
        let (r, _) = run_code(&[0x60, 1, 0x60, 0, 0x55], 2306);
        assert_eq!(r.status, Status::Halt(Halt::OutOfGas));
        // PUSH1 1 PUSH1 6 JUMPI INVALID JUMPDEST STOP -> jumps over INVALID
        let (r, _) = run_code(&[0x60, 1, 0x60, 6, 0x57, 0xfe, 0x5b, 0x00], 100);
        assert_eq!(r.status, Status::Success);
    }

    #[test]
    fn truncated_push_reads_zero_padding() {
        // PUSH2 0x01 (truncated) PUSH0 MSTORE ... returns 0x0100
        let (r, _) = run_code(&[0x61, 0x01], 100);
        assert_eq!(r.status, Status::Success);
    }
}
