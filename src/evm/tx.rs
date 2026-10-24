//! Transaction-level processing: validation, intrinsic gas, fee payment,
//! refunds and end-of-transaction cleanup (Yellow Paper section 6 with the
//! Berlin/London/Shanghai amendments).

use super::gas;
use super::precompiles;
use super::state::Log;
use super::{CallKind, CallMessage, CreateMessage, Evm, Status, Tracer};
use crate::types::Address;
use crate::u256::U256;

/// Fee fields of a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GasPrice {
    /// Pre-London `gasPrice` (types 0 and 1).
    Legacy(U256),
    /// EIP-1559 fee caps (type 2).
    Eip1559 {
        /// `maxFeePerGas`.
        max_fee: U256,
        /// `maxPriorityFeePerGas`.
        max_priority_fee: U256,
    },
}

/// A transaction, already authenticated (the sender is given, not recovered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Sender.
    pub caller: Address,
    /// Recipient; `None` creates a contract from `data`.
    pub to: Option<Address>,
    /// Value in wei.
    pub value: U256,
    /// Calldata or init code.
    pub data: Vec<u8>,
    /// Gas limit.
    pub gas_limit: u64,
    /// Expected sender nonce; `None` skips the check (fuzzing convenience).
    pub nonce: Option<u64>,
    /// Fee fields.
    pub gas_price: GasPrice,
    /// EIP-2930 access list.
    pub access_list: Vec<(Address, Vec<U256>)>,
}

impl Transaction {
    /// A zero-fee call, convenient for fuzzing and tests.
    pub fn call(caller: Address, to: Address, data: Vec<u8>, value: U256, gas_limit: u64) -> Self {
        Transaction {
            caller,
            to: Some(to),
            value,
            data,
            gas_limit,
            nonce: None,
            gas_price: GasPrice::Legacy(U256::ZERO),
            access_list: Vec::new(),
        }
    }

    /// A zero-fee contract creation.
    pub fn create(caller: Address, init_code: Vec<u8>, value: U256, gas_limit: u64) -> Self {
        Transaction { to: None, ..Transaction::call(caller, Address::ZERO, init_code, value, gas_limit) }
    }

    /// Intrinsic gas (EIP-2028 calldata, EIP-2930 access list, EIP-3860 initcode).
    pub fn intrinsic_gas(&self) -> u64 {
        let zeros = self.data.iter().filter(|&&b| b == 0).count() as u64;
        let nonzeros = self.data.len() as u64 - zeros;
        let mut g = gas::TX_BASE + zeros * gas::TX_DATA_ZERO + nonzeros * gas::TX_DATA_NONZERO;
        if self.to.is_none() {
            g += gas::TX_CREATE + gas::INITCODE_WORD * gas::words(self.data.len() as u64);
        }
        for (_, keys) in &self.access_list {
            g += gas::ACCESS_LIST_ADDRESS + gas::ACCESS_LIST_STORAGE_KEY * keys.len() as u64;
        }
        g
    }
}

/// Reasons a transaction is invalid (it is then not executed at all).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxError {
    /// Nonce does not match the sender's account.
    #[error("nonce mismatch: account has {expected}, transaction has {got}")]
    NonceMismatch {
        /// Account nonce.
        expected: u64,
        /// Transaction nonce.
        got: u64,
    },
    /// The sender nonce is at its maximum.
    #[error("sender nonce overflow")]
    NonceOverflow,
    /// The sender has code (EIP-3607).
    #[error("sender is not an EOA")]
    SenderNotEoa,
    /// Gas limit exceeds the block gas limit.
    #[error("gas limit exceeds block gas limit")]
    GasLimitExceedsBlock,
    /// Gas limit below intrinsic gas.
    #[error("intrinsic gas {intrinsic} exceeds gas limit {limit}")]
    IntrinsicGasTooLow {
        /// Required intrinsic gas.
        intrinsic: u64,
        /// Provided gas limit.
        limit: u64,
    },
    /// Fee cap below the block base fee.
    #[error("fee cap below base fee")]
    FeeCapTooLow,
    /// Priority fee above fee cap.
    #[error("priority fee exceeds fee cap")]
    PriorityFeeTooHigh,
    /// Sender cannot pay `gas_limit * price + value`.
    #[error("insufficient funds for gas * price + value")]
    InsufficientFunds,
    /// Creation init code larger than 49152 bytes (EIP-3860).
    #[error("init code exceeds size limit")]
    InitcodeTooLarge,
}

/// Outcome of an executed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxResult {
    /// Top-frame status.
    pub status: Status,
    /// Gas charged to the sender (after refunds).
    pub gas_used: u64,
    /// Return or revert data.
    pub output: Vec<u8>,
    /// Logs (empty unless successful).
    pub logs: Vec<Log>,
    /// Created contract address, for successful creations.
    pub created: Option<Address>,
}

impl<T: Tracer> Evm<T> {
    fn validate(&self, tx: &Transaction) -> Result<(U256, U256), TxError> {
        let sender = self.state.account(&tx.caller);
        let nonce = sender.map_or(0, |a| a.nonce);
        if let Some(n) = tx.nonce {
            if n != nonce {
                return Err(TxError::NonceMismatch { expected: nonce, got: n });
            }
        }
        if nonce == u64::MAX {
            return Err(TxError::NonceOverflow);
        }
        if sender.is_some_and(|a| !a.code.is_empty()) {
            return Err(TxError::SenderNotEoa);
        }
        if tx.gas_limit > self.block.gas_limit {
            return Err(TxError::GasLimitExceedsBlock);
        }
        let base_fee = self.block.base_fee;
        let (effective, fee_cap) = match tx.gas_price {
            GasPrice::Legacy(p) => {
                if p < base_fee {
                    return Err(TxError::FeeCapTooLow);
                }
                (p, p)
            }
            GasPrice::Eip1559 { max_fee, max_priority_fee } => {
                if max_priority_fee > max_fee {
                    return Err(TxError::PriorityFeeTooHigh);
                }
                if max_fee < base_fee {
                    return Err(TxError::FeeCapTooLow);
                }
                let tip = max_priority_fee.min(max_fee.wrapping_sub(base_fee));
                (base_fee.wrapping_add(tip), max_fee)
            }
        };
        let limit = U256::from_u64(tx.gas_limit);
        let (gas_cost, o1) = limit.overflowing_mul(fee_cap);
        let (max_cost, o2) = gas_cost.overflowing_add(tx.value);
        if o1 || o2 || sender.map_or(U256::ZERO, |a| a.balance) < max_cost {
            return Err(TxError::InsufficientFunds);
        }
        let intrinsic = tx.intrinsic_gas();
        if intrinsic > tx.gas_limit {
            return Err(TxError::IntrinsicGasTooLow { intrinsic, limit: tx.gas_limit });
        }
        if tx.to.is_none() && tx.data.len() > gas::MAX_INITCODE_SIZE {
            return Err(TxError::InitcodeTooLarge);
        }
        Ok((effective, effective.wrapping_sub(base_fee)))
    }

    /// Validates and executes a transaction, then applies end-of-transaction
    /// cleanup. On `Err` the state is untouched.
    pub fn transact(&mut self, tx: &Transaction) -> Result<TxResult, TxError> {
        let (price, tip) = self.validate(tx)?;
        self.unsupported = None;
        self.origin = tx.caller;
        self.gas_price = price;

        let upfront = U256::from_u64(tx.gas_limit).wrapping_mul(price);
        self.state.sub_balance(tx.caller, upfront);

        // EIP-2929 / EIP-2930 / EIP-3651 warm set.
        self.state.warm_account(tx.caller);
        if let Some(to) = tx.to {
            self.state.warm_account(to);
        }
        for p in precompiles::addresses() {
            self.state.warm_account(p);
        }
        self.state.warm_account(self.block.coinbase);
        for (addr, keys) in &tx.access_list {
            self.state.warm_account(*addr);
            for k in keys {
                self.state.warm_slot(*addr, *k);
            }
        }

        let exec_gas = tx.gas_limit - tx.intrinsic_gas();
        let result = match tx.to {
            Some(to) => {
                let nonce = self.state.nonce(&tx.caller);
                self.state.set_nonce(tx.caller, nonce + 1);
                self.call_message(&CallMessage {
                    kind: CallKind::Call,
                    caller: tx.caller,
                    target: to,
                    code_address: to,
                    value: tx.value,
                    input: tx.data.clone(),
                    gas: exec_gas,
                    is_static: false,
                    depth: 0,
                })
            }
            None => self.create_message(&CreateMessage {
                caller: tx.caller,
                value: tx.value,
                init_code: tx.data.clone(),
                gas: exec_gas,
                salt: None,
                depth: 0,
            }),
        };

        let mut gas_left = result.gas_left;
        let used_before_refund = tx.gas_limit - gas_left;
        let refund = u64::try_from(self.state.refund().max(0)).unwrap_or(0);
        gas_left += refund.min(used_before_refund / gas::MAX_REFUND_QUOTIENT);
        let gas_used = tx.gas_limit - gas_left;

        self.state.add_balance(tx.caller, U256::from_u64(gas_left).wrapping_mul(price));
        self.state.add_balance(self.block.coinbase, U256::from_u64(gas_used).wrapping_mul(tip));
        // A failed top frame already reverted its logs.
        let logs = self.state.take_logs();
        self.state.finalize_tx();
        Ok(TxResult { status: result.status, gas_used, output: result.output, logs, created: result.created })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Account, BlockEnv, Halt, WorldState};
    use super::*;

    fn setup(code: Vec<u8>) -> (Evm, Address, Address) {
        let sender = Address::from_low_u64(0xaaaa);
        let target = Address::from_low_u64(0xbbbb);
        let mut ws = WorldState::new();
        ws.insert(sender, Account { balance: U256::from_u64(10u64.pow(18)), ..Account::default() });
        ws.insert(target, Account::with_code(code));
        (Evm::new(ws, BlockEnv::default()), sender, target)
    }

    #[test]
    fn plain_call_charges_intrinsic_gas_and_bumps_nonce() {
        let (mut evm, sender, target) = setup(vec![0x00]);
        let tx = Transaction::call(sender, target, vec![0, 1], U256::ZERO, 100_000);
        assert_eq!(tx.intrinsic_gas(), 21000 + 4 + 16);
        let r = evm.transact(&tx).unwrap();
        assert_eq!(r.status, Status::Success);
        assert_eq!(r.gas_used, 21020);
        assert_eq!(evm.state.nonce(&sender), 1);
    }

    #[test]
    fn validation_errors_leave_state_untouched() {
        let (mut evm, sender, target) = setup(vec![0x00]);
        let before = evm.state.world().clone();
        let mut tx = Transaction::call(sender, target, vec![], U256::ZERO, 20_000);
        assert!(matches!(evm.transact(&tx), Err(TxError::IntrinsicGasTooLow { .. })));
        tx.gas_limit = 100_000_000;
        assert_eq!(evm.transact(&tx), Err(TxError::GasLimitExceedsBlock));
        tx.gas_limit = 30_000;
        tx.nonce = Some(4);
        assert!(matches!(evm.transact(&tx), Err(TxError::NonceMismatch { expected: 0, got: 4 })));
        tx.nonce = None;
        tx.value = U256::MAX;
        assert_eq!(evm.transact(&tx), Err(TxError::InsufficientFunds));
        let from_contract = Transaction::call(target, sender, vec![], U256::ZERO, 30_000);
        assert_eq!(evm.transact(&from_contract), Err(TxError::SenderNotEoa));
        evm.block.base_fee = U256::from_u64(7);
        tx.value = U256::ZERO;
        assert_eq!(evm.transact(&tx), Err(TxError::FeeCapTooLow));
        tx.gas_price = GasPrice::Eip1559 { max_fee: U256::from_u64(8), max_priority_fee: U256::from_u64(9) };
        assert_eq!(evm.transact(&tx), Err(TxError::PriorityFeeTooHigh));
        assert_eq!(evm.state.world(), &before);
    }

    #[test]
    fn create_tx_deploys_runtime_code() {
        let (mut evm, sender, _) = setup(vec![]);
        // Init code returning one byte 0x00: PUSH1 0 PUSH1 0 MSTORE8 PUSH1 1 PUSH1 0 RETURN
        let init = vec![0x60, 0, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xf3];
        let r = evm.transact(&Transaction::create(sender, init, U256::ZERO, 200_000)).unwrap();
        let addr = r.created.expect("created");
        assert_eq!(addr, super::super::create_address(&sender, 0));
        assert_eq!(&evm.state.code(&addr)[..], &[0x00]);
        assert_eq!(evm.state.nonce(&addr), 1);
        // An 0xEF-prefixed runtime is rejected (EIP-3541).
        let bad = vec![0x60, 0xef, 0x60, 0, 0x53, 0x60, 1, 0x60, 0, 0xf3];
        let r = evm.transact(&Transaction::create(sender, bad, U256::ZERO, 200_000)).unwrap();
        assert_eq!(r.status, Status::Halt(Halt::InvalidCodePrefix));
        let huge = vec![0u8; gas::MAX_INITCODE_SIZE + 1];
        assert_eq!(evm.transact(&Transaction::create(sender, huge, U256::ZERO, 29_000_000)), Err(TxError::InitcodeTooLarge));
    }

    #[test]
    fn eip1559_fees_flow_to_coinbase() {
        let (mut evm, sender, target) = setup(vec![0x00]);
        evm.block.base_fee = U256::from_u64(10);
        let mut tx = Transaction::call(sender, target, vec![], U256::ZERO, 50_000);
        tx.gas_price = GasPrice::Eip1559 { max_fee: U256::from_u64(15), max_priority_fee: U256::from_u64(2) };
        let before = evm.state.balance(&sender);
        evm.transact(&tx).unwrap();
        assert_eq!(evm.state.balance(&evm.block.coinbase.clone()), U256::from_u64(21000 * 2));
        assert_eq!(before.wrapping_sub(evm.state.balance(&sender)), U256::from_u64(21000 * 12));
    }

    #[test]
    fn refunds_are_capped_at_one_fifth() {
        let sender = Address::from_low_u64(0xaaaa);
        let target = Address::from_low_u64(0xbbbb);
        let mut ws = WorldState::new();
        ws.insert(sender, Account { balance: U256::from_u64(10u64.pow(18)), ..Account::default() });
        let mut acc = Account::with_code(vec![0x5f, 0x5f, 0x55, 0x00]); // SSTORE(0, 0)
        acc.storage.insert(U256::ZERO, U256::ONE);
        ws.insert(target, acc);
        let mut evm = Evm::new(ws, BlockEnv::default());
        let r = evm.transact(&Transaction::call(sender, target, vec![], U256::ZERO, 100_000)).unwrap();
        // 21000 + 2 + 2 + 2100 + 2900 = 26004 used; refund 4800 capped to 26004/5 = 5200 -> 4800.
        assert_eq!(r.gas_used, 26004 - 4800);
    }
}
