//! World state with a revertible journal.
//!
//! [`WorldState`] is the plain account map (cheap to clone for fuzzing
//! snapshots). [`JournaledState`] wraps it with the transaction-scoped
//! substate the Yellow Paper calls `A`: accessed addresses/slots (EIP-2929),
//! touched accounts (EIP-161), self-destruct set, logs and refund counter,
//! plus an undo journal so nested call frames can be reverted in
//! O(changes) without copying state.

use crate::crypto::{keccak256, EMPTY_CODE_HASH};
use crate::fxhash::{FxHashMap, FxHashSet};
use crate::rlp;
use crate::trie::{secure_trie_root, EMPTY_ROOT};
use crate::types::{Address, B256};
use crate::u256::U256;
use std::sync::Arc;

/// Immutable contract code shared between frames and snapshots.
pub type Code = Arc<[u8]>;

/// An account in the world state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    /// Transaction / creation counter.
    pub nonce: u64,
    /// Balance in wei.
    pub balance: U256,
    /// Deployed bytecode.
    pub code: Code,
    /// `keccak256(code)`, cached.
    pub code_hash: B256,
    /// Non-zero storage slots.
    pub storage: FxHashMap<U256, U256>,
}

impl Default for Account {
    fn default() -> Self {
        Account {
            nonce: 0,
            balance: U256::ZERO,
            code: Arc::from(Vec::new()),
            code_hash: EMPTY_CODE_HASH,
            storage: FxHashMap::default(),
        }
    }
}

impl Account {
    /// Builds an account with the given code.
    pub fn with_code(code: Vec<u8>) -> Self {
        let code_hash = keccak256(&code);
        Account { code: Arc::from(code), code_hash, ..Account::default() }
    }

    /// EIP-161 emptiness: no nonce, no balance, no code.
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance.is_zero() && self.code.is_empty()
    }

    /// Storage trie root.
    pub fn storage_root(&self) -> B256 {
        if self.storage.values().all(U256::is_zero) {
            return EMPTY_ROOT;
        }
        secure_trie_root(
            self.storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (k.to_be_bytes().to_vec(), rlp::encode_u256(*v))),
        )
    }
}

/// The account map.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorldState {
    accounts: FxHashMap<Address, Account>,
}

impl WorldState {
    /// Empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts or replaces an account.
    pub fn insert(&mut self, addr: Address, account: Account) {
        self.accounts.insert(addr, account);
    }

    /// Looks up an account.
    pub fn get(&self, addr: &Address) -> Option<&Account> {
        self.accounts.get(addr)
    }

    /// Iterates over all accounts.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.accounts.iter()
    }

    /// Number of accounts.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// True when there are no accounts.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Balance of `addr` (zero if absent).
    pub fn balance(&self, addr: &Address) -> U256 {
        self.accounts.get(addr).map_or(U256::ZERO, |a| a.balance)
    }

    /// Storage value (zero if absent).
    pub fn storage(&self, addr: &Address, key: &U256) -> U256 {
        self.accounts.get(addr).and_then(|a| a.storage.get(key)).copied().unwrap_or(U256::ZERO)
    }

    /// State trie root (Yellow Paper section 4.1).
    pub fn state_root(&self) -> B256 {
        secure_trie_root(self.accounts.iter().map(|(addr, acc)| {
            let body = rlp::encode_list(&[
                rlp::encode_u64(acc.nonce),
                rlp::encode_u256(acc.balance),
                rlp::encode_bytes(&acc.storage_root().0),
                rlp::encode_bytes(&acc.code_hash.0),
            ]);
            (addr.0.to_vec(), body)
        }))
    }
}

/// An emitted log record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Log {
    /// Emitting contract.
    pub address: Address,
    /// Up to four topics.
    pub topics: Vec<B256>,
    /// Unindexed data.
    pub data: Vec<u8>,
}

/// `keccak256(rlp(logs))`, the value `ethereum/tests` calls `logs`.
pub fn logs_hash(logs: &[Log]) -> B256 {
    let items: Vec<Vec<u8>> = logs
        .iter()
        .map(|l| {
            let topics: Vec<Vec<u8>> = l.topics.iter().map(|t| rlp::encode_bytes(&t.0)).collect();
            rlp::encode_list(&[rlp::encode_bytes(&l.address.0), rlp::encode_list(&topics), rlp::encode_bytes(&l.data)])
        })
        .collect();
    keccak256(&rlp::encode_list(&items))
}

#[derive(Debug)]
enum Entry {
    Created(Address),
    Replaced(Address, Box<Account>),
    Balance(Address, U256),
    Nonce(Address, u64),
    Storage(Address, U256, U256),
    Code(Address, Code, B256),
    Touched(Address),
    WarmAccount(Address),
    WarmSlot(Address, U256),
    Destructed(Address),
    Refund(i64),
}

/// A point the journal can be reverted to.
#[derive(Clone, Copy, Debug)]
pub struct Checkpoint {
    journal_len: usize,
    logs_len: usize,
}

/// RIPEMD-160 precompile address: stays touched across reverts (the
/// consensus quirk from the 2016 state-clearing incident, kept by every client).
const RIPEMD_ADDRESS: Address = Address([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

/// World state plus the transaction substate and undo journal.
#[derive(Debug, Default)]
pub struct JournaledState {
    state: WorldState,
    journal: Vec<Entry>,
    warm_accounts: FxHashSet<Address>,
    warm_slots: FxHashSet<(Address, U256)>,
    touched: FxHashSet<Address>,
    destructed: FxHashSet<Address>,
    originals: FxHashMap<(Address, U256), U256>,
    logs: Vec<Log>,
    refund: i64,
}

impl JournaledState {
    /// Wraps a world state.
    pub fn new(state: WorldState) -> Self {
        JournaledState { state, ..Default::default() }
    }

    /// Read access to the underlying world state.
    pub fn world(&self) -> &WorldState {
        &self.state
    }

    /// Consumes the wrapper, returning the world state.
    pub fn into_world(self) -> WorldState {
        self.state
    }

    /// Logs emitted so far in the current transaction.
    pub fn logs(&self) -> &[Log] {
        &self.logs
    }

    /// Takes the logs emitted in the current transaction.
    pub fn take_logs(&mut self) -> Vec<Log> {
        std::mem::take(&mut self.logs)
    }

    /// Current refund counter.
    pub fn refund(&self) -> i64 {
        self.refund
    }

    /// Records a checkpoint.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint { journal_len: self.journal.len(), logs_len: self.logs.len() }
    }

    /// Undoes every change made since `cp`.
    pub fn revert_to(&mut self, cp: Checkpoint) {
        while self.journal.len() > cp.journal_len {
            let entry = self.journal.pop().expect("journal length checked");
            self.undo(entry);
        }
        self.logs.truncate(cp.logs_len);
    }

    fn undo(&mut self, entry: Entry) {
        match entry {
            Entry::Created(a) => {
                self.state.accounts.remove(&a);
            }
            Entry::Replaced(a, prev) => {
                self.state.accounts.insert(a, *prev);
            }
            Entry::Balance(a, v) => self.account_mut(&a).balance = v,
            Entry::Nonce(a, n) => self.account_mut(&a).nonce = n,
            Entry::Storage(a, k, v) => {
                let acc = self.account_mut(&a);
                if v.is_zero() {
                    acc.storage.remove(&k);
                } else {
                    acc.storage.insert(k, v);
                }
            }
            Entry::Code(a, code, hash) => {
                let acc = self.account_mut(&a);
                acc.code = code;
                acc.code_hash = hash;
            }
            Entry::Touched(a) => {
                if a != RIPEMD_ADDRESS {
                    self.touched.remove(&a);
                }
            }
            Entry::WarmAccount(a) => {
                self.warm_accounts.remove(&a);
            }
            Entry::WarmSlot(a, k) => {
                self.warm_slots.remove(&(a, k));
            }
            Entry::Destructed(a) => {
                self.destructed.remove(&a);
            }
            Entry::Refund(r) => self.refund = r,
        }
    }

    fn account_mut(&mut self, a: &Address) -> &mut Account {
        self.state.accounts.get_mut(a).expect("journal entry refers to a live account")
    }

    fn touch(&mut self, a: Address) {
        if self.touched.insert(a) {
            self.journal.push(Entry::Touched(a));
        }
    }

    /// Ensures the account exists (creating an empty one) and returns it.
    fn ensure(&mut self, a: Address) -> &mut Account {
        if let std::collections::hash_map::Entry::Vacant(slot) = self.state.accounts.entry(a) {
            slot.insert(Account::default());
            self.journal.push(Entry::Created(a));
        }
        self.touch(a);
        self.state.accounts.get_mut(&a).expect("just inserted")
    }

    /// True if the account exists.
    pub fn exists(&self, a: &Address) -> bool {
        self.state.accounts.contains_key(a)
    }

    /// True if the account is absent or EIP-161 empty.
    pub fn is_dead(&self, a: &Address) -> bool {
        self.state.accounts.get(a).is_none_or(Account::is_empty)
    }

    /// Account lookup.
    pub fn account(&self, a: &Address) -> Option<&Account> {
        self.state.accounts.get(a)
    }

    /// Balance (zero if absent).
    pub fn balance(&self, a: &Address) -> U256 {
        self.state.balance(a)
    }

    /// Nonce (zero if absent).
    pub fn nonce(&self, a: &Address) -> u64 {
        self.state.accounts.get(a).map_or(0, |x| x.nonce)
    }

    /// Code (empty if absent).
    pub fn code(&self, a: &Address) -> Code {
        self.state.accounts.get(a).map_or_else(|| Arc::from(Vec::new()), |x| x.code.clone())
    }

    /// Code hash for `EXTCODEHASH`: zero for dead accounts.
    pub fn ext_code_hash(&self, a: &Address) -> B256 {
        match self.state.accounts.get(a) {
            Some(acc) if !acc.is_empty() => acc.code_hash,
            _ => B256::ZERO,
        }
    }

    /// Current storage value.
    pub fn sload(&self, a: &Address, key: &U256) -> U256 {
        self.state.storage(a, key)
    }

    /// Storage value at the start of the transaction.
    pub fn original(&self, a: &Address, key: &U256) -> U256 {
        self.originals.get(&(*a, *key)).copied().unwrap_or_else(|| self.sload(a, key))
    }

    /// Writes a storage slot (the account must exist).
    pub fn sstore(&mut self, a: Address, key: U256, value: U256) {
        let prev = self.sload(&a, &key);
        self.originals.entry((a, key)).or_insert(prev);
        let acc = self.ensure(a);
        if value.is_zero() {
            acc.storage.remove(&key);
        } else {
            acc.storage.insert(key, value);
        }
        self.journal.push(Entry::Storage(a, key, prev));
    }

    /// Adds to a balance, creating and touching the account (even for zero).
    pub fn add_balance(&mut self, a: Address, v: U256) {
        let acc = self.ensure(a);
        let prev = acc.balance;
        acc.balance = prev.wrapping_add(v);
        if !v.is_zero() {
            self.journal.push(Entry::Balance(a, prev));
        }
    }

    /// Subtracts from a balance; returns false (and changes nothing) if insufficient.
    pub fn sub_balance(&mut self, a: Address, v: U256) -> bool {
        if self.balance(&a) < v {
            return false;
        }
        let acc = self.ensure(a);
        let prev = acc.balance;
        acc.balance = prev.wrapping_sub(v);
        if !v.is_zero() {
            self.journal.push(Entry::Balance(a, prev));
        }
        true
    }

    /// Moves `v` wei; false if the sender cannot afford it.
    pub fn transfer(&mut self, from: Address, to: Address, v: U256) -> bool {
        if !self.sub_balance(from, v) {
            return false;
        }
        self.add_balance(to, v);
        true
    }

    /// Sets a nonce.
    pub fn set_nonce(&mut self, a: Address, n: u64) {
        let acc = self.ensure(a);
        let prev = acc.nonce;
        acc.nonce = n;
        self.journal.push(Entry::Nonce(a, prev));
    }

    /// Installs code.
    pub fn set_code(&mut self, a: Address, code: Vec<u8>) {
        let hash = keccak256(&code);
        let acc = self.ensure(a);
        let prev_code = std::mem::replace(&mut acc.code, Arc::from(code));
        let prev_hash = std::mem::replace(&mut acc.code_hash, hash);
        self.journal.push(Entry::Code(a, prev_code, prev_hash));
    }

    /// Creates a fresh account at `a` for CREATE, keeping any pre-existing balance.
    pub fn create_account(&mut self, a: Address) {
        match self.state.accounts.remove(&a) {
            Some(prev) => {
                let fresh = Account { balance: prev.balance, ..Account::default() };
                self.state.accounts.insert(a, fresh);
                self.journal.push(Entry::Replaced(a, Box::new(prev)));
            }
            None => {
                self.state.accounts.insert(a, Account::default());
                self.journal.push(Entry::Created(a));
            }
        }
        self.touch(a);
    }

    /// Marks an account as warm; returns true if it was cold.
    pub fn warm_account(&mut self, a: Address) -> bool {
        let cold = self.warm_accounts.insert(a);
        if cold {
            self.journal.push(Entry::WarmAccount(a));
        }
        cold
    }

    /// True if the account is already warm.
    pub fn is_warm(&self, a: &Address) -> bool {
        self.warm_accounts.contains(a)
    }

    /// Marks a slot as warm; returns true if it was cold.
    pub fn warm_slot(&mut self, a: Address, key: U256) -> bool {
        let cold = self.warm_slots.insert((a, key));
        if cold {
            self.journal.push(Entry::WarmSlot(a, key));
        }
        cold
    }

    /// Adjusts the refund counter.
    pub fn add_refund(&mut self, delta: i64) {
        self.journal.push(Entry::Refund(self.refund));
        self.refund += delta;
    }

    /// Appends a log.
    pub fn push_log(&mut self, log: Log) {
        self.logs.push(log);
    }

    /// Marks an account for destruction at the end of the transaction and zeroes its balance.
    pub fn self_destruct(&mut self, a: Address) {
        if self.destructed.insert(a) {
            self.journal.push(Entry::Destructed(a));
        }
        let acc = self.ensure(a);
        let prev = acc.balance;
        acc.balance = U256::ZERO;
        self.journal.push(Entry::Balance(a, prev));
    }

    /// True if `a` self-destructed in this transaction.
    pub fn is_destructed(&self, a: &Address) -> bool {
        self.destructed.contains(a)
    }

    /// Ends the transaction: deletes self-destructed accounts and touched
    /// empty accounts (EIP-161), then clears the substate.
    pub fn finalize_tx(&mut self) {
        for a in self.destructed.drain() {
            self.state.accounts.remove(&a);
        }
        for a in self.touched.drain() {
            if self.state.accounts.get(&a).is_some_and(Account::is_empty) {
                self.state.accounts.remove(&a);
            }
        }
        self.journal.clear();
        self.warm_accounts.clear();
        self.warm_slots.clear();
        self.originals.clear();
        self.refund = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u64) -> Address {
        Address::from_low_u64(n)
    }

    #[test]
    fn revert_restores_everything() {
        let mut ws = WorldState::new();
        ws.insert(addr(1), Account { balance: U256::from_u64(100), ..Account::default() });
        let mut js = JournaledState::new(ws.clone());
        let cp = js.checkpoint();
        assert!(js.transfer(addr(1), addr(2), U256::from_u64(40)));
        js.sstore(addr(2), U256::ONE, U256::from_u64(7));
        js.set_nonce(addr(1), 5);
        js.set_code(addr(2), vec![0x00]);
        js.warm_account(addr(9));
        js.warm_slot(addr(9), U256::ONE);
        js.add_refund(10);
        js.push_log(Log { address: addr(2), topics: vec![], data: vec![] });
        js.self_destruct(addr(1));
        assert!(js.is_destructed(&addr(1)));
        js.revert_to(cp);
        assert_eq!(js.world(), &ws);
        assert!(!js.is_warm(&addr(9)));
        assert_eq!(js.refund(), 0);
        assert!(js.logs().is_empty());
        assert!(!js.is_destructed(&addr(1)));
    }

    #[test]
    fn originals_survive_multiple_writes() {
        let mut js = JournaledState::new(WorldState::new());
        js.sstore(addr(1), U256::ONE, U256::from_u64(5));
        js.sstore(addr(1), U256::ONE, U256::from_u64(6));
        assert_eq!(js.original(&addr(1), &U256::ONE), U256::ZERO);
        assert_eq!(js.sload(&addr(1), &U256::ONE), U256::from_u64(6));
    }

    #[test]
    fn finalize_deletes_touched_empty_accounts() {
        let mut ws = WorldState::new();
        ws.insert(addr(5), Account::default());
        let mut js = JournaledState::new(ws);
        js.add_balance(addr(5), U256::ZERO);
        js.add_balance(addr(6), U256::ZERO);
        js.finalize_tx();
        assert!(js.world().is_empty());
        assert_eq!(js.world().state_root(), EMPTY_ROOT);
    }

    #[test]
    fn create_account_keeps_balance_and_reverts() {
        let mut ws = WorldState::new();
        let mut acc = Account { balance: U256::from_u64(3), ..Account::default() };
        acc.storage.insert(U256::ONE, U256::ONE);
        ws.insert(addr(7), acc);
        let mut js = JournaledState::new(ws.clone());
        let cp = js.checkpoint();
        js.create_account(addr(7));
        assert_eq!(js.balance(&addr(7)), U256::from_u64(3));
        assert_eq!(js.sload(&addr(7), &U256::ONE), U256::ZERO);
        js.revert_to(cp);
        assert_eq!(js.world(), &ws);
    }

    #[test]
    fn ripemd_touch_survives_revert() {
        let mut js = JournaledState::new(WorldState::new());
        let cp = js.checkpoint();
        js.add_balance(RIPEMD_ADDRESS, U256::ZERO);
        js.revert_to(cp);
        assert!(!js.exists(&RIPEMD_ADDRESS));
        assert!(js.touched.contains(&RIPEMD_ADDRESS));
    }
}
