//! The invariant expression language.
//!
//! Invariants are declared in the campaign file as boolean expressions over
//! contract views, balances and storage, for example
//!
//! ```text
//! Token.totalSupply() == sum(a in accounts, Token.balanceOf(a))
//! balance(Vault) >= Vault.totalDeposits()
//! address(Pool.tokenB()).balanceOf(Pool) == Pool.reserveB()
//! ```
//!
//! Grammar (lowest to highest precedence):
//!
//! ```text
//! expr    := or
//! or      := and ('||' and)*
//! and     := not ('&&' not)*
//! not     := '!' not | cmp
//! cmp     := add (('=='|'!='|'<'|'<='|'>'|'>=') add)?
//! add     := mul (('+'|'-') mul)*
//! mul     := postfix (('*'|'/'|'%') postfix)*
//! postfix := primary ('.' IDENT '(' args? ')')*
//! primary := NUMBER UNIT? | 'true' | 'false' | '(' expr ')'
//!          | ('sum'|'all'|'any') '(' IDENT 'in' SET ',' expr ')'
//!          | IDENT '(' args? ')'          -- builtin: balance, storage, address, uint
//!          | IDENT                        -- contract, actor or bound variable
//! SET     := 'actors' | 'contracts' | 'accounts'
//! UNIT    := 'wei' | 'gwei' | 'ether'
//! ```
//!
//! A method call `x.f(a, b)` ABI-encodes `f` with argument types inferred from
//! the argument values (`address`, `bool` or `uint256`) and reads the first
//! return word. Arithmetic is checked: overflow, underflow and division by
//! zero are evaluation errors, and so is a reverting view call. An invariant
//! holds when its value is non-zero; an evaluation error counts as a
//! violation (as in Echidna, a property that cannot be evaluated is broken).

use crate::abi::{AbiType, AbiValue, Function};
use crate::types::Address;
use crate::u256::U256;
use std::fmt;

/// Parse or evaluation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvariantError {
    /// Syntax error with byte offset.
    #[error("syntax error at {pos}: {msg}")]
    Syntax {
        /// Byte offset in the source.
        pos: usize,
        /// Description.
        msg: String,
    },
    /// An identifier does not name a contract, actor or bound variable.
    #[error("unknown name `{0}`")]
    UnknownName(String),
    /// Runtime failure while evaluating.
    #[error("{0}")]
    Eval(String),
}

/// Address sets a quantifier can range over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSet {
    /// Fuzzing senders.
    Actors,
    /// Deployed contracts and aliases.
    Contracts,
    /// Every address the fuzzer can pass as an argument (actors, contracts, zero).
    Accounts,
}

/// Quantifier kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quantifier {
    /// Sum of the body over the set.
    Sum,
    /// True if the body holds for every element.
    All,
    /// True if the body holds for some element.
    Any,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    /// `||`
    Or,
    /// `&&`
    And,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
}

impl BinOp {
    fn symbol(self) -> &'static str {
        match self {
            BinOp::Or => "||",
            BinOp::And => "&&",
            BinOp::Eq => "==",
            BinOp::Ne => "!=",
            BinOp::Lt => "<",
            BinOp::Le => "<=",
            BinOp::Gt => ">",
            BinOp::Ge => ">=",
            BinOp::Add => "+",
            BinOp::Sub => "-",
            BinOp::Mul => "*",
            BinOp::Div => "/",
            BinOp::Rem => "%",
        }
    }

    fn is_comparison(self) -> bool {
        matches!(self, BinOp::Eq | BinOp::Ne | BinOp::Lt | BinOp::Le | BinOp::Gt | BinOp::Ge)
    }
}

/// Builtin functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    /// `balance(addr)`: Ether balance in wei.
    Balance,
    /// `storage(addr, slot)`: raw storage word.
    Storage,
    /// `address(x)`: reinterpret as an address.
    Address,
    /// `uint(x)`: reinterpret as an unsigned integer.
    Uint,
}

/// Parsed expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Integer literal.
    Num(U256),
    /// Boolean literal.
    Bool(bool),
    /// Contract, actor or bound variable.
    Name(String),
    /// Builtin application.
    Builtin(Builtin, Vec<Expr>),
    /// View call `target.method(args)`.
    Call {
        /// Address-valued expression.
        target: Box<Expr>,
        /// Function name.
        method: String,
        /// Arguments.
        args: Vec<Expr>,
    },
    /// Quantifier over an address set.
    Quant {
        /// Kind.
        kind: Quantifier,
        /// Bound variable.
        var: String,
        /// Range.
        set: AddressSet,
        /// Body.
        body: Box<Expr>,
    },
    /// Logical negation.
    Not(Box<Expr>),
    /// Binary operation.
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

/// Static kind of a runtime value (drives ABI type inference).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `uint256`.
    Uint,
    /// `address`.
    Address,
    /// `bool`.
    Bool,
}

/// A runtime value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Value {
    /// The 256-bit word.
    pub word: U256,
    /// How to encode it as a call argument.
    pub kind: Kind,
}

impl Value {
    fn uint(word: U256) -> Self {
        Value { word, kind: Kind::Uint }
    }

    fn boolean(b: bool) -> Self {
        Value { word: U256::from(b), kind: Kind::Bool }
    }

    fn address(a: Address) -> Self {
        Value { word: a.to_word(), kind: Kind::Address }
    }

    /// Truthiness (non-zero).
    pub fn truthy(&self) -> bool {
        !self.word.is_zero()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            Kind::Uint => write!(f, "{}", self.word),
            Kind::Address => write!(f, "{}", Address::from_word(self.word)),
            Kind::Bool => write!(f, "{}", self.truthy()),
        }
    }
}

/// What the evaluator needs from the outside world.
pub trait EvalContext {
    /// Address of a named contract or actor.
    fn resolve(&self, name: &str) -> Option<Address>;
    /// Members of an address set.
    fn members(&self, set: AddressSet) -> Vec<Address>;
    /// Executes a read-only call and returns its output, or an error string if it fails.
    fn view(&mut self, to: Address, data: Vec<u8>) -> Result<Vec<u8>, String>;
    /// Ether balance.
    fn balance(&self, a: &Address) -> U256;
    /// Storage word.
    fn storage(&self, a: &Address, slot: U256) -> U256;
    /// Display name of an address in explanations.
    fn name_of(&self, a: &Address) -> String {
        a.to_string()
    }
}

// ---------------------------------------------------------------- lexer

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Num(U256),
    Ident(String),
    Punct(&'static str),
    End,
}

fn lex(src: &str) -> Result<Vec<(usize, Tok)>, InvariantError> {
    const PUNCT: [&str; 18] =
        ["&&", "||", "==", "!=", "<=", ">=", "<", ">", "!", "+", "-", "*", "/", "%", "(", ")", ",", "."];
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                // Stop before a unit suffix written without a space only for decimals ("1ether" is not allowed).
                i += 1;
            }
            let text: String = src[start..i].chars().filter(|&c| c != '_').collect();
            let v = U256::from_str_radix_auto(&text)
                .map_err(|_| InvariantError::Syntax { pos: start, msg: format!("bad number `{text}`") })?;
            out.push((start, Tok::Num(v)));
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            out.push((start, Tok::Ident(src[start..i].to_string())));
        } else {
            let p = PUNCT
                .iter()
                .find(|p| src[i..].starts_with(**p))
                .ok_or_else(|| InvariantError::Syntax { pos: i, msg: format!("unexpected character `{}`", c as char) })?;
            out.push((i, Tok::Punct(p)));
            i += p.len();
        }
    }
    out.push((src.len(), Tok::End));
    Ok(out)
}

// ---------------------------------------------------------------- parser

struct Parser {
    toks: Vec<(usize, Tok)>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> &Tok {
        &self.toks[self.i].1
    }

    fn pos(&self) -> usize {
        self.toks[self.i].0
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, InvariantError> {
        Err(InvariantError::Syntax { pos: self.pos(), msg: msg.into() })
    }

    fn eat(&mut self, p: &str) -> bool {
        if matches!(self.peek(), Tok::Punct(q) if *q == p) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, p: &str) -> Result<(), InvariantError> {
        if self.eat(p) {
            Ok(())
        } else {
            self.err(format!("expected `{p}`"))
        }
    }

    fn ident(&mut self) -> Result<String, InvariantError> {
        match self.peek().clone() {
            Tok::Ident(s) => {
                self.i += 1;
                Ok(s)
            }
            _ => self.err("expected identifier"),
        }
    }

    fn expr(&mut self) -> Result<Expr, InvariantError> {
        self.or()
    }

    fn or(&mut self) -> Result<Expr, InvariantError> {
        let mut lhs = self.and()?;
        while self.eat("||") {
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(self.and()?));
        }
        Ok(lhs)
    }

    fn and(&mut self) -> Result<Expr, InvariantError> {
        let mut lhs = self.not()?;
        while self.eat("&&") {
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(self.not()?));
        }
        Ok(lhs)
    }

    fn not(&mut self) -> Result<Expr, InvariantError> {
        if self.eat("!") {
            return Ok(Expr::Not(Box::new(self.not()?)));
        }
        self.cmp()
    }

    fn cmp(&mut self) -> Result<Expr, InvariantError> {
        let lhs = self.add()?;
        let op = match self.peek() {
            Tok::Punct("==") => BinOp::Eq,
            Tok::Punct("!=") => BinOp::Ne,
            Tok::Punct("<") => BinOp::Lt,
            Tok::Punct("<=") => BinOp::Le,
            Tok::Punct(">") => BinOp::Gt,
            Tok::Punct(">=") => BinOp::Ge,
            _ => return Ok(lhs),
        };
        self.i += 1;
        Ok(Expr::Binary(op, Box::new(lhs), Box::new(self.add()?)))
    }

    fn add(&mut self) -> Result<Expr, InvariantError> {
        let mut lhs = self.mul()?;
        loop {
            let op = if self.eat("+") {
                BinOp::Add
            } else if self.eat("-") {
                BinOp::Sub
            } else {
                return Ok(lhs);
            };
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.mul()?));
        }
    }

    fn mul(&mut self) -> Result<Expr, InvariantError> {
        let mut lhs = self.postfix()?;
        loop {
            let op = if self.eat("*") {
                BinOp::Mul
            } else if self.eat("/") {
                BinOp::Div
            } else if self.eat("%") {
                BinOp::Rem
            } else {
                return Ok(lhs);
            };
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(self.postfix()?));
        }
    }

    fn args(&mut self) -> Result<Vec<Expr>, InvariantError> {
        self.expect("(")?;
        let mut args = Vec::new();
        if self.eat(")") {
            return Ok(args);
        }
        loop {
            args.push(self.expr()?);
            if self.eat(")") {
                return Ok(args);
            }
            self.expect(",")?;
        }
    }

    fn postfix(&mut self) -> Result<Expr, InvariantError> {
        let mut e = self.primary()?;
        while self.eat(".") {
            let method = self.ident()?;
            let args = self.args()?;
            e = Expr::Call { target: Box::new(e), method, args };
        }
        Ok(e)
    }

    fn primary(&mut self) -> Result<Expr, InvariantError> {
        match self.peek().clone() {
            Tok::Num(v) => {
                self.i += 1;
                let scale = match self.peek() {
                    Tok::Ident(u) if u == "ether" => Some(U256::from_u64(1_000_000_000_000_000_000)),
                    Tok::Ident(u) if u == "gwei" => Some(U256::from_u64(1_000_000_000)),
                    Tok::Ident(u) if u == "wei" => Some(U256::ONE),
                    _ => None,
                };
                match scale {
                    Some(s) => {
                        self.i += 1;
                        match v.checked_mul(s) {
                            Some(x) => Ok(Expr::Num(x)),
                            None => self.err("literal overflows 256 bits"),
                        }
                    }
                    None => Ok(Expr::Num(v)),
                }
            }
            Tok::Punct("(") => {
                self.i += 1;
                let e = self.expr()?;
                self.expect(")")?;
                Ok(e)
            }
            Tok::Ident(name) => {
                self.i += 1;
                match name.as_str() {
                    "true" => return Ok(Expr::Bool(true)),
                    "false" => return Ok(Expr::Bool(false)),
                    _ => {}
                }
                if !matches!(self.peek(), Tok::Punct("(")) {
                    return Ok(Expr::Name(name));
                }
                let quant = match name.as_str() {
                    "sum" => Some(Quantifier::Sum),
                    "all" => Some(Quantifier::All),
                    "any" => Some(Quantifier::Any),
                    _ => None,
                };
                if let Some(kind) = quant {
                    self.expect("(")?;
                    let var = self.ident()?;
                    if self.ident()? != "in" {
                        return self.err("expected `in`");
                    }
                    let set = match self.ident()?.as_str() {
                        "actors" => AddressSet::Actors,
                        "contracts" => AddressSet::Contracts,
                        "accounts" => AddressSet::Accounts,
                        other => return self.err(format!("unknown set `{other}` (actors, contracts, accounts)")),
                    };
                    self.expect(",")?;
                    let body = self.expr()?;
                    self.expect(")")?;
                    return Ok(Expr::Quant { kind, var, set, body: Box::new(body) });
                }
                let (b, arity) = match name.as_str() {
                    "balance" => (Builtin::Balance, 1),
                    "storage" => (Builtin::Storage, 2),
                    "address" => (Builtin::Address, 1),
                    "uint" | "uint256" => (Builtin::Uint, 1),
                    other => return self.err(format!("unknown function `{other}`")),
                };
                let args = self.args()?;
                if args.len() != arity {
                    return self.err(format!("`{name}` takes {arity} argument(s)"));
                }
                Ok(Expr::Builtin(b, args))
            }
            _ => self.err("expected expression"),
        }
    }
}

impl Expr {
    /// Parses an invariant expression.
    pub fn parse(src: &str) -> Result<Expr, InvariantError> {
        let mut p = Parser { toks: lex(src)?, i: 0 };
        let e = p.expr()?;
        if *p.peek() != Tok::End {
            return p.err("unexpected trailing input");
        }
        Ok(e)
    }

    /// Checks that every free name is known (`known(name)`), so typos fail at load time.
    pub fn check_names(&self, known: &dyn Fn(&str) -> bool) -> Result<(), InvariantError> {
        fn walk(e: &Expr, bound: &mut Vec<String>, known: &dyn Fn(&str) -> bool) -> Result<(), InvariantError> {
            match e {
                Expr::Num(_) | Expr::Bool(_) => Ok(()),
                Expr::Name(n) => {
                    if bound.iter().any(|b| b == n) || known(n) {
                        Ok(())
                    } else {
                        Err(InvariantError::UnknownName(n.clone()))
                    }
                }
                Expr::Builtin(_, args) => args.iter().try_for_each(|a| walk(a, bound, known)),
                Expr::Call { target, args, .. } => {
                    walk(target, bound, known)?;
                    args.iter().try_for_each(|a| walk(a, bound, known))
                }
                Expr::Quant { var, body, .. } => {
                    bound.push(var.clone());
                    let r = walk(body, bound, known);
                    bound.pop();
                    r
                }
                Expr::Not(x) => walk(x, bound, known),
                Expr::Binary(_, a, b) => {
                    walk(a, bound, known)?;
                    walk(b, bound, known)
                }
            }
        }
        walk(self, &mut Vec::new(), known)
    }

    /// Evaluates the expression.
    pub fn eval(&self, ctx: &mut dyn EvalContext) -> Result<Value, InvariantError> {
        eval(self, ctx, &mut Vec::new())
    }

    /// Explains why the expression is false: operand values of a failing
    /// comparison, and the first counterexample of a failing `all(...)`.
    pub fn explain(&self, ctx: &mut dyn EvalContext) -> Option<String> {
        explain(self, ctx, &mut Vec::new())
    }
}

fn explain(e: &Expr, ctx: &mut dyn EvalContext, env: &mut Vec<(String, Address)>) -> Option<String> {
    match e {
        Expr::Binary(op, a, b) if op.is_comparison() => {
            let l = eval(a, ctx, env).ok()?;
            let r = eval(b, ctx, env).ok()?;
            Some(format!("lhs = {l}, rhs = {r} (expected lhs {} rhs)", op.symbol()))
        }
        Expr::Quant { kind: Quantifier::All, var, set, body } => {
            for m in ctx.members(*set) {
                env.push((var.clone(), m));
                let failed = eval(body, ctx, env).map(|v| !v.truthy()).unwrap_or(true);
                let why = if failed { explain(body, ctx, env) } else { None };
                env.pop();
                if failed {
                    let name = ctx.name_of(&m);
                    return Some(match why {
                        Some(w) => format!("fails for {var} = {name}: {w}"),
                        None => format!("fails for {var} = {name}"),
                    });
                }
            }
            None
        }
        _ => None,
    }
}

fn eval(e: &Expr, ctx: &mut dyn EvalContext, env: &mut Vec<(String, Address)>) -> Result<Value, InvariantError> {
    let fail = |m: String| InvariantError::Eval(m);
    Ok(match e {
        Expr::Num(v) => Value::uint(*v),
        Expr::Bool(b) => Value::boolean(*b),
        Expr::Name(n) => match env.iter().rev().find(|(k, _)| k == n) {
            Some((_, a)) => Value::address(*a),
            None => Value::address(ctx.resolve(n).ok_or_else(|| InvariantError::UnknownName(n.clone()))?),
        },
        Expr::Builtin(b, args) => {
            let vals = args.iter().map(|a| eval(a, ctx, env)).collect::<Result<Vec<_>, _>>()?;
            match b {
                Builtin::Balance => Value::uint(ctx.balance(&Address::from_word(vals[0].word))),
                Builtin::Storage => Value::uint(ctx.storage(&Address::from_word(vals[0].word), vals[1].word)),
                Builtin::Address => Value::address(Address::from_word(vals[0].word)),
                Builtin::Uint => Value::uint(vals[0].word),
            }
        }
        Expr::Call { target, method, args } => {
            let to = Address::from_word(eval(target, ctx, env)?.word);
            let vals = args.iter().map(|a| eval(a, ctx, env)).collect::<Result<Vec<_>, _>>()?;
            let (inputs, abi_args): (Vec<AbiType>, Vec<AbiValue>) = vals
                .iter()
                .map(|v| match v.kind {
                    Kind::Uint => (AbiType::Uint(256), AbiValue::Uint(v.word)),
                    Kind::Address => (AbiType::Address, AbiValue::Address(Address::from_word(v.word))),
                    Kind::Bool => (AbiType::Bool, AbiValue::Bool(v.truthy())),
                })
                .unzip();
            let f = Function { name: method.clone(), inputs, payable: false };
            let data = f.encode_call(&abi_args).map_err(|e| fail(e.to_string()))?;
            let out = ctx.view(to, data).map_err(|why| fail(format!("{}.{} reverted: {why}", to, f.signature())))?;
            if out.len() < 32 {
                return Err(fail(format!("{}.{} returned {} bytes, expected a word", to, f.signature(), out.len())));
            }
            Value::uint(U256::from_be_slice(&out[..32]))
        }
        Expr::Quant { kind, var, set, body } => {
            let members = ctx.members(*set);
            let mut acc = match kind {
                Quantifier::Sum | Quantifier::Any => U256::ZERO,
                Quantifier::All => U256::ONE,
            };
            for m in members {
                env.push((var.clone(), m));
                let v = eval(body, ctx, env);
                env.pop();
                let v = v?;
                match kind {
                    Quantifier::Sum => {
                        acc = acc.checked_add(v.word).ok_or_else(|| fail("overflow in sum(...)".into()))?;
                    }
                    Quantifier::All if !v.truthy() => return Ok(Value::boolean(false)),
                    Quantifier::Any if v.truthy() => return Ok(Value::boolean(true)),
                    _ => {}
                }
            }
            match kind {
                Quantifier::Sum => Value::uint(acc),
                Quantifier::All => Value::boolean(true),
                Quantifier::Any => Value::boolean(false),
            }
        }
        Expr::Not(x) => Value::boolean(!eval(x, ctx, env)?.truthy()),
        Expr::Binary(op, a, b) => {
            let l = eval(a, ctx, env)?;
            // Short-circuit logic operators.
            match op {
                BinOp::And if !l.truthy() => return Ok(Value::boolean(false)),
                BinOp::Or if l.truthy() => return Ok(Value::boolean(true)),
                _ => {}
            }
            let r = eval(b, ctx, env)?;
            let (x, y) = (l.word, r.word);
            let arith = |res: Option<U256>, what: &str| {
                res.map(Value::uint).ok_or_else(|| fail(format!("{what} in `{x} {} {y}`", op.symbol())))
            };
            match op {
                BinOp::Or | BinOp::And => Value::boolean(r.truthy()),
                BinOp::Eq => Value::boolean(x == y),
                BinOp::Ne => Value::boolean(x != y),
                BinOp::Lt => Value::boolean(x < y),
                BinOp::Le => Value::boolean(x <= y),
                BinOp::Gt => Value::boolean(x > y),
                BinOp::Ge => Value::boolean(x >= y),
                BinOp::Add => arith(x.checked_add(y), "overflow")?,
                BinOp::Sub => arith(x.checked_sub(y), "underflow")?,
                BinOp::Mul => arith(x.checked_mul(y), "overflow")?,
                BinOp::Div => arith(x.div_rem(y).map(|(q, _)| q), "division by zero")?,
                BinOp::Rem => arith(x.div_rem(y).map(|(_, r)| r), "division by zero")?,
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fake world: `Token` at 0x100 answers `totalSupply()` and `balanceOf(address)`.
    struct Fake {
        balances: HashMap<Address, U256>,
        supply: U256,
        calls: usize,
    }

    fn token() -> Address {
        Address::from_low_u64(0x100)
    }

    impl EvalContext for Fake {
        fn resolve(&self, name: &str) -> Option<Address> {
            match name {
                "Token" => Some(token()),
                "alice" => Some(Address::from_low_u64(1)),
                _ => None,
            }
        }
        fn members(&self, set: AddressSet) -> Vec<Address> {
            match set {
                AddressSet::Actors => vec![Address::from_low_u64(1), Address::from_low_u64(2)],
                AddressSet::Contracts => vec![token()],
                AddressSet::Accounts => vec![Address::from_low_u64(1), Address::from_low_u64(2), token()],
            }
        }
        fn view(&mut self, to: Address, data: Vec<u8>) -> Result<Vec<u8>, String> {
            self.calls += 1;
            if to != token() {
                return Err("no code".into());
            }
            let ts = Function::parse("totalSupply()").unwrap().selector();
            let bo = Function::parse("balanceOf(address)").unwrap().selector();
            if data[..4] == ts {
                Ok(self.supply.to_be_bytes().to_vec())
            } else if data[..4] == bo {
                let a = Address::from_word(U256::from_be_slice(&data[4..36]));
                Ok(self.balances.get(&a).copied().unwrap_or(U256::ZERO).to_be_bytes().to_vec())
            } else if data[..4] == Function::parse("short()").unwrap().selector() {
                Ok(vec![1])
            } else {
                Err("Error(\"no selector\")".into())
            }
        }
        fn balance(&self, a: &Address) -> U256 {
            if *a == token() {
                U256::from_u64(5)
            } else {
                U256::ZERO
            }
        }
        fn storage(&self, _a: &Address, slot: U256) -> U256 {
            slot.wrapping_add(U256::ONE)
        }
    }

    fn fake(b1: u64, b2: u64, supply: u64) -> Fake {
        let mut balances = HashMap::new();
        balances.insert(Address::from_low_u64(1), U256::from_u64(b1));
        balances.insert(Address::from_low_u64(2), U256::from_u64(b2));
        Fake { balances, supply: U256::from_u64(supply), calls: 0 }
    }

    fn eval_str(src: &str, ctx: &mut Fake) -> Result<Value, InvariantError> {
        Expr::parse(src).unwrap().eval(ctx)
    }

    #[test]
    fn supply_conservation() {
        let src = "Token.totalSupply() == sum(a in actors, Token.balanceOf(a))";
        assert!(eval_str(src, &mut fake(30, 70, 100)).unwrap().truthy());
        let mut broken = fake(30, 71, 100);
        assert!(!eval_str(src, &mut broken).unwrap().truthy());
        let why = Expr::parse(src).unwrap().explain(&mut broken).unwrap();
        assert_eq!(why, "lhs = 100, rhs = 101 (expected lhs == rhs)");
    }

    #[test]
    fn arithmetic_precedence_units_and_errors() {
        let mut f = fake(0, 0, 0);
        assert_eq!(eval_str("1 + 2 * 3 - 4 / 2 % 3", &mut f).unwrap().word, U256::from_u64(5));
        assert_eq!(eval_str("(1 + 2) * 3", &mut f).unwrap().word, U256::from_u64(9));
        assert_eq!(eval_str("2 gwei + 1 wei", &mut f).unwrap().word, U256::from_u64(2_000_000_001));
        assert_eq!(eval_str("1 ether", &mut f).unwrap().word, U256::from_u64(10u64.pow(18)));
        assert_eq!(eval_str("0x10 + 1_000", &mut f).unwrap().word, U256::from_u64(1016));
        assert!(matches!(eval_str("0 - 1", &mut f), Err(InvariantError::Eval(m)) if m.contains("underflow")));
        assert!(eval_str("1 / 0", &mut f).is_err());
        assert!(eval_str("1 % 0", &mut f).is_err());
        assert!(eval_str("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff + 1", &mut f).is_err());
        assert!(eval_str("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff * 2", &mut f).is_err());
    }

    #[test]
    fn logic_and_comparisons() {
        let mut f = fake(0, 0, 0);
        for (src, want) in [
            ("1 < 2 && 2 <= 2 && 3 > 2 && 3 >= 3 && 1 != 2", true),
            ("!(1 == 1) || false", false),
            ("true && !false", true),
            ("all(a in accounts, balance(a) <= 5)", true),
            ("any(a in contracts, balance(a) == 5)", true),
            ("any(a in actors, balance(a) == 5)", false),
            ("all(a in actors, balance(a) == 5)", false),
            ("storage(Token, 7) == 8", true),
            ("address(0x100) == Token", true),
            ("uint(Token) == 256", true),
        ] {
            assert_eq!(eval_str(src, &mut f).unwrap().truthy(), want, "{src}");
        }
    }

    #[test]
    fn short_circuit_skips_calls() {
        let mut f = fake(0, 0, 0);
        assert!(!eval_str("false && Token.totalSupply() == 0", &mut f).unwrap().truthy());
        assert!(eval_str("true || Token.nope() == 0", &mut f).unwrap().truthy());
        assert_eq!(f.calls, 0);
    }

    #[test]
    fn call_failures_are_errors() {
        let mut f = fake(0, 0, 0);
        let e = eval_str("Token.nope() == 0", &mut f).unwrap_err();
        assert!(e.to_string().contains("nope() reverted"), "{e}");
        assert!(eval_str("alice.totalSupply() == 0", &mut f).is_err());
        assert!(eval_str("Token.short() == 0", &mut f).unwrap_err().to_string().contains("returned 1 bytes"));
        assert!(matches!(eval_str("Bob == 1", &mut f), Err(InvariantError::UnknownName(_))));
        // Bool and address arguments pick their ABI types.
        assert!(eval_str("Token.balanceOf(alice) == 0", &mut f).unwrap().truthy());
        assert!(eval_str("Token.balanceOf(true) == 0", &mut f).is_err());
    }

    #[test]
    fn syntax_errors_and_name_checks() {
        for bad in ["", "1 +", "(1", "Token.", "Token.f(", "sum(a of actors, 1)", "sum(a in people, 1)", "foo(1)", "1 $ 2", "balance(1, 2)", "1 2", "sum(1 in actors, 1)", "Token.f(1 2)"] {
            assert!(Expr::parse(bad).is_err(), "{bad:?}");
        }
        assert!(Expr::parse("99999999999999999999999999999999999999999999999999999999999999999999999999999999 ether").is_err());
        let e = Expr::parse("sum(a in actors, Token.balanceOf(a)) == Tok.x()").unwrap();
        let known = |n: &str| n == "Token";
        assert_eq!(e.check_names(&known), Err(InvariantError::UnknownName("Tok".into())));
        let ok = Expr::parse("!all(x in accounts, storage(x, 1) + balance(Token) > 0)").unwrap();
        assert!(ok.check_names(&known).is_ok());
        assert!(Expr::parse("1 == 2").unwrap().explain(&mut fake(0, 0, 0)).is_some());
        let all = Expr::parse("all(a in actors, Token.balanceOf(a) <= 50)").unwrap();
        let why = all.explain(&mut fake(10, 70, 80)).unwrap();
        assert_eq!(why, "fails for a = 0x0000000000000000000000000000000000000002: lhs = 70, rhs = 50 (expected lhs <= rhs)");
        assert!(all.explain(&mut fake(10, 20, 30)).is_none());
        let all_bool = Expr::parse("all(a in actors, false)").unwrap();
        assert_eq!(all_bool.explain(&mut fake(0, 0, 0)).unwrap(), "fails for a = 0x0000000000000000000000000000000000000001");
        assert!(Expr::parse("true").unwrap().explain(&mut fake(0, 0, 0)).is_none());
    }

    #[test]
    fn value_display() {
        assert_eq!(Value::boolean(true).to_string(), "true");
        assert_eq!(Value::address(Address::from_low_u64(1)).to_string(), "0x0000000000000000000000000000000000000001");
        assert_eq!(Value::uint(U256::from_u64(7)).to_string(), "7");
    }
}
