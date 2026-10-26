# Design decisions

Key design decisions in evmfuzz, each with the reasoning and what it would cost
if it turned out wrong, in the form `- <what> — <why> — <cost if wrong>`.

## Interpreter

- implement the EVM from scratch (own U256, Keccak-256, RLP, Merkle-Patricia root) instead of wrapping revm — the fuzzer needs hooks inside the dispatch loop, and owning that loop lets the coverage/comparison hooks compile away for the no-op tracer — more code to keep correct; mitigated by the ethereum/tests conformance suite and U256 property tests against num-bigint.
- target the Shanghai fork only — one fork keeps the gas schedule and conformance target unambiguous; Cancun opcodes (TLOAD/TSTORE/MCOPY/BLOBHASH) are undefined and halt as invalid — contracts compiled for Cancun will not run; fixtures are compiled with `--evm-version shanghai`.
- implement precompiles 0x02 (SHA-256), 0x03 (RIPEMD-160), 0x04 (identity) and the input-validation path of 0x01 (ECRECOVER); report the rest as `Unsupported` after charging their gas — elliptic-curve and big-number precompiles are large and irrelevant to the fuzzing goal; reporting rather than guessing keeps conformance numbers honest — 54 pinned conformance cases are "unsupported", and target contracts that call those precompiles cannot be fuzzed meaningfully.
- conformance is checked through the post-state root and logs hash of GeneralStateTests (`ethereum/tests` v13.3), using the `GeneralStateTests/VMTests` form for the VM tests — v13 no longer ships the legacy VMTests format, and the root comparison checks gas, refunds, balances, nonces and storage all at once — a root mismatch does not localise the bug (the runner's job, not the test's).
- pin 26 complete suites (562 files, ~14 MB), not the whole repository — keeps the committed test data under 20 MB; suites were chosen by opcode relevance, and every pinned suite is included in full (no cherry-picked files) — omitted suites (notably precompile and stress suites) are untested.
- `BLOCKHASH(n)` returns `keccak256(decimal(n))` for the 256 previous blocks — the convention the reference test fillers use when no chain exists — contracts that rely on real block hashes see synthetic values.
- the loop-heavy `vmPerformance` suite lives in a `slow_` test that `make test` runs and the instrumented coverage run skips — under `-C instrument-coverage` it took over 15 CPU minutes — coverage numbers exclude what only those three files exercise (nothing that other tests miss, as far as line coverage shows).

## Fuzzer

- invariants are an expression language in the campaign file (calls, `balance`, `storage`, `sum/all/any` over address sets), not Solidity property functions — user-declared invariants like `totalSupply == sum of balances` are the main use case, and a contract cannot express them without tracking holders; property functions still work as `Contract.echidna_x()` calls — an extra mini-language to learn.
- a reverting or non-evaluable invariant counts as a violation — same convention as Echidna; a property that cannot be checked is a finding — campaigns with fragile views report noise.
- invariants are evaluated only after transactions that succeeded — a reverted transaction leaves contract state unchanged (only the sender's nonce changes), so re-checking is wasted work — time-dependent views (e.g. a vesting schedule) are not re-checked after a failed call that advanced the timestamp.
- address arguments are drawn only from the campaign's address pool (actors, contracts, aliases, zero) — keeps `sum(a in accounts, ...)` invariants sound and makes reproducers readable — bugs that need an arbitrary third-party address are only reachable through the pool's members.
- coverage = AFL-style hit-count buckets over `JUMPI` directions only — JUMPI is where Solidity branches; JUMP edges mostly reflect internal call/return plumbing — two paths that differ only in JUMP targets look identical.
- value feedback has three parts — bytecode PUSH constants (pinned, jump targets excluded), runtime comparison operands with ±1 neighbours, and input-to-state hints per (function, argument) — on development seeds the first two alone left the four-stage `staged` fixture at a ~100k-transaction median; input-to-state brought it to ~3.5k — more knobs; the `no-dict` ablation turns all three off together.
- comparison operands equal to one of the call's own calldata words or its value are not added to the dictionary — they are the fuzzer's own inputs echoed back and flooded the dictionary (4,096 entries on the vault fixture) — a constant that happens to equal a generated argument is learned only via the input-to-state path.
- every sequence replays from the genesis snapshot (no mid-sequence state snapshots) — simple, deterministic and the fixtures need ≤ 10 calls — long sequences re-execute their prefix each time.
- the budget is counted in fuzzing transactions, not seconds — results are reproducible bit-for-bit from (seed, budget) on any machine; `--time-limit` exists but makes a run timing-dependent — wall-clock comparisons need the separate `bench` numbers.
- shrinking = truncate, ddmin chunk removal, per-call simplification (sender, warp, value, arguments by 0/1/binary search), plus *linked* passes that change equal values and equal senders together — the registry and staged fixtures otherwise stay at `configure(1e9)/store(1e9, …)` and mixed senders — binary search assumes monotonicity; a non-monotone property just keeps the current value (never a wrong result).
- the assertion oracle checks only the top-level call's result (Panic 0x01 or the INVALID opcode) — nested frames whose failure is caught by the caller are the caller's business — an `assert` inside a `try` block is not reported.
- fuzzer parameters were tuned on development seeds 1-10 only; README results use held-out seeds 1001-1030 — avoids reporting on the data the knobs were tuned on — 30 seeds is a small sample; medians, not means, are reported.

## Engineering

- the repository includes compiled fixture bytecode and a script that rebuilds it with a checksum-verified solc 0.8.24 (`make fixtures-check`) — `make check`/`make demo` must work offline without a Solidity toolchain — the committed bytecode could drift from the sources; the CI `fixtures` job guards it.
- `cargo-llvm-cov` with an 80% line threshold over the whole crate (CLI and benchmarks included) — one honest number, no per-file exclusions — CLI-only paths drag the number down slightly.
- MSRV 1.82, enforced by a CI job that builds every target with the committed `Cargo.lock` (`--locked`), and dependency updates resolved MSRV-aware (`.cargo/config.toml`, `incompatible-rust-versions = "fallback"`) — a lockfile resolved on a newer toolchain once pulled in `indexmap` 2.14 / `hashbrown` 0.17 (edition 2024, Rust 1.85) and broke the MSRV build — some dependencies stay a minor version behind their latest release.
- rustfmt `max_width = 120` — the interpreter's match arms read better unwrapped — none.
- CLI exit codes: `fuzz` 0 = all properties held, 1 = something broke (as in Echidna/Foundry), 2 = usage/loading error; `replay` 0 = reproduced, 1 = not reproduced — scripts can assert outcomes; `make demo` checks them explicitly — users expecting 0 on findings must read the docs.
