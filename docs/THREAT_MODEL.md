# Threat model

## What this tool is

An offline, educational/defensive tool: an EVM interpreter and a fuzzer that
searches for call sequences breaking properties of contracts **you supply as
bytecode**. It never connects to a network, a node, an RPC endpoint or a wallet;
there is no transaction signing, no key material and no mainnet/testnet state.
The bundled targets are contracts written for this repository with deliberately
planted bugs.

## Assets and trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Campaign TOML, bytecode, ABI JSON | Semi-trusted (written by the user) | Parsed with `deny_unknown_fields`; every error is reported with context; nothing is executed outside the interpreter. |
| Contract bytecode | **Untrusted** (it is the thing under test) | Runs only inside the interpreter: gas-metered, 1024-frame depth limit, 1024-item stack, memory bounded by gas (hard cap 4 GiB of addressable memory is unreachable because expansion is charged quadratically first). No host access exists in the instruction set. |
| ethereum/tests JSON | Third-party data | Pinned commit + SHA-256 manifest. |
| Reproducer JSON | Semi-trusted | Parsed and type-checked against the campaign; mismatches are errors. |

## Threats considered

* **Resource exhaustion by a target contract.** Bounded by the per-call gas
  limit (25M by default) and the transaction budget. Deep recursion runs on a
  thread with a 256 MiB stack (64 MiB per eval worker) sized for the 1024-frame
  limit. Coverage maps are fixed-size; the dictionary and per-argument hint lists
  are capped; the comparison log is capped per transaction.
* **Hash flooding.** Hash maps use a fast non-cryptographic hasher (Fx). Keys
  (addresses, slots) are chosen by contract code, so a hostile contract could
  degrade map performance; this only slows a local fuzzing run and is accepted.
* **Misleading results.** A false "property holds" is the main risk of any
  fuzzer: absence of a finding is not a proof. Reports say "not falsified within
  budget". Semantics gaps (see README Limitations: unimplemented precompiles) are
  surfaced as `Unsupported` in conformance runs instead of silently diverging.
* **Supply chain.** Dependencies are pinned in `Cargo.lock`; Keccak is
  implemented in-tree and tested against known vectors; solc is only needed to
  rebuild fixtures and is checksum-verified when downloaded.

## Out of scope / non-goals

Attacking deployed contracts, interacting with live chains, generating exploit
transactions for real systems, key handling, and any stealth or evasion feature.
