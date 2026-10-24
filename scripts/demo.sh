#!/usr/bin/env bash
# Offline end-to-end demo: conformance summary, a fuzzing campaign per
# fixture (fixed seed, documented budget), and a reproducer replay.
set -uo pipefail

BIN="${1:?usage: scripts/demo.sh path/to/evmfuzz}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="out/demo"   # git-ignored
rm -rf "$OUT" && mkdir -p "$OUT"
fail=0

banner() { printf '\n==== %s ====\n' "$1"; }

banner "1. interpreter conformance: pinned ethereum/tests subset (Shanghai)"
"$BIN" statetest tests/ethtests/GeneralStateTests | tail -n 1 || fail=1

banner "2. fuzzing the planted-bug fixtures (seed 1, budget 100000 tx)"
for f in token vault staged registry amm; do
  echo
  "$BIN" fuzz "fixtures/$f/campaign.toml" --seed 1 --max-tx 100000 --save-dir "$OUT"
  code=$?
  # Exit status 1 means "a property was broken", which is the expected outcome here.
  [[ $code == 1 ]] || { echo "!! expected a broken property in $f (exit $code)"; fail=1; }
done

banner "3. the bug-free control (same API and invariants as token)"
"$BIN" fuzz fixtures/token-fixed/campaign.toml --seed 1 --max-tx 100000
code=$?
[[ $code == 0 ]] || { echo "!! control reported a violation (exit $code)"; fail=1; }

banner "4. replaying the saved staged reproducer"
cat "$OUT/staged-payout-capped.json"; echo
"$BIN" replay fixtures/staged/campaign.toml "$OUT/staged-payout-capped.json" || fail=1

banner "5. raw interpreter: run and trace 2+3"
"$BIN" run 0x60026003015f5260205ff3 --trace 11 || fail=1

if [[ $fail == 0 ]]; then
  echo; echo "demo OK"
else
  echo; echo "demo FAILED"; exit 1
fi
