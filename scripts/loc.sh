#!/usr/bin/env bash
# Line counts used in the README: non-blank lines of library/CLI source
# excluding inline `#[cfg(test)]` modules, and integration-test lines.
set -euo pipefail
cd "$(dirname "$0")/.."
src=$(awk 'FNR==1{t=0} /^#\[cfg\(test\)\]/{t=1} !t' $(find src -name '*.rs' | sort) | grep -cv '^[[:space:]]*$')
unit=$(awk 'FNR==1{t=0} /^#\[cfg\(test\)\]/{t=1} t' $(find src -name '*.rs' | sort) | grep -cv '^[[:space:]]*$')
integ=$(cat tests/*.rs | grep -cv '^[[:space:]]*$')
sol=$(cat fixtures/*/*.sol | grep -cv '^[[:space:]]*$')
echo "source (non-blank, excl. unit tests): $src"
echo "unit tests (inline cfg(test)):        $unit"
echo "integration tests (tests/*.rs):       $integ"
echo "Solidity fixtures:                    $sol"
