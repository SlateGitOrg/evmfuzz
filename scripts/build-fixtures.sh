#!/usr/bin/env bash
# Compiles the fixture contracts with a pinned solc and writes the creation
# bytecode (*.bin) and ABI (*.abi.json) next to each source.
#
#   scripts/build-fixtures.sh          # (re)build all fixtures
#   scripts/build-fixtures.sh --check  # rebuild into a temp dir, diff against committed files
#
# The compiled artefacts are committed, so `make check` and `make demo` never
# need solc or the network. This script downloads solc 0.8.24 (macOS universal
# or Linux static build) into .tools/ and verifies its SHA-256 first.
set -euo pipefail

VERSION=0.8.24
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/.tools"
SOLC="$TOOLS/solc-$VERSION"

case "$(uname -s)" in
  Darwin) URL="https://binaries.soliditylang.org/macosx-amd64/solc-macosx-amd64-v0.8.24+commit.e11b9ed9"
          SHA=cc2d44c706905ccc382f484625dff61d741e0c24232d226f139a6835fc644f3f ;;
  Linux)  URL="https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.24+commit.e11b9ed9"
          SHA=fb03a29a517452b9f12bcf459ef37d0a543765bb3bbc911e70a87d6a37c30d5f ;;
  *) echo "unsupported OS" >&2; exit 1 ;;
esac

if [[ ! -x "$SOLC" ]]; then
  mkdir -p "$TOOLS"
  curl -sfL --retry 3 -o "$SOLC.part" "$URL"
  echo "$SHA  $SOLC.part" | shasum -a 256 -c --quiet
  mv "$SOLC.part" "$SOLC" && chmod +x "$SOLC"
fi

# fixture-dir:Source.sol:Contract
FIXTURES=(
  "token:Token.sol:Token"
  "token-fixed:Token.sol:Token"
  "vault:Vault.sol:Vault"
  "staged:Staged.sol:Staged"
  "registry:Registry.sol:Registry"
  "amm:Pool.sol:Pool"
)
FLAGS=(--evm-version shanghai --optimize --optimize-runs 200 --metadata-hash none)

OUT="$ROOT/fixtures"
CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
  OUT="$(mktemp -d)"
  trap 'rm -rf "$OUT"' EXIT
fi

for spec in "${FIXTURES[@]}"; do
  IFS=: read -r dir src contract <<<"$spec"
  tmp="$(mktemp -d)"
  "$SOLC" "${FLAGS[@]}" --bin --abi -o "$tmp" "$ROOT/fixtures/$dir/$src" >/dev/null
  mkdir -p "$OUT/$dir"
  tr -d '\n' < "$tmp/$contract.bin" > "$OUT/$dir/$contract.bin"
  python3 -m json.tool --indent 1 "$tmp/$contract.abi" > "$OUT/$dir/$contract.abi.json"
  rm -rf "$tmp"
  if [[ $CHECK == 1 ]]; then
    for f in "$contract.bin" "$contract.abi.json"; do
      cmp -s "$OUT/$dir/$f" "$ROOT/fixtures/$dir/$f" || { echo "MISMATCH fixtures/$dir/$f" >&2; exit 1; }
    done
  fi
  echo "fixtures/$dir/$contract.bin ($(( $(wc -c < "$OUT/$dir/$contract.bin") / 2 )) bytes)"
done
[[ $CHECK == 1 ]] && echo "all fixture artefacts match solc $VERSION output"
exit 0
