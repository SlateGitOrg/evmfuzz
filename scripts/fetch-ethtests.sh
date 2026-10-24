#!/usr/bin/env bash
# Re-fetches (or verifies) the pinned ethereum/tests subset used by the
# conformance suite. The files are committed, so this is only needed to
# audit provenance or restore a damaged checkout.
#
#   scripts/fetch-ethtests.sh           # download missing files, verify all
#   scripts/fetch-ethtests.sh --verify  # offline checksum verification only
set -euo pipefail

COMMIT=faf33b471465d3c6cdc3d04fbd690895f78d33f2   # ethereum/tests tag v13.3
BASE="https://raw.githubusercontent.com/ethereum/tests/${COMMIT}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/tests/ethtests"
MANIFEST="${DIR}/MANIFEST.sha256"

cd "$DIR"
if [[ "${1:-}" != "--verify" ]]; then
  while read -r _sum path; do
    if [[ ! -f "$path" ]]; then
      mkdir -p "$(dirname "$path")"
      curl -sfL --retry 3 -o "$path" "${BASE}/${path}"
      echo "fetched $path"
    fi
  done < "$MANIFEST"
fi
shasum -a 256 --quiet -c "$MANIFEST"
echo "verified $(wc -l < "$MANIFEST" | tr -d ' ') files against ${MANIFEST##*/} (ethereum/tests@${COMMIT:0:10})"
