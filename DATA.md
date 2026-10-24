# Data

All data is committed (about 14 MB) and verified by checksum; nothing is
downloaded during `make check` or `make demo`.

## ethereum/tests subset — `tests/ethtests/`

| | |
|---|---|
| Source | <https://github.com/ethereum/tests>, tag **v13.3**, commit `faf33b471465d3c6cdc3d04fbd690895f78d33f2` |
| License | MIT (copy in `tests/ethtests/LICENSE.ethereum-tests`) |
| Format | filled GeneralStateTests JSON (`pre`, `transaction`, `post.<fork>` with state root + logs hash) |
| Files | 562 JSON files, listed with SHA-256 in `tests/ethtests/MANIFEST.sha256` |
| Verify | `scripts/fetch-ethtests.sh --verify` (offline; part of `make check`) |
| Refetch | `scripts/fetch-ethtests.sh` (downloads any missing file from the pinned commit, then verifies) |

Selection: 26 suites chosen for the opcodes and behaviours the interpreter
implements. Every suite is included in full; the file counts were checked against
the upstream git tree at the pinned commit:

* `GeneralStateTests/VMTests/*` (all 6 suites: arithmetic, bitwise, IO and flow,
  logs, performance, misc). ethereum/tests v13 ships the old VMTests only in this
  state-test form.
* `GeneralStateTests/Shanghai/*` (EIP-3651 warm coinbase, EIP-3855 PUSH0,
  EIP-3860 initcode metering).
* `stCallCodes`, `stChainId`, `stCodeCopyTest`, `stCreate2`, `stEIP2930`,
  `stEIP3607`, `stExtCodeHash`, `stInitCodeTest`, `stLogTests`, `stRefundTest`,
  `stReturnDataTest`, `stRevertTest`, `stSLoadTest`, `stSStoreTest`,
  `stSelfBalance`, `stShift`, `stZeroCallsTest`.

Upstream has 67 GeneralStateTests suites (2,807 files) at that commit; the other
41 suites (precompile-heavy ones such as `stPreCompiledContracts`, `stZeroKnowledge`,
`stQuadraticComplexityTest`, plus large stress suites) were not pinned. See the
README's Limitations section.

## Fixture contracts — `fixtures/`

Written for this project (MIT, same license as the repository). Each directory
holds the Solidity source, the creation bytecode (`*.bin`, hex) and ABI
(`*.abi.json`) compiled by solc **0.8.24** (`--evm-version shanghai --optimize
--optimize-runs 200 --metadata-hash none`), and a `campaign.toml`.
`scripts/build-fixtures.sh --check` downloads the pinned solc (SHA-256 checked)
and confirms the committed artefacts are byte-identical to its output. The bugs
are planted on purpose and documented in each source file's header comment.
