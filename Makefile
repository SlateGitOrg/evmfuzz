# evmfuzz — one entry point for every gate.
#
#   make check   format check + clippy (zero warnings) + type-check + tests under
#                coverage with an 80% line threshold + fixture-data checksums
#   make demo    offline end-to-end demo against the bundled fixtures
#   make bench   interpreter + fuzzing throughput (release build)
#   make eval    held-out ablation study (seeds 1001..1030, 100k tx budget)

CARGO       ?= cargo
COV_MIN     ?= 80
EVAL_SEEDS  ?= 1001..=1030
EVAL_BUDGET ?= 100000
JOBS        ?= 3
FIXTURES    := token token-fixed vault staged registry amm
CAMPAIGNS   := $(foreach f,$(FIXTURES),fixtures/$(f)/campaign.toml)
BIN          = $${CARGO_TARGET_DIR:-target}/release/evmfuzz

.PHONY: check fmt-check lint typecheck test cov data-verify build demo bench eval fixtures-check clean

check: fmt-check lint typecheck data-verify test cov

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --all-targets --locked -- -D warnings

typecheck:
	$(CARGO) check --all-targets --locked

test:
	$(CARGO) test --locked

# Runs the test suite instrumented (minus the loop-heavy `slow_` conformance
# test, which `make test` already ran) and fails below COV_MIN% line coverage.
cov:
	$(CARGO) llvm-cov --locked --summary-only --fail-under-lines $(COV_MIN) -- --skip slow_

data-verify:
	scripts/fetch-ethtests.sh --verify

build:
	$(CARGO) build --release --locked

demo: build
	scripts/demo.sh "$(BIN)"

bench: build
	$(BIN) bench $(filter-out fixtures/token/campaign.toml,$(CAMPAIGNS))

eval: build
	$(BIN) eval $(filter-out fixtures/token-fixed/campaign.toml,$(CAMPAIGNS)) \
		--seeds $(EVAL_SEEDS) --max-tx $(EVAL_BUDGET) --jobs $(JOBS)

# Recompiles the Solidity fixtures with the pinned solc (downloads it) and
# diffs against the committed bytecode. Needs network on first use.
fixtures-check:
	scripts/build-fixtures.sh --check

clean:
	$(CARGO) clean
