set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

NEXTEST_PROFILE := env("NEXTEST_PROFILE", "default")
SDK_PACKAGES := "-p sapling-sdk -p ark-lib -p bark-server-rpc"
SDK_FEATURES := "sapling-sdk/onchain-bdk"

export TEST_DIRECTORY := env("TEST_DIRECTORY", justfile_directory() / "test")
export BITCOIND_SNAPSHOT_DIR := env("BITCOIND_SNAPSHOT_DIR", justfile_directory() / "test" / "_bitcoind_snapshot")
export CHAIN_SOURCE := env("CHAIN_SOURCE", "bitcoind")

# List the SDK development commands.
default:
	@just --list

prechecks:
	bash contrib/prechecks.sh rust_no_spaces_for_indent
	bash contrib/prechecks.sh rust_no_whitespace_on_empty_lines

# Type-check native SDK, protocol, and RPC targets without integration fixtures.
check:
	cargo check --locked {{SDK_PACKAGES}} --features {{SDK_FEATURES}} --all-targets

check-lib-arithmetic:
	cargo clippy --locked -p ark-lib --tests

# Rebuild sdk/protocol/rpc from vendor/bark-upstream + patches/.
bark-sync:
	bash contrib/bark/sync.sh

# Fail if the patched crates are out of sync with patches/.
bark-check:
	bash contrib/bark/sync.sh
	git diff --exit-code -- sdk protocol rpc

# Vendor a new upstream bark revision, then run bark-sync.
bark-update REV:
	bash contrib/bark/update.sh {{REV}}

checks: prechecks check-lib-arithmetic check

build:
	cargo build --locked {{SDK_PACKAGES}}

# Run unit/regression tests without enabling external integration dependencies.
unit TEST="":
	cargo nextest run --locked --no-fail-fast --profile {{NEXTEST_PROFILE}} {{SDK_PACKAGES}} --features {{SDK_FEATURES}} {{quote(TEST)}}

test-doc:
	cargo test --locked --doc {{SDK_PACKAGES}} --features {{SDK_FEATURES}}

rustdocs:
	cargo doc --locked {{SDK_PACKAGES}} --features {{SDK_FEATURES}} --no-deps

# External fixture binaries must match upstream 626c9b241dd25d73212915d8fca959ab5e3b8f1f.
# Supply absolute paths; this repository does not build server or wallet applications.
[private]
integration-fixtures:
	#!/usr/bin/env bash
	set -euo pipefail
	for name in CAPTAIND_EXEC WATCHMAND_EXEC BITCOIND_EXEC; do
		path="${!name:-}"
		if [[ "$path" != /* || ! -x "$path" ]]; then
			echo "Set $name to an absolute path to the external fixture executable." >&2
			exit 1
		fi
	done
	: "${POSTGRES_BINS:?Set POSTGRES_BINS to the external PostgreSQL bin directory}"
	for executable in initdb pg_ctl postgres psql; do
		test -x "$POSTGRES_BINS/$executable" || { echo "Missing $POSTGRES_BINS/$executable" >&2; exit 1; }
	done
	if [[ -n "${LIGHTNINGD_DOCKER_IMAGE:-}" ]]; then
		command -v docker >/dev/null
	else
		: "${LIGHTNINGD_EXEC:?Set LIGHTNINGD_EXEC to external lightningd, or supply LIGHTNINGD_DOCKER_IMAGE}"
		test -x "$LIGHTNINGD_EXEC"
	fi
	: "${LIGHTNINGD_PLUGIN_DIR:?Set LIGHTNINGD_PLUGIN_DIR to the cln-grpc and hold plugin directory (inside the container when using Docker)}"
	case "$CHAIN_SOURCE" in
		bitcoind) ;;
		esplora) test -x "${ESPLORA_ELECTRS_EXEC:?Set ESPLORA_ELECTRS_EXEC for the Esplora backend}" ;;
		mempool) test -x "${MEMPOOL_ELECTRS_EXEC:?Set MEMPOOL_ELECTRS_EXEC for the mempool backend}" ;;
		*) echo "Unknown CHAIN_SOURCE: $CHAIN_SOURCE" >&2; exit 1 ;;
	esac

# SDK integration tests using the external Bitcoin/Ark/PostgreSQL/CLN fixtures.
int TEST="": integration-fixtures
	cargo nextest run --locked --no-fail-fast --profile {{NEXTEST_PROFILE}} -p sapling-testing --features integration --test sapling-sdk {{quote(TEST)}}

int-esplora TEST="":
	CHAIN_SOURCE=esplora just int {{quote(TEST)}}

int-mempool TEST="":
	CHAIN_SOURCE=mempool just int {{quote(TEST)}}

# Exercise wallet action reentrancy without a CLI adapter.
int-reentrancy TEST="":
	SAPLING_DOUBLE_DRIVE_ACTIONS=1 just int {{quote(TEST)}}

# Real Sapio TEE tests: requires local-dev TEE and template-hash-v1 WASM.
# Ports 8000 and 8367 must be free; keep these fixed-port tests serial.
int-sapio TEST="sapio_": integration-fixtures
	#!/usr/bin/env bash
	set -euo pipefail
	: "${SAPIO_TEE_EXEC:?Set SAPIO_TEE_EXEC to the local-dev Sapio TEE executable}"
	: "${SAPIO_TEMPLATEHASH_WASM:?Set SAPIO_TEMPLATEHASH_WASM to the template-hash-v1 WASM artifact}"
	test -x "$SAPIO_TEE_EXEC"
	test -f "$SAPIO_TEMPLATEHASH_WASM"
	if [[ -z "${SAPIO_LIFECYCLE_WASM:-}" ]]; then
		mkdir -p "$TEST_DIRECTORY/_sapio"
		wat2wasm testing/fixtures/sapio/output_value_floor.wat -o "$TEST_DIRECTORY/_sapio/output_value_floor.wasm"
		export SAPIO_LIFECYCLE_WASM="$TEST_DIRECTORY/_sapio/output_value_floor.wasm"
	fi
	test -f "$SAPIO_LIFECYCLE_WASM"
	cargo nextest run --locked --no-fail-fast --profile {{NEXTEST_PROFILE}} -p sapling-testing --features sapio-integration --test sapling-sdk --test-threads 1 {{quote(TEST)}}
