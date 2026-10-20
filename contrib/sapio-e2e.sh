#!/usr/bin/env bash
# Run the real Sapio/TEE integration suite against local service fixtures.
#
# The TEE owns loopback ports 8000 and 8367. If another service already owns
# them on the host, this script runs the suite in an isolated network namespace
# with bubblewrap. Both fixture processes and `nix develop` remain reachable
# through the bind-mounted root.
#
# Required environment:
#   CAPTAIND_EXEC, WATCHMAND_EXEC, BITCOIND_EXEC, POSTGRES_BINS
#   LIGHTNINGD_EXEC, LIGHTNINGD_PLUGIN_DIR
#   SAPIO_TEE_EXEC, SAPIO_TEMPLATEHASH_WASM
#
# Optional: SAPIO_LIFECYCLE_WASM is built from the checked-in WAT fixture by
# `just int-sapio` when unset. Pass a nextest test filter as the first argument;
# the default runs every `sapio_` test.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST="${1:-sapio_}"

for variable in \
	CAPTAIND_EXEC WATCHMAND_EXEC BITCOIND_EXEC POSTGRES_BINS \
	LIGHTNINGD_EXEC LIGHTNINGD_PLUGIN_DIR \
	SAPIO_TEE_EXEC SAPIO_TEMPLATEHASH_WASM
do
	: "${!variable:?Set $variable before running the Sapio integration suite}"
done

if command -v bwrap >/dev/null 2>&1 \
	&& bwrap --dev-bind / / --unshare-net --proc /proc --dev /dev true 2>/dev/null
then
	exec bwrap --dev-bind / / --unshare-net --proc /proc --dev /dev \
		--chdir "$ROOT" nix develop --command just int-sapio "$TEST"
fi

echo "note: bubblewrap network isolation unavailable; using the host network" >&2
echo "note: ports 8000 and 8367 must be free" >&2
exec nix develop --command just int-sapio "$TEST"
