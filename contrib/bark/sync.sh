#!/usr/bin/env bash
# Rebuild the patched bark crates from the vendored upstream snapshot.
#
# Layout:
#   vendor/bark-upstream/{bark,lib,server-rpc}  clean upstream sources
#   patches/0001-sapling-base.patch             Sapio + standalone extraction
#   patches/0002-local-fixes.patch              local hardening on top
#
# Updating bark: replace vendor/bark-upstream with the new upstream crates
# (and bump BARK_UPSTREAM_REV), then run `just bark-sync`. Conflicts are in
# the patch files, not in a hand-maintained wallet copy.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VENDOR="${1:-$ROOT/vendor/bark-upstream}"

for pair in "bark:sdk" "lib:protocol" "server-rpc:rpc"; do
	src="$VENDOR/${pair%%:*}"
	dst="$ROOT/${pair##*:}"
	if [[ ! -d "$src" ]]; then
		echo "missing upstream source: $src" >&2
		exit 1
	fi
	rm -rf "$dst"
	cp -a "$src" "$dst"
done

for patch in "$ROOT"/patches/*.patch; do
	echo "applying $(basename "$patch")"
	git -C "$ROOT" apply --whitespace=nowarn "$patch"
done

echo "bark patch series applied to sdk/, protocol/, and rpc/"
