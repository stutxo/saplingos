#!/usr/bin/env bash
# Replace vendor/bark-upstream with crates from another bark revision.
#
# Usage: contrib/bark/update.sh <git-rev>
#
# Fetches `upstream` first, snapshots the bark/lib/server-rpc crates at the
# revision, then asks you to run `just bark-sync`. Patch conflicts show up as
# ordinary `git apply` failures, so the local delta stays reviewable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REV="${1:?usage: contrib/bark/update.sh <git-rev>}"
VENDOR="$ROOT/vendor/bark-upstream"

git -C "$ROOT" fetch --quiet upstream
git -C "$ROOT" rev-parse --verify "$REV^{commit}" >/dev/null

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

for pair in "bark:bark" "lib:lib" "server-rpc:server-rpc"; do
	revdir="${pair%%:*}"
	out="${pair##*:}"
	mkdir -p "$tmp/$out"
	git -C "$ROOT" archive "$REV:$revdir" | tar -x -C "$tmp/$out"
	rm -rf "$VENDOR/$out"
	mv "$tmp/$out" "$VENDOR/$out"
done

{
	echo "https://gitlab.com/ark-bitcoin/bark.git"
	git -C "$ROOT" rev-parse "$REV^{commit}"
} > "$ROOT/BARK_UPSTREAM_REV"

echo "vendored bark $REV"
echo "run 'just bark-sync' to reapply patches/"
