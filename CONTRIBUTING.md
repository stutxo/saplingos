# Contributing to Sapling

Use the SDK development environment and commands in [BUILDING.md](BUILDING.md).
The repository contains client code and its protocol/RPC support, not upstream
server applications. Changes to unchanged upstream helpers belong upstream;
update their pinned dependency revision here when adopting a fix.

## Verification

```sh
nix develop
just checks
just unit
just test-doc
just rustdocs
```

Exercise changed wallet behavior through the public SDK as well as relevant
regression tests. Service scenarios live in `testing/tests/sdk/` and are
explicitly enabled through `just int` or `just int-sapio`; their external
fixture requirements are documented in the build guide. Never replace a real
program-service authorization with a test approval stub.

Persistence changes must preserve crash/restart safety and existing wallet
state. The full SQLite DDL is in `sdk/schema.sql`; when migrations change it,
regenerate it with:

```sh
cargo run --locked -p sapling-sdk --example dump-sqlite-schema
```

The command prints the schema to stdout. Review the generated schema before
updating the tracked file.

## Style and commits

- Use tabs and surrounding Rust conventions; do not mass-format unrelated code.
- Follow [code style](CONTRIBUTING/STYLE.md) and
  [writing vocabulary](CONTRIBUTING/style_guide.md).
- Keep public API documentation and SDK examples current.
- Use descriptive commit prefixes such as `sdk:`, `protocol:`, `rpc:`,
  `testing:`, or `ci:`. Explain why the change is needed.
- Keep commits independently buildable. Do not reintroduce application
  binaries or a vendored copy of an unchanged upstream crate for convenience.

The old monorepo release fragments and server-release automation have been
removed. Upstream release history remains available in Git history and
[upstream Bark](https://gitlab.com/ark-bitcoin/bark).
