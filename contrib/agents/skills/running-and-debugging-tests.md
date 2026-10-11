# Running and debugging SDK tests

## Development environment

Use `nix develop` or run commands through `nix develop .#build --command`.
The SDK shell contains compilation, SQLite, and unit-test tooling. Server,
PostgreSQL, CLN, and Sapio service fixtures are external and opt-in; consult
`BUILDING.md` for their exact environment variables and pinned upstream source.

## Checks and unit tests

```sh
just checks
just unit
just unit test_name
just test-doc
just rustdocs
```

`just checks` runs whitespace checks, the protocol arithmetic clippy check,
and native SDK/protocol/RPC target checks. `just unit` runs those packages with
nextest and the supplied BDK on-chain backend enabled, not the optional service
harness. Test-name arguments are substring filters.

## Integration tests require just

Never run service integration tests directly with `cargo test`.
`just` supplies `TEST_DIRECTORY`, `BITCOIND_SNAPSHOT_DIR`, and `CHAIN_SOURCE`,
and checks the externally supplied fixture paths. It does not build server or
wallet executables. No `BARK_EXEC` is needed.

```sh
just int
just int test_name
just int-reentrancy test_name
just int-esplora test_name
just int-mempool test_name
just int-sapio test_name
```

The recipes use `--no-fail-fast`. The Sapio recipe enables the real TEE and WASM
scenarios and runs them serially. Missing real fixtures are an error, not a
reason to substitute an approval mock. The internal ignored `sdk_process`
test is only a subprocess entry point: parent scenarios reinvoke it to reopen
wallets, drive the daemon, or recover without a CLI.

To type-check the full harness without starting services:

```sh
cargo check --locked -p sapling-testing --features sapio-integration --test sapling-sdk
```

## Failure evidence

Use the failing scenario's logs and database state before changing code.
Artifacts live below `test/` or the supplied `TEST_DIRECTORY`; SDK wallets
store `db.sqlite`, `config.toml`, and `mnemonic` in their named directory.
Do not disclose seeds, witness material, or recovery exports from these files.

The upstream fixtures retain their own service log and PostgreSQL directory
layout. `KEEP_ALL_TEST_DATA=1` retains successful integration artifacts too.
The SDK shell provides `sqlite3`; use the externally supplied PostgreSQL
binaries to inspect a service database. Do not restart a shared or production
service while debugging a test.
