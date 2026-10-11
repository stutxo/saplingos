# Building Sapling

## SDK development environment

```sh
nix develop
just checks
just unit
just test-doc
just rustdocs
```

`nix develop` and `nix develop .#build` select the same SDK shell, with Rust
1.90.0, C/C++ and Clang tooling, protobuf, SQLite, OpenSSL, CMake, Boost, `just`,
`cargo-nextest`, and `wat2wasm`. CMake and Boost support the protocol tests'
bitcoin consensus kernel. Without Nix, supply equivalent native dependencies;
`sqlite-bundled` can replace the system SQLite dependency.

`just checks`, `just unit`, and the documentation recipes include the optional
BDK on-chain implementation. The default `cargo build --locked` builds only
`sapling-sdk`, `ark-lib`, and `bark-server-rpc`, without server applications or
integration fixtures. `just build` builds the same default SDK packages.
There are no Nix application-release targets in this repository.

Documentation is generated under `target/doc/sapling/`. The source-only package
can be consumed from a separate application's Cargo manifest without copying
this workspace's patches. See [the SDK guide](sdk/README.md).

## Optional service integration tests

The `sapling-testing` package has no default features. Enabling `integration`
fetches the upstream service fixtures at commit
`626c9b241dd25d73212915d8fca959ab5e3b8f1f`. It deliberately does not vendor or
build replacement server executables. Full test-only dependencies, including
upstream wallet/REST helper libraries used by those fixtures, are isolated from
SDK consumers.

Provide external fixtures compatible with that revision:

| Variable | Required external fixture |
|---|---|
| `CAPTAIND_EXEC` | Absolute executable path to upstream `captaind` |
| `WATCHMAND_EXEC` | Absolute executable path to upstream `watchmand` |
| `BITCOIND_EXEC` | Absolute executable path to Bitcoin Core |
| `POSTGRES_BINS` | Directory containing `initdb`, `pg_ctl`, `postgres`, and `psql` |
| `LIGHTNINGD_EXEC` | Core Lightning executable, or use `LIGHTNINGD_DOCKER_IMAGE` |
| `LIGHTNINGD_PLUGIN_DIR` | Directory containing `cln-grpc` and the hold plugin; container path when using Docker |

Build the server binaries from the
[pinned upstream source](https://gitlab.com/ark-bitcoin/bark/-/tree/626c9b241dd25d73212915d8fca959ab5e3b8f1f)
in a separate checkout. Its development tooling documents its Bitcoin, CLN,
plugin, and PostgreSQL requirements. No Bark wallet executable is required:
these tests construct Sapling wallets directly. Tests needing a fresh process
reinvoke an internal test fixture that opens the same SDK database and seed.

Run through `just`, which supplies the test directory and chain-backend
configuration:

```sh
just int
just int recovery_finds_vtxos_separated_by_the_gap_limit
just int-reentrancy
```

Do not run service integration tests with `cargo test` directly.
`just int-esplora` and `just int-mempool` additionally require
`ESPLORA_ELECTRS_EXEC` or `MEMPOOL_ELECTRS_EXEC`, respectively. Data and logs
are written below `test/` unless `TEST_DIRECTORY` is set. Compile the complete
harness without starting services using:

```sh
cargo check --locked -p sapling-testing --features sapio-integration --test sapling-sdk
```

## Real Sapio service scenarios

`just int-sapio` additionally requires:

- `SAPIO_TEE_EXEC`: the real `sapio-tee` binary built with `local-dev` support.
- `SAPIO_TEMPLATEHASH_WASM`: the reviewed BIP-446 template-hash-v1 artifact,
  SHA256 `0fbc4e2cc68722474e3a708ffb934c0784990806ea1fb4a3dda64805fdd340a1`.
- A private network namespace with exclusive loopback ports 8000 and 8367.
  The helper also uses a cross-process lock to serialize the fixed-port service.

The recipe compiles `testing/fixtures/sapio/output_value_floor.wat` using
`wat2wasm`, unless `SAPIO_LIFECYCLE_WASM` names a precompiled artifact. This
fixture exercises the real evaluator; it is not a signature or approval mock.
Missing service binaries or artifacts fail explicitly.

```sh
just int-sapio
just int-sapio sapio_bip446_receive_exact_payout_and_offline_sdk_recovery
```

These scenarios cover commitment ordering, coordinated receiving, restart
recovery, hArk disclosure branches, and Lightning transitions. They are opt-in
and are not part of default CI. Local-dev execution provides no hardware
attestation evidence.

## Dependency updates

Upstream sources are pinned in the root and integration manifests. Update
those revisions deliberately, along with `Cargo.lock`, and review the retained
protocol/RPC changes against the new base. Do not replace the local modified
protocol library with an unmodified upstream crate: that would discard
Sapling's nested-signing and recovery behavior.
