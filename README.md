# Sapling SDK

Sapling is a Rust client SDK for program-controlled Ark wallets, derived from
[Second's Bark wallet](https://gitlab.com/ark-bitcoin/bark). Applications use
`sapling::Wallet`; this repository no longer ships an Ark server, a wallet CLI,
or a REST application.

Sapio evaluates the exact configured program and co-signs with the wallet.
Before committing funds, the wallet saves and verifies the program-authorized
recovery transactions. A separate on-chain wallet pays recovery mining fees;
saved beneficiary outputs cannot be redirected later.

This integration is experimental. Local verification does not establish
production Nitro attestation or replace an independent cryptographic review.
See [the SDK guide](sdk/README.md) for configuration, coordinated receiving,
and recovery APIs.

## Use the SDK

For a checkout next to your application:

```toml
[dependencies]
sapling-sdk = { path = "../Sapling/sdk" }
```

The Cargo package is `sapling-sdk`; its Rust crate is `sapling`. The package is
source-only, not published on crates.io. A Git dependency must select a commit
containing this SDK extraction. Consumers do not need workspace patches.
Enable `onchain-bdk` to use the supplied on-chain wallet implementation, or
implement `sapling::onchain::OnchainWalletTrait` in the application.

The application owns seed storage, configuration, database location, and wallet
lifecycle. `Config::load` reads `SAPLING_` environment variables, then a config
file, then network defaults. There is no `BARK_` environment compatibility alias.

## Repository boundary

| Directory | Package | Responsibility |
|---|---|---|
| `sdk/` | `sapling-sdk` | Wallet API, persistence, external signing, coordinated receive, and recovery |
| `protocol/` | `ark-lib` | Client protocol primitives, including Sapling's program keys and nested signing |
| `rpc/` | `bark-server-rpc` | Wire schemas and RPC bindings using those protocol types; not a server application |
| `testing/` | `sapling-testing` | Opt-in SDK regressions using external upstream service fixtures |

This is an extraction of the modified client, not a thin wrapper around an
unmodified Bark release. The wallet and protocol changes are needed to preserve
program ownership and recovery across every commitment point. The support
packages retain their upstream Cargo names so the integration fixtures share
the same protocol types.

Unchanged `bark-common`, `bark-runtime`, `bark-bitcoin-ext`, and `bip321` come from
GitLab, pinned to upstream commit
[`626c9b241dd25d73212915d8fca959ab5e3b8f1f`](https://gitlab.com/ark-bitcoin/bark/-/tree/626c9b241dd25d73212915d8fca959ab5e3b8f1f).
There is no floating upstream branch. The optional integration harness also
fetches upstream server/test helpers at that revision. Its dependencies are
absent from the default build and from SDK consumers, though Cargo records
optional dependencies in the workspace lockfile.

The root Cargo patches apply only when building the optional upstream fixtures
inside this workspace. The SDK declares its local support dependencies directly.

## Develop

```sh
nix develop
just checks
just unit
just test-doc
just rustdocs
```

The default workspace contains only the SDK, protocol, and RPC libraries.
The Nix shell does not build or install server applications. See
[BUILDING.md](BUILDING.md) for prerequisites and opt-in integration tests, and
[CONTRIBUTING.md](CONTRIBUTING.md) for contribution conventions.

## Migration from the monorepo

- Depend on `sapling-sdk` and import `sapling`, not `bark-wallet` / `bark`.
- Use `WalletPersister`, `WalletNetwork`, `WalletBip321Uri`,
  `WalletBip321UriBuilder`, and `WalletExtension` in place of their `Bark*` names.
- Use the wallet and recovery APIs instead of invoking a bundled CLI or REST API.
- Supply server binaries externally for integration tests; no `BARK_EXEC` is needed.
- Wallet derivation paths, persisted state, protocol encodings, and authenticated
  domain separators have not been renamed. Existing `bark.*` movement subsystem
  identifiers remain stable data, not new application branding.

## Related projects

- [sapio_tee](https://github.com/stutxo/sapio_tee): program evaluation and the
  enclave's share of the nested MuSig signature.
- [Sapio](https://github.com/sapio-lang/sapio): program identities and bounded WASM runtime.
- [Upstream Bark](https://gitlab.com/ark-bitcoin/bark): server applications,
  unchanged support crates, and upstream release history.
- [Sapling issues](https://github.com/stutxo/saplingos/issues): non-sensitive
  fork-specific issues. See [SECURITY.md](SECURITY.md) for security reporting.

Released under the [MIT license](LICENSE). Original upstream attribution and
Git history are retained.
