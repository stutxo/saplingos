# Sapling client SDK

The `sapling-sdk` Cargo package exposes the `sapling` Rust crate. It provides an
Ark wallet with native keys or Sapio-backed program keys, persistence, payment
operations, and resumable recovery. It does not run an Ark server or expose an
administrative REST API.

New to the design? Read [How Sapling contracts work](../docs/README.md) for the
escrow example, emergency exit guarantees, and backup requirements.

## Open a wallet

Applications supply configuration, secure seed storage, persistence, and an
on-chain wallet for boarding and fee payment. With the default native features
and `onchain-bdk`, the supplied SQLite and BDK implementations can be used:

```toml
[dependencies]
sapling-sdk = { path = "../Sapling/sdk", features = ["onchain-bdk"] }
anyhow = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync"] }
```

```rust,no_run
use std::path::PathBuf;
use std::sync::Arc;

use sapling::ark::bitcoin::Network;
use sapling::bip39::Mnemonic;
use sapling::onchain::OnchainWallet;
use sapling::persist::{WalletPersister, sqlite::SqliteClient};
use sapling::{Config, OpenWalletArgs, Wallet, WalletSeed};
use tokio::sync::RwLock;

pub async fn open_wallet(
	network: Network,
	datadir: PathBuf,
	mnemonic: &Mnemonic,
	config: Config,
) -> anyhow::Result<Wallet> {
	std::fs::create_dir_all(&datadir)?;
	let db: Arc<dyn WalletPersister> = Arc::new(
		SqliteClient::open(datadir.join("db.sqlite"))?,
	);
	let onchain = Arc::new(RwLock::new(OnchainWallet::load_or_create(
		network, mnemonic.to_seed(""), db.clone(),
	).await?));
	Wallet::open(
		network,
		WalletSeed::new_from_mnemonic(network, mnemonic),
		config,
		OpenWalletArgs {
			datadir: Some(datadir),
			persister: Some(db),
			onchain: Some(onchain),
			create_if_not_exists: true,
			..Default::default()
		},
	).await
}
```

Configure `server_address` and either an Esplora endpoint or bitcoin RPC backend
before opening. Bitcoin Core must run with `txindex=1`; the SDK checks the chain
network and index before use, including when the Ark server is unavailable.
`Config::load(network, path)` merges `SAPLING_` environment variables over the
file and network defaults. For example,
`SAPLING_ESPLORA_ADDRESS` overrides `esplora_address`. `BARK_` variables are not
read. A new wallet normally requires a successful server connection; explicit
`create_without_server` does not provide a verified server identity.

`Wallet::new_address`, `Wallet::balance`, and payment methods operate on the
opened wallet. The default `OpenWalletArgs` starts its background daemon.
Call `Wallet::stop_daemon_wait` before application shutdown. An application
supplying its own persistence must also choose a lock manager whose scope
matches its deployment; native persisted wallets use their data directory for
cross-process coordination.

Delegated rounds can return VTXOs in a different order from the output requests.
The SDK checks the exact amounts, policies, and number of each requested output.
Each output must have a distinct VTXO ID and pass the tree and expiry checks.
The saved participation order does not change.

An Esplora broadcast can fail after the transaction has already confirmed.
After a broadcast error, the SDK fetches the transaction by its computed ID.
It accepts the replay only if the returned transaction has that same ID.
If the lookup fails or returns no matching transaction, the original broadcast
error remains. This lets a saved offboard resume without a replacement payment
or a manual change to its input locks.

The `simple_setup` example opens an existing configured signet wallet using
`SAPLING_DATADIR` and `SAPLING_MNEMONIC`. It never prints the seed phrase.
Production applications should use their own protected seed storage rather
than treating environment variables as a secret store.

### Features

- Default: native RPC transport, SQLite, native TLS roots, randomness, bitcoin RPC.
- `onchain-bdk`: supplied BDK on-chain wallet; not required for custom implementations.
- `sqlite-bundled`: build SQLite from source rather than use the system library.
- `tls-webpki-roots`: alternative TLS roots; disable defaults when selecting it alone.
- `socks5-proxy`: proxy support.
- `wasm-web` and `indexed-db`: browser transport and persistence, selected without
  native defaults. Applications still own their browser runtime and locking scope.

## Sapio-backed VTXOs

Sapio defines the spend rules. The TEE checks those rules and co-signs with
the wallet. Saved recovery transactions support an on-chain exit.

A configured wallet uses a joint user and program key:

```text
S = program-instance key derived from the attested Sapio root
C = sorted KeyAgg(U, S)
cooperative key = native sorted KeyAgg(C, A)
delayed claim = CSV + C
```

`U` belongs to the wallet. `A` belongs to the Ark server. The enclave evaluates
the exact program and holds `S`. The Ark server sees an ordinary public key
`C`; native VTXO policies and the server wire protocol do not change. Neither
`U` nor `S` alone can sign as `C`. An unavailable or rejecting program service
never causes a native-key fallback.

### Configure the program

Set `Config::sapio` to a `sapling::sapio::SapioConfig` before issuing program
keys. Its fields are:

- `endpoint`: the program signing service URL.
- `root`: an xpub pinned from independently verified enclave attestation.
- `program`: the evaluator SHA256 identity and exact `program` and `parameters`
  byte arrays. The instance key commits to all three.
- `recovery`: explicit beneficiary outputs, an optional `remainder_output`
  index, a consensus `lock_time`, and the program's recovery `witness` bytes.
  Serialized outputs use consensus `TxOut` hex. A zero-value output can receive
  the remainder; no beneficiary is chosen implicitly.
- Optional `coordinator_url` and `receive_bind` for coordinated receiving.
  The listener exposes only receive preparation and commit, not wallet administration.

Use HTTPS for remote services. Plain HTTP is limited to literal loopback
addresses. Do not obtain the trusted root from an unauthenticated response
from the service you intend to trust. The SDK does not verify enclave
attestation for you. A `local-dev` service has no enclave protection or
hardware attestation.

Supply ordinary spend evidence with `Config::sapio_witnesses`, a map from `C`
public keys to evidence byte arrays. An absent entry supplies an empty witness,
which the program must still accept. Recovery evidence is separate. Keep both
evidence sets and stored wallet configuration private. `Config::redacted`
consumes a configuration and returns it without bitcoin RPC passwords or either
witness set. It does not change the stored file and is not a general-purpose
sanitizer for every configuration field.

Programs must accept each actual transaction used by the operation, including
checkpoint, change, refresh, offboard-forfeit, HTLC, and recovery transactions.
A recovery construction template is not an authorization exception. An exact
BIP-446 template can authorize a received position's saved payout yet reject
an outgoing Ark transaction with different outputs. The wallet rejects that
operation rather than widening the program.

### Prepare before commitment

The wallet saves and verifies an authorized recovery before releasing funding,
cooperative signatures, or a Lightning receive preimage. If preparation fails,
the operation does not cross that commitment point. Its old safe position
remains available. HTLC admission also checks whether the fixed recovery can
complete before the relevant expiry.

The sender retains its durable checkpoint when program-service or coordinator
failures interrupt coordinated delivery. A later wallet sync resumes the saved
stage rather than replacing signed outputs. Board funding remains serialized
with ordinary on-chain spends through its initial broadcast; unpublished board
change is not available for coin selection.

Program-backed addresses require coordinated delivery. The recipient saves
recovery for the exact proposed outputs before acknowledging preparation.
The sender verifies that acknowledgement before signing. Commit acknowledges
the complete signed VTXOs. A lost acknowledgement can be retried without
replacing the saved claim.

These addresses have no mailbox fallback. Legacy clients and unsolicited raw
deposits cannot provide this preparation guarantee. The wallet quarantines
rejected wire bytes as diagnostic metadata, not as spendable or canonical VTXOs.
See the repository's `docs/addresses.md` for the delivery format.

### Recover without either co-signer

Keep a private recovery export as well as the wallet database and seed phrase:

- `Wallet::program_recovery_bundle(&outpoints)` exports the selected positions;
  an empty selection exports live or already-selected recovery positions,
  including durable crash-gap outputs, but not superseded claims.
  Serialize the returned `ProgramRecoveryBundle` to private durable storage.
- `Wallet::recover_program_vtxos(&outpoints, fee_rate)` selects local recovery
  positions and advances their on-chain recovery.
- `sapling::sapio::recovery::recover_program_bundle(&bundle, &chain,
  &mut fee_wallet, fee_rate)` recovers an exported bundle using a chain backend
  and an ordinary on-chain fee wallet, without an Ark or program-service connection.

Export does not reserve positions. Local recovery reserves selected positions
and prevents their cooperative actions from continuing. Reopening the wallet
with its background daemon continues durable recovery selections after a
restart; it does not automatically recover unrelated spendable change or
sibling positions. For an imported bundle, stop concurrent spending from the
source wallet first. The importing wallet cannot lock another wallet's state.

Keep confirmed funds in the fee wallet. Fees use CPFP through the saved P2A
anchor; they do not alter signed beneficiary outputs. `AwaitingFees` reports
available and required fee-wallet amounts without discarding progress. Confirm
fee-wallet change or add confirmed funds, then resume recovery. Beneficiary
scripts are explicit destinations, not proof that this wallet owns them.

Cryptographic readiness and chain progress differ. A complete saved claim can
still await ancestor confirmation, CSV maturity, or its fixed locktime. A
conditional hArk branch can await publication of the server's forfeit. The
export retains the existing leaf signature and authenticated disclosure path,
so a preimage revealed by an on-chain server claim can unlock that exact leaf
without a new co-signature.

`Balance::pending_program_recovery` reports selected recovery value until
payout confirmation. Old, forfeit, and replacement alternatives count once,
not as independent balances. Confirmed payouts leave this category even when
their beneficiary is external to the wallet.

### Compiler reference

The design takes artifact discipline from the
[Arkade compiler](https://github.com/arkade-os/compiler/blob/f4e2d3db18f52873f4bf6ae998c7d8bf41dab41b/src/models/mod.rs#L175-L277)
and its [program API](https://github.com/arkade-os/ts-sdk/blob/cfc332b9b1a58d393ebd28fde409e162a2179d8f/packages/sdk/src/arkade/program.ts#L664-L759):
bind exact program and constructor bytes, keep witness roles explicit, and
retain the data needed to spend. It does not reuse Arkade's VM or infer that a
compiler's emergency-exit branch preserves every cooperative payout constraint.
