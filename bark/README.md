![bark: Ark on bitcoin](https://gitlab.com/ark-bitcoin/bark/-/raw/master/assets/bark-header-white.jpg)

<div align="center">
<h1>Bark: Ark on bitcoin</h1>
<p>Fast, low-cost, self-custodial payments on bitcoin.</p>
</div>

<p align="center">
  <br />
  <a href="https://docs.second.tech">Docs</a> ·
  <a href="https://gitlab.com/ark-bitcoin/bark/issues">Issues</a> ·
  <a href="https://second.tech">Website</a> ·
  <a href="https://blog.second.tech">Blog</a> ·
  <a href="https://www.youtube.com/@2ndbtc">YouTube</a>
</p>

<div align="center">

[![Release](https://img.shields.io/gitea/v/release/ark-bitcoin/bark?label=release&gitea_url=https://gitlab.com)](https://gitlab.com/ark-bitcoin/bark/tags)
[![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg)](https://gitlab.com/ark-bitcoin/bark)
[![License](https://img.shields.io/badge/license-CC0--1.0-blue.svg)](https://gitlab.com/ark-bitcoin/bark/LICENSE)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=git)](https://gitlab.com/ark-bitcoin/bark/CONTRIBUTING.md)
[![Community](https://img.shields.io/badge/community-forum-blue?logo=discourse)](https://community.second.tech)

</div>
<br />

Bark is an implementation of the Ark protocol on bitcoin, led by [Second](https://second.tech).

# A tour of Bark

Integrating the Ark-protocol offers

- 🏃‍♂️ **Smooth boarding**: No channels to open, no on-chain setup required-create a wallet and start transacting
- 🤌 **Simplified UX**: Send and receive without managing channels, liquidity, or routing
- 🌐 **Universal payments**: Send Ark, Lightning, and on-chain payments from a single off-chain balance
- 🔌 **Easier integration**: Client-server architecture reduces complexity compared to P2P protocols
- 💸 **Lower costs**: Instant payments at a fraction of on-chain fees
- 🔒 **Self-custodial**: Users maintain full control of their funds at all times

This guide puts focus on how to use the Rust-API and assumes
some basic familiarity with the Ark protocol. We refer to the
[protocol docs](http://docs.second.tech/ark-protocol) for an introduction.

For setup and usage instructions, see the [Getting Started guide](https://docs.second.tech/getting-started/) or look at our [Rust API docs](https://docs.rs/bark-wallet)? 

## Sapio-backed VTXOs

A configured wallet uses a joint user and program key:

```text
S = program-instance key derived from the attested Sapio root
C = sorted KeyAgg(U, S)
cooperative key = native sorted KeyAgg(C, A)
delayed claim = CSV + C
```

`U` belongs to the wallet. `A` belongs to the Ark server. The same enclave
evaluates the exact program and holds `S`. The Ark server sees an ordinary
public key `C`; its policies and RPC protocol do not change. Neither `U` nor
`S` alone can sign as `C`. An unavailable or rejecting program service never
causes a native-key fallback.

### Configure the program

Set `Config::sapio` in the SDK, or supply `bark create --sapio-config FILE`
with the normal network, chain source, and Ark server arguments. `FILE` is
JSON for `bark::sapio::SapioConfig`. It contains:

- `endpoint`: the program signing service URL.
- `root`: an xpub pinned from independently verified enclave attestation.
- `program`: the evaluator SHA256 identity and exact `program` and `parameters`
  byte arrays. The instance key commits to all three.
- `recovery`: explicit beneficiary outputs, an optional `remainder_output`
  index, a consensus `lock_time`, and the program's recovery `witness` bytes.
  Encode each output as consensus `TxOut` hex. A zero-value output can receive
  the remainder; no beneficiary is chosen implicitly.
- Optional `coordinator_url` and `receive_bind` for coordinated receiving.
  The listener exposes only receive preparation and commit, not wallet
  administration.

Use HTTPS for remote services. Plain HTTP is limited to literal loopback
addresses. Do not obtain the trusted root from an unauthenticated response
from the service you intend to trust. This configuration command does not
verify attestation for you. A `local-dev` service has no enclave protection
or hardware attestation.

Supply ordinary spend evidence with `Config::sapio_witnesses` or
`--sapio-witnesses FILE`. This file is a JSON map from `C` public keys to
evidence byte arrays. An absent entry supplies an empty witness, which the
program must still accept. Recovery evidence is separate. Keep both files
and the stored wallet configuration private.

Programs must accept each actual transaction used by the operation, including
checkpoint, change, refresh, offboard-forfeit, HTLC, and recovery transactions.
A recovery construction template is not an authorization exception. For example, an exact
BIP-446 template can authorize a received position's saved payout yet reject
an outgoing Ark transaction with different outputs. Bark rejects that
operation; it does not silently widen the program.

### Prepare before commitment

Bark saves and verifies an authorized recovery before it releases funding,
cooperative signatures, or a Lightning receive preimage. If preparation fails,
the operation does not cross that commitment point. Its old safe position
remains available. HTLC admission also checks whether the fixed recovery can
complete before the relevant expiry.

The sender retains its durable checkpoint when program-service or coordinator
failures interrupt coordinated delivery.
A later wallet sync resumes the saved stage rather than replacing signed outputs.
Board funding remains serialized with ordinary on-chain spends through its
initial broadcast; unpublished board change is not available for coin selection.

Program-backed addresses require coordinated delivery. The recipient saves
recovery for the exact proposed outputs before acknowledging preparation.
The sender verifies that acknowledgement before it signs. Commit acknowledges
the complete signed VTXOs. A lost acknowledgement can be retried without
replacing the saved claim.

These addresses have no mailbox fallback. Legacy clients and unsolicited raw
deposits cannot provide this preparation guarantee. Bark quarantines rejected
wire bytes as diagnostic metadata, not as spendable or canonical VTXOs.
See [coordinated delivery](../docs/addresses.md#coordinated-program-delivery).

### Recover without either co-signer

Keep a private recovery export as well as the wallet database and seed phrase:

```sh
bark sapio recovery-export --all --output recovery.json
bark sapio recover --outpoint TXID:VOUT
bark sapio recover --bundle recovery.json
```

Export does not reserve positions. Local recovery reserves the selected
positions and prevents their cooperative actions from continuing. `bark watch`
continues those durable recovery selections after a restart; it does not
automatically recover unrelated spendable change or sibling positions.
For an imported bundle, stop concurrent spending from the source wallet first.
The importing wallet cannot lock another wallet's state.

Recovery uses bitcoin and an ordinary on-chain fee wallet. It does not contact
the Ark server or the program service. Keep confirmed funds in that fee wallet.
Fees use CPFP through the saved P2A anchor; they do not alter signed beneficiary
outputs. `AwaitingFees` reports the available and required fee-wallet amounts
without discarding progress. Confirm fee-wallet change or add confirmed funds,
then resume recovery; `bark watch` also continues selected positions.

The beneficiary scripts are explicit destinations, not proof that this wallet
owns those destinations.

Cryptographic readiness and chain progress differ. A complete saved claim can
still await ancestor confirmation, CSV maturity, or its fixed locktime. A
conditional hArk branch can await publication of the server's forfeit. The
export retains the existing leaf signature and the authenticated disclosure
path, so a preimage revealed by an on-chain server claim can unlock that exact
leaf without a new co-signature.

`pending_program_recovery_sat` reports selected recovery value until payout
confirmation. Old, forfeit, and replacement alternatives count once, not as
independent balances. Confirmed payouts leave this category even when their
beneficiary is external to the wallet.

### Compiler reference

The design takes artifact discipline from the
[Arkade compiler](https://github.com/arkade-os/compiler/blob/f4e2d3db18f52873f4bf6ae998c7d8bf41dab41b/src/models/mod.rs#L175-L277)
and its [program API](https://github.com/arkade-os/ts-sdk/blob/cfc332b9b1a58d393ebd28fde409e162a2179d8f/packages/sdk/src/arkade/program.ts#L664-L759):
bind exact program and constructor bytes, keep witness roles explicit, and
retain the data needed to spend. It does not reuse Arkade's VM or infer that a
compiler's emergency-exit branch preserves every cooperative payout constraint.