# How Sapling contracts work

Sapling lets an application use program-controlled Ark VTXOs. It also keeps
approved recovery transactions for an emergency exit onto bitcoin.

This guide explains the design, an Alice-and-Bob escrow example, and the state
an application must preserve. For Rust setup and configuration, use the
[SDK reference](../sdk/README.md).

> An emergency exit leaves Ark. It does not bypass the contract, guarantee an
> immediate payout, or give every depositor an unconditional refund.

This integration is experimental. A valid recovery transaction is not an audit
of a contract or proof of a production enclave's identity.

## The main parts

| Part | What it does |
|---|---|
| Your application | Defines the contract, presents its terms, manages keys, and keeps backups. |
| Sapling SDK | Runs the client wallet app, manages VTXOs, requests signatures, and saves recovery state. |
| Ark server | Coordinates normal Ark operations and supplies its required signatures. |
| Sapio service | Evaluates the configured program in a trusted execution environment (TEE) and co-signs approved requests. |
| bitcoin | Enforces transaction signatures, output scripts, and timelocks when transactions reach the chain. |

A VTXO is an off-chain position backed by a bitcoin transaction graph. The
recovery data describes how to publish the required transactions and claim the
position on-chain. A VTXO is not a separate token or a record of a balance alone.

WASM runs in Sapio, not in bitcoin consensus. A program decides whether to
approve a proposed transaction. It can require extra evidence, called a
**witness**, such as a counterparty's approval. The program must check that
evidence; arbitrary witness bytes are not permission to spend.

This is not an EVM-style shared on-chain virtual machine. Use the supported
Sapio interface and resource limits. Define any application state, oracle
inputs, and approval rules explicitly. The SDK does not supply them by itself.

## Who can sign?

A program-backed position uses these keys:

```text
U = your wallet key
S = the Sapio program-instance key
C = the joint key that requires U and S
A = the Ark server key

Normal cooperative spend: C + A
Delayed emergency claim: C
```

Sapio holds the private key for `S`. Its public identity depends on the trusted
Sapio root, evaluator identity, exact program bytes, and exact constructor
parameters. The joint key `C` also depends on your public key `U`.

Your key `U` alone cannot sign as `C`. Sapio alone cannot sign as `C` either.
There is no automatic fallback to a user-only key if Sapio rejects a request or
becomes unavailable.

This creates an important requirement: **prepare the emergency claim while
Sapio can still authorize it.**

## Prepare recovery before commitment

The SDK constructs a recovery claim with explicit payout outputs. Sapio checks
that actual transaction against the program. The wallet app verifies and saves
the authorized claim and its recovery dependencies around the guarded
commitment steps.

The normal SDK paths prepare recovery before they release bitcoin funding,
cooperative signatures, or a Lightning receive preimage. If preparation fails,
they do not cross that commitment point.

The recovery configuration is a construction template, not a special permission
to bypass the program. Programs must also handle the actual transactions for
checkpoints, change, refreshes, and other operations they support. A rule that
accepts one final payout does not necessarily accept an entire Ark operation.

Program-backed receives use a coordinated prepare/commit exchange. The recipient
saves recovery state before it acknowledges preparation. Do not assume that an
unsolicited raw deposit or a legacy client's transfer provides the same
protection. The SDK quarantines rejected raw deposits instead of treating them
as spendable positions.

## Example: Alice and Bob keep an escrow locked

Assume Alice and Bob agree on a contract position worth **100,000 sats**.
They want neither party to take the sats without the other's approval.

This is a worked contract design, not a supplied escrow application or an
audited WASM program.

### 1. Agree on both normal and emergency rules

Their program must enforce these rules:

- A normal settlement requires both parties' approval of the exact payout.
- Any intermediate Ark transaction must preserve the contract's restrictions
  and value, subject to their agreed fee policy.
- An emergency claim pays the 100,000 sats to a specific on-chain 2-of-2 escrow
  output that requires Alice and Bob.
- No path pays everything to Alice merely because she starts an emergency exit.

The on-chain escrow uses Alice's and Bob's ordinary on-chain keys, not the
Sapio joint key `C`. They must preserve those keys and the escrow script.
They also need a wallet app that can spend that multisig output.

### 2. Inspect the prepared exit

Before they accept the funded contract position, they verify the contract
identity, the actual VTXO, and its recovery data. The expected recovery payout is:

```text
100,000-sat program-controlled VTXO
                  |
         pre-signed emergency claim
                  |
100,000 sats to the agreed Alice-and-Bob 2-of-2 escrow
```

The recovery transaction also has a zero-value fee anchor. Separate confirmed
bitcoin in a fee wallet pays the recovery mining fees. The fee mechanism does
not reduce or redirect the signed 100,000-sat beneficiary output.

Bob computes the expected escrow script from their agreed keys and compares it
with the actual transaction output. He does not accept an address merely because
Alice labels it "escrow". An address alone does not reveal all of its spend rules.

### 3. Follow the appropriate path

| Situation | Result |
|---|---|
| Alice and Bob approve a settlement of 60,000 sats to Alice and 40,000 sats to Bob | The program can approve that exact settlement under the agreed rules. |
| Ark or Sapio becomes unavailable | A complete, valid recovery branch can move the position to the agreed on-chain escrow without new signatures from those services. |
| Alice tries to change the saved recovery payout to her own address | Its existing signature is no longer valid. |
| Alice requests a different transaction that pays only her | The program must reject it. Showing Bob one safe transaction is not enough if the program also permits this unsafe one. |
| Alice publishes the approved emergency claim | The sats reach the on-chain escrow. Alice still needs Bob to spend that output. |

A pre-signed exit does not require Bob to sign again at exit time. Spending the
resulting 2-of-2 output does require both parties. **The exit removes the Ark
and Sapio availability requirement; it does not remove the escrow restriction.**

A plain 2-of-2 escrow can remain locked if either party refuses to cooperate.
If the application needs eventual one-party settlement, the parties must agree
on an appropriate timeout or dispute path. That on-chain path must use rules
that bitcoin can enforce. Arbitrary WASM logic does not automatically continue
on-chain after the exit.

## What can a counterparty verify?

A counterparty with the signed claim and supporting recovery data can check:

1. The claim spends the expected contract position.
2. The actual output scripts and amounts match the agreement.
3. The signatures, timelocks, and transaction dependencies are valid.
4. The VTXO uses the joint key for the agreed program, parameters, and trusted
   Sapio root.

Our recovery verifier requires Taproot `SIGHASH_DEFAULT`. That signature mode
commits to every output. A different destination or amount invalidates the
signature. The check does not need a private key. The recovery data must be
shared for this inspection; it is not automatically public before broadcast.

There are two different security questions:

| Question | What establishes the answer |
|---|---|
| Can Alice redirect this already-signed claim? | The transaction signature commits to its outputs. |
| Can Alice obtain or use a different, unauthorized payout? | The actual VTXO's spend paths and the exact program must prevent it. Sapio must enforce that program. |

`ProgramRecoveryBundle::verify()` checks cryptographic and construction
consistency. It does not know Alice and Bob's agreement. The application must
compare the outputs and program identity against independently agreed terms,
not merely against a template supplied by the other party.

Creating a safe transaction does not revoke another valid, conflicting
transaction. Changing a wallet app's configuration does not rewrite an existing
VTXO. Verify the current position and its real authorization rules.

Program enforcement depends on the trusted enclave and its software. Pin the
Sapio root from independently verified attestation. Do not trust a root merely
because the same service returns it. **The SDK does not verify enclave
attestation for the application.** A local development service does not provide
hardware isolation or attestation.

## What happens during an emergency exit?

For a funded, still-valid recovery branch:

1. Register the selected positions for recovery. Stop their normal spend paths.
2. Use a bitcoin backend to check the saved transactions against the chain.
3. Publish the required ancestor transactions. These connect the off-chain
   position to a confirmed on-chain output.
4. Wait for required confirmations, relative delays, and absolute locktimes.
5. Publish the fixed recovery claim and wait for its payout to confirm.

The driver advances this process over repeated calls. It does not create a new
program signature or choose a new beneficiary at exit time.

### Fees do not change the payout

Recovery uses child-pays-for-parent (CPFP). An ordinary fee wallet spends the
saved transaction's fee anchor and contributes confirmed bitcoin to a child
transaction. The child pays enough fees for the package.

If the fee wallet lacks sufficient confirmed bitcoin, recovery reports
`AwaitingFees`. Add confirmed bitcoin or wait for suitable fee-wallet change to
confirm, then resume. Keep the fee wallet separate from the locked payout in the
application's fee plan.

### A saved record is not always ready

| Readiness | Meaning |
|---|---|
| `Prepared` | The saved recovery data is still incomplete. Do not treat it as a ready exit. |
| `Conditional` | A specific server publication determines whether a branch becomes available. Preserve the complete old fallback and the relevant dependency data. |
| `Complete` | The saved authorization checks pass. Chain publication, confirmations, timelocks, or required disclosures can still affect progress. |

A successful `verify()` call is not a promise of immediate broadcastability.
Use `readiness()` and the chain progress results as separate checks. Preserve
signed hashlocked dependencies and their authenticated disclosure paths. A
preimage disclosed on-chain can complete an existing authorization without a
fresh Sapio signature.

### There are deadlines

Ark positions and some transaction branches have expiry or timeout rules.
Relevant ancestors can become reclaimable by the server. Refresh or start
recovery early enough to account for confirmations, delays, and congestion.
A backup does not make an off-chain position safe to ignore indefinitely.

The local recovery path reserves selected positions against normal operations.
The daemon resumes saved recovery selections after a restart. Do not assume
that an outage automatically starts recovery for every position.

An export does not reserve positions. Before standalone replay, stop all other
wallet instances that can spend the source positions. An imported bundle cannot
lock a different database or another device.

## What must the application preserve?

**A seed phrase alone is not enough for program-backed recovery.** It cannot
reconstruct lost program descriptors or saved signatures while the services
are unavailable.

| Backup material | Why it matters |
|---|---|
| Seed phrase and relevant private keys | Restore normal signing capability and access to ordinary bitcoin outputs. Preserve any separate beneficiary or multisig keys too. |
| Full, consistent wallet database | Keeps VTXOs, program descriptors, recovery records, pending actions, and recovery selections. |
| Current `ProgramRecoveryBundle` | Keeps exact program descriptors, payout templates, claims, previous outputs, ancestor transactions, and conditional unlock/disclosure data for independent replay. |
| Fee-wallet recovery material | Restores access to the confirmed bitcoin needed to pay recovery fees. |
| Application configuration and contract state | Preserves any external evidence, escrow scripts, or application data needed for normal operation and final settlement. |

Keep the actual transaction graph, not just a balance, transaction IDs, or a
program hash. A completed claim already has its authorization; replay does not
need the original key to sign that claim again. You still need fee payment and
the appropriate keys to spend its payout.

### Keep the backup current

Receives, payments, change, and refreshes can create new positions. An old
backup may describe positions that are no longer spendable. Preserve the
current state and the old/new fallback branches for incomplete transitions.
Do not discard a fallback merely because a newer candidate exists.

The supplied SQLite persistence is local. Its write-before-sign discipline is
not an off-device backup guarantee. If the application promises recovery after
device loss, it must arrange off-device durability at the relevant commitment
boundaries. A periodic export leaves a data-loss window.

For SQLite, use a consistent backup mechanism or stop the wallet app before a
file copy. Do not copy a live database while ignoring journal or WAL state.
Protect backups with encryption and keep independently accessible copies.
Recovery must not depend on the application operator's continued availability.
Do not publish the full backup as a counterparty proof; it can contain private
contract evidence. Share only the data needed for the agreed checks.

## Which APIs connect these steps?

| Task | API |
|---|---|
| Export eligible current recovery positions | `wallet.program_recovery_bundle(&[])` |
| Check a bundle's internal consistency | `bundle.verify()` |
| Check a saved position's readiness | `bundle.readiness(outpoint)` |
| Start or advance coordinated local recovery | `wallet.recover_program_vtxos(&outpoints, fee_rate)` |
| Replay a bundle with only a chain backend and an ordinary fee wallet | `sapling::sapio::recovery::recover_program_bundle(...)` |

The export includes eligible live, already-selected, and durable crash-gap
positions. It does not select superseded claims as new recovery targets.
Drive recovery until payout confirmation, not merely until export or broadcast.

## Before an application accepts a contract

- Agree on the normal settlement and emergency payout rules.
- Bind the exact program and parameters to a verified Sapio identity.
- Check the actual VTXO and recovery outputs against that agreement.
- Preserve complete recovery branches and any required fallbacks.
- Ensure the intended beneficiaries can spend the on-chain outputs.
- Keep current, independently accessible backups and confirmed fee bitcoin.
- Monitor relevant deadlines and test the full recovery path before real use.

The useful promise is: **an emergency exit preserves the contract-authorized
entitlement without fresh Ark or Sapio signatures.** It is not an unconditional
refund, an instant withdrawal, or proof that every possible WASM contract is safe.

## Further reading

- [Repository overview and dependencies](../README.md)
- [Rust setup, configuration, and recovery API details](../sdk/README.md)
- [Program-backed addresses and coordinated delivery](addresses.md)
- [Recovery implementation and verification](../sdk/src/sapio/recovery.rs)
- [Persisted program descriptors and recovery records](../sdk/src/persist/models.rs)
