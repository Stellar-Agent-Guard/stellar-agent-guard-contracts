# Deployment runbook — the guard contract, end to end

The ordered sequence for deploying Stellar Agent Guard: **build → upload → create →
initialize → install a policy → verify with `status()`**. It is written for the raw
`stellar` CLI (verified against `stellar-cli` 27.1.0). Sibling repositories
(`stellar-agent-guard-sdk`, `stellar-agent-guard-dashboard`) are out of scope.

> **The guard is a custom account, not an ordinary contract.** After `initialize`, the
> agent's address *is* the contract address, and the money the agent spends sits **at the
> contract address (`C...`)**, held by the Stellar Asset Contract. The agent's `G...` key is
> only the identity that signs — it is not the account that holds the balance. Every step
> below that touches funds uses the `C...` address.

Deploying a custom account is not the standard Soroban flow: the WASM must be uploaded and
the contract created *before* `initialize` can be called, and a wrong order produces
confusing failures (most commonly `AlreadyInitialized` on a retried `initialize`). Follow
the steps in order and record each output.

## Before you start

- [ ] The pinned Rust toolchain and the `wasm32v1-none` target (`rust-toolchain.toml`;
      `rustup` installs it from a clone — confirm with `rustc --version`).
- [ ] `stellar-cli` 22+ and an RPC endpoint (`testnet`, `futurenet`, or mainnet — this
      contract is **unaudited**; do not put real funds on mainnet).
- [ ] A funded `deployer` identity for upload/create, and the **admin** identity whose
      address will be installed. `initialize` and `set_policy` must be signed by the admin,
      so do not plan to deploy with one key and administer with another on the same call.
- [ ] The agent's **raw 32-byte Ed25519 public key** (64 lowercase hex characters), derived
      offline from the agent secret — not its `G...` address:
      `echo 'S...' | cargo run --example agent_pubkey`.
- [ ] A decision on `dms_grace_secs` (see [step 5](#5-install-the-policy)). If you are going
      to arm the dead-man switch, read the
      [incident playbook](incident-playbook-admin-key-lost.md) first: arming it makes the
      admin key a liveness dependency for the whole balance.

Placeholders used below: `<WASM_HASH>`, `<GUARD_ID>`, `<ADMIN_G>`, `<ADMIN_ALIAS>`,
`<AGENT_PUBKEY_HEX>`, `<SAC_ID>`, `<RECIPIENT_G>`.

## 1. Build the contract WASM

```bash
cargo build --release --target wasm32v1-none
# → target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm
sha256sum target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm
```

**Expected:** the build succeeds and the artifact exists; record the SHA-256 next to the
deployment record.

**Most likely failure:** `error: target 'wasm32v1-none' not found` — the pinned toolchain
is missing the target. Run `rustup target add wasm32v1-none` (the target is `wasm32v1-none`,
not `wasm32-unknown-unknown`). If you are deploying a released artifact instead of building,
follow [Download a released artifact](../../README.md#download-a-released-artifact-instead-of-building)
and verify its checksum first.

## 2. Upload the WASM

```bash
stellar contract upload \
  --wasm target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm \
  --source-account deployer \
  --network testnet
# → <WASM_HASH>   (64 hex characters; this is the uploaded code hash, not a contract ID)
```

**Expected:** a single hash. Record it — `create` takes this hash, not the file path.

**Most likely failure:** a fee or sequence error (`tx_insufficient_fee`, `tx_bad_seq`) or an
unreachable RPC. There is no state to repair: nothing has been created yet, so fix the fee
or endpoint and repeat. On an older CLI this subcommand is named `install`.

## 3. Create the contract (the account address)

```bash
stellar contract deploy \
  --wasm-hash <WASM_HASH> \
  --source-account deployer \
  --network testnet
# → <GUARD_ID>   (C...), e.g. the fixture's deployed guard
```

**Expected:** one `C...` address. **Record it immediately.** This is the address funds will
live at and the address the agent will use from now on.

**Most likely failure:** a retry that returns a *different* contract ID. The ID is derived
from the source account and a salt; a repeated `deploy` is a new deployment, not a resume.
If you retry, compare the returned address with the first attempt and keep exactly one
guard — two guards split the policy admin you are about to install. Insufficient XLM for
the account reserve also fails here.

## 4. Initialize (admin + agent key)

```bash
stellar contract invoke \
  --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- \
  initialize \
  --admin <ADMIN_G> \
  --agent_pubkey <AGENT_PUBKEY_HEX>
```

**Expected:** success. `initialize` writes the admin address and the agent's raw Ed25519
public key and leaves the account **default-deny** — no policy exists yet, so every agent
authorization is refused with `no_policy`. Do not expect an `auth_checked` event; verify
state with `status()` in [step 6](#6-verify-with-status).

**Most likely failure — `AlreadyInitialized` (`Error(Contract, #2)`).** This is usually
*not* a failed deployment: a fee-bump double-submit or a panic-retry hit it after the first
call already succeeded. **Do not redeploy a fresh guard.** Check `status()` first. If it
reads sane (`has_policy: false`, `admin_frozen: false`, the expected agent key), continue to
step 5. Redeploy only if `status()` shows nothing was ever initialized.

**Second most likely failure:** an authorization error because `--source-account` is not
the admin address being installed. `initialize` does `require_auth(admin)`; the CLI signs
for the source account, so deploy and initialize can use different keys only if the source
key *is* `<ADMIN_G>`.

## 5. Install the policy

```bash
stellar contract invoke \
  --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- \
  set_policy --config '{
    "active_from": 0, "active_until": 0, "allow_any_recipient": false,
    "assets": ["<SAC_ID>"], "dms_grace_secs": 0, "paused": false,
    "per_tx_cap": "100", "protocols": [], "recipients": ["<RECIPIENT_G>"],
    "window_cap": "500", "window_secs": 86400 }'
# → Event: EventPolicySet (event_policy_set)
```

**Expected:** `EventPolicySet`. From this moment the agent can authorize calls that satisfy
the policy; before it, the account is default-deny. The JSON shape is validated by tooling
against [`policy.schema.json`](../../policy.schema.json) (the contract remains the
authoritative validator), and the policy fields are described in
[`set_policy`](../../README.md#set_policy).

**Most likely failure — `InvalidConfig` (`Error(Contract, #4)`).** Common causes: an
`active_until` that is not after `active_from`, a negative cap, `window_cap > 0` with
`window_secs == 0`, duplicate assets/recipients, a recipient that is both allowed and
blocked, or an `asset_caps` entry for an asset not in `assets`. The policy is validated
**before** anything is written, so a rejected config leaves the previous policy intact
(fail-closed). Fix the config and resubmit.

**Grace choice.** `dms_grace_secs: 0` disables the dead-man switch. Any positive value arms
a clock at install time (a *first* install only; a later policy edit preserves the existing
window and clock, per issue #289). The 60-second value in the testnet fixtures is a demo
value so the freeze is observable — production guidance is several days. Once armed, the
agent must heartbeat within the grace or the account self-freezes, and only the admin can
reverse that. See the [incident playbook](incident-playbook-admin-key-lost.md).

## 6. Verify with `status`

Reads are permissionless and simulation-only, so use `--send=no`:

```bash
stellar contract invoke \
  --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- status
# → {"admin_frozen":false,"dms_grace_secs":0,"has_policy":true,
#    "heartbeat_expired":false,"heartbeat_expires_at":null,
#    "last_heartbeat":<install time>,"now":<ledger time>,
#    "outside_active_window":false,"paused":false,"window_remaining":"500"}
```

Also read back the exact policy and pin a drift baseline:

```bash
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- policy

stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- policy_hash
# → the SHA-256 of the canonical policy encoding; record it next to the deployment
```

**Expected:** `has_policy: true`, `admin_frozen: false`, `paused: false`,
`outside_active_window: false`. With `dms_grace_secs == 0`, `heartbeat_expired` is `false`
and `heartbeat_expires_at` is `null` (or absent) regardless of silence.

**What a surprising read means:**

| Read | Meaning |
|---|---|
| `has_policy: false` | Step 5 did not land (or was reverted). Re-check the `set_policy` output. |
| `admin_frozen: true` | An admin `freeze` is in effect; `unfreeze` (admin) is the reversal. |
| `heartbeat_expired: true` right after install | More than `dms_grace_secs` has elapsed since install with no agent heartbeat. Start the agent loop, then `unfreeze` (admin) — a heartbeat cannot revive an expired account. |
| `outside_active_window: true` | The policy's `active_from`/`active_until` does not cover the current ledger time. Only a `set_policy` with a renewed window revives the account. |

## 7. Put the balance where the guard expects it

Funds must arrive at `<GUARD_ID>` (the `C...` address), not at the agent's `G...` key. An
inbound transfer needs no authorization from the recipient, so it does **not** pass through
`__check_auth` and is not counted against caps or the rolling window. Migrating an existing
funded wallet — including the one-unit rehearsal that is your last free abort point — is the
[migration guide](migration-guide.md).

Two cost notes that are easy to get backwards:

- Transaction fees and storage rent are paid by the transaction's **fee-paying source
  account**, not by the guard's balance. Keep the operator/agent `G...` account funded
  ([rent and TTL](../rent-and-ttl.md)).
- The guard contract account cannot be a fee source and cannot perform classic Stellar
  operations; every action it takes is a Soroban invocation through `__check_auth`
  ([SPEC §1](../../SPEC.md#1-mechanism-and-non-custodial-guarantee)).

## 8. Hand over to the agent loop

With a policy installed and a balance at the contract address, start the steady-state loop:
heartbeat every `interval ≤ grace / 3`, pre-flight each transfer with `agent-tx preflight`,
and stop on `heartbeat_expired` (see [`examples/agent-loop.md`](../../examples/agent-loop.md)).
The `stellar` CLI cannot sign auth entries whose address is a contract, so agent-side
submissions use `tools/agent-tx`
([usage](../../tools/agent-tx/README.md)).

## Deployment record

Keep these with the deployment, because every later incident question starts from them:

- contract address, WASM hash, WASM SHA-256, network, protocol version, ledger of each step;
- admin `G...` address and where its key is held;
- agent public key (hex) and fingerprint;
- `policy_hash` after the first install, and the `set_policy` transaction;
- `dms_grace_secs` and the heartbeat cadence the agent runtime is configured with.

## See also

- [Migration guide](migration-guide.md) — moving an existing funded wallet into the account.
- [Incident playbook — DMS-frozen, admin key unavailable](incident-playbook-admin-key-lost.md) —
  what arming the dead-man switch commits you to.
- [`docs/key-rotation.md`](../key-rotation.md) — agent-key rotation and the two-step admin
  handover.
- [Testnet fixtures](../../tests/fixtures/README.md) — the recorded Phase-1 deployment this
  runbook reproduces.
- [SPEC §7](../../SPEC.md#7-public-surface--exact-signatures-and-auth-placement) — exact
  signatures and auth placement for every function used above.
