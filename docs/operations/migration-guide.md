# Migration guide — moving an existing funded agent wallet into the guard

Adopting the guard for an agent that already holds funds is a **one-time transfer of
custody**. The steady-state framing ("non-custodial, no deposit step") is accurate for an
account that already lives at the guard address; it does not describe the first move. This
page covers that move: what changes, how to do it in the safe order, how to verify, and
what the reverse path is.

> **Read this first.** After funds arrive at the guard's `C...` address, they are controlled
> by the guard's `__check_auth`: only the registered agent key can authorize a transfer, and
> only within an installed policy. The **admin can never move them** — there is no sweep,
> withdraw, or override, and no admin function transfers value. Deploying a new guard does
> not move the old balance. This is the same property that makes the guard useful; it is
> also why the migration deserves a rehearsal.

## What changes

| | Before adoption | After adoption |
|---|---|---|
| Account address | The agent's `G...` key is the account; it signs classic operations and Soroban calls. | The **contract address (`C...`)** is the account. The `G...` key is only the identity registered as the agent (`AgentPubkey`) and the fee-paying source for its transactions. |
| Who can move funds | The holder of the `G...` secret, without limits. | The registered agent key, only through `__check_auth`, only inside the policy. |
| Who can stop a transfer | Nobody (or the network). | The policy engine (caps, window, allowlists, pause, freeze, dead-man switch). |
| Classic operations | Available to the `G...` account. | A contract account cannot perform classic Stellar operations; every action is a Soroban invocation. |
| Fees and rent | Paid by the `G...` account. | Still paid by the fee-paying source account (`G...`); not debited from the guard's balance ([rent and TTL](../rent-and-ttl.md)). |

Inbound transfers are not inspected: a payment to the guard address needs no authorization
from the recipient, so it does not call `__check_auth` and is not counted against the
rolling window. Migration inflows are therefore **not** gated by the policy — which is why
the destination must be verified before the first real transfer.

## Preconditions

- [ ] The guard is deployed and `initialize`d (admin and agent key installed) — the
      [deployment runbook](deployment-runbook.md).
- [ ] The agent key is the one you intend to keep, and you can sign with it (prove it with a
      heartbeat on testnet before committing a balance).
- [ ] You have the admin key and can sign `set_policy` / `unfreeze` / `revoke_policy`.
- [ ] The target policy is decided: `assets`, `recipients`, `per_tx_cap`, `window_cap`,
      `window_secs`, `dms_grace_secs`, `active_from`/`active_until`.
- [ ] You know the source balance and the destination addresses, and you have recorded the
      guard contract ID.

## 1. Confirm the source balance and the destination

Reads are permissionless; use `--send=no` so nothing is submitted.

```bash
# Source: the agent's current G... balance in the SAC (a read, no auth).
stellar contract invoke --id <SAC_ID> --network testnet \
  --source-account <AGENT_ALIAS> --send=no -- balance --id <AGENT_G>
# → an i128 amount

# Destination check: the guard is initialized and has a policy.
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- status
# → expect "has_policy":true (or install the policy first — see step 2)
```

For a classic asset, also confirm the asset is the SAC you expect (`<SAC_ID>`) and that the
asset can be held by the destination. The fixture deployment minted to the guard's contract
address directly and recorded a **trustline** transaction for the human-controlled
recipient, so if you are moving a classic asset out of a `G...` account, treat the
one-unit rehearsal below as the check for the destination's requirements.

**Do not skip the destination check.** A transfer to the wrong contract address is
irreversible: nobody — not the admin, not the deployer — can pull funds back out of an
address whose agent key you do not control.

## 2. Install the target policy first

Install the policy the agent will operate under *before* the balance moves:

```bash
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- set_policy --config '{
    "active_from": 0, "active_until": 0, "allow_any_recipient": false,
    "assets": ["<SAC_ID>"], "dms_grace_secs": 0, "paused": false,
    "per_tx_cap": "100", "protocols": [], "recipients": ["<RECIPIENT_G>"],
    "window_cap": "500", "window_secs": 86400 }'
# → Event: EventPolicySet
```

Why first: the account is default-deny until a policy exists. Installing it first means you
can verify the policy, the agent key, and the reads while the balance is still at its old
address — and the policy is yours to edit while the admin key is available. Installing a
policy does not put anything at risk; it only defines what the agent may authorize later.

`dms_grace_secs: 0` here keeps the dead-man clock out of the migration. If you intend to arm
it, do that as a deliberate later edit (or account for the clock from the start — a first
install arms it at install time, and a later edit leaves it running, per issue #289).

## 3. Rehearse with one unit

Send a deliberately small amount and verify it arrives. This is the last cheap abort point.

```bash
# Signed by the agent's G... key: the source account authorizes `from`, so this is a
# normal classic-account authorization, not a guard authorization.
stellar contract invoke --id <SAC_ID> --network testnet \
  --source-account <AGENT_ALIAS> --send=yes -- \
  transfer --from <AGENT_G> --to <GUARD_ID> --amount 1
```

Expected: a submitted transaction whose SAC `transfer` event shows the guard address as the
recipient. Then confirm the balance at the guard address (step 5). If the one-unit transfer
fails, or the destination is wrong, **stop**: nothing else has moved, and no policy change
is needed to abandon the migration.

## 4. Move the balance

Only after the rehearsal verifies:

```bash
stellar contract invoke --id <SAC_ID> --network testnet \
  --source-account <AGENT_ALIAS> --send=yes -- \
  transfer --from <AGENT_G> --to <GUARD_ID> --amount <BALANCE>
```

If the asset is XLM, leave enough in the `G...` source account to keep paying fees — the
guard cannot be a fee source (`SPEC §10.3`). The guard's own XLM balance is funds under
policy, not a fee budget.

## 5. Verify the funds arrived

Read the SAC balance at the **contract** address, not the `G...` address:

```bash
stellar contract invoke --id <SAC_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- balance --id <GUARD_ID>
# → the migrated amount (i128)

stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=no -- status
# → "has_policy":true, "admin_frozen":false, "heartbeat_expired":false
```

Also prove the agent can spend **within** the new policy, with a pre-flight that never
broadcasts:

```bash
cd tools/agent-tx && cargo build --release
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
./target/release/agent-tx preflight --guard <GUARD_ID> --asset <SAC_ID> \
  --to <RECIPIENT_G> --amount 1
# exit 0 = admitted by the real __check_auth; exit 1 = blocked (reason printed); exit 2 = inconclusive
```

A `preflight` that is blocked usually means the policy's `assets`/`recipients` do not match
the token and destination you are testing, or the account is outside its active window.
Fix the policy before relying on the account.

## 6. The reverse path — abandoning the guard

**Without the registered agent key there is no reverse path.** The admin cannot move funds,
no admin function transfers value, and a contract cannot be upgraded in place (Soroban
contracts are immutable; see [architecture](../architecture.md#enforcement-equivalent-upgrade-policy)).
Deploying a second guard does not move the first one's balance. If both the agent key and
the admin key are unavailable, see the
[incident playbook](incident-playbook-admin-key-lost.md).

If you still hold the agent key, the exit is a deliberate, bounded policy that lets that key
send the balance to one address you control, then a revoke:

```bash
# 1. Admin: a temporary exit policy. One recipient, caps at the balance, DMS off.
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- set_policy --config '{
    "active_from": 0, "active_until": 0, "allow_any_recipient": false,
    "assets": ["<SAC_ID>"], "dms_grace_secs": 0, "paused": false,
    "per_tx_cap": "<BALANCE>", "protocols": [], "recipients": ["<WITHDRAW_G>"],
    "window_cap": "0", "window_secs": 86400 }'
# → Event: EventPolicySet

# 1a. If the dead-man grace had already expired, a policy *edit* does not re-arm the
#     clock (issue #289). The admin's unfreeze is required before the agent can authorize.
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- unfreeze

# 2. Agent: sign the outbound transfer. The stellar CLI cannot sign auth entries whose
#    address is a contract, so use the submission helper.
agent-tx transfer --guard <GUARD_ID> --token <SAC_ID> \
  --to <WITHDRAW_G> --amount <BALANCE>
# → RESULT: ALLOWED (or BLOCKED with the reason, if the policy still does not match)

# 3. Admin: leave the account default-deny once the balance is out.
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ADMIN_ALIAS> --send=yes -- revoke_policy
# → Event: EventPolicyRevoked
```

Notes on the exit policy:

- It is **deliberately permissive** for one recipient. Anyone holding the agent key during
  this window can move the balance to `<WITHDRAW_G>` only (the allowlist still binds), so do
  it promptly and revoke afterwards.
- `per_tx_cap` must cover the whole balance, and `window_cap: 0` disables the rolling window
  (if you set a positive `window_cap`, `window_secs` must be positive too, and the shared
  window must cover the amount).
- If the assets list does not contain the token, the outbound transfer is blocked as an
  unlisted asset — that is the policy doing its job, not a stuck account.
- If the admin key is gone too, this section is not available: the balance stays at the
  contract address.

## Migration checklist

- [ ] Destination verified: `<GUARD_ID>` is the guard you deployed and initialized.
- [ ] Agent key proven (heartbeat or preflight) before value moves.
- [ ] Target policy installed and read back; `policy_hash` recorded.
- [ ] One-unit rehearsal arrived; balance read at the `C...` address confirms it.
- [ ] Remaining balance moved; `G...` retains enough XLM for fees.
- [ ] Agent preflight admitted under the production policy.
- [ ] Deployment record updated (guard ID, policy hash, migrated amount, transactions).
- [ ] Reverse path understood and recorded, including who holds the agent key and the admin
      key.

## See also

- [Deployment runbook](deployment-runbook.md) — the ordered deploy sequence.
- [Incident playbook — DMS-frozen, admin key unavailable](incident-playbook-admin-key-lost.md).
- [Upgrade compatibility matrix](../upgrade-compatibility.md) — the SDK, Rust, WASM, schema,
  and storage versions to keep consistent when a migration also bumps a dependency.
- [`docs/key-rotation.md`](../key-rotation.md) — rotating the agent key, including after a
  suspected leak.
- [`examples/agent-loop.md`](../../examples/agent-loop.md) — the steady-state loop for the
  migrated agent.
- [SPEC §1](../../SPEC.md#1-mechanism-and-non-custodial-guarantee) — the custody guarantee
  this guide transfers into.
