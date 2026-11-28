# Incident playbook — account DMS-frozen and the admin key is unavailable

The dead-man switch is the product's sharpest trust trade: it stops a runaway or abandoned
agent, but it makes the **admin key a liveness dependency for the entire balance**. If the
admin key is lost while the switch is armed, the reversal path does not exist, and an
account that freezes stays frozen with the funds inside it.

This page is the operator's side of that trade: how to recognise the state, what is and is
not recoverable, and how to avoid it. The normative behavior is
[SPEC §5](../../SPEC.md#5-dead-man-switch--precise-definition) and
[SPEC §10](../../SPEC.md#10-threat-model-what-this-does-and-does-not-do).

## The short version

- **Freezing is automatic and lazy.** Nothing has to run: once
  `now - last_heartbeat > dms_grace_secs`, every authorization the account attempts —
  including the agent's own `heartbeat` — is rejected with `heartbeat_expired`.
- **Only the admin can reverse it.** `unfreeze()` is admin-only and is the only call that
  clears the condition; it also stamps `LastHeartbeat = now`. Silence cannot self-revive.
- **The admin cannot be replaced without the current admin.** `propose_admin_rotation`
  requires the current admin's signature, so a lost admin key cannot be handed over.
- **There is no other lever.** No second admin, no recovery key, no permissionless
  unfreeze, no timelock, no in-place upgrade. The one in-contract exception is a
  **pre-existing pending admin** (below).
- **Therefore:** if the account is already frozen and the admin key is gone, the balance at
  the contract address is permanently unspendable. Treat it as lost access, not as funds
  that can be recovered later.

## Emergency freeze sequence (when the admin key is available)

If an incident is active and you **still control the admin key** (for example, suspected
agent-key leak, runaway loop, or compromised host), halt transfers immediately before
investigating. Combine the account-level `freeze()` brake with the
[`examples/policies/emergency-freeze.json`](../../examples/policies/emergency-freeze.json)
lockdown preset so every authorization is blocked and no allowlist entry survives an
accidental `resume()` or `unfreeze()`.

### 1. Freeze and strip policy permissions

```bash
# Step 1 — immediate account-level halt (rule #1, blocks transfers, protocol calls, and heartbeat)
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- freeze
# → Event: frozen (by: <ADMIN_G>)

# Step 2 — replace the stored policy with the zero-permission emergency-freeze preset
# (paused=true, empty assets/recipients/protocols, dms_grace_secs=0)
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- \
  set_policy --config "$(cat examples/policies/emergency-freeze.json)"
# → Event: policy_set (by: <ADMIN_G>, revision: <N+1>)
```

If the agent key may have leaked, rotate it while the account is frozen:

```bash
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- \
  rotate_agent_key --new_pubkey <NEW_64_HEX_CHARS>
# → Event: agent_rotated (old_fingerprint, new_fingerprint)
```

### 2. Verify the freeze before standing down

Run all three read-only checks and record the outputs in your incident log:

```bash
# Confirm both account-level freeze and policy pause are active
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- status
# → expected: "admin_frozen":true, "paused":true, "has_policy":true, "dms_grace_secs":0

# Record the installed policy digest and confirm allowlists are empty
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- policy_hash

# Prove an agent-signed transfer is rejected pre-broadcast with admin_frozen
./tools/agent-tx/target/release/agent-tx preflight --guard <GUARD_ID> \
  --asset <SAC_ID> --to <RECIPIENT_G> --amount 1
# → exit 1, reason `admin_frozen`
```

### 3. Recover after the incident is resolved

Never call `unfreeze()` until the replacement policy is validated and installed, because
`unfreeze()` clears `AdminFrozen` and re-arms `LastHeartbeat = now` in one transaction:

1. **Validate the replacement policy off-chain / via simulation:**
   ```bash
   stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
     --source-account <ADMIN_ALIAS> --send=no -- \
     validate_policy --config "$(cat <VETTED_POLICY_JSON>)"
   # → Valid
   ```
2. **Install the replacement policy** (still while `admin_frozen: true`, so the agent
   cannot spend until the final step):
   ```bash
   stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
     --source-account <ADMIN_ALIAS> --send=yes -- \
     set_policy --config "$(cat <VETTED_POLICY_JSON>)"
   ```
3. **Clear the freeze (and re-arm DMS):**
   ```bash
   stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
     --source-account <ADMIN_ALIAS> --send=yes -- unfreeze
   # → Event: unfrozen (by: <ADMIN_G>, rearmed_dms: true/false)
   ```
   If the replacement policy was intentionally staged with `paused: true`, also call
   `resume` once you are ready to admit traffic.
4. **Verify live recovery:**
   - Re-run `status` and confirm `admin_frozen: false`, `paused: false`,
     `heartbeat_expired: false`, and the expected `dms_grace_secs`.
   - Run `agent-tx preflight` for a known-good transfer (expect exit `0`) and an
     over-cap transfer (expect exit `1`, `per_tx_cap_exceeded`).
   - Confirm the agent's heartbeat loop is running on the new key before leaving the
     incident channel.

If the admin key is **not** available during an incident, the agent itself can still pull
the emergency brake with `self_lock()` (sets `AdminFrozen = true`), or silence will
trigger the dead-man switch — but reversal still requires the admin key as detailed below.

## 1. Recognise the state

Reads are permissionless and simulation-only, so they work even while the account is frozen:

```bash
stellar contract invoke --id <GUARD_ID> --network testnet \
  --source-account <ANY_FUNDED_ACCOUNT> --send=no -- status
# → {"admin_frozen":false,"dms_grace_secs":<grace>,"has_policy":true,
#    "heartbeat_expired":true,"heartbeat_expires_at":<last_heartbeat+grace>,
#    "last_heartbeat":<unix>,"now":<unix>,
#    "outside_active_window":false,"paused":false,"window_remaining":"<n>"}
```

`dms_health()` is the advisory view (`Ok` / `Warn` at ≥80% of the grace / `Expired`) and is
useful before the freeze, not after it.

The state is **DMS-expired** when `dms_grace_secs > 0`, `last_heartbeat != 0`, and
`heartbeat_expired: true` with `admin_frozen: false`. Distinguish it from the other gates
that also stop the account — they have different reversal paths, and only one of them needs
the admin key *at that moment*:

| Observation | Gate | Reversed by |
|---|---|---|
| `admin_frozen: true` | Admin freeze (rule #1) | Admin `unfreeze()` |
| `heartbeat_expired: true`, `admin_frozen: false` | Dead-man switch (rule #2) | Admin `unfreeze()` only |
| `has_policy: false` | No policy (rule #3) | Admin `set_policy()` |
| `paused: true` | Policy pause (rule #4) | Admin `resume()` / `set_policy()` |
| `outside_active_window: true` | Active window (rule #5) | Admin `set_policy()` with a renewed window |
| `window_remaining` at `0` | Rolling window cap (rule #7d) | Time, or admin `reset_window()` |

Two or more can be true at once; the engine reports only the first (admin freeze, then
dead-man, then pause, then active window), so **read the combination, not the single
reason** — [SPEC §5.2](../../SPEC.md#52-when-two-transaction-level-gates-fire-at-once-issue-426).

A frozen account is still *readable*: `status`, `policy`, `policy_hash`, and `check` all
answer. They are not gated by the switch, which is why the state is diagnosable at all.

## 2. What recovery exists

### If a pending admin proposal was already in flight

This is the only in-contract recovery, and it must have been set up **before** the loss:

- `propose_admin_rotation(new_admin)` requires the current admin, so it cannot be started
  after the key is gone.
- `confirm_admin_rotation()` requires only the **pending** admin's signature. If a proposal
  was pending and you still control that key, you can complete the handover without the old
  admin, then use the new admin to `unfreeze`.
- `cancel_admin_rotation()` requires the current admin, so the pending admin can still
  confirm even though the outgoing admin is unavailable.

The trade-off is real: a pre-staged pending admin is effectively a **recovery key that can
take over unilaterally**. While the current admin is alive it can cancel or overwrite the
proposal, but after the loss the pending admin acts alone. Stage it only with a key whose
custody is at least as strong as the admin's, and record the decision.

### If there is no pending admin

Nothing on-chain recovers the account:

| Attempt | Result |
|---|---|
| Agent `heartbeat` | Rejected (`heartbeat_expired`) — silence cannot self-revive. |
| `refresh_deadman()` | Permissionless, but only *records* the already-true fact and emits a telemetry event. It cannot unfreeze. |
| `freeze` / `unfreeze` | Admin-only; the signature cannot be produced. |
| `set_policy` / `revoke_policy` / `rotate_agent_key` | Admin-only. Also: a policy *edit* does not restart the dead-man clock (issue #289), so even a successful `set_policy` would not be a reversal on its own. |
| `propose_admin_rotation` | Requires the current admin. There is nobody to propose. |
| Redeploy a fresh guard | Produces a new, empty account. It does not move the old balance. |
| Upgrade the contract in place | No upgrade path exists; a deployed Soroban contract is immutable (`docs/architecture.md`). |

**Result: the balance is unspendable, permanently.** It is not stolen — nobody can move it,
including the admin — but it is not recoverable either. Say that plainly to stakeholders
rather than implying an escalation path exists.

## 3. If the admin key is lost but the account is still live

There is a race, and it is worth naming because it is the only situation with a choice. The
account freezes only on silence, so while the agent key is alive and heartbeating the
balance is still spendable **inside the existing policy** — but unmanageable:

- You cannot change caps, allowlists, `paused`, or the active window.
- You cannot rotate the agent key if it is later compromised.
- You cannot unfreeze once the grace lapses, and you cannot revive the account after
  `active_until` passes.
- The agent's heartbeat is now the only thing keeping the balance alive.

If the loss is confirmed, decide immediately between:

1. **Keep operating under the frozen policy.** Maintain heartbeats at `interval ≤ grace / 3`
   and accept that the account is one missed heartbeat away from permanent immobility. This
   is only reasonable when the policy is already the one you want and the agent key is
   secure.
2. **Wind the balance down.** Move what you need to a new, properly administered guard while
   the account is still live, using the existing policy's caps and allowlists. You cannot
   widen them, so plan the move against the current `per_tx_cap` and `window_cap` (the
   [migration guide](migration-guide.md#6-the-reverse-path--abandoning-the-guard) describes
   the mechanics and the reverse-path policy you cannot use here, because the admin is
   gone).

Do not pause, freeze, or let `active_until` pass "to be safe" — each of those is a one-way
door when you cannot sign as the admin.

## 4. Prevention

The switch is a managed risk, not a hidden trap. The controls, in order of value:

1. **Admin-key custody.** Keep the admin secret offline and separate from the agent host
   and the runtime's `AGENT_SECRET`. Back it up in a form you have actually restored once.
   Because admin compromise is also a control compromise (it can rewrite policy and rotate
   the agent key), custody has to be strong, not merely available.
2. **Size the grace deliberately.** Production guidance is several days, not the 60 seconds
   the testnet fixtures use. `dms_grace_secs: 0` disables the switch entirely and removes
   the liveness dependency — a legitimate choice for an account you can watch directly.
3. **Heartbeat cadence with margin.** Schedule at `interval ≤ grace / 3`, alert on
   `dms_health() == Warn` (80% of the grace), and page on `Expired`, not merely on failed
   transactions.
4. **Rehearse the reversal before it matters.** On testnet, arm a short grace, let it
   expire, and perform the admin `unfreeze` with the exact key and access path you would use
   in production. A dry run that uses a different key store or a different machine proves
   nothing about the incident path.
5. **Rehearse the handover while both keys are live.** The two-step ceremony
   (`propose_admin_rotation` → `confirm_admin_rotation`) is the only supported way to move
   admin authority; running it once means the key you would rely on in an incident has been
   exercised. See [`docs/key-rotation.md`](../key-rotation.md#admin-rotation-ceremony-two-step-handover).
6. **Decide the pending-admin question explicitly.** Either stage a pending admin and treat
   it as a recovery key with matching custody, or document that there is none and that
   admin-key loss is terminal.
7. **Record the recovery facts.** Guard ID, admin address, where the admin key lives, the
   current grace, and the last known `heartbeat_expires_at`. An incident is the wrong time
   to discover that the admin key was on the host that died.

## 5. Relationship to the admin-rotation work

The current design has one admin, and the two-step handover only helps while the current
admin can still sign. A **second admin / threshold model** would change this playbook: a
quorum could attest liveness and call `unfreeze` after one key is lost, so a single lost key
would no longer make the balance immobile. That work is not implemented — it is research in
[`docs/research/multi-sig-threshold-models.md`](../research/multi-sig-threshold-models.md),
and the current single-key model is specified in
[SPEC §7](../../SPEC.md#7-public-surface--exact-signatures-and-auth-placement) (the two-step
handover functions sit in the public surface) and
[SPEC §10](../../SPEC.md#10-threat-model-what-this-does-and-does-not-do).

When that lands, update this page rather than rewriting it: replace
[§2](#2-what-recovery-exists) with the quorum reversal procedure, keep the recognition and
prevention sections, and revisit the "no pending admin → terminal" statement.

## Incident checklist

- [ ] Confirm the gate: `status()` reports `admin_frozen: false`, `heartbeat_expired: true`,
      `has_policy: true`; `dms_health()` reports `Expired`.
- [ ] Check for a pending admin. There is no dedicated pending-admin read; use the
      `admin_rotation_proposed` event (or the SDK/dashboard view of it) and the proposal your
      operator recorded. If one exists and its key is available, confirm the handover, then
      `unfreeze`.
- [ ] If no pending admin: confirm the admin key is genuinely lost, not merely on another
      machine, and that no backup exists. Record the evidence.
- [ ] If the account is still live, choose between maintaining heartbeats and winding the
      balance down, and record the decision.
- [ ] Notify stakeholders in plain terms: funds are not stolen, but they are not recoverable
      without the admin key.
- [ ] Post-incident: move remaining operations to a new guard with rehearsed custody, or
      disable the switch, and update the runbook with what failed.

## See also

- [SPEC §5](../../SPEC.md#5-dead-man-switch--precise-definition) — the normative dead-man
  definition and its reversal boundary.
- [Dead-Man Switch](../concepts/dead-man-switch.md) — the explanatory concept page.
- [`docs/functions/freeze-unfreeze.md`](../functions/freeze-unfreeze.md) — `unfreeze`
  semantics, including `rearmed_dms` telemetry.
- [Storage rent and TTL](../rent-and-ttl.md) — what happens to persistent state if the
  account goes quiet for long enough that its entries expire.
- [Migration guide](migration-guide.md) — moving a balance into (and, with the agent key,
  out of) the guard.
