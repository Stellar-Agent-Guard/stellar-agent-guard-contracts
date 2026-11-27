# Rollback and policy-recovery runbook

Recovery after a bad policy installation has three different levers, and picking the wrong one
is how an incident becomes a loss of control. This page separates them: **pause** (stop spending
without changing the policy), **replacement** (install a known-good policy or move to a new guard
deployment), and **key rotation** (change who is authoritative). It is written for the admin
holding the key and for the on-call operator who has to decide quickly.

> **There is no code rollback.** Soroban contracts are immutable and cannot be upgraded in
> place; a deployed guard keeps its WASM forever
> ([architecture](../architecture.md#enforcement-equivalent-upgrade-policy)). "Rollback" below
> always means policy state, keys, or a new contract — never a downgraded binary. And no admin
> function moves funds: recovery changes *who may spend and under what policy*, it never
> withdraws a balance.

## Which lever

| Situation | Lever | Reversible? | Affects funds directly? |
|---|---|---|---|
| The agent must stop now; the installed policy and spend history are otherwise correct. | [Pause](#1-pause) — `freeze()` or `pause()` | Yes (`unfreeze()` / `resume()`) | No |
| The policy content is wrong: a cap, recipient, asset, active window, or DMS grace. | [Policy replacement](#2-policy-replacement) — corrected `set_policy` | Yes, by reinstalling the recorded previous config | No |
| The agent key may be leaked, or the agent key was lost. | [Agent-key rotation](#3-key-rotation) — `rotate_agent_key` | Partly (the old key can be reinstalled until it is retired) | No |
| The admin key is compromised, or you are handing administration over. | [Admin rotation](#3-key-rotation) — `propose_admin_rotation` → `confirm_admin_rotation` | Only until `confirm_admin_rotation` lands | No |
| The deployed WASM is wrong or a fix is required in contract code. | [Guard replacement](#4-replacing-the-guard-itself) — new deploy + migration | No (the old guard keeps its code and balance) | Funds must be migrated by the agent |

Two cases are **not** recovery levers:

- `unfreeze()` is not a general unblock. It clears `AdminFrozen` and re-arms the dead-man clock,
  so use it when the freeze is the reason the agent is blocked — not to paper over a policy that
  denies the spend.
- `revoke_policy` is not a pause. It removes the policy and leaves the account default-deny; the
  only way back is a full `set_policy`, which as a first install seeds a new window and a new
  dead-man clock. Use [`pause()`](#1-pause) when you intend to resume the same policy.

## Before any recovery step

Read the current state and record it. Every step below assumes these three reads are already in
your incident notes:

```bash
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- status
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- policy
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- policy_hash
# → record status, the full PolicyConfig, policy_hash, and policy_revision
```

`--send=no` is a simulation: it submits nothing and persists no TTL change. Confirm the network
and contract ID in every command before dropping `--send=no`; a recovery command sent to the
wrong network or a stale guard ID is the most common way to "recover" an account that was never
broken.

> **Universal confirmation checkpoint.** Before each state-changing call: (1) the `status` read
> above was taken within the last few minutes, (2) the command targets the recorded `<GUARD_ID>`
> on the recorded `<NETWORK>`, and (3) the exact JSON/arguments were rehearsed with `--send=no`.
> Record the resulting transaction hash next to the old state. If any of the three is missing,
> stop.

## 1. Pause

Two distinct pause mechanisms exist and they are not interchangeable
([SPEC §4.2](../../SPEC.md#42-admin-freeze-and-policy-pause)):

| | `pause()` / `resume()` | `freeze()` / `unfreeze()` |
|---|---|---|
| State touched | `PolicyConfig.paused` (in place) | `AdminFrozen` (separate persistent key) |
| Policy and window | Policy content and accumulated window spend preserved | Preserved |
| Side effect on recovery | `resume()` restores admissibility, **not** budget | `unfreeze()` sets `LastHeartbeat = now`, re-arming the dead-man clock |
| Prefer when | The policy is correct and you want the same policy back | You need an immediate halt and the freeze flag is what the operator runbook expects |

```bash
# Immediate halt without touching the policy.
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- freeze
# → Event: frozen (by: <ADMIN_G>)

# Same intent, expressed as policy pause (keeps freeze state untouched).
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- pause
# → Event: paused (by: <ADMIN_G>, revision: <N>)
```

**Verify before you walk away.** `status` must show `admin_frozen: true` (freeze) or `paused:
true` (pause), and an agent preflight must be blocked with the matching reason:

```bash
cd tools/agent-tx && cargo build --release
./target/release/agent-tx preflight --guard <GUARD_ID> --asset <SAC_ID> \
  --to <RECIPIENT_G> --amount 1
# → exit 1, reason `admin_frozen` or `paused`
```

> **Confirmation checkpoint (resume).** `resume()` restores spending immediately against the
> same window. Before resuming, confirm the policy is the one you intend to keep and that the
> window still has headroom — an incident pause does not refund already-counted spend.
> `unfreeze()` additionally re-arms the dead-man clock from now; if the agent is not yet running,
> prefer `resume()` when only the pause flag was set.

## 2. Policy replacement

Replacement means installing a **complete** `PolicyConfig`, not patching a field. `set_policy`
validates the whole config before writing anything, so a rejected config leaves the installed
policy intact ([validation rules](../../SPEC.md#8-config-validation-set_policy)).

Use this lever when the policy itself is wrong — a typo in `recipients`, a cap that is too low,
an `active_until` in the past, or an accidental `allow_any_recipient: true`.

1. Write the intended config to a file so the transaction is reviewable and repeatable.
2. Rehearse it: `validate_policy` names the first failing rule without changing state, and
   `set_policy --send=no` proves the full call simulates.
3. Install it and read back `policy`, `policy_hash`, and `policy_revision`.

```bash
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- validate_policy --config "$(cat policy.json)"
# → Valid   (or Invalid(rule) naming the field to fix)

stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=yes -- set_policy --config "$(cat policy.json)"
# → Event: policy_set (by: <ADMIN_G>, revision: <N+1>)
```

Rehearse that the corrected policy actually admits the intended spend **before** trusting it:

```bash
./tools/agent-tx/target/release/agent-tx preflight --guard <GUARD_ID> \
  --asset <SAC_ID> --to <RECIPIENT_G> --amount 1
```

Editing an installed policy **preserves the rolling window and the dead-man clock** (issue #289):
already-counted spend stays counted, and a DMS-expired account stays expired. If the incident is
"the account is blocked because the window is exhausted", a policy edit is not the fix — choose
one of the deliberate budget levers instead:

- `reset_window()` — admin-attested, zeroes accumulated spend, emits `window_reset`. This is the
  right call when the window was consumed by a runaway loop rather than by an attacker.
- `increase_window_cap(new_cap)` — raises the cap in place without refunding spend, emits
  `window_cap_increased`.
- `revoke_policy` → `set_policy` — the only path that starts a **fresh** window and grace, because
  the reinstall counts as a first install. It also leaves the account default-deny in between, so
  do not use it as a pause.

> **Confirmation checkpoint (destructive).** `reset_window()` erases spend accounting and
> `revoke_policy` removes the policy entirely. Before either, confirm the spend you are erasing is
> understood and written down (window contents via the events log, transaction hashes in your
> incident note), and that the agent is paused or frozen so new spend cannot arrive between the
> reset and the reinstall.

## 3. Key rotation

Key rotation changes authority without moving funds. The full ceremonies — offline key
generation, rehearsal, verification that the new key signs, and rollback — are in
[`docs/key-rotation.md`](../key-rotation.md). The recovery-specific points:

- **Agent key** — admin-only `rotate_agent_key(new_pubkey)`. There is no confirmation step: the
  new key is authoritative as soon as the transaction lands. Keep the old secret until the new
  key has produced a successful heartbeat and a preflight, then retire it.
- **Admin key** — two-step handover. `propose_admin_rotation(new_admin)` is reversible with
  `cancel_admin_rotation()`; `confirm_admin_rotation()` is signed by the *pending* admin and is
  the point of no return — the outgoing admin loses authority immediately.
- **Lost agent key** — rotate first, then `unfreeze` if the dead-man switch expired; a heartbeat
  cannot revive an expired account. If the admin key is also gone, the balance stays at the
  contract address: see the
  [incident playbook](incident-playbook-admin-key-lost.md).

Agent key rotation, in short (admin signs; `new_pubkey` is 64 lowercase hex characters, not a
`G...` address):

```bash
stellar contract invoke --id <GUARD_ID> --network <NETWORK> \
  --source-account <ADMIN_ALIAS> --send=no -- \
  rotate_agent_key --new_pubkey <NEW_64_HEX_CHARS>
# rehearse, then repeat with --send=yes
# → Event: agent_rotated (old_fingerprint, new_fingerprint)
```

> **Confirmation checkpoint (irreversible).** Before `rotate_agent_key`, prove you hold the new
> secret and have derived the correct raw pubkey offline (`cargo run --example agent_pubkey`).
> Rotating to a pubkey whose secret you do not hold locks the agent out permanently — the admin
> can rotate again, but only the admin key can, and only if it survives. Before
> `confirm_admin_rotation`, confirm both admins agree and the new admin has successfully signed a
> test transaction; there is no admin-of-last-resort after that point.

## 4. Replacing the guard itself

Required when the deployed WASM is wrong. A new guard is a **new custom account**: a new `C...`
address, a fresh `initialize`, a new policy, and a balance that is still at the old address.
Nothing carries over automatically, and the old guard remains fully operational under its own
keys, so retiring it is a separate decision.

1. Deploy and initialize the replacement — [deployment runbook](deployment-runbook.md).
2. Install and read back the policy; record `policy_hash`.
3. Move the balance with the [migration guide](migration-guide.md), including its one-unit
   rehearsal. The admin cannot sweep the old balance; only the registered agent key can, and only
   inside the old policy (a permissive exit policy is the documented path).
4. Revoke the old policy so the old account is default-deny.

> **Confirmation checkpoint (destructive).** A transfer to an unverified contract address is
> irreversible, and a contract cannot be upgraded later. Before moving value: the destination
> guard's `status` was read from the same network, a one-unit transfer was verified at the
> `C...` address, and the old account's exit policy names exactly one recipient. Do not batch
> the balance move with any other change.

## Recovery record

Complete this for the incident file and the deployment record:

- [ ] Symptom, first observation time (UTC), and which read proved it.
- [ ] Lever chosen, and why the other two were rejected.
- [ ] Pre-change `status`, `policy`, `policy_hash`, `policy_revision`.
- [ ] Every transaction hash submitted during recovery, in order, with its event.
- [ ] Post-change reads proving the intended state (pause flag, policy hash, agent fingerprint).
- [ ] Whether the dead-man clock was re-armed, and the agent's heartbeat deadline if so.
- [ ] Follow-ups: policy template correction, alerting gap, or key-custody change.

The redaction-safe evidence layout for these notes is the
[incident evidence bundle](incident-evidence-bundle.md).

## See also

- [Deployment runbook](deployment-runbook.md) — the ordered deploy and verification sequence.
- [Migration guide](migration-guide.md) — moving a balance into a guard, and the exit path.
- [Key rotation](../key-rotation.md) — the full agent/admin rotation ceremonies.
- [Incident playbook — DMS-frozen, admin key lost](incident-playbook-admin-key-lost.md).
- [SPEC §4.2](../../SPEC.md#42-admin-freeze-and-policy-pause) — freeze vs pause semantics.
