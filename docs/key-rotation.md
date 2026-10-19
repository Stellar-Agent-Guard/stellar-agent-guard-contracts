# Key rotation ceremony — agent key + admin key

Operational runbook for rotating the keys that govern a guarded account.
Audience: the operator holding the admin identity, and any contributor
rehearsing the ceremony on testnet.

> **Scope.** This is the raw-contract / CLI path. Sibling repositories
> (`stellar-agent-guard-sdk`, `stellar-agent-guard-dashboard`) are out of
> scope — cross-repo work is tracked in its own repository.

## What can and cannot rotate

| Key | Stored in | Rotation mechanism | Status |
|---|---|---|---|
| Agent key (`AgentPubkey`, `BytesN<32>`) | instance storage, set at `initialize` | `rotate_agent_key(new_pubkey)` — admin-only | ✅ Available today |
| Admin (`Admin`, `Address`) | instance storage, set at `initialize` | two-step handover: `propose_admin_rotation` (current admin) → `confirm_admin_rotation` (pending admin); `cancel_admin_rotation` aborts | ✅ Available — see [Admin rotation ceremony](#admin-rotation-ceremony-two-step-handover) |

The admin address is written by `initialize` (`src/lib.rs`) and changed only
by the two-step handover below (SPEC §7.2,
[function reference](functions/admin-rotation.md)). The ceremony is
deliberately two transactions: the confirmation must be signed by the
**incoming** admin, which proves the new key is live and makes a typo'd
proposal un-harmful (it can never confirm, and the current admin can overwrite
or cancel it). Until `confirm_admin_rotation` lands, the current admin stays
fully authoritative.

Losing the admin key does **not** put funds at risk: the admin holds no
fund-moving authority (SPEC §1, `SECURITY.md`). It means losing the ability
to change policy, freeze/unfreeze, or rotate the agent key. If the admin key
is lost (not merely compromised), no handover is possible — there is nobody to
sign the proposal — and the recovery path is still to deploy a fresh guard,
`initialize` it with a new admin, `set_policy` to mirror the old policy, and
move operations over.

## When to rotate the agent key

- **Suspected leak** — the agent secret may have been exfiltrated
  (prompt-injection exfil, log leak, compromised host). Use the
  [incident variant](#incident-variant-suspected-agent-key-leak) below:
  freeze first, then rotate, then unfreeze.
- **Personnel / infrastructure change** — whoever held the agent secret is
  leaving, or the runtime moves to a new host. Scheduled rotation; no freeze
  needed if there is no suspicion of compromise.
- **Scheduled hygiene** — periodic rotation on a calendar (e.g. quarterly).
  Cheap, single-transaction, and rehearsed below.

In all three cases the mechanics are identical; only the freeze-first
ordering differs.

## Scheduled rotation ceremony (step by step)

Prerequisites: the guard contract ID, the admin identity (`guard_admin`
below), and the **current** agent public key hex (so you can roll back).
Keep the old secret reachable until the new key is confirmed working —
rotation is atomic and the old key stops authorizing immediately.

### 0. Record the current state

```bash
# Confirm the account is healthy before touching keys.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → expect {"admin_frozen":false,...,"heartbeat_expired":false,...}

stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- policy
# → expect the active PolicyConfig (has_policy:true in status)
```

**Verify:** `admin_frozen` is `false`, `heartbeat_expired` is `false`.
If either is `true`, run the
[freeze / unfreeze](functions/freeze-unfreeze.md) reversal first — rotating
the key on a frozen account leaves you with a new key on a still-frozen
account.

### 1. Generate the new key offline

Generate a fresh Stellar secret **off the agent host** (new machine, HSM,
or `stellar keys` store) and derive the raw 32-byte Ed25519 public key the
contract registers — not the `G...` address:

```bash
# Derive the raw pubkey hex from the NEW secret (repo helper).
echo 'SNEW...' | cargo run --example agent_pubkey
# → <64 lowercase hex chars, e.g. 1cb479ac...>
```

**Verify:** the output is 64 hex chars and differs from the current agent
pubkey. Save both hex strings; you need the old one for rollback.

### 2. Rehearse the rotation (testnet-safe, nothing submitted)

`rotate_agent_key` is admin-only (`require_auth(Admin)`, SPEC §7). Simulate
it first with `--send=no` — this runs validation without writing anything:

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  rotate_agent_key --new_pubkey <NEW_64_HEX_CHARS>
# → success (no event yet — simulation only)
```

**Verify:** the simulation succeeds. There is no config validation to trip
here (a pubkey is just 32 bytes), so a failure means the admin auth or the
contract ID is wrong — fix that before proceeding.

### 3. Rotate (admin transaction)

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=yes -- \
  rotate_agent_key --new_pubkey <NEW_64_HEX_CHARS>
# → Event: EventAgentRotated (event_agent_rotated),
#    by: "<admin>", old_fingerprint: <8B>, new_fingerprint: <8B>
```

**Verify — the event is the confirmation.** `agent_rotated` carries
`by` (the admin), `old_fingerprint`, and `new_fingerprint` (SPEC §9). A
fingerprint is `sha256(pubkey)[0..8]` — the first 8 bytes of the SHA-256
digest, rendered as 16 lowercase hex characters off-chain. Check that
`old_fingerprint` matches the key you just replaced and `new_fingerprint`
matches the key from step 1. If either is wrong, you rotated to the wrong
key — roll back immediately (below).

Storage touched: `AgentPubkey` (instance) is overwritten. Nothing else
changes — the policy, window, heartbeat clock, and freeze flags are
untouched, so spending headroom and DMS grace carry over.

### 4. Confirm the new key signs before retiring the old

Point the agent runtime at the **new** secret and prove it authorizes
through the real `__check_auth` path. The `stellar` CLI cannot sign auth
entries whose address is a contract, so use the submission helper:

```bash
cd tools/agent-tx && cargo build --release && cd ../..

# New-key heartbeat (agent-signed self-call through __check_auth).
./tools/agent-tx/target/release/agent-tx heartbeat \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --agent-secret SNEW...
# → RESULT: ALLOWED, event (event_heartbeat) data=at:<unix>
```

**Verify:** `RESULT: ALLOWED` and a fresh `event_heartbeat`. Then prove the
old key is dead — a transfer signed with the **old** secret must now fail
closed (blocked pre-broadcast, never consuming window):

```bash
./tools/agent-tx/target/release/agent-tx transfer \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 1 \
  --agent-secret SOLD... --expect-blocked
# → BLOCKED (pre-broadcast, enforced simulation)
```

**Verify:** the old key is `BLOCKED`. Only now — new key demonstrated live,
old key demonstrated dead — is it safe to delete the old secret. Update the
runtime's stored secret (`AGENT_SECRET`) to the new value and restart the
heartbeat scheduler from the
[agent loop](../examples/agent-loop.md) (`interval ≤ grace / 3`).

### 5. Rollback (if anything above fails)

Rotation is just another admin write, so rollback is rotation in reverse —
call `rotate_agent_key` with the **old** pubkey hex you saved in step 1:

```bash
# Rehearse first, exactly as in step 2.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  rotate_agent_key --new_pubkey <OLD_64_HEX_CHARS>

# Then roll back.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=yes -- \
  rotate_agent_key --new_pubkey <OLD_64_HEX_CHARS>
# → Event: EventAgentRotated, fingerprints swapped back
```

**Verify:** the event's `new_fingerprint` equals the original key's
fingerprint, and the original agent secret heartbeats `ALLOWED` again
(step 4 with `SOLD...`). Rollback is safe to attempt at any point — before
or after the new key was confirmed — because it only re-binds which key
`__check_auth` verifies; it never moves funds or alters policy.

## Incident variant: suspected agent-key leak

Ordering: **freeze → rotate → unfreeze.** Do not rotate first.

**Rationale (freeze first — stop the bleeding before the ceremony).**
`AdminFrozen` is decision-table gate #1 (SPEC §4): it blocks *every*
authorization, including transfers signed with the leaked key and even that
key's heartbeats. Rotation alone leaves a window — between suspicion and the
rotation transaction confirming — in which the leaked key still authorizes
within policy (caps and allowlists bind it, but small drains are still
possible). `freeze` closes that window in one admin transaction, and because
it also blocks heartbeats, the attacker cannot extend their foothold via
the DMS clock while you work. The ceremony below then proceeds with the
account inert.

```bash
# 1. Freeze — one admin transaction, immediate effect.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- freeze
# → Event: EventFrozen (event_frozen)

# 2. Verify the freeze before doing anything else.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → expect {"admin_frozen":true,...} — the account is now inert.

# 3. Generate the new key offline (ceremony step 1) and rotate (steps 2–3).
#    Rotation works while frozen — it is an admin function, not an agent
#    authorization — so no unfreeze is needed first.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=yes -- \
  rotate_agent_key --new_pubkey <NEW_64_HEX_CHARS>
# → Event: EventAgentRotated

# 4. Unfreeze — the admin's liveness attestation. This clears AdminFrozen
#    AND restarts the heartbeat clock (LastHeartbeat = now), so the new key
#    gets full DMS grace from this moment.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- unfreeze
# → Event: EventUnfrozen (event_unfrozen)

# 5. Confirm the new key (ceremony step 4): new-secret heartbeat ALLOWED,
#    old-secret transfer BLOCKED. Then retire the old secret.
```

**Verify at the end:** `status` reads `admin_frozen: false`,
`heartbeat_expired: false`; the new secret heartbeats `ALLOWED`; the old
secret is `BLOCKED`. If the new key misbehaves, the rollback (above) still
applies — re-freeze first if the old key is still considered hostile.

## Admin rotation ceremony (two-step handover)

Prerequisites: the guard contract ID, the current admin identity
(`guard_admin` below), and the **new** admin address (`GNEW...` below) whose
secret you control — the confirmation must be signed by the incoming admin, so
rehearse with access to both identities.

### 1. Propose (current admin transaction)

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=yes -- \
  propose_admin_rotation --new_admin GNEW...
# → Event: EventAdminRotationProposed (event_admin_rotation_proposed),
#    by: "<current admin>", proposed: "<new admin>"
```

**Verify:** the event's `proposed` is exactly the address you intend. Nothing
else changed — the current admin is still authoritative, the policy and its
revision are untouched, and the agent key still spends. If the address is
wrong, stop here: overwrite with a corrected proposal or `cancel_admin_rotation`
— no harm done, no second key involved yet.

### 2. Confirm (incoming admin transaction)

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin_new --send=yes -- \
  confirm_admin_rotation
# → Event: EventAdminRotated (event_admin_rotated),
#    old: "<outgoing admin>", new: "<incoming admin>"
```

**Verify — three reads, in order:**

```bash
# 1. The handover completed: policy revision unchanged (rotation moves the
#    manager, not the policy).
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin_new --send=no -- status
# → expect {"has_policy":true,"policy_revision":<same as before>,...}

# 2. The new admin is authoritative (freeze + unfreeze round-trip).
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin_new --send=yes -- freeze
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin_new --send=yes -- unfreeze

# 3. The old admin is dead: any admin call signed by it is now rejected.
```

Only now is it safe to retire the old admin secret. There is no rollback
distinct from rotation itself — handing back is another propose → confirm in
reverse.

### Incident variant: suspected admin-key compromise

Ordering: **rotate first, then audit policy.** Unlike the agent-key leak, there
is no freeze-first shortcut that helps beyond the normal one: the compromised
key *is* an admin, so it can unfreeze itself. `freeze` still buys a window
(the attacker must issue an `unfreeze` to act, which is itself an auditable
event), but treat the policy as hostile until re-attested:

1. `freeze` from a still-honest admin path if one exists (delays, does not stop).
2. Complete the handover to a fresh admin (propose → confirm).
3. From the new admin: re-`set_policy` to a known-good config (this resets the
   window and restarts the DMS clock — review both), `unfreeze` if frozen, and
   `rotate_agent_key` if the agent key may also be exposed.
4. Reconcile the event log (`admin_rotation_proposed` → `admin_rotated`,
   any `policy_set` by the old key) before resuming operations.

## Storage keys touched

| Function | Key | Kind | Action |
|---|---|---|---|
| `rotate_agent_key` | `AgentPubkey` | instance (`BytesN<32>`) | overwritten with the new key |
| `propose_admin_rotation` | `PendingAdmin` | instance (`Address`) | set to the proposed admin (overwrites) |
| `confirm_admin_rotation` | `Admin` | instance (`Address`) | set to the pending admin |
| `confirm_admin_rotation` | `PendingAdmin` | instance (`Address`) | removed |
| `cancel_admin_rotation` | `PendingAdmin` | instance (`Address`) | removed |
| `freeze` (incident only) | `AdminFrozen` | persistent (`bool`) | set to `true` |
| `unfreeze` (incident only) | `AdminFrozen` | persistent (`bool`) | set to `false` |
| `unfreeze` (incident only) | `LastHeartbeat` | persistent (`u64`) | set to `now` (full grace restart) |

## See also

- [admin rotation](functions/admin-rotation.md) — the propose/confirm/cancel
  function reference with typo-recovery steps
- [freeze / unfreeze](functions/freeze-unfreeze.md) — the kill switch and
  reversal used by the incident variant
- [heartbeat](functions/heartbeat.md) — proving the new key through the
  real `__check_auth` path
- [Dead-Man Switch](concepts/dead-man-switch.md) — why `unfreeze` restarts
  the clock
- [Agent runtime loop](../examples/agent-loop.md) — heartbeat cadence and
  blocked-reason handling after rotation
- SPEC §7 (auth placement: admin-only rotation), §9 (the `agent_rotated`
  event and fingerprint construction)
