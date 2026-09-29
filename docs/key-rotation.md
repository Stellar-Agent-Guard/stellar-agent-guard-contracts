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
| Admin (`Admin`, `Address`) | instance storage, set at `initialize` | none | ❌ No rotation today — the admin is immutable |

The admin address is written **once** by `initialize` (`src/lib.rs`) and no
public function changes it. There is deliberately no `rotate_admin` in v1:
until one lands, treat the admin identity as permanent. If the admin key is
lost or suspected compromised, the recovery path is to deploy a fresh guard,
`initialize` it with a new admin, `set_policy` to mirror the old policy, and
move operations over — there is no in-place admin handover. (If a
`rotate_admin` issue lands in the tracker, this paragraph must be updated to
link it.)

Losing the admin key does **not** put funds at risk: the admin holds no
fund-moving authority (SPEC §1, `SECURITY.md`). It means losing the ability
to change policy, freeze/unfreeze, or rotate the agent key.

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

## Storage keys touched

| Function | Key | Kind | Action |
|---|---|---|---|
| `rotate_agent_key` | `AgentPubkey` | instance (`BytesN<32>`) | overwritten with the new key |
| `freeze` (incident only) | `AdminFrozen` | persistent (`bool`) | set to `true` |
| `unfreeze` (incident only) | `AdminFrozen` | persistent (`bool`) | set to `false` |
| `unfreeze` (incident only) | `LastHeartbeat` | persistent (`u64`) | set to `now` (full grace restart) |

## See also

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
