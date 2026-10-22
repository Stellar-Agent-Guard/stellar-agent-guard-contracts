# admin rotation (`propose` / `confirm` / `cancel`)

Two-step handover of the policy admin to a new address (SPEC §7.2).

## Why two steps

The admin governs policy, freeze, and keys — but holds no fund-moving power
(SPEC §1). A single-step rotation on the current admin's authority alone would
hand that power to whatever address was typed: one typo locks out policy
management with no recovery path. The handover is therefore split:

1. **Propose** — the current admin records intent. Nothing else changes, so a
   proposal to a wrong address is inert.
2. **Confirm** — only the *proposed* admin can complete it, by signing. The
   confirmation doubles as proof the new key is live and correctly recorded,
   which is what makes typos un-harmful: a proposal to an uncontrolled address
   can never be confirmed.
3. **Cancel** (or overwrite with a fresh proposal) — the current admin's
   recovery path while a proposal is pending.

## propose_admin_rotation

### Signature

```rust
pub fn propose_admin_rotation(env: Env, new_admin: Address)
```

### Auth placement

`require_auth(Admin)` — only the current policy admin can propose its successor.

### Behavior

1. Rejects self-proposal (`new_admin == Admin`) with `InvalidConfig` — a no-op
   handover that would emit a misleading event trail.
2. Stores `PendingAdmin = new_admin` in instance storage (overwrites any
   earlier proposal).
3. Emits `EventAdminRotationProposed` with `by: admin` and `proposed: new_admin`.

The current admin stays fully authoritative until confirmation.

### Example

```bash
stellar contract invoke --id GUARD_CONTRACT_ID \
  --network testnet --source-account guard_admin --send=yes -- \
  propose_admin_rotation --new_admin GNEW...
# → Event: EventAdminRotationProposed (event_admin_rotation_proposed),
#    by: "<current admin>", proposed: "<new admin>"
```

## confirm_admin_rotation

### Signature

```rust
pub fn confirm_admin_rotation(env: Env)
```

### Auth placement

`require_auth(PendingAdmin)` — only the proposed admin can confirm. Anyone
else (including the still-current admin) is rejected by the host before any
state changes.

### Behavior

1. No `Admin` stored (pre-`initialize`) → `NotInitialized`.
2. No `PendingAdmin` stored → `NoPendingAdmin`.
3. Sets `Admin = pending`, clears `PendingAdmin`, in one write — there is no
   window in which both admins (or neither) can act.
4. Emits `EventAdminRotated` with `old: <outgoing>` and `new: <incoming>`.

Policy, window, heartbeat clock, and freeze flags are untouched, and
`PolicyRevision` does **not** bump — the policy did not change, only its
manager.

### Example

```bash
stellar contract invoke --id GUARD_CONTRACT_ID \
  --network testnet --source-account guard_admin_new --send=yes -- \
  confirm_admin_rotation
# → Event: EventAdminRotated (event_admin_rotated),
#    old: "<outgoing admin>", new: "<incoming admin>"
```

Note the `--source-account`: the confirmation must be signed by the **new**
admin identity, not the old one.

### Post-confirm

The old admin's authorization satisfies nothing anymore — subsequent
`set_policy`, `freeze`, `propose_admin_rotation`, or any other admin gate
signed by the old key is rejected. Verify with `status()` (policy revision
unchanged) and one new-admin write (e.g. `freeze` + `unfreeze`).

## cancel_admin_rotation

### Signature

```rust
pub fn cancel_admin_rotation(env: Env)
```

### Auth placement

`require_auth(Admin)` — only the current admin can cancel. The pending address
has no power until it confirms.

### Behavior

1. No `PendingAdmin` stored → `NoPendingAdmin` (a double cancel fails loudly
   rather than silently succeeding).
2. Clears `PendingAdmin`.
3. Emits `EventAdminRotationCancelled` with `by: admin` and
   `cancelled: <pending>`.

### Example

```bash
stellar contract invoke --id GUARD_CONTRACT_ID \
  --network testnet --source-account guard_admin --send=yes -- \
  cancel_admin_rotation
# → Event: EventAdminRotationCancelled (event_admin_rotation_cancelled),
#    by: "<current admin>", cancelled: "<pending admin>"
```

## Typo recovery

Proposed the wrong address? Either transaction recovers — the current admin is
still authoritative:

```bash
# Option A: overwrite with the correct address, then have it confirm.
stellar contract invoke --id GUARD_CONTRACT_ID \
  --network testnet --source-account guard_admin --send=yes -- \
  propose_admin_rotation --new_admin GCORRECT...

# Option B: cancel outright.
stellar contract invoke --id GUARD_CONTRACT_ID \
  --network testnet --source-account guard_admin --send=yes -- \
  cancel_admin_rotation
```

## Storage keys touched

| Function | Key | Type | Action |
|---|---|---|---|
| `propose_admin_rotation` | `PendingAdmin` | `Address` (instance) | Set to the proposed admin (overwrites) |
| `confirm_admin_rotation` | `Admin` | `Address` (instance) | Set to the pending admin |
| `confirm_admin_rotation` | `PendingAdmin` | `Address` (instance) | Removed |
| `cancel_admin_rotation` | `PendingAdmin` | `Address` (instance) | Removed |

## See also

- [Key rotation ceremony](../key-rotation.md) — the operator runbook for both keys
- SPEC §7.2 (two-step rationale), §9 (event vocabulary)
