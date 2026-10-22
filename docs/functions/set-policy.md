# set\_policy

Admin-only function. Installs or replaces the spend policy on the guarded account.

## Signature

```rust
pub fn set_policy(env: Env, config: PolicyConfig)
```

## Auth placement

`require_auth(Admin)` — only the policy admin can change the policy.

## Behavior

1. Validates the config (see [Configuration validation](#configuration-validation) below). Invalid config fails with `InvalidConfig` and leaves the policy unchanged (fail-closed).
2. Stores the new `PolicyConfig` in persistent storage.
3. Increments `PolicyRevision` (0 before the first policy action; never reset by `revoke_policy`).
4. **Preserves the rolling window** when a policy is already installed (issue #289):
   pausing, tightening, or widening a policy no longer hands the agent a fresh budget.
   Only a *first* install (no policy stored — including an install after `revoke_policy`)
   removes the window entry and starts from an empty ledger.
5. Sets `LastHeartbeat = now` **on first install only** — a fresh policy gets full
   dead-man-switch grace, while a policy *edit* leaves the DMS clock untouched (a
   DMS-expired account stays expired; the reversal path is `unfreeze`, §5.1).
6. Emits `EventPolicySet`, whose data carries `by` and the new `revision` value — the
   join key telemetry uses to attribute `auth_checked` events to the exact policy
   generation in force (issue #38).

The explicit window zeroing is the separate admin entry point
[`reset_window`](#reset_window) (issue #289); to flip only the kill switch without
rewriting the policy, use [`pause` / `resume`](freeze-unfreeze.md#pause--resume) (issue
#290).

## PolicyConfig fields

| Field | Type | Meaning |
|---|---|---|
| `per_tx_cap` | `i128` | per asset-transfer call cap; `0` = disabled |
| `window_secs` | `u64` | rolling window width in seconds (default 86,400) |
| `window_cap` | `i128` | rolling cap within `window_secs`; `0` = disabled |
| `assets` | `Vec<Address>` | SAC token contracts whose transfers get parsed and enforced |
| `protocols` | `Vec<ProtocolRule>` | allowlisted non-asset contracts |
| `recipients` | `Vec<Address>` | allowed SAC transfer destinations |
| `allow_any_recipient` | `bool` | escape hatch: skip recipient allowlist (caps still apply) |
| `active_from` | `u64` | active window start (unix seconds); `0` = unrestricted |
| `active_until` | `u64` | active window end (unix seconds); `0` = unrestricted |
| `paused` | `bool` | admin kill switch |
| `dms_grace_secs` | `u64` | dead-man switch grace; `0` = disabled |

## Configuration validation

The following rules are checked before anything is written. Invalid config returns `InvalidConfig` and leaves the policy unchanged:

- `per_tx_cap >= 0` and `window_cap >= 0` (no negative caps)
- If `window_cap > 0` then `window_secs > 0`
- `per_tx_cap <= window_cap` when both are enabled (both > 0)
- If `active_until != 0` then `active_until > active_from`
- No duplicate addresses in `assets` or `recipients`
- No duplicate protocol contracts
- Empty per-protocol `fns` lists are rejected
- Self-address may not appear in `assets`, `protocols`, **or `recipients`** — the account
  paying itself is a no-op loop that almost certainly signals a mis-pasted address

## Example

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=yes -- set_policy --config '{
    "active_from": 0, "active_until": 0, "allow_any_recipient": false,
    "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
    "dms_grace_secs": 60, "paused": false, "per_tx_cap": "1000",
    "protocols": [], "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
    "window_cap": "150", "window_secs": 60 }'
# → Event: EventPolicySet (event_policy_set)
```

Real Phase-1 policy transaction (scenarios 1–4): `6f17c5707d86754cc64f7f5adf6d9b9840904f0bea4d10ae5620ffe065c61174`

## Edge cases

### Invalid active window

```bash
# active_until (100) <= active_from (200) → InvalidConfig
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- set_policy --config '{
    "active_from": 200, "active_until": 100, ...}'
# → Error(Contract, #4)  (InvalidConfig)
```

### Window cap without window secs

```bash
# window_cap > 0 but window_secs == 0 → InvalidConfig
```

### Replacing an existing policy

`set_policy` replaces the existing policy and **preserves the rolling window and the
dead-man-switch clock** (issue #289). Accumulated spend keeps counting against the new
cap, and a policy edit cannot restart a lapsed dead-man grace — neither the kill switch
nor a tightening hands the agent a fresh budget. Only a *first* install (no policy stored,
including after `revoke_policy`) starts from an empty window with a freshly armed DMS
clock.

### `reset_window` — the explicit reset

```rust
pub fn reset_window(env: Env)
```

Admin-only (`require_auth(Admin)`). Removes the `Window` entry — the explicit,
admin-attested zeroing `set_policy` no longer performs implicitly (issue #289). Idempotent
(an absent or empty window is a no-op that still records the admin action), does not touch
`Policy`, `PolicyRevision`, or `LastHeartbeat`, and emits `EventWindowReset` carrying
`by`. Reach for it only when a fresh budget is actually intended (e.g. after raising
`window_cap` mid-incident).

## Storage keys touched

| Key | Type | Action |
|---|---|---|
| `Policy` | `PolicyConfig` | Write |
| `PolicyRevision` | `u64` | Increment |
| `Window` | `WindowState` | Removed on **first install only** (issue #289); preserved across edits — `reset_window` is the explicit reset |
| `LastHeartbeat` | `u64` | Set to now on **first install only** (issue #289); preserved across edits |

## See also

- [initialize](initialize.md) — must be called first
- [Enforcement Scope](../enforcement-scope.md) — what the policy can and cannot enforce
