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
3. Resets the rolling window to empty (`Ledger::empty`).
4. Sets `LastHeartbeat = now` — a fresh policy gets full dead-man-switch grace.
5. Emits `EventPolicySet`.

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

`set_policy` replaces the existing policy and **resets the rolling window**. This is by design: a fresh policy gets a fresh window, preventing an old window's accumulated spend from carrying over into a new policy's cap.

## Storage keys touched

| Key | Type | Action |
|---|---|---|
| `Policy` | `PolicyConfig` | Write |
| `Window` | `WindowState` | Reset to empty |
| `LastHeartbeat` | `u64` | Set to now |

## See also

- [initialize](initialize.md) — must be called first
- [Enforcement Scope](../enforcement-scope.md) — what the policy can and cannot enforce
