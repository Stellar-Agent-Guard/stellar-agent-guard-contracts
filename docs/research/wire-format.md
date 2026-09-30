# JSON Wire Format for Contract Read Functions

This document specifies the exact JSON serialization format returned by the contract's read functions (`policy`, `status`, `check`). These are the wire forms that non-Rust consumers (TypeScript SDK, dashboard, other language bindings) must decode.

**Source of truth:** Verified against live testnet deployment (contract `CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7`) as documented in README. The Soroban host uses `soroban-sdk`'s `serde` implementation for contract type serialization.

---

## `policy()` → `Option<PolicyConfig>`

Returns the current policy or `null` (default-deny).

### Example (live output, fixture policy):

```json
{
  "active_from": 0,
  "active_until": 0,
  "allow_any_recipient": false,
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "dms_grace_secs": 60,
  "paused": false,
  "per_tx_cap": "1000",
  "protocols": [],
  "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
  "window_cap": "150",
  "window_secs": 60
}
```

### Field naming convention:
- All fields are **snake_case** (matching Rust struct field names exactly)
- `i128` values serialize as **strings** (e.g., `"1000"`, `"150"`) — this is `soroban-sdk` behavior for large integers
- `Address` serializes as base32 string (e.g., `"CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"`)
- `Vec<T>` serializes as JSON array
- `Option<T>` serializes as `null` for `None`, or the inner value for `Some`

### Empty policy (default-deny):
```json
null
```

---

## `status()` → `Status`

Returns account status snapshot.

### Example (live output, before the #29 additive fields):

```json
{
  "admin_frozen": false,
  "has_policy": true,
  "heartbeat_expired": true,
  "last_heartbeat": 1788855212,
  "now": 1788863857,
  "policy_revision": 1
}
```

`policy_revision` is the `PolicyRevision` sequence counter (issue #38): it
increments on every `set_policy`/`revoke_policy` (starting at 1 after the first
install, never reset by a revoke) and is the join key that ties `auth_checked`
events to the policy generation in force — the `policy_set`, `policy_revoked`,
and `auth_checked` events stamp the same counter as additive `revision` data.

### Additive operational fields (issue #29):

`status()` additionally returns three operational fields. They are additive —
older decoders keep working because no existing key was renamed or removed:

```json
{
  "paused": false,
  "window_remaining": "150",
  "outside_active_window": false
}
```

- `paused` — the installed policy's admin kill switch; `false` when no policy
  is installed (default-deny has nothing to pause).
- `window_remaining` — global rolling-window headroom (`window_cap - spent`,
  expired entries pruned); `null` when the global cap is disabled, including
  the no-policy case. It mirrors `check_detailed().remaining_window` for a
  recipient without a per-recipient override. Note `Option<i128>` serializes
  as `null`/`"<i128-as-string>"` per the convention above.
- `outside_active_window` — `true` when `now` is outside the policy's
  `active_from`/`active_until` bounds (both inclusive); `false` with no policy
  or an unrestricted window.

### Field naming convention:
- All fields are **snake_case** (matching Rust struct field names exactly)
- `bool` fields serialize as JSON booleans (`true`/`false`)
- `u64` fields serialize as JSON numbers (or strings if >2^53, but timestamps fit in 53 bits)
- `Option<i128>` fields serialize as `null` for `None`, or a **string** for `Some`
  (same i128-as-string rule as `PolicyConfig` amounts)

---

## `check()` → `CheckResult`

Pre-flight simulation of an SAC transfer decision. Returns an enum with two variants.

### Allowed (bare variant):

```json
"Allowed"
```

### Blocked (tagged map with single key):

```json
{
  "Blocked": "heartbeat_expired"
}
```

### Enum serialization convention:
- **`Allowed`** serializes as a bare JSON string: `"Allowed"`
- **`Blocked(reason)`** serializes as a JSON object with a single key `"Blocked"` whose value is the reason string: `{"Blocked": "reason_string"}`
- This is the **externally tagged** enum representation used by `soroban-sdk`'s `serde` implementation
- The `reason` is a `Symbol` in Rust, which serializes as a plain JSON string

### All possible `Blocked` reason values (from `Error::reason()`):

| Reason String | Corresponding Error |
|---------------|---------------------|
| `unauthorized` | `Unauthorized` |
| `already_initialized` | `AlreadyInitialized` |
| `not_initialized` | `NotInitialized` |
| `invalid_config` | `InvalidConfig` |
| `invalid_amount` | `InvalidAmount` |
| `admin_frozen` | `AdminFrozen` |
| `heartbeat_expired` | `HeartbeatExpired` |
| `no_policy` | `NoPolicy` |
| `paused` | `Paused` |
| `outside_active_window` | `OutsideActiveWindow` |
| `asset_not_allowed` | `AssetNotAllowed` |
| `recipient_not_allowed` | `RecipientNotAllowed` |
| `per_tx_cap_exceeded` | `PerTxCapExceeded` |
| `window_cap_exceeded` | `WindowCapExceeded` |
| `protocol_not_allowed` | `ProtocolNotAllowed` |
| `function_not_allowed` | `FunctionNotAllowed` |
| `unknown_contract` | `UnknownContract` |
| `self_function_not_allowed` | `SelfFunctionNotAllowed` |
| `create_contract_not_allowed` | `CreateContractNotAllowed` |

---

## Decoder Breakage Warning

> ⚠️ **Field renames are breaking for SDK/dashboard — additive fields only**
>
> The JSON field names above are derived directly from Rust struct field names via `soroban-sdk`'s `#[contracttype]` derive. Any rename of a Rust field (e.g., `admin_frozen` → `is_admin_frozen`) changes the JSON wire format silently — non-Rust decoders (TypeScript, Python, etc.) will see `undefined`/`missing` fields, not an error.
>
> **Rule:** Only add new fields. Never rename or remove existing fields. Treat the JSON field names as a stable public API contract.

This rule applies to:
- `PolicyConfig` (all fields)
- `Status` (all fields)
- `CheckResult` enum tagging convention (`Allowed` bare vs `{"Blocked": "..."}`)

---

## Verification

The examples above were verified by invoking the live testnet contract:

```bash
# policy()
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- policy

# status()
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status

# check()
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  check --asset CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
```

Cross-reference: [README.md live outputs](../README.md) and [tests/fixtures/README.md](../tests/fixtures/README.md).