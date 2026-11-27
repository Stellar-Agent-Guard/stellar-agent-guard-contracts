# End-to-end walkthrough — guarded token transfer

This walkthrough traces the complete lifecycle of a guarded account from deployment through a live token transfer, covering policy creation, installation, an authorized transfer, a denied transfer, and the events each step emits. It is designed so each stage can be run against Stellar testnet without secrets in the shell history.

> **Prerequisites:** `stellar` CLI installed, a testnet account funded via Friendbot, and `tools/agent-tx` built (`cargo build --release --manifest-path tools/agent-tx/Cargo.toml`). The contract WASM is built with `cargo build --release --target wasm32v1-none`.

---

## 1. Deploy and initialize

### 1a. Deploy the contract WASM

```bash
stellar contract deploy \
  --wasm target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm \
  --source guard_admin \
  --network testnet
# → CONTRACT_ID  (e.g. CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7)
```

### 1b. Derive the agent's Ed25519 public key

The agent holds a Stellar key pair. Its raw 32-byte Ed25519 public key is what gets registered:

```bash
echo 'S<AGENT_SECRET>' | cargo run --example agent_pubkey
# → <32-byte hex pubkey, e.g. 1cb479ac...>
```

### 1c. Initialize the guard

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --network testnet \
  --source guard_admin \
  --send=yes \
  -- initialize \
  --admin $(stellar keys address guard_admin) \
  --agent_pubkey <32-byte hex pubkey>
```

**What happens inside `initialize`:**
- The admin address and agent pubkey are stored in instance storage.
- `AdminFrozen` is set to `false`, `LastHeartbeat` to `0`.
- An `EventInitialized` event is emitted with the first 4 bytes of the agent pubkey as `agent_fingerprint`.

After this call the account is **default-deny** — no policy is installed, so every authorization attempt returns `NoPolicy`.

---

## 2. Create and install a policy

### 2a. Define a spend policy

Policies are expressed as `PolicyConfig` structs. Here is a minimal payment-bot policy in Rust terms:

```rust
PolicyConfig {
    per_tx_cap: 1_000_000_000,     // 100 XLM per transfer (7 decimal places)
    window_secs: 86_400,            // 24-hour rolling window
    window_cap: 10_000_000_000,     // 1000 XLM total per window
    assets: vec![env, xlm_contract_address],
    protocols: Vec::new(env),
    recipients: vec![env, treasury_address],
    recipient_window_caps: Vec::new(env),
    blocked_recipients: Vec::new(env),
    asset_caps: Vec::new(env),
    allow_any_recipient: false,
    active_from: 0,
    active_until: 0,
    paused: false,
    dms_grace_secs: 86_400,         // 24-hour dead-man window
    protocol_calls_per_window: 0,
}
```

This policy:
- Allows up to 100 XLM per transfer to `treasury_address`.
- Allows up to 1 000 XLM total in any rolling 24-hour window.
- Blocks all recipients except `treasury_address` (`allow_any_recipient: false`).
- Enables the dead-man switch — if the agent misses a heartbeat for 24 hours, the account freezes.

### 2b. Install the policy with `set_policy`

```bash
stellar contract invoke \
  --id $CONTRACT_ID \
  --network testnet \
  --source guard_admin \
  --send=yes \
  -- set_policy \
  --config '{ "per_tx_cap": "1000000000", "window_secs": 86400, ... }'
```

**What happens inside `set_policy`:**
1. SPEC §8 validates the config (bounds, duplicate detection, overlap checks). Invalid config returns `InvalidConfig` and leaves the policy unchanged.
2. The new `PolicyConfig` is stored in persistent storage and the rolling window is preserved (or cleared on first install).
3. `PolicyRevision` is incremented; `LastHeartbeat` is set to `now` on first install only.
4. An `EventPolicySet` event is emitted with `by` and the new `revision`.

---

## 3. Authorized transfer

The agent wants to send 50 XLM to `treasury_address`. It builds and submits a transaction using `tools/agent-tx`:

```bash
./target/release/agent-tx transfer \
  --contract $CONTRACT_ID \
  --secret $AGENT_SECRET \
  --asset $XLM_CONTRACT_ADDRESS \
  --to $TREASURY_ADDRESS \
  --amount 500000000 \
  --network testnet
```

**What happens inside `__check_auth`:**
1. The host routes the transaction to `__check_auth` because the guarded address is a custom account.
2. The agent's Ed25519 signature over the auth payload is verified. A bad signature traps before any policy logic runs.
3. The policy snapshot is loaded: `PolicyConfig`, `AdminFrozen = false`, `LastHeartbeat`, current ledger time.
4. Account-level gates are evaluated in order:
   - `NoPolicy`? No — policy is installed.
   - `AdminFrozen`? No.
   - DMS grace elapsed? No — agent heartbeated within 24 hours.
   - `paused`? No.
   - Outside `active_from`/`active_until`? No — bounds are both `0` (disabled).
5. `parse_call` classifies the transfer as `AssetTransfer { asset: xlm, to: treasury, amount: 500_000_000 }`.
6. Per-kind enforcement runs:
   - Recipient `treasury_address` is in `recipients` list → pass.
   - Amount 500_000_000 ≤ `per_tx_cap` 1_000_000_000 → pass.
   - Window projection: running total + 500_000_000 ≤ `window_cap` 10_000_000_000 → pass.
   - Amount > 0 → pass.
7. The admission is committed to storage. `Ok(())` approves the transaction.
8. An `EventAuthChecked` event is emitted: `result = "allowed"`, `reason = "ok"`, `revision = 1`.

**Events emitted:**
```
topics: [event_auth_checked, allowed, ok]
data:   { contract: <xlm>, fn_name: transfer, context_index: 0, revision: 1 }
```

---

## 4. Denied transfer — amount exceeds per-tx cap

The agent now tries to send 200 XLM (amount 2_000_000_000, which is 200 × 10^7):

```bash
./target/release/agent-tx transfer \
  --contract $CONTRACT_ID \
  --secret $AGENT_SECRET \
  --asset $XLM_CONTRACT_ADDRESS \
  --to $TREASURY_ADDRESS \
  --amount 2000000000 \
  --network testnet
```

**Inside `__check_auth`:**
- Gates 1–5 pass as before.
- `parse_call` returns `AssetTransfer { amount: 2_000_000_000 }`.
- Amount 2_000_000_000 > `per_tx_cap` 1_000_000_000 → `PerTxCapExceeded`.
- The staged window admission is discarded (never committed — amount that fails the per-tx check never touches the rolling window).
- `Err(PerTxCapExceeded)` rejects the transaction.

**Events emitted:**
```
topics: [event_auth_checked, blocked, per_tx_cap_exceeded]
data:   { contract: <xlm>, fn_name: transfer, context_index: 0, revision: 1 }
```

The `reason` symbol `per_tx_cap_exceeded` is the stable identifier defined in [SPEC §7.1](../../SPEC.md#71-stable-reason-symbols). See the [Reason Glossary](../reason-glossary.md) for the agent/operator/auditor interpretation.

---

## 5. Denied transfer — recipient not in allowlist

The agent tries to send 10 XLM to `attacker_address`, which is not in `recipients`:

```bash
./target/release/agent-tx transfer \
  --contract $CONTRACT_ID \
  --secret $AGENT_SECRET \
  --asset $XLM_CONTRACT_ADDRESS \
  --to $ATTACKER_ADDRESS \
  --amount 100000000 \
  --network testnet
```

**Inside `__check_auth`:**
- `parse_call` returns `AssetTransfer { to: attacker_address, amount: 100_000_000 }`.
- Recipient `attacker_address` is not in `recipients` and `allow_any_recipient = false` → `RecipientNotAllowed`.
- Transaction rejected.

**Events emitted:**
```
topics: [event_auth_checked, blocked, recipient_not_allowed]
data:   { contract: <xlm>, fn_name: transfer, context_index: 0, revision: 1 }
```

---

## 6. Denied call — unknown contract

The agent is prompted (e.g. by a prompt-injection attack) to call an arbitrary DEX contract not in `protocols`:

```bash
# The contract is not in the policy's protocols list
./target/release/agent-tx call --contract $CONTRACT_ID --target $DEX_CONTRACT -- swap ...
```

**Inside `__check_auth`:**
- `parse_call` classifies the DEX call as `Unknown { contract: dex, fname: swap }` (default-deny: not in `assets` or `protocols`).
- Result: `Err(UnknownContract)`.

**Events emitted:**
```
topics: [event_auth_checked, blocked, unknown_contract]
data:   { contract: <dex>, fn_name: swap, context_index: 0, revision: 1 }
```

---

## 7. Recovery — dead-man switch fires

After 25 hours without a heartbeat (> `dms_grace_secs`), the agent tries another transfer:

**Inside `__check_auth`:**
- DMS check: `now - last_heartbeat = 90_000s > dms_grace_secs = 86_400s`.
- `auto_freeze` triggers: `AdminFrozen` is set to `true`, an `EventDmsAutoFrozen` event is emitted.
- The transfer is rejected with `HeartbeatExpired`.

**To recover:**
```bash
# Admin unfreezes the account; the DMS clock restarts
stellar contract invoke \
  --id $CONTRACT_ID \
  --network testnet \
  --source guard_admin \
  --send=yes \
  -- unfreeze
```

The `unfreeze` call also re-arms the dead-man switch by setting `LastHeartbeat = now`, which starts a fresh grace window. The `EventUnfrozen` event carries `rearmed_dms: true` to make this side effect auditable (SPEC §9).

---

## 8. Inspection — reading the current state

```bash
# Current policy, revision, window state, freeze flag
stellar contract invoke \
  --id $CONTRACT_ID \
  --network testnet \
  --source any_account \
  -- status

# Detailed per-recipient cap and window projection
stellar contract invoke \
  --id $CONTRACT_ID \
  --network testnet \
  --source any_account \
  -- check_detailed \
  --recipient $TREASURY_ADDRESS
```

The `status()` response includes:
- `has_policy` — whether a policy is installed.
- `admin_frozen` — freeze flag state.
- `dms_health` — `Ok`, `Warn` (within warning threshold), or `Expired`.
- `revision` — the current policy generation counter.
- `window_remaining` — global window headroom.
- `per_tx_remaining` — global per-tx cap.

---

## Summary of events

| Step | Event topics | Key data |
|---|---|---|
| Deploy + initialize | `event_initialized` | `by`, `agent_fingerprint` |
| Install policy | `event_policy_set` | `by`, `revision` |
| Transfer allowed | `event_auth_checked`, `allowed`, `ok` | `contract`, `fn_name`, `revision` |
| Transfer blocked (per-tx) | `event_auth_checked`, `blocked`, `per_tx_cap_exceeded` | `context_index`, `revision` |
| Transfer blocked (recipient) | `event_auth_checked`, `blocked`, `recipient_not_allowed` | `context_index`, `revision` |
| Unknown contract blocked | `event_auth_checked`, `blocked`, `unknown_contract` | `contract`, `fn_name` |
| DMS auto-freeze | `event_dms_auto_frozen` | `at` |
| Admin unfreeze | `event_unfrozen` | `by`, `rearmed_dms` |

All events are on-chain and permanent. `revision` in every `event_auth_checked` joins the authorization to the exact policy generation in force at decision time — correlating denials to a specific `set_policy` call in the audit log.

---

## Further reading

- [Architecture](../architecture.md) — the full `__check_auth` → `parse_call` → `decide` pipeline.
- [Enforcement Scope](../enforcement-scope.md) — what the guard enforces for SAC transfers vs. all other calls.
- [Spend Limits](../concepts/spend-limits.md) — per-tx cap, per-asset caps, and rolling window mechanics.
- [Dead-Man Switch](../concepts/dead-man-switch.md) — grace window, freeze, and recovery.
- [Reason Glossary](../reason-glossary.md) — every denial reason with agent/operator/auditor interpretation.
