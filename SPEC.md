# Stellar Agent Guard Contract Specification

## 1. Overview

Stellar Agent Guard is a Soroban smart contract acting as a custom account guardian for autonomous agents. It interposes between agent-initiated transactions and the Soroban protocol's auth check (`__check_auth`), enforcing spend caps, allowed protocols, recipient allowlists, active time windows, rolling spend budgets, an explicit admin kill switch, and an automated dead-man switch.

### 1.1 Non-goals and design boundaries

- The contract does **not** protect against admin compromise. The admin can rewrite policy, pause enforcement, drain funds if permitted by the policy, or rotate the agent key at will. Admin key custody is an off-chain operational trust dependency.
- The contract does **not** handle agent key rotation without admin signature.
- The contract relies on Soroban custom-account auth routing (`CustomAccountInterface`). Every transaction the agent signs through this account passes through the guard.

---

## 2. Storage Schema

All state is stored in the contract's persistent storage using Soroban host storage keys.

| Key | Type | Description |
|---|---|---|
| `Admin` | `Address` | The authorized administrator of the guard. |
| `AgentKey` | `BytesN<32>` | The Ed25519 public key authorized to sign agent transactions. |
| `Policy` | `PolicyConfig` | The current active spend policy. Absent if no policy is installed. |
| `PolicyRevision` | `u64` | Monotonically increasing counter incremented on every `set_policy`. |
| `Window` | `WindowState` | Rolling window tracking state (`start_time`, `spent`, `protocol_calls`). |
| `LastHeartbeat` | `u64` | Unix timestamp of the last agent heartbeat or policy installation. |
| `AdminFrozen` | `bool` | True if the admin has explicitly frozen the account. |
| `PendingAdmin` | `Address` | Optional pending admin for a two-step rotation ceremony. |

---

## 3. Configuration Model (`PolicyConfig`)

The spend policy restricts what transactions the agent can sign and submit through the guarded account.

```rust
pub struct PolicyConfig {
    pub per_tx_cap: i128,
    pub window_secs: u64,
    pub window_cap: i128,
    pub assets: Vec<Address>,
    pub protocols: Vec<ProtocolRule>,
    pub recipients: Vec<Address>,
    pub recipient_window_caps: Vec<RecipientCap>,
    pub blocked_recipients: Vec<Address>,
    pub asset_caps: Vec<AssetCap>,
    pub allow_any_recipient: bool,
    pub active_from: u64,
    pub active_until: u64,
    pub paused: bool,
    pub dms_grace_secs: u64,
    pub protocol_calls_per_window: u32,
}
```

---

## 4. Authorization Decision Pipeline

When `__check_auth` is invoked, the engine evaluates the transaction against the following rules in strict order. The first rule that matches produces the final decision (`Allowed` or `Blocked(Error)`).

1. **Admin Freeze (`AdminFrozen`)**: If `AdminFrozen == true`, block with `AdminFrozen`. Only the admin's `unfreeze()` call can clear this.
2. **Dead-Man Switch (`LastHeartbeat`, `dms_grace_secs`)**: If `dms_grace_secs > 0`, `LastHeartbeat > 0`, and current ledger timestamp exceeds `LastHeartbeat + dms_grace_secs`, block with `HeartbeatExpired`.
3. **Absence of Policy**: If no policy is installed (`Policy` key is absent), block with `NoPolicy`.
4. **Pause Switch**: If `Policy.paused == true`, block with `Paused`.
5. **Active Window**: If `active_from > 0` or `active_until > 0`, check that current ledger time falls within the range. If outside, block with `OutsideActiveWindow`.
6. **Self-Calls**: If the call is a self-call (to the guard contract itself):
   - Allowed only if the function name is `heartbeat`.
   - Any other self-call (e.g., `set_policy`, `freeze`, `unfreeze`) is blocked with `SelfFunctionNotAllowed`.
7. **Asset Transfers (SAC)**:
   - Must target a token contract listed in `Policy.assets`.
   - Function must be `transfer` or `transfer_from`.
   - Recipient must be in `Policy.recipients` (unless `allow_any_recipient == true` or recipient is explicitly blocked).
   - Amount must be `> 0` and `<= per_tx_cap` (if `per_tx_cap > 0`).
   - Rolling window budget must not be exceeded (`window_cap`).
8. **Protocol Calls**: Contracts listed in `Policy.protocols` with approved function selectors are allowed.
9. **Default Fallback**: Any other call (unknown contract, unapproved function, untrusted asset) is blocked.

---

## 5. Dead-Man Switch & Precise Definition

The dead-man switch prevents orphaned accounts from remaining spendable indefinitely if an autonomous agent loses connectivity or ceases operation.

- **Heartbeat**: The agent calls `heartbeat()`, which sets `LastHeartbeat = now` and emits an event. `heartbeat()` is the only self-call permitted by the policy when active.
- **Expiry**: If `now - LastHeartbeat > dms_grace_secs`, the account is automatically frozen. Enforcement is lazy (evaluated on every authorization check).
- **Policy Installation Side Effect**: Installing or replacing a policy via `set_policy` re-arms the dead-man clock by stamping `LastHeartbeat = now`, counting the admin's action as a liveness attestation. By contrast, `revoke_policy` removes the policy config but leaves `LastHeartbeat` untouched (the clock is not re-armed when clearing a policy).
- **Reversal**: Only the admin can revive a frozen account by calling `unfreeze()`, which clears `AdminFrozen` and resets `LastHeartbeat = now`.

---

## 6. Events

All state-mutating actions emit structured Soroban diagnostic events.

| Event Name | Trigger | Payload |
|---|---|---|
| `EventInitialized` | `initialize` | `admin`, `agent_key` |
| `EventPolicySet` | `set_policy` | `by`, `revision` |
| `EventPolicyRevoked` | `revoke_policy` | `by` |
| `EventHeartbeat` | `heartbeat` | `at` |
| `EventFrozen` | `freeze` | `by` |
| `EventUnfrozen` | `unfreeze` | `by` |
| `EventPaused` | `pause` | `by` |
| `EventResumed` | `resume` | `by` |
| `EventWindowReset` | `reset_window` | `by` |
| `EventAgentKeyRotated` | `rotate_agent_key` | `by` |

---

## 7. Public Surface & Exact Signatures

- `initialize(admin: Address, agent_key: BytesN<32>)`
- `set_policy(config: PolicyConfig)`
- `revoke_policy()`
- `heartbeat()`
- `freeze()`
- `unfreeze()`
- `pause()`
- `resume()`
- `reset_window()`
- `rotate_agent_key(new_agent_key: BytesN<32>)`
- `status() -> AccountStatus`
- `policy() -> Option<PolicyConfig>`
- `dms_health() -> DmsHealth`

---

## 8. Configuration Validation Rules

`set_policy` validates configurations before writing:
- `per_tx_cap >= 0`, `window_cap >= 0`
- If `window_cap > 0`, then `window_secs > 0`
- `per_tx_cap <= window_cap` when both are enabled
- Active window bounds check (`active_until > active_from` if non-zero)
- No duplicate addresses in lists
- Self-address may not appear in `assets`, `protocols`, or `recipients`
