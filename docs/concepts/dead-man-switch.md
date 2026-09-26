# Dead-Man Switch

## Purpose

If the agent stops operating (lost key, dead process, operator disappearance), the account must not remain spendable forever. The dead-man switch guards against *silence*; it does not guard against a live attacker who keeps heartbeating (spend caps do that — see [Architecture](../architecture.md)).

## How it works

### Heartbeat

The `heartbeat()` function is the agent's liveness signal. It records `LastHeartbeat = now` and emits an `EventHeartbeat`. It is the only self-call the policy allows (see [heartbeat](../functions/heartbeat.md)).

### Grace period

The `dms_grace_secs` field in `PolicyConfig` sets the grace window in seconds. If the agent has not heartbeated within `dms_grace_secs` seconds of the last heartbeat, the account is automatically frozen.

- `dms_grace_secs: 0` disables the dead-man switch entirely.
- Recommended production value: several days.
- Recommended testnet value: small (e.g., 60s) so the freeze is observable.

### Automatic freeze (lazy, no background write)

The freeze is **automatic and lazy**. There is no stored "auto-frozen" flag — the engine derives the freeze from `LastHeartbeat` and ledger time on every authorization:

```
if dms_grace_secs > 0
    && last_heartbeat != 0
    && now - last_heartbeat > dms_grace_secs:
    → Block (HeartbeatExpired)
```

This means:
- The account is frozen the moment the grace elapses, with zero transactions and zero background writes required.
- The account can **never** be "unfrozen by time passing."
- Even a heartbeat arriving after the grace window expired is rejected — silence cannot self-revive.

### Reversal path (admin-only)

The admin's `unfreeze()` function is the reversal path:

```rust
pub fn unfreeze(env: Env) {
    let admin = Self::admin_or_panic(&env);
    persist_set(&env, &DataKey::AdminFrozen, &false);
    let now = env.ledger().timestamp();
    persist_set(&env, &DataKey::LastHeartbeat, &now);
    emit_unfrozen(&env, &admin);
}
```

`unfreeze` does two things:
1. Clears the `AdminFrozen` flag.
2. Sets `LastHeartbeat = now` — the admin's signature is the liveness attestation that revives the account.

After `unfreeze`, a subsequently-heartbeating agent keeps the account alive from there.

For the agent-side steady-state loop that keeps this clock alive — heartbeat cadence
(`interval ≤ grace / 3`), pre-flight, and the stop conditions when grace does lapse —
see [`examples/agent-loop.md`](../../examples/agent-loop.md).

## Admin freeze vs. dead-man freeze

These are **separate conditions**:

| | Admin freeze (`freeze()`) | Dead-man freeze (automatic) |
|---|---|---|
| Trigger | Admin calls `freeze()` | `now - last_heartbeat > dms_grace_secs` |
| Immediate? | Yes | Yes (derived lazily on next auth) |
| Blocks heartbeats? | Yes | Yes (after grace expires) |
| Reversed by | `unfreeze()` | `unfreeze()` only |
| Can agent self-revive? | No | No |

Both are cleared by `unfreeze()`, which also restarts the heartbeat clock. The key point: **a live attacker who keeps the agent key heartbeating cannot trigger the dead-man switch**, but spend caps still bind them.

## Timeline example

```
t=0:     set_policy (dms_grace_secs: 60) → LastHeartbeat = 0
t=10:    heartbeat → LastHeartbeat = 10
t=50:    transfer → Allowed (50 - 10 = 40 < 60)
t=80:    transfer → Blocked (80 - 10 = 70 > 60, HeartbeatExpired)
t=80:    heartbeat → Blocked (heartbeat after grace expired)
t=80:    admin unfreeze() → LastHeartbeat = 80, AdminFrozen = false
t=85:    heartbeat → Allowed (agent keeps it alive)
t=150:   transfer → Allowed (150 - 85 = 65 < 60? No — wait, 65 > 60)
         → Actually blocked again unless another heartbeat
```

## Relationship to other gates

The dead-man switch check is **rule #2** in the decision table (see [Architecture](../architecture.md)), evaluated after admin freeze but before pause and active window. It applies to **every** call the account makes — SAC transfers, protocol calls, and even `heartbeat` itself.

This means: if the grace has expired, the agent cannot heartbeat its way out. Only the admin can revive the account.
