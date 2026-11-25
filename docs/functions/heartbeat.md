# heartbeat

Agent liveness signal. Records the current time as the last heartbeat, keeping the account alive past the dead-man switch grace period.

## Signature

```rust
pub fn heartbeat(env: Env)
```

## Auth placement

`require_auth(env.current_contract_address())` — this is a self-call. The host routes it through `__check_auth`, which verifies the registered agent's Ed25519 signature. Only the agent can heartbeat.

## Behavior

1. Records `LastHeartbeat = now` (current ledger timestamp) in persistent storage.
2. Emits `EventHeartbeat` with `at: now`.

## Why it routes through `__check_auth`

`heartbeat` does `require_auth` on the contract itself. Since the contract is a custom account, the host invokes `__check_auth` to verify the authorization. This means:

- The agent's Ed25519 signature is verified.
- All account-level gates are evaluated: no policy, admin freeze (including an agent `self_lock`), dead-man switch, pause, active window.
- A heartbeat arriving after the grace window expired is **rejected** — silence cannot self-revive.
- A heartbeat while admin-frozen is **rejected**.

This is the precise freeze/reversal boundary: the only way to revive a frozen account is the admin's `unfreeze()`.

## Example

The `stellar` CLI cannot invoke `heartbeat` directly because it cannot sign Soroban auth entries whose address is a contract. Use the `agent-tx` submission helper instead:

```bash
cd tools/agent-tx && cargo build --release
./target/release/agent-tx heartbeat \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --agent-secret SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4
```

Or via the `AGENT_SECRET` environment variable:

```bash
AGENT_SECRET=SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4 \
  ./target/release/agent-tx heartbeat \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7
```

## Edge cases

### Heartbeat after grace expires

If `dms_grace_secs > 0` and `now - last_heartbeat > dms_grace_secs`, the heartbeat is blocked with `HeartbeatExpired`. The agent cannot revive itself — only the admin's `unfreeze()` can.

### Heartbeat while admin-frozen

If `AdminFrozen` is set, the heartbeat is blocked with `AdminFrozen`. Again, only `unfreeze()` can clear this.

### Heartbeat with no policy

If no policy is installed, the account is default-deny and the heartbeat is blocked with `NoPolicy`.

## Storage keys touched

| Key | Type | Action |
|---|---|---|
| `LastHeartbeat` | `u64` | Set to now |

## See also

- [Dead-Man Switch](../concepts/dead-man-switch.md) — the full mechanism
- [freeze / unfreeze](freeze-unfreeze.md) — admin freeze and reversal
