# freeze / unfreeze

Admin-only freeze and reversal functions.

## freeze

### Signature

```rust
pub fn freeze(env: Env)
```

### Auth placement

`require_auth(Admin)` — only the policy admin can freeze the account.

### Behavior

1. Sets `AdminFrozen = true` in persistent storage.
2. Emits `EventFrozen` with `by: admin`.

### Effect

Once frozen, **every** authorization is blocked with `AdminFrozen` — including transfers, protocol calls, and even `heartbeat`. The agent cannot do anything until the admin calls `unfreeze`.

This is the **immediate admin kill switch**: it blocks even a live, heartbeating agent.

### Example

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- freeze
# → Event: EventFrozen (event_frozen), by: "GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS"
```

## unfreeze

### Signature

```rust
pub fn unfreeze(env: Env)
```

### Auth placement

`require_auth(Admin)` — only the policy admin can unfreeze.

### Behavior

1. Clears `AdminFrozen` (sets to `false`).
2. Sets `LastHeartbeat = now` — the admin's signature is the liveness attestation that revives the account.
3. Emits `EventUnfrozen` with `by: admin` and `rearmed_dms: bool`.

### Why `unfreeze` resets the heartbeat

The admin's unfreeze is the **reversal path** for both admin freeze and dead-man switch freeze. By setting `LastHeartbeat = now`, the admin attests that the agent is alive. A subsequently-heartbeating agent keeps the account alive from there.

If `unfreeze` did not reset the heartbeat, a dead-man-frozen account would immediately re-freeze after unfreeze because the old heartbeat would still be expired.

### Re-arm warning (the two jobs of one call)

`unfreeze` is both the brake release and the liveness attestation. If you unfreeze an account whose
DMS grace had **already elapsed**, you are silently re-arming the liveness clock on the admin's
authority — the grace window restarts from this moment. That is the intended reversal semantics
(SPEC §5), but operators must not mistake it for a no-op on the DMS.

The event makes it auditable: `EventUnfrozen` carries `rearmed_dms: bool` —

| `rearmed_dms` | Meaning |
|---|---|
| `true` | The call changed `LastHeartbeat` — the DMS clock was re-armed (the typical DMS-expired reversal). |
| `false` | `LastHeartbeat` already equaled `now` — the DMS was fresh; only the admin brake was released. |

Splits into `unfreeze` + an explicit heartbeat-equivalent were considered and rejected: the
deployed ABI is stable, and a two-call reversal risks an operator issuing only the brake release,
leaving the account still DMS-frozen. The semantics stay; the event and these docs are the loud part.

### Example

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- unfreeze
# → ✅ Transaction submitted successfully!
#    tx=dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5
# → Event: EventUnfrozen (event_unfrozen),
#    by: "GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS",
#    rearmed_dms: true (the Phase-1 fixture ran with an expired DMS grace)
```

Real Phase-1 unfreeze transaction (DMS reversal): `dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5`

### Post-unfreeze

Immediately after `unfreeze`, the agent can transact again:

```bash
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 10
# → submitted: hash=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512
# → RESULT: ALLOWED tx=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512
```

Horizon: `successful: true`, ledger 4566327.

## Admin freeze vs. dead-man freeze

| | Admin freeze | Dead-man freeze |
|---|---|---|
| Trigger | Admin calls `freeze()` | `now - last_heartbeat > dms_grace_secs` |
| Reversed by | `unfreeze()` | `unfreeze()` only |
| Can agent self-revive? | No | No |

Both are cleared by `unfreeze()`, which also restarts the heartbeat clock — the `rearmed_dms`
field in `event_unfrozen` reports when that restart actually happened (i.e. the DMS was expired
at unfreeze time).

## Storage keys touched

| Function | Key | Type | Action |
|---|---|---|---|
| `freeze` | `AdminFrozen` | `bool` | Set to `true` |
| `unfreeze` | `AdminFrozen` | `bool` | Set to `false` |
| `unfreeze` | `LastHeartbeat` | `u64` | Set to now |

## See also

- [Dead-Man Switch](../concepts/dead-man-switch.md) — the full mechanism
- [heartbeat](heartbeat.md) — the agent's liveness signal
