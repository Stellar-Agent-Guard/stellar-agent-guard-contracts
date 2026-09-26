# initialize

One-time setup function. Registers the policy admin and the agent's Ed25519 public key.

## Signature

```rust
pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>)
```

## Auth placement

`require_auth(admin)` — only the address that will become the policy admin can call this.

## Behavior

- Stores `admin` as the policy admin in instance storage.
- Stores `agent_pubkey` (raw Ed25519 public key, 32 bytes) as the agent's registered key.
- Sets `AdminFrozen = false` and `LastHeartbeat = 0` in persistent storage.
- Emits `EventInitialized`.
- Can only be called **once** — subsequent calls fail with `AlreadyInitialized`.

## What happens after initialize

Until `set_policy` runs, the account is **default-deny** — every authorization is rejected with `NoPolicy`. This is the safe initial state: the account exists but cannot do anything.

## Example

```bash
# Derive the agent's raw pubkey from a Stellar secret key
echo 'S...' | cargo run --example agent_pubkey
# → 1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05

# Initialize the guard contract
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- \
  initialize \
  --admin GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS \
  --agent_pubkey 1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05
```

Real Phase-1 initialize transaction: `cb17b7b1c65bff74b6bc99f67fe3cf1070c7a28f14bdd71527ba60c9d4a81264`

## Edge cases

### Calling twice

```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  initialize \
  --admin GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS \
  --agent_pubkey 1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05
# → ❌ transaction simulation failed: HostError: Error(Contract, #2)
#    (AlreadyInitialized)
```

**`AlreadyInitialized` is not a bug — it is your first attempt succeeding.** Deploy
scripts that retry (fee-bump double-submit, operator panic-retry) read this error as a
failure and redeploy, which is the wrong recovery. The correct procedure:

1. Call `status()` on the same contract ID:
   ```bash
   stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
     --network testnet --source-account guard_admin --send=no -- status
   ```
2. If it reads sane (`has_policy: false`, `admin_frozen: false` — freshly initialized,
   no policy installed yet), your first `initialize` landed. **Do not redeploy.** Proceed
   directly to the next step: [`set_policy`](set-policy.md).
3. Redeploy a fresh contract only if `status()` shows the account was never actually
   initialized (`NotInitialized` on admin operations).

Do not redeploy a second guard for the same agent: the old and new contract IDs would
split the policy admin, and the agent key would be registered on the wrong one.

## Storage keys touched

| Key | Type | Kind |
|---|---|---|
| `Initialized` | `bool` | instance |
| `Admin` | `Address` | instance |
| `AgentPubkey` | `BytesN<32>` | instance |
| `AdminFrozen` | `bool` | persistent |
| `LastHeartbeat` | `u64` | persistent |

## See also

- [set\_policy](set-policy.md) — install a policy after initialization
- [heartbeat](heartbeat.md) — the agent's liveness signal
