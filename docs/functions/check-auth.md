# check\_auth

The enforcement entrypoint. This is **not a user-callable function** — the Soroban host invokes it automatically on every authorization the account must approve.

## Signature

```rust
fn __check_auth(
    env: Env,
    signature_payload: Hash<32>,
    signatures: BytesN<64>,
    auth_contexts: Vec<Context>,
) -> Result<(), Error>
```

## Why you don't call this directly

`__check_auth` is a trait method on `CustomAccountInterface`. The Soroban host calls it when an authorization is needed — you never invoke it yourself. The host supplies:

- `signature_payload`: the digest the presented signature must verify against (computed by the host from the transaction's authorized invocation).
- `signatures`: the Ed25519 signature over that payload.
- `auth_contexts`: the list of calls this account must authorize, each with `contract`, `fn_name`, and `args`.

## Step-by-step execution

1. **Load the registered agent pubkey** from instance storage. Missing → `NotInitialized` (default-deny until `initialize`).

2. **Verify the Ed25519 signature.** Calls `env.crypto().ed25519_verify(agent, signature_payload, signatures)`. A wrong key or bad signature **traps the frame** — the host rejects the authorization before any policy logic runs.

3. **Snapshot policy state.** Loads `PolicyConfig` (missing → `NoPolicy`), `AdminFrozen`, `LastHeartbeat`, and ledger time.

4. **Run the decision table** (`decide` function):
   - Account-level gates first: admin freeze → dead-man switch → pause → active window.
   - Per-context classification: each `Context` is parsed into a typed call (`SelfCall`, `AssetTransfer`, `AssetOther`, `Protocol`, `Unknown`, `CreateContract`).
   - Per-kind enforcement: asset transfers get recipient allowlist + per-tx cap + rolling window. Protocol calls get contract + function allowlist. Everything else is denied.
   - **All-or-nothing commit:** Window admissions are staged and only committed to storage if *every* context passes.

5. **Return `Ok(())`** to approve, or **`Err(reason)`** to reject the entire transaction.

6. **Emit `auth_checked` event** either way — the same event vocabulary used by the `check` pre-flight function. Its data carries `context_index` and `revision` (the `PolicyRevision` counter in force at decision time, issue #38), so telemetry can join each admission/rejection to the exact policy generation.

## The auth context

Each `Context` in `auth_contexts` is a `Contract` variant containing:

```rust
pub struct ContractContext {
    pub contract: Address,   // the contract being called
    pub fn_name: Symbol,     // the function name
    pub args: Vec<Val>,      // raw arguments
}
```

For SAC token calls, the arguments are at known positions:
- `transfer(from, to, amount)` — recipient at args[1], amount at args[2]
- `transfer_from(from, spender, to, amount)` — recipient at args[2], amount at args[3]

For other calls, the arguments are not interpretable — see [Enforcement Scope](../enforcement-scope.md).

## Error codes

| Error | Code | Meaning |
|---|---|---|
| `Unauthorized` | 1 | Signature verification failed (host trap) |
| `NotInitialized` | 3 | No agent key registered |
| `NoPolicy` | 12 | No policy installed (default-deny) |
| `AdminFrozen` | 10 | Admin freeze active |
| `HeartbeatExpired` | 11 | Dead-man switch triggered |
| `Paused` | 13 | Policy paused |
| `OutsideActiveWindow` | 14 | Current time outside active_from/active_until |
| `AssetNotAllowed` | 20 | Transfer on unregistered SAC |
| `RecipientNotAllowed` | 21 | Transfer to non-allowlisted address |
| `PerTxCapExceeded` | 22 | Transfer exceeds per-tx cap |
| `WindowCapExceeded` | 23 | Transfer would exceed rolling window cap |
| `ProtocolNotAllowed` | 24 | Call to non-allowlisted contract |
| `FunctionNotAllowed` | 25 | Function not in protocol's allowlist |
| `UnknownContract` | 26 | Contract not in assets or protocols |
| `SelfFunctionNotAllowed` | 27 | Self-call to non-heartbeat function |
| `CreateContractNotAllowed` | 28 | Contract creation denied in v1 |

## How agent-tx drives `__check_auth`

The `tools/agent-tx` CLI helper demonstrates the full flow:

1. Build the `SorobanAuthorizationEntry` for the **guard** address (a contract, not an account).
2. Sign the `HashIdPreimage::SorobanAuthorization` payload with the agent's Ed25519 key.
3. Simulate the call with the signed entry — this runs the **real** `__check_auth` against live testnet state.
4. On approval, submit the transaction.

The `stellar` CLI cannot do step 1–2 because it cannot sign auth entries whose address is a contract. That is why `agent-tx` exists.

## See also

- [Architecture](../architecture.md) — the full `__check_auth` → `parse_call` → `decide` pipeline
- [Enforcement Scope](../enforcement-scope.md) — what `__check_auth` can and cannot enforce
