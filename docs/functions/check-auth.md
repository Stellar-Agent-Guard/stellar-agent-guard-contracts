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
   - Context-count bound first: more than `MAX_AUTH_CONTEXTS` (64) contexts returns one aggregate
     `TooManyAuthContexts` verdict (§4 row 0) before any context is parsed.
   - Account-level gates next: admin freeze → dead-man switch → pause → active window.
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
| `Unauthorized` | 1 | **Reserved — never emitted** (issue #292): a bad signature dies in the `ed25519_verify` host trap (`InvokeError::Abort`) before any policy state is read |
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
| `RecipientBlocked` | 29 | Transfer to an explicitly blocked recipient |
| `ProtocolCallRateExceeded` | 30 | Protocol call rate limit exceeded |
| `DecisionInvariantViolation` | 31 | Internal enforcement verdict invariant failed |
| `TooManyAuthContexts` | 33 | Batch exceeds `MAX_AUTH_CONTEXTS` (64) contexts (§4 row 0) |

## What an operator sees when this rejects (issue #425)

`__check_auth` has no return channel a client reads directly. It returns `Result<(), Error>` to
the **host**, and the host turns an `Err` into three separate artifacts:

1. a failed authorization frame (which the host escalates into a transaction failure),
2. a contract error carrying the numeric [`Error`](#error-codes) code from SPEC §7.1,
3. an `auth_checked` event whose third topic is the **reason symbol**.

Which of those an operator can observe depends on *where* in the call lifecycle the transaction
was stopped. There are three surfaces below. Only the first carries the reason legibly and costs
nothing; the second needs XDR decoding and a paid fee; the third is the first one wrapped in a
tool.

### Surface 1 — simulation: the reason is fully visible

`soroban-rpc`'s `simulateTransaction` reports a failed simulation **inside the result object**,
as three fields:

| field | type | content |
|---|---|---|
| `error` | string | the host error line plus the full event log, newest event first |
| `events` | array of string | each entry is base64 `DiagnosticEvent` XDR |
| `latestLedger` | number | ledger the simulation ran against |

A JSON-RPC-level `error` object (`{"code": -32603, "message": "…"}`) is reserved for requests the
node refused to run at all — malformed XDR, bad params, internal fault. It never carries policy
information: a policy rejection arrives as `result.error` with HTTP 200.

Verbatim capture, 2026-10-18, Testnet, an agent-signed `agent-tx preflight` of a 1100-unit
transfer against the Phase-1 guard (contract IDs elided):

```text
HostError: Error(Auth, InvalidAction)

Event log (newest first):
   0: [Diagnostic Event] contract:<asset>, topics:[error, Error(Auth, InvalidAction)], data:["failed account authentication with error", <guard>, Error(Contract, #11)]
   1: [Failed Diagnostic Event (not emitted)] contract:<guard>, topics:[error, Error(Contract, #11)], data:"escalating Ok(ScErrorType::Contract) frame-exit to Err"
   2: [Failed Contract Event (not emitted)] contract:<guard>, topics:[event_auth_checked, blocked, heartbeat_expired], data:{}
   3: [Diagnostic Event] contract:<asset>, topics:[fn_call, <guard>, __check_auth], data:[<32-byte payload>, <64-byte signature>, [[Contract, {args: [<guard>, <recipient>, 1100], contract: <asset>, fn_name: transfer}]]]
```

Read it bottom-up, which is the order the engine ran:

- Line 3 proves the guard's own `__check_auth` was invoked, with the payload, signature and the
  auth context it was asked to approve. A rejection that **lacks** this line never reached the
  contract — that is the signature-failure case below.
- Line 2 is the contract's `auth_checked` event: `topics = [event_auth_checked, blocked,
  heartbeat_expired]`. **The reason symbol is the third topic**, and `(not emitted)` is the
  rollback: the frame failed, so this event exists in diagnostics only, never as a committed
  ledger event (SPEC §9). Current `main` also stamps `context_index` and `revision` into the
  event's data map (SPEC §9, issue #38); the empty `data:{}` above is the older Phase-1
  deployment, which predates those fields.
- Line 1 is the host converting the account's `Ok(ScError)` into a frame error, carrying the
  numeric code — `#11` = `HeartbeatExpired` (SPEC §7.1).
- Line 0 is the outer wrapper: because the failure came from an authorization callback, the host
  re-labels it `Error(Auth, InvalidAction)` and puts the underlying contract error in `data`.

That re-labelling is the trap for a naive decoder: **the auth-level error is not the policy
reason**. Match the `event_auth_checked` topic (or the `Error(Contract, #N)` inside the nested
data), not the top-level `Error(Auth, …)`.

### Surface 2 — after broadcast: the reason is not in a readable field

If the transaction was submitted anyway, rejection makes the whole transaction fail:

- `sendTransaction` returns `status` one of `PENDING` / `DUPLICATE` / `TRY_AGAIN_LATER` / `ERROR`,
  and for `ERROR`: `hash`, `latestLedger`, `latestLedgerCloseTime`, `errorResultXdr` and
  `diagnosticEventsXdr` (base64 arrays).
- `getTransaction` polls the same outcome as `status: "FAILED"` with `resultXdr`.
- Horizon's transaction resource exposes `successful: false`, `result_xdr`, `fee_charged`,
  `max_fee` (plus `inner_transaction` for fee-bumped submissions). The transaction result code is
  `txFAILED` — "one of the operations failed (none were applied)" — and the operation's own
  result inside `result_xdr` carries the `ScError` (type `Contract`, the numeric code above).

No field on this surface spells out `heartbeat_expired`: it has to be decoded from
`result_xdr`/`errorResultXdr`, or read from the `diagnosticEventsXdr` the RPC hands back. The
fee is still charged. This is the mechanical reason SPEC §11 and [Enforcement
Scope](../enforcement-scope.md) insist the SDK pre-flights **before** signing rather than
reacting after submission.

### Surface 3 — the CLI

`agent-tx preflight --secret …` is the enforced path (steps 1–3 above, no submission): it prints
`BLOCKED (pre-broadcast, enforced simulation):`, then `broadcast: no`, and exits `1`. An admitted
signed simulation prints `RESULT: ALLOWED (preflight only)` with the estimated fee and exits `0`;
without `--secret` the verdict is `INDETERMINATE` and exits `2`. See
[tools/agent-tx/README.md](../../tools/agent-tx/README.md).

### The rejection classes, and what distinguishes them

| Rejection class | Reaches the engine? | `auth_checked` in diagnostics | Contract code an observer finds | Pinning evidence |
|---|---|---|---|---|
| No agent key registered | step 1 only | no | `NotInitialized` (3) | `auth_verification_order_uninitialized_account_rejects_with_not_initialized` |
| Bad signature / wrong key | no — `ed25519_verify` aborts the frame | **absent**, and no `fn_call … __check_auth` line either | none: `Unauthorized` (1) is ABI-only, the host traps instead (SPEC §7.1) | `wrong_signature_is_rejected_by_host_crypto` |
| Account-level gate (freeze, dead-man, pause, active window) | yes, once per transaction | one per context, **all** `blocked` with the same reason | `AdminFrozen` 10 / `HeartbeatExpired` 11 / `Paused` 13 / `OutsideActiveWindow` 14; which one, per SPEC §5.2's precedence | the capture above (11), `account_gates_order_beats_calls` |
| Batch over `MAX_AUTH_CONTEXTS` (64) | §4 row 0 only — no context is parsed | **one** event, `context_index = 0`, not one per context | `TooManyAuthContexts` (33) | `auth_context_batch_over_limit_fails_before_staging_admissions`, SPEC §6 |
| Per-call denial (rule 7) | yes, per context | earlier contexts `allowed`, first failing one `blocked` | 20–31, reporting the **first** failing context in auth-context iteration order | SPEC §6.0, `mixed_multi_context_batch_reports_the_first_failing_context` |

The symbol ↔ code ↔ reachability correspondence for all 25 variants is
[SPEC §7.1](../../SPEC.md#71-error-code--checkresult-variant--reason-symbol-mapping), and what
each symbol means to a human reader is [docs/reason-glossary.md](../reason-glossary.md). The
canonical topic list for every outcome, including the empty reason topic on an allow, is
[tests/fixtures/auth-checked-vocabulary.json](../../tests/fixtures/auth-checked-vocabulary.json).

**Do not read a rejection as proof of an attack.** Enforcement is default-deny and applies to
every authorization the guard sees, so anyone holding the registered agent key can produce the
per-call denials above on demand — the same shapes a misbehaving agent or an adversary would
generate, at no cost to the guarded account and with no effect on the spend budget. The
availability side of that, the bound, and the telemetry signature that separates it from a real
overspend attempt are threat-modelled in
[SPEC §10.3](../../SPEC.md#103-availability-a-compromised-agent-key-can-grief-block-its-own-transactions-issue-424).

### Two gaps in the tooling surface (documented here, not fixed)

Caught while writing this section against the live deployment; both are tool-side, and neither
changes the contract-level mapping above.

1. **`agent-tx` looks for the reason in the wrong place.** Its block report reads
   `error.code`, `error.message` and `error.data.events` — the JSON-RPC *error-object* shape — but
   simulation failures come back as `result.error` (a string) with diagnostics in `result.events`
   (Surface 1). So the live block prints `BLOCKED (pre-broadcast, enforced simulation):`
   immediately followed by `broadcast: no`, with none of the `message:` / `diagnostic events:`
   lines the examples in [tools/agent-tx/README.md](../../tools/agent-tx/README.md) and the
   repository README show. The exit code (`1`) is still correct, so scripts that branch on it are
   unaffected; only the human-readable reason is lost. Fix: treat `result.error` as the message
   and decode `result.events` at the four sites that parse a simulation response
   (`tools/agent-tx/src/main.rs:415`, `:692`, `:909`, `:2203`).
2. **`agent-tx check` cannot see an enforced block.** It simulates the SAC transfer with **no
   auth entry** (`tools/agent-tx/src/main.rs:2198`), so the host never calls the guard's
   `__check_auth`; recorded live, it printed `result: allowed` for the same 1100-unit transfer
   that `preflight --secret` blocked with `heartbeat_expired`. It is a fee/auth-requirement probe,
   not a policy verdict. Use the on-chain `check`/`check_detailed` views (SPEC §7, which
   reproduce the §6.2 decision path without auth) or `preflight --secret` for the enforced answer.

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
