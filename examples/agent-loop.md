# Agent runtime example — the full 24/7 loop

The [Installation](../docs/installation.md) and
[Testnet Verification](../docs/verification.md) docs cover **one-shot operator
setup**: deploy the guard, install a policy, run a scenario. This document is the
other half — the **steady-state loop an autonomous agent must run for as long as
it is alive**, using the raw contract and the `tools/agent-tx` CLI helper.

> **Scope.** This is the raw-contract / CLI path: every command below submits (or
> simulates) directly against the deployed guard. If your agent is TypeScript and
> uses the `stellar-agent-guard-sdk`, read its companion guide
> [stellar-agent-guard-sdk#74 — agent-runtime integration guide][sdk-issue]
> instead: it shows the same loop through the SDK's `check()` / `invoke()` calls.
> Both docs describe one loop; neither duplicates the other. (The SDK doc is still
> open — until it lands, SDK users can follow this doc's pre-flight and blocked-
> reason handling and substitute SDK calls for the CLI ones.)

[sdk-issue]: https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk/issues/74

## The four loop responsibilities

A guarded agent runtime has exactly four jobs, run on overlapping cadences:

1. **Heartbeat** — periodically call `heartbeat()` so the dead-man switch
   (DMS) never fires. This is the agent's liveness proof.
2. **Pre-flight every outgoing transfer** — call the read-only `check()`
   function *before* signing, so a policy violation is caught locally instead of
   trapping at broadcast.
3. **React to blocked reasons** — map each `check()` block reason to a concrete
   operator action (table below), never retry a block blindly.
4. **Watch the DMS countdown** — alert the operator before grace lapses, and
   stop cleanly once it has (only an admin `unfreeze` revives the account).

These run independently: the heartbeat scheduler ticks on its own timer, while
the transfer path is request-driven. One must never starve the other.

> **Enforcement is on-chain, not in this loop.** A bug in your runtime cannot
> bypass the guard: even if the loop skips `check()`, the transfer's auth still
> routes through `__check_auth`, which applies the same decision table and
> rejects the transaction pre-broadcast. The loop exists to make agents *fail
> gracefully and observably*, not to be the security boundary.

## Heartbeat cadence: `interval ≤ grace / 3`

Given the policy's `dms_grace_secs` grace window, schedule heartbeats at:

```
interval = grace / 3          # strictly less than; use integer division
```

**Rationale.** The dead-man switch fires when
`now - last_heartbeat > dms_grace_secs` (see
[Dead-Man Switch](../docs/concepts/dead-man-switch.md)). Heartbeating every
`grace / 3` seconds puts **at least three heartbeat opportunities inside every
grace window**, so the loop tolerates up to **two consecutive missed beats** —
an RPC outage, a slow ledger, one crashed cron run — before the account
freezes. A cadence of `grace / 2` tolerates only one miss and leaves no margin;
`grace` itself leaves none at all.

| `dms_grace_secs` | Heartbeat every (`grace / 3`) | Misses tolerated before freeze |
|---|---|---|
| 60 (testnet fixture) | 20s | 2 |
| 3 600 (1h) | 1 200s (20m) | 2 |
| 86 400 (1 day, recommended prod) | 28 800s (8h) | 2 |
| 259 200 (3 days) | 86 400s (24h) | 2 |

Never heartbeat *more* often than once per ledger second — `heartbeat()` is a
measured no-op when `LastHeartbeat` already equals `now`, but round-tripping a
transaction every second is pure cost with no liveness benefit.

### Log the expiry, not just the beat

`heartbeat()` emits `EventHeartbeat { at }` where `at` is the ledger timestamp of
the accepted beat. The **expiry** the operator actually cares about is derived:

```
expires_at = heartbeat.at + policy.dms_grace_secs
```

Log `at`, `expires_at`, and the remaining seconds at every beat, and alert when
remaining drops below your warn threshold (a good default is one heartbeat
interval, i.e. `grace / 3`). `status()` returns the same clock read-side without
writing anything:

```jsonc
{ "has_policy": true, "policy_revision": 3, "admin_frozen": false,
  "heartbeat_expired": false, "last_heartbeat": 1788855212, "now": 1788855400 }
```

`heartbeat_expired` is derived lazily from `last_heartbeat + grace`, so a
`status()` poll is a sufficient alert source — **no event subscription is
required** for the DMS countdown.

## Full-loop pseudocode

```text
GUARD, TOKEN, RECIPIENT = ...
grace = policy(GUARD).dms_grace_secs
interval = grace / 3
warn_below = interval

once per interval (heartbeat task):
    try:
        tx = agent_tx("heartbeat", --guard GUARD)
        log("heartbeat at=tx.heartbeat.at expires_at=at+grace")
    catch Blocked(reason):
        # heartbeat itself can be blocked by a non-DMS gate
        handle_block(reason)          # see table; e.g. admin_frozen -> alert operator
        if reason == heartbeat_expired:
            STOP()                    # only admin unfreeze revives; do not retry
    catch RpcError:
        log("heartbeat failed; backoff"); retry_with_backoff()
        if elapsed_since_last_beat > grace:
            STOP()                    # we may already be frozen; verify with status()

once per outbound transfer:
    result = stellar contract invoke --id GUARD -- check --asset TOKEN --to TO --amount N
    if result == Allowed:
        agent_tx("transfer", --guard GUARD --token TOKEN --to TO --amount N)
    else:                             # result == Blocked(reason)
        handle_block(reason)          # table below; never blind-retry

every few minutes (alert task):
    st = stellar contract invoke --id GUARD -- status
    if st.heartbeat_expired:  alert("DMS EXPIRED — unfreeze ceremony required"); STOP()
    elif st.admin_frozen:     alert("admin freeze active — operator action required")
    elif remaining(st) < warn_below: alert("DMS warning: <threshold>s to expiry")
```

## Real commands (testnet fixture)

Every command form below is the exact one used against the live Phase-1 testnet
fixture, and each output is backed by a recorded transcript (tx hash, ledger,
emitted event) in [`../tests/fixtures/README.md`](../tests/fixtures/README.md) or
[`../docs/verification.md`](../docs/verification.md). The fixture values:

```text
GUARD     = CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7
TOKEN     = CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7
RECIPIENT = GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX
grace     = 60            # dms_grace_secs -> heartbeat interval 20s
```

```bash
# One-time: build the submission helper (the stellar CLI cannot sign auth
# entries whose address is a contract — see docs/functions/heartbeat.md).
cd tools/agent-tx && cargo build --release && cd ../..
```

```bash
# 1. Read the policy and the DMS clock (read-only, no auth).
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → {"admin_frozen":false,"has_policy":true,"heartbeat_expired":true,
#    "last_heartbeat":1788855212,"now":1788863857}

# 2. Pre-flight a transfer BEFORE signing. Pure read replica of the SAC-transfer
#    decision path; emits the same auth_checked vocabulary as the real path.
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  check --asset CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
# → {"Blocked":"heartbeat_expired"}   (fixture account is DMS-frozen today)

# 3. Heartbeat (agent-signed self-call; the CLI cannot do this).
./tools/agent-tx/target/release/agent-tx heartbeat \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --agent-secret S...   # or set AGENT_SECRET
# → submitted: hash=... status=PENDING
# → RESULT: ALLOWED tx=...
#    event [guard] topics=(event_heartbeat) data=at:<unix>

# 4. Transfer through the guard (agent-signed SAC transfer). agent-tx simulates
#    with the real __check_auth first, so a policy block surfaces pre-broadcast.
./tools/agent-tx/target/release/agent-tx transfer \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
# → submitted: hash=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8
# → RESULT: ALLOWED tx=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8

# 5. A blocked transfer, intentionally (--expect-blocked makes a block a success
#    and prints the contract's own auth_checked diagnostic).
./tools/agent-tx/target/release/agent-tx transfer \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDMVA2IQH63BYCFZMOVDYCUDGJZYSUCDGCVFDPU5BLTHFUEZ6BF5EPP7 \
  --amount 10 --expect-blocked
# → BLOCKED (pre-broadcast, enforced simulation)
#    event [guard] topics=(event_auth_checked, blocked, recipient_not_allowed)

# 6. Stop condition: DMS expired -> admin unfreeze ceremony (agent cannot self-revive).
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- unfreeze
# → ✅ Transaction submitted successfully!
#    tx=dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5
```

**Evidence per command** (so a reviewer can check each one): step 1 `status` and
step 2 `check` are the live reads transcribed in the README function reference
(`status` → `…"heartbeat_expired":true…`; `check` → `{"Blocked":"heartbeat_expired"}`);
step 3 `heartbeat` is the documented invocation in
[`docs/functions/heartbeat.md`](../docs/functions/heartbeat.md) — the fixture's DMS
scenario deliberately *skipped* it, which is why the account reads expired; step 4
is fixture scenario 1 (tx `4c575929…`); step 5 is fixture scenario 4 (event
`blocked, recipient_not_allowed`); step 6 is the fixture unfreeze tx
`dd327d32…`.

`--expect-blocked` is the fixture-friendly form used above. In production, drop
it: a policy block then exits non-zero, which is exactly the fail-closed signal
your loop should branch on.

> **Note on `check()` vs `agent-tx`.** `check()` is the cheap, read-only probe;
> use it as the routine pre-flight. `agent-tx` re-runs the *real* `__check_auth`
> inside its enforced simulation, so it is the second, authoritative gate just
> before broadcast. Together they give the two-layer pattern the SDK guide
> describes for TypeScript agents.

## Blocked-reason handling

`check()` returns `{"Blocked": "<reason>"}` and `agent-tx` prints the same symbol
as the third `event_auth_checked` topic. The stable reason strings are the `Error`
reason names listed in the [`check_auth` error table](../docs/functions/check-auth.md).
Treat any reason you do not recognize as **fatal for that transaction** (fail
closed) and alert.

| Reason | Meaning | Operator / agent action |
|---|---|---|
| `no_policy` | Account is default-deny (policy revoked or never set). | Alert operator — account cannot transact until `set_policy`. Do not retry. |
| `not_initialized` | No agent key registered yet. | Setup error; re-run `initialize` (operator). |
| `admin_frozen` | Admin called `freeze()`. | Stop the loop, alert operator. Only admin `unfreeze()` clears it. |
| `heartbeat_expired` | DMS grace lapsed. | **Stop the loop.** Alert operator; run the unfreeze ceremony (below). Retrying cannot self-revive. |
| `paused` | Policy `paused: true`. | Hold transfers; alert operator to `set_policy` with `paused: false`. |
| `outside_active_window` | `now` outside `active_from`/`active_until`. | Schedule the work inside the window, or ask the operator to widen it. |
| `asset_not_allowed` | Token not in the policy's `assets`. | Do not retry. Operator must add the SAC to the policy. |
| `recipient_not_allowed` | Destination not in `recipients`. | Do not retry. Operator must allowlist the address (or set `allow_any_recipient`). |
| `per_tx_cap_exceeded` | Amount > `per_tx_cap`. | Split the payment across transactions, or raise the cap (operator). |
| `window_cap_exceeded` | Amount would exceed `window_cap`. | Back off until entries roll out of `window_secs`, then retry once. |
| `protocol_not_allowed` | Call to a contract not in `protocols`. | Do not retry. Operator allowlists the contract. |
| `function_not_allowed` | Function not in that rule's `fns`. | Do not retry. Operator adds the function. |
| `unknown_contract` | Call to a contract that is neither an asset nor a protocol. | Fatal; default-deny. Operator must classify it. |
| `self_function_not_allowed` | Guard self-call other than `heartbeat`. | Programming error in the runtime. |
| `create_contract_not_allowed` | Contract creation denied in v1. | Out of scope; do not attempt. |
| `invalid_amount` | Amount ≤ 0. | Fix the call; never send non-positive amounts. |

**Two rules for every reason:** (1) never blind-retry a block — the policy did
not change, so the same call fails the same way and only burns fees; (2)
distinguish *transient* from *terminal*: only `window_cap_exceeded` is
self-recoverable by waiting, everything else needs the operator.

## Stop conditions

The loop must terminate cleanly (no further retries) when any of these hold:

- **DMS expired** (`heartbeat_expired: true` in `status()`, or a
  `heartbeat_expired` block). The agent's key is still valid but the account is
  dead to it — only the admin's `unfreeze()` revives it, and a heartbeat after
  expiry is rejected too. Alert the operator and run the
  [unfreeze ceremony](../docs/functions/freeze-unfreeze.md). Do not spin.
- **Admin freeze** (`admin_frozen: true`) — same operator-required reversal.
- **No policy** (`no_policy`) — nothing can be authorized; setup is incomplete.
- **Paused** — hold, do not terminate; resume when unpaused.

On any stop condition, the correct sequence is: **stop submitting → alert the
operator with the reason symbol and current `status()` → await the admin action**.
Silence never self-heals: the account freezes itself with zero transactions once
grace lapses, exactly as designed.

## Cross-links

- SDK companion guide: [`stellar-agent-guard-sdk#74`][sdk-issue] (TypeScript
  `check()` / `invoke()` path). This doc links it; #74 already covers the same
  raw-contract/`agent-tx` branch, and adds its reverse link to this page when it
  lands. Cross-repo edits are tracked in the SDK repository.
- Dead-man switch mechanics: [`docs/concepts/dead-man-switch.md`](../docs/concepts/dead-man-switch.md).
- Function reference: [`heartbeat`](../docs/functions/heartbeat.md),
  [`check`](../docs/functions/check-auth.md),
  [`freeze / unfreeze`](../docs/functions/freeze-unfreeze.md).
- Fixture evidence: [`tests/fixtures/README.md`](../tests/fixtures/README.md),
  [`docs/verification.md`](../docs/verification.md).
- Submission helper: [`tools/agent-tx`](../tools/agent-tx/src/main.rs).
