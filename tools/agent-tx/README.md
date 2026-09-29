# agent-tx

`agent-tx` builds Soroban authorization entries for the guard's custom-account
address. Build it from the repository root with:

```bash
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

## Preflight

Run a transfer simulation without submitting a transaction:

```bash
agent-tx preflight --guard C... --asset C... --to G... --amount 1100 --secret "$AGENT_SECRET"
```

The signed path uses the registered agent secret (also accepted as
`--agent-secret` or from `AGENT_SECRET`) to simulate through the live
`__check_auth`. A policy denial is returned with diagnostic event details. For
example, with the repository fixture policy's `per_tx_cap: 1000`:

```text
BLOCKED (pre-broadcast, enforced simulation):
  message: auth_checked: per_tx_cap_exceeded
  diagnostic events:
  event [C...] topics=(event_auth_checked, blocked, per_tx_cap_exceeded) data=...
  broadcast: no
```

An admitted signed simulation prints `RESULT: ALLOWED (preflight only)`, the
estimated fee in stroops, and `broadcast: no`. The fee estimate is the RPC's
`minResourceFee`, plus the inclusion fee and the guard-footprint fee allowance;
actual inclusion costs can differ.

Every preflight invocation begins with `send=no (preflight only)`, including
blocked and inconclusive outcomes.

`--secret` is optional. Without it, `agent-tx` reads the registered public key
from guard instance storage and builds an unsigned simulation. This can provide
a fee estimate, but it cannot authenticate the custom account or establish
that `__check_auth` would admit the transfer. The result is therefore marked
`INDETERMINATE`, with exit code `2` even if the unsigned simulation itself
succeeds. Use the signed path for an admission verdict.

| Exit code | Meaning |
|---|---|
| `0` | Signed simulation admitted the call. |
| `1` | Signed simulation blocked the call; inspect its diagnostic reason. |
| `2` | Unsigned simulation; admission is inconclusive. |

The preflight implementation only reads ledger state and invokes
`simulateTransaction`; its RPC interface has no transaction-submission method.
It does not increment the account sequence or broadcast a transaction.

## Submission commands

`transfer` and `heartbeat` submit transactions after successful simulation and
require `--agent-secret` (or `AGENT_SECRET`). They are distinct from the
non-broadcasting `preflight` command. See the repository README for the
submission error mapping and troubleshooting guidance.
