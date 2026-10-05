# agent-tx

`agent-tx` builds Soroban authorization entries for the guard's custom-account
address. Build it from the repository root with:

```bash
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

## Network selection

Every subcommand resolves its endpoint from a named preset, which fixes both the RPC
URL and the network passphrase the signed auth payload commits to:

```bash
agent-tx status --guard C...                    # testnet is the default
agent-tx status --guard C... --network futurenet
```

| `--network` | Endpoint | Passphrase |
|---|---|---|
| `testnet` (default) | `https://soroban-testnet.stellar.org` | `Test SDF Network ; September 2015` |
| `futurenet` | `https://rpc-futurenet.stellar.org` | `Test SDF Future Network ; October 2022` |
| `mainnet` | `https://soroban.stellar.org` | `Public Global Stellar Network ; September 2015` |

- `--rpc-url <url>` points at a custom or self-hosted node instead. `--network` and
  `--rpc-url` together are rejected: they name two endpoints, and guessing which one
  an operator meant is exactly the failure mode presets exist to remove. A URL that
  *is* a preset endpoint is recognised, so `--rpc-url https://soroban.stellar.org`
  still signs the mainnet payload.
- `--network-passphrase <phrase>` overrides the passphrase (a local
  `stellar standalone` network, a fork).
- Selecting mainnet prints a one-line reminder on stderr that this contract is
  unaudited and gates real funds; see the repository [SECURITY.md](../../SECURITY.md).

## Input validation

`--guard`, `--asset`/`--token`, `--to`, the `guards add` address and its admin, and
`--agent-secret` are validated as StrKeys *of the expected kind* before any RPC
request is made: `C...` for contract IDs (guard, token), `G...` for account IDs
(recipients accepted as either, admin must be an account), `S...` for the secret seed.
Length, the base-32 alphabet, and the CRC16 checksum are all checked, so a copy-paste
that lost a character fails with a message naming the flag, the value, and the rule.

The leading character encodes the key *type*, never the network, so validation cannot
(and does not claim to) catch a testnet contract ID used against mainnet — the
`--network` preset and passphrase decide that.

## Read-only diagnostics

Read the guard's current state without simulation or submission.

### `status`

Fetch and display the guard's current status (JSON output):

```bash
agent-tx status --guard C...
```

Output includes:
- `has_policy`: whether a policy is installed
- `admin_frozen`: whether the admin has frozen the account
- `heartbeat_expired`: whether the heartbeat has expired (dead-man switch triggered)
- `last_heartbeat`: unix seconds of the last heartbeat (0 = never)
- `now`: current ledger sequence (used as proxy for "now")

Example:
```json
{
  "has_policy": true,
  "admin_frozen": false,
  "heartbeat_expired": false,
  "last_heartbeat": 1788855212,
  "now": 1788863857
}
```

### `policy`

Fetch and display the installed policy (or `null` if none):

```bash
agent-tx policy --guard C...
```

Returns the current `PolicyConfig` structure, or `null` if no policy is installed (default-deny state).

### `check`

Simulate a prospective transfer and display the decision without submitting:

```bash
agent-tx check --guard C... --asset C... --to G... --amount 1100
```

Output shows:
- `result`: `allowed` or `blocked`
- If blocked: `reason` (the policy rejection reason, e.g., `per_tx_cap_exceeded`)
- If allowed: `estimated_fee_stroops` (RPC's `minResourceFee`)

Example (blocked by per-tx cap):
```text
result: blocked
reason: per_tx_cap_exceeded
```

These reads use `getLedgerEntries` and `simulateTransaction` — no auth, no submission, no sequence advancement.

## Preflight

Run a transfer simulation without submitting a transaction (deprecated in favor of `check`):

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

## Planned: generic `invoke` subcommand (scenario 7)

`transfer` and `heartbeat` only build SAC-transfer and self-call auth entries,
so the protocol-allowlist proof (SPEC section 11, scenario 7) needs a generic
call path. The executing PR adds `invoke`, reusing the existing
simulate-then-submit flow (`run`) and the `Call::invocation` auth-entry
construction with a parameterized variant:

```text
agent-tx invoke --guard C... --contract C... --fn <name> [--arg <type:value> ...] --agent-secret S...
```

Contract for the implementation (kept small on purpose):

- New `Call::Invoke { contract: ScAddress, fn_name: ScSymbol, args: Vec<ScVal> }`
  variant; `invocation()` returns it verbatim as the `InvokeContractArgs` for
  both the operation and the guard's auth entry root — the same "exact args in
  both places" rule `Transfer` follows today.
- `--arg` repeats; each value parses as `address:<C|G...>`, `i128:<n>`,
  `u64:<n>`, or `symbol:<name>` (extend only with a documented reason; the
  scenario-7 protocol contract needs no more than this).
- Unknown `--arg` types and malformed values fail before any simulation, with
  exit code `2` and no broadcast.
- Admit/block reporting and exit codes match `transfer` (admitted submits and
  prints the hash; `--expect-blocked` inverts the verdict for deny runs 7b/7c).
- Unit tests mirror the existing `MockPreflightRpc` exit-code tests for at
  least one admit and one deny shape.
