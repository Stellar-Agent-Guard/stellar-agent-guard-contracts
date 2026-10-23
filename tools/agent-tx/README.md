# agent-tx

`agent-tx` builds Soroban authorization entries for the guard's custom-account address. Build it from the repository root with:

```bash
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

## Why this tool exists

The `stellar` CLI builds Soroban auth entries and signs them with the transaction source key, but for a *custom account* the auth entry's address is a **contract** (the guard), not the source account, and the CLI refuses ("Missing signing key for account C..."). The only way to exercise the guard's `__check_auth` on-chain is to build the `SorobanAuthorizationEntry` for the guard address and sign its payload with the registered agent Ed25519 key — exactly what this tool does.

## Five-step flow

Every signed transaction follows this sequence:

1. **Simulate the call with no auths** (records requirements + footprint).
2. **Merge the guard's own storage keys** into the footprint (policy, window, heartbeat, freeze, instance — the parts only `__check_auth` touches).
3. **Sign each returned auth entry** (address = guard) with the agent key over the `HashIdPreimage::SorobanAuthorization` payload.
4. **Re-simulate with the signed entries** — this runs the *real* `__check_auth` against live testnet state, so policy blocks surface here, pre-broadcast.
5. **On success, send the transaction and poll for the result**.

## Network selection

Every subcommand resolves its endpoint from a named preset, which fixes both the RPC URL and the network passphrase the signed auth payload commits to:

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
  still signs the mainnet payload. An unrecognized URL requires an explicit
  `--network-passphrase`; the tool never guesses the network identity.
- `--network-passphrase <phrase>` overrides a preset passphrase or specifies the
  network identity for a custom node (for example, a local `stellar standalone`
  network or a fork). The resolved passphrase source is printed before submission.
- `--rpc-timeout <secs>` bounds every RPC request (connect, send, and reading the
  response; default 30). A stalled endpoint ends the invocation with
  `RESULT: RPC TIMEOUT`, exit code 3 and a message naming the RPC method, instead
  of hanging. A timed-out `getTransaction` poll counts as still pending; a
  timed-out `sendTransaction` prints the locally computed tx hash so you can check
  it before resubmitting. The tool does not retry on its own: retries belong to
  the caller (see the Troubleshooting table).
- Selecting mainnet prints a one-line reminder on stderr that this contract is
  unaudited and gates real funds; see the repository [SECURITY.md](../../SECURITY.md).

## Input validation

`--guard`, `--asset`/`--token`, `--to`, the `guards add` address and its admin, and
`AGENT_SECRET` are validated as StrKeys *of the expected kind* before any RPC
request is made: `C...` for contract IDs (guard, token), `G...` for account IDs
(recipients accepted as either, admin must be an account), `S...` for the secret seed.
Length, the base-32 alphabet, and the CRC16 checksum are all checked, so a copy-paste
that lost a character fails with a message naming the flag, the value, and the rule.

The leading character encodes the key *type*, never the network, so validation cannot (and does not claim to) catch a testnet contract ID used against mainnet — the `--network` preset and passphrase decide that.

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
- If blocked: `reason` (the RPC's error code), plus `diagnostic_reason` decoded
  from the diagnostic events when they are present
- If allowed: `estimated_fee_stroops` (RPC's `minResourceFee`)

Example (blocked by per-tx cap):
```text
result: blocked
reason: per_tx_cap_exceeded
```

**`check` is not a policy verdict.** It simulates the SAC transfer with **no
authorization entry** (`src/main.rs`, `cmd_check`: `invoke_op(&invocation,
VecM::default())`), so the host never calls the guard's `__check_auth` and the
policy engine never runs. Recorded against the live testnet deployment, the
same 1100-unit transfer printed `result: allowed` here while a signed
`preflight` blocked it with `heartbeat_expired`. What `check` reports
is whether the *unsigned* simulation succeeds — i.e. the operation shape,
footprint and fee — so treat `allowed` from `check` as "the call is well-formed
and costed", never as "the policy admits it". For an enforced answer use a
signed `preflight` with `AGENT_SECRET` (below) or the on-chain `check` / `check_detailed`
read-only contract views (SPEC section 7), which run the same decision path
without needing auth.

These reads use `getLedgerEntries` and `simulateTransaction` — no auth, no submission, no sequence advancement.

## Preflight (deprecated in favor of `check`)

Run a transfer simulation without submitting a transaction:

```bash
# Read without echo so the secret is not saved in shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx preflight --guard C... --asset C... --to G... --amount 1100
```

Run `unset AGENT_SECRET` when you finish the shell session to clear it from
subsequent commands.

The signed path uses the registered agent secret from `AGENT_SECRET` to
simulate through the live
`__check_auth`. A policy denial is returned with diagnostic event details. For
example, with the repository fixture policy's `per_tx_cap: 1000`:

```text
BLOCKED (pre-broadcast, enforced simulation):
  message: auth_checked: per_tx_cap_exceeded
  diagnostic events:
  event [C...] topics=(event_auth_checked, blocked, per_tx_cap_exceeded) data=...
  broadcast: no
```

Read the reason from the `auth_checked` event's third topic. `preflight` is the
only local path that is guaranteed to see it, because it is the only one that
signs: the simulation failure comes back as `result.error` plus base64
diagnostic events in `result.events`, and a submitted transaction that fails
carries no readable reason field at all. The full observable-error → policy-reason
mapping, with a verbatim live capture, is
[`docs/functions/check-auth.md`](../../docs/functions/check-auth.md#what-an-operator-sees-when-this-rejects-issue-425)
and the reason vocabulary is
[`docs/reason-glossary.md`](../../docs/reason-glossary.md).

> Known reporting gap, verified live (documented in the check-auth section above,
> not fixed here): the block report parses the JSON-RPC *error-object* shape
> (`error.code` / `error.message` / `error.data.events`) while soroban-rpc returns
> a simulation failure as `result.error` (a string) with diagnostics in
> `result.events`. Against the current deployment the header and
> `broadcast: no` print but the `message:` / `diagnostic events:` lines above do
> not. The exit code is unaffected, so `1` still means "the enforced simulation
> blocked this call" — decode the reason from your own `simulateTransaction`
> response if you need the symbol from a script.

An admitted signed simulation prints `RESULT: ALLOWED (preflight only)`, the
estimated fee in stroops, and `broadcast: no`. The fee estimate is the RPC's
`minResourceFee`, plus the inclusion fee and the guard-footprint fee allowance;
actual inclusion costs can differ.

Every preflight invocation begins with `send=no (preflight only)`, including blocked and inconclusive outcomes.

The secret is optional. Without `AGENT_SECRET`, `agent-tx` reads the registered
public key from guard instance storage and builds an unsigned simulation. This can provide
a fee estimate, but it cannot authenticate the custom account or establish
that `__check_auth` would admit the transfer. The result is therefore marked
`INDETERMINATE`, with exit code `2` even if the unsigned simulation itself
succeeds. Use the signed path for an admission verdict.

| Exit code | Meaning |
|---|---|
| `0` | Signed simulation admitted the call. |
| `1` | Signed simulation blocked the call; inspect its diagnostic reason. |
| `2` | Unsigned simulation; admission is inconclusive. |

The preflight implementation only reads ledger state and invokes `simulateTransaction`; its RPC interface has no transaction-submission method. It does not increment the account sequence or broadcast a transaction.

## Submission commands

`transfer` and `heartbeat` submit transactions after successful simulation and
require the registered agent secret in `AGENT_SECRET`. They are distinct from the
non-broadcasting `preflight` command. See the repository README for the
submission error mapping and troubleshooting guidance.

`transfer-from` constructs the token call in the exact order
`transfer_from(from, spender, to, amount)`. It requires `--from`; the guard is
the spender and receives the signed authorization, while `--to` and `--amount`
occupy argument positions 2 and 3. The token must already have an allowance for
the guard as spender. This command uses the same simulate, sign, and submit flow
as `transfer`.

Submission fees use RPC `getFeeStats.inclusionFee.mode` plus the simulated
`minResourceFee` and the guard-footprint fee allowance. `--inclusion-fee
<stroops>` overrides the network-reported inclusion fee. If fee statistics are
unavailable, the tool reports that it is using the 100-stroop fallback.

RPC transport failures, HTTP failures, JSON-RPC rejections, and simulation-level
transaction rejections are reported as distinct outcomes. `--expect-blocked`
returns success only when the simulation contains a guard `auth_checked` block;
other transaction failures are not treated as policy denials.

## Planned: generic `invoke` subcommand (scenario 7)

Transfer tokens via the guard's custom account:

```bash
# Read without echo so the secret is not saved in shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx invoke --guard C... --contract C... --fn <name> [--arg <type:value> ...]
```

## Secret handling

For security, prefer supplying the agent secret via:
- Environment variable: `AGENT_SECRET` (recommended for automation)
- File flag: `--agent-secret <path-to-file>` (reads the secret from a file)

Avoid passing the secret directly on the command line (`--agent-secret S...`) as it may be exposed in shell history or process listings. The file flag and environment variable prevent the secret from appearing in `ps` output or shell history.

If using `--agent-secret` with a value, the secret is still accepted but less secure. The tool will accept it for backward compatibility, but users are strongly encouraged to use `AGENT_SECRET` or a file.

## AGENT_TX_DEBUG output

Set the `AGENT_TX_DEBUG` environment variable to enable detailed diagnostic output to stderr, including:
- Simulated transaction keys and error details
- Footprint merge statistics
- minResourceFee, resourceFee, and final fee calculations
- Submitted transaction envelope (XDR base64)
- Send transaction response
- Transaction status polling details

Example:
```bash
AGENT_TX_DEBUG=1 agent-tx check --guard C... --asset C... --to G... --amount 1100
```

## Prototype for SDK signing path

This tool serves as the prototype for the SDK signing path. Its design decisions — particularly the five-step flow, strict input validation, and separation of read-only vs submission commands — are informed by the architecture described in [ARCHITECTURE.md](../../ARCHITECTURE.md). The SDK will follow the same principles for constructing and signing Soroban transactions on behalf of the guard's custom account.

## Troubleshooting

See the [Troubleshooting section in the root README](../../README.md#troubleshooting) for submission error mappings and remediation flags (e.g., `--fee-multiplier`).

---
*Link this file from the root README's repository-layout section and from CONTRIBUTING.md's project structure.*