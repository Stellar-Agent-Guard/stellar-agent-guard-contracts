# Quickstart — derive → initialize → policy → heartbeat

> **Testnet only. Unaudited software.** This contract gates real fund access and
> has not been independently audited. Do not use these commands on mainnet or
> with funds you cannot lose. See [`SECURITY.md`](../SECURITY.md).

This is the one-page operator sequence from a fresh testnet deployment to the
first agent-signed heartbeat. It reuses the existing
[`agent_pubkey.rs`](agent_pubkey.rs) derivation example and the checked-in
[fixture policy](../tests/fixtures/policy-config-parity.json). For the
steady-state loop after setup, continue with
[`agent-loop.md`](agent-loop.md).

Two address forms matter throughout:

- The admin and agent wallets have `G...` public addresses and `S...` secrets.
- After `initialize`, the agent's account **is** the guard's `C...` contract
  address. Agent authorizations are signed with the agent's `S...` secret but
  are submitted as auth entries for the `C...` guard. The Stellar CLI cannot
  sign those entries, which is why the heartbeat uses `agent-tx`.

## Prerequisites

- Rust 1.91+ with the `wasm32v1-none` target (this repo's
  `rust-toolchain.toml` pins the exact compiler).
- `stellar` CLI 22+ (verified against 27.1.0).
- `bash`, `curl`, and `jq` for the optional
  [fixture re-verification script](../scripts/verify-fixtures-live.sh).
- Friendbot access to testnet for the fresh admin and agent accounts.

All commands below run from the repository root with `set -euo pipefail` in
effect.

## 0. Build the contract and the signing helper

```bash
set -euo pipefail

cargo build --release --target wasm32v1-none
cargo build --release --manifest-path tools/agent-tx/Cargo.toml

AGENT_TX=tools/agent-tx/target/release/agent-tx
sha256sum target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm
```

**Success signal:** both binaries exist and `sha256sum` prints a 64-hex digest.

## 1. Generate funded testnet identities

```bash
ADMIN_ALIAS="qs-admin-$(date +%s)"
AGENT_ALIAS="qs-agent-$(date +%s)"

stellar keys generate "$ADMIN_ALIAS" --network testnet --fund
stellar keys generate "$AGENT_ALIAS" --network testnet --fund

ADMIN="$(stellar keys public-key "$ADMIN_ALIAS")"
AGENT="$(stellar keys public-key "$AGENT_ALIAS")"
printf 'ADMIN=%s\nAGENT=%s\n' "$ADMIN" "$AGENT"
```

**Success signal:** two `G...` addresses are printed. The `--fund` step is
testnet-only and requires Friendbot; if it fails, fund both accounts manually
before continuing. Use new aliases — `stellar keys generate` refuses to
overwrite an existing alias.

## 2. Derive the raw agent public key

`initialize` takes the 32-byte Ed25519 **verifying key** as `BytesN<32>`,
not the `G...` StrKey. Derive it with the repository example:

```bash
read -rsp "Agent secret for $AGENT_ALIAS: " AGENT_SECRET; echo
export AGENT_SECRET

AGENT_PUBKEY="$(printf '%s\n' "$AGENT_SECRET" | cargo run --quiet --example agent_pubkey)"
printf '%s\n' "$AGENT_PUBKEY"
[[ "$AGENT_PUBKEY" =~ ^[0-9a-f]{64}$ ]] && echo 'OK: 64-char lowercase hex pubkey'
```

**Success signal:** one 64-character lowercase hex string, followed by
`OK: 64-char lowercase hex pubkey`.

`agent_pubkey.rs` deliberately does not validate the StrKey checksum, so a
mistyped secret can still yield plausible hex. The `G...` address printed in
step 1 comes from `stellar keys public-key`, which does validate it; compare
the derived key with that identity before submitting. Keep `AGENT_SECRET`
exported — step 7 needs it. Do not pass the secret as a command-line argument.

## 3. Upload the WASM and create the guard

```bash
WASM_HASH="$(stellar contract upload \
  --wasm target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm \
  --source-account "$ADMIN_ALIAS" \
  --network testnet | tail -n 1)"

GUARD="$(stellar contract deploy \
  --wasm-hash "$WASM_HASH" \
  --source-account "$ADMIN_ALIAS" \
  --network testnet | tail -n 1)"

printf 'WASM_HASH=%s\nGUARD=%s\n' "$WASM_HASH" "$GUARD"
```

**Success signal:** `WASM_HASH` is 64 hex characters and `GUARD` starts with
`C`. Record both. A retried `deploy` creates a *new* contract, so do not leave
two guards with different policy admins.

## 4. Initialize — bind admin and agent key

```bash
stellar contract invoke \
  --id "$GUARD" \
  --network testnet \
  --source-account "$ADMIN_ALIAS" \
  --send=yes -- \
  initialize \
  --admin "$ADMIN" \
  --agent_pubkey "$AGENT_PUBKEY"
```

**Success signal:** `transaction submitted successfully` and a `tx=<64 hex>`
line.

Verify before installing a policy:

```bash
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=no -- status
```

**Expected shape:** `has_policy: false`, `admin_frozen: false`,
`heartbeat_expired: false`.

If a retry returns `Error(Contract, #2)` (`AlreadyInitialized`), the first
attempt succeeded. Do **not** deploy a second guard: re-read `status()` and go
straight to step 5 if it looks sane.

## 5. Install the shared fixture policy

The config comes verbatim from
[`tests/fixtures/policy-config-parity.json`](../tests/fixtures/policy-config-parity.json);
it is schema-checked in CI, and the contract remains the authoritative
validator. It sets `per_tx_cap: 1000`, `window_cap: 150` over a 60-second
window, one testnet SAC asset, one allowed recipient, and `dms_grace_secs: 60`.

```bash
POLICY_JSON="$(cat tests/fixtures/policy-config-parity.json)"

# Rehearse without submitting (optional):
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=no -- \
  set_policy --config "$POLICY_JSON"

# Install:
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=yes -- \
  set_policy --config "$POLICY_JSON"
```

**Success signal:** `EventPolicySet` / `event_policy_set` in the output, plus a
`tx=<64 hex>` line for the submitted call. `Error(Contract, #4)` means
`InvalidConfig` and leaves the previous policy unchanged.

The 60-second grace is a **demo value that arms the dead-man switch**. The
first install starts the clock; production deployments should use a grace that
matches their heartbeat cadence (see [`agent-loop.md`](agent-loop.md), which
recommends an interval of `grace / 3`).

## 6. Verify state before the first heartbeat

```bash
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=no -- status
```

**Expected shape immediately after install:** `has_policy: true`,
`paused: false`, `admin_frozen: false`, `heartbeat_expired: false`, with
`last_heartbeat` set to the install time.

If more than 60 seconds have elapsed, `heartbeat_expired` is `true` and the
agent's heartbeat will be rejected — silence cannot self-revive. The admin
must re-arm it first:

```bash
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=yes -- unfreeze
```

`unfreeze` also resets `LastHeartbeat` to now; its event carries
`rearmed_dms: true` when that changed an already-expired clock.

## 7. First heartbeat, signed by the agent

`AGENT_SECRET` is still exported from step 2. The guard's `C...` address is the
auth entry's address, so only `agent-tx` can produce the signature the host
routes through `__check_auth`:

```bash
"$AGENT_TX" heartbeat --guard "$GUARD" --network testnet
```

**Success signal:**

```text
submitted: hash=<64 hex> status=PENDING
RESULT: ALLOWED tx=<64 hex>
event [<GUARD>] topics=(event_heartbeat) data=at:<unix>
```

With `--json`, expect a single object on stdout such as:

```json
{"outcome":"allowed","tx_hash":"<64 hex>","ledger":<number>,"network":"testnet"}
```

Exit code `0` means the signed simulation was admitted; `1` means blocked (often
`heartbeat_expired` if the grace lapsed); `2` means the unsigned simulation was
inconclusive. Do not use `--expect-blocked` on the happy path.

## 8. Confirm and clean up

```bash
stellar contract invoke \
  --id "$GUARD" --network testnet \
  --source-account "$ADMIN_ALIAS" --send=no -- status

unset AGENT_SECRET
```

**Success signal:** `heartbeat_expired: false` and `last_heartbeat` advanced to
the heartbeat's ledger time.

## Troubleshooting quick reference

| Symptom | Meaning | Action |
|---|---|---|
| `Error(Contract, #2)` on `initialize` | `AlreadyInitialized` | Check `status()`; continue to `set_policy`, do not redeploy |
| `Error(Contract, #4)` on `set_policy` | `InvalidConfig` | Validate against [`policy.schema.json`](../policy.schema.json); policy was not changed |
| `heartbeat_expired` | DMS grace lapsed | Admin `unfreeze`; then resume the heartbeat loop |
| `failed ED25519 verification` | Secret does not match the registered agent key | Re-derive from the same secret, or admin `rotate_agent_key` |
| `tx_bad_seq` / `tx_insufficient_fee` | Submission fee/sequence issue | Retry via `agent-tx` with a higher fee or refreshed sequence |

## References

- [Deployment runbook](../docs/operations/deployment-runbook.md) — ordered
  upload → create → initialize → set_policy → status sequence with expected
  failures.
- [Agent runtime loop](agent-loop.md) — heartbeat cadence, pre-flight checks,
  blocked-reason handling, and stop conditions.
- [`tools/agent-tx/README.md`](../tools/agent-tx/README.md) — secret handling,
  network presets, `--json`, and exit codes.
- [Live Phase-1 fixtures](../tests/fixtures/README.md) — real testnet hashes,
  ledgers, and the
  [read-only re-verification script](../scripts/verify-fixtures-live.sh).
- [SPEC.md](../SPEC.md) — normative authorization and policy semantics.
