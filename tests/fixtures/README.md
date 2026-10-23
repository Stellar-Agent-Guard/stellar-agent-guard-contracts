# Testnet fixtures — Phase 1 ground-truth evidence

This directory records the **real, on-chain** testnet proof for Phase 1 of
`stellar-agent-guard-contracts`. Every transaction below was actually submitted
to Stellar testnet and verified via Horizon / the RPC at the time of writing.
Nothing here is simulated.

- Network: Stellar testnet (protocol 28, `Test SDF Network ; September 2015`)
- Date: 2026-09-08 (ledgers ~4565xxx–4566xxx)
- RPC used for submissions: `https://soroban-testnet.stellar.org`
- Horizon used for verification: `https://horizon-testnet.stellar.org`

This file is the on-chain half of [SECURITY.md § Verified against](../../SECURITY.md#verified-against):
that section names the protocol and `soroban-sdk` version, and this file records
the transactions that prove the behaviour on them. `index.json` mirrors the
network (including `network.protocol: 28`) so the claim is machine-checkable;
when the protocol or SDK changes, both files move together.

## Deployed contracts

| Component | Address |
|---|---|
| Guard (custom account) | `CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7` |
| SAC token (`GUARD:GD5S5...`) | `CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7` |

## Accounts

| Role | Address | Key alias (stellar CLI) |
|---|---|---|
| Admin | `GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS` | `guard_admin` |
| Agent (guarded keypair) | `GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP` | `guard_agent` |
| Allowed recipient | `GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX` | `guard_recv` |
| Non-allowlisted address | `GDMVA2IQH63BYCFZMOVDYCUDGJZYSUCDGCVFDPU5BLTHFUEZ6BF5EPP7` | `guard_other` |

## Setup transactions

| Step | Tx hash |
|---|---|
| Upload guard WASM | `d43edd086ac9b376371f33b72ad89b37a9b6b4d43bf34dfea9717a29688b887c` |
| Create guard contract | `a968bc517af34b0cb1ed53a4523d1cb8b9e562e9a9b1e8367acfabcbf18211b1` |
| Create token (SAC) | `19f1e36cf4c67feab4e6eb490b4ef424a7fbcc978fcbfa2cad96a079e93ec828` |
| Mint 100_000 to guard | `bdeab1808f83c8db3c7a8cf675690afa7039a7aaae5e92fdc9fb7d6700adfeb2` |
| Initialize guard (agent pubkey) | `cb17b7b1c65bff74b6bc99f67fe3cf1070c7a28f14bdd71527ba60c9d4a81264` |
| Policy (scenarios 1–4) | `6f17c5707d86754cc64f7f5adf6d9b9840904f0bea4d10ae5620ffe065c61174` |
| Trustline (recipient) | `81479a058dd03457fb91e7b129f941eef64e0bc0752a7f0a5fb3928d5f644fb4` |
| Policy (DMS grace 60s) | `1ddad388f914e267b282855ddc8e5478fabfb8542e7798e4402447e5341e3f9a` |
| Unfreeze (DMS reversal) | `dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5` |

The policies installed:

```
# Scenarios 1–4 (6f17c570…):
per_tx_cap: 1000, window_cap: 150, window_secs: 60,
assets: [token], recipients: [GDUYLF…], blocked_recipients: [], dms_grace_secs: 0 (DMS off)

# DMS scenario (1ddad388…): same policy with dms_grace_secs: 60
```

## How scenarios were executed

The `stellar` CLI cannot sign Soroban auth entries whose address is a
**contract** (the guard) — it only signs for the transaction source account and
errors with "Missing signing key for account C…" (known CLI limitation). So
submissions go through the repo's `tools/agent-tx` helper, which does exactly
what Phase 2's SDK must do:

1. Build the `SorobanAuthorizationEntry` for the **guard** address with the
   agent's registered Ed25519 key (same `HashIdPreimage::SorobanAuthorization`
   payload the host hands to `__check_auth`).
2. Simulate the call — the enforced simulation runs the **real** `__check_auth`
   against live testnet state, so policy blocks surface pre-broadcast.
3. On approval, submit and report the on-chain result.

Each invocation draws a fresh auth nonce: the latest ledger sequence in the high
32 bits and 32 bits of OS randomness in the low 32, independent of the tx
sequence, so a retry after a failed or unconsumed attempt never reuses one (the
host records every consumed nonce on-chain until the entry's signature
expiration; the guard's own `__check_auth` ignores nonces, per SPEC §6). The
collision argument is on `auth_nonce` in `tools/agent-tx/src/main.rs`. The runs
below predate this and used the tx sequence as the nonce.

`agent-tx transfer-from` now builds `transfer_from(from, guard, to, amount)` with
the guard as spender and preserves the token contract's exact argument order.
This path is not demonstrated by the live fixtures: no allowance transaction
was run or verified for the deployed testnet token.

## How to read the blocks

Every scenario block below carries the account state that produced its result —
inline on the command or on the line directly above it — and live runs also
carry the transaction hash and ledger that prove them. This is the same convention as the README's
["How to read the output blocks"](../../README.md#how-to-read-the-output-blocks-in-this-readme)
(issue #418): a block with no state line should not be cited as evidence, and a
blocked result is only meaningful relative to the state that produced it.

## The five scenarios — real results

The recorded `agent-tx` commands omit secret material. To reproduce them, load
the appropriate seed into `AGENT_SECRET` with a hidden prompt; this keeps it out
of shell history:

```bash
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
```

### 1. Allowed transaction — PASSED on-chain

```text
agent-tx transfer --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --token CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
→ submitted: hash=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8 status=PENDING
→ RESULT: ALLOWED tx=4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8
```

Horizon: `successful: true`, ledger 4566285, created 08:10:12Z. The guard's
`event_auth_checked, allowed` event was emitted by the guard contract during the
enforced preflight (topic symbols `auth_checked` / `allowed`), and the SAC
`transfer` event fired on-chain. Funds moved from the guard account to the
allowed recipient.

> Note: a debug-era transfer of the same shape landed earlier as
> `6f5dd410d62e8d83b4d70330d3541ac40678f05b545a4584cbf8e4dce6d07d9b` (ledger
> 4565852) while bring-up of the submission tool was still in progress; the
> five canonical scenarios above and below are the ones recorded here.

### 2. Per-tx cap violation — BLOCKED (pre-broadcast)

```text
agent-tx transfer … --to GDUYLF… --amount 1100 --expect-blocked   # 1100 > per_tx_cap 1000
→ BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event (from the enforced simulation, real `__check_auth`):

```
[Contract Event] topics: [event_auth_checked, blocked, per_tx_cap_exceeded]
```

No transaction was broadcast — the violation was caught by `__check_auth`
before the SAC call could be authorized. Verified against live testnet state.

### 3. Rolling-window cap violation — BLOCKED (pre-broadcast)

Sequence: after scenario 1 spent 50 in the window, a second transfer of 110
(50 + 110 = 160 > window_cap 150) within the 60s window:

```text
agent-tx transfer … --to GDUYLF… --amount 110 --expect-blocked   # window 50+110=160 > 150
→ BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, window_cap_exceeded]
```

This is a **genuinely rolling** 60-second window (SPENT entries carry
`spent_ts`; expired entries are pruned at evaluation time — see
`src/window.rs`), not a fixed-bucket reset.

### 4. Allowlist violation — BLOCKED (pre-broadcast)

```text
agent-tx transfer … --to GDMVA2IQH63BYCFZMOVDYCUDGJZYSUCDGCVFDPU5BLTHFUEZ6BF5EPP7 \
    --amount 10 --expect-blocked
→ BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, recipient_not_allowed]
```

The recipient is not in the policy's `recipients` allowlist; the transfer never
reached the token contract.

### 5. Dead-man switch — trigger FROZEN, then reversal UNFROZEN

Policy with `dms_grace_secs: 60` was installed (tx `1ddad388…`), which starts
the DMS clock (`LastHeartbeat = now` at install, per SPEC §5). After the 60s
grace lapsed with no heartbeat:

```text
agent-tx transfer … --amount 10 --expect-blocked   # 65s after policy install, no heartbeat
→ BLOCKED (pre-broadcast, enforced simulation)
```

Guard diagnostic event:

```
[Contract Event] topics: [event_auth_checked, blocked, heartbeat_expired]
```

Reversal via admin `unfreeze()` (the SPEC §5 reversal path — silence cannot
self-revive; heartbeats are also blocked once expired, so only the admin
attestation restores the account):

```text
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    --network testnet --source guard_admin --send=yes -- unfreeze
→ ✅ Transaction submitted successfully!  tx=dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5
→ Event: EventUnfrozen (event_unfrozen), by: "GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS"
```

Immediately after, the agent's transfer works again:

```text
agent-tx transfer … --amount 10
→ submitted: hash=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512 status=PENDING
→ RESULT: ALLOWED tx=b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512
```

Horizon: `successful: true`, ledger 4566327, created 08:13:42Z.

## Planned scenarios 6-8 (pending live run - issue #49)

Scenarios 6-8 are defined in SPEC section 11 to the same evidentiary standard
as 1-5, but their live runs have not happened yet: nothing below has a hash,
a ledger, or a timestamp, and `index.json` stays at `schema_version: 1` with
scenarios 1-5 until the executing PR records them. Scenario 6 absorbs issue #5
(agent-key rotation proof); the executing PR closes #5 and #49 together.

Conventions: `<GUARD>`, `<TOKEN>`, `<ADMIN>` are the canonical deployment from
the tables above. `<PROTOCOL>` is a minimal protocol contract deployed fresh
at run time (any contract with two functions, e.g. `ping` allowlisted and
`admin_fn` denied - its contract ID is recorded then). `<NEW_PUBKEY_HEX>` is
the 64-character raw Ed25519 public key of a fresh agent keypair (derive it
with `cargo run --example agent_pubkey`). Load the corresponding old or new
secret interactively into `AGENT_SECRET` before each command. Every `(recorded
at run time)` marker below is a value the executing PR fills in, in both this
prose and `index.json`.

### 6. Agent-key rotation + old-key rejection (pending)

Precondition: the account is live - `status` shows `admin_frozen: false` and
`heartbeat_expired: false` (run `unfreeze` and/or install a scenario policy
first; record each admin hash as a setup entry). Read `status` before starting
(the `last_heartbeat` value is needed for the DMS-interplay assertion).

1. Admin rotates with the stellar CLI under the current admin identity:

```text
stellar contract invoke --id <GUARD> --network testnet \
  --source-account <ADMIN> --send=yes -- \
  rotate_agent_key --new_pubkey <NEW_PUBKEY_HEX>
(recorded at run time: tx hash, event_agent_rotated old/new fingerprints)
```

2. Old key rejected. A transfer signed with the old secret never authorizes:
signature verification traps before policy evaluation, so there are no
`auth_checked` topics - the evidence is the simulation error, not an event:

```bash
# Hidden prompt keeps the old secret out of shell history.
read -rsp "Old agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx transfer --guard <GUARD> --token <TOKEN> --to <RECIPIENT> \
  --amount 10 --expect-blocked
# recorded at run time: host signature-trap error output; broadcast: no
```

3. New key admitted:

```bash
# Hidden prompt keeps the new secret out of shell history.
read -rsp "New agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx transfer --guard <GUARD> --token <TOKEN> --to <RECIPIENT> \
  --amount 10
# recorded at run time: submitted hash, ledger, created_at; topics [event_auth_checked, allowed]
```

4. DMS interplay: `status` after step 3 shows the same `last_heartbeat` as
before step 1 (rotation resets nothing), and a new-key `heartbeat` succeeds
inside the existing grace.

5. Restore: `rotate_agent_key` back to the canonical pubkey (hash recorded),
then prove the canonical key spends again. The shared fixture deployment ends
exactly as it started, so scenarios 1-5 stay reproducible.

### 7. Protocol allowlist admit + deny (pending)

Setup: deploy the minimal protocol contract (record its contract ID as
`<PROTOCOL>`), then install a scenario policy allowlisting it with a
per-function rule (`fns` holds `ping`, so `admin_fn` on the same contract
stays denied). Record the `set_policy` hash as a setup entry.

Scenario 7 needs the `invoke` subcommand in `tools/agent-tx` (transfer and
heartbeat only today) - specified in that tool's README and implemented in
the executing PR:

- 7a admit:

```bash
# Hidden prompt keeps the secret out of shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx invoke --guard <GUARD> --contract <PROTOCOL> --fn ping
# recorded at run time: submitted hash, ledger, created_at; topics [event_auth_checked, allowed]
```

- 7b deny (wrong function, same contract):

```bash
# Hidden prompt keeps the secret out of shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx invoke --guard <GUARD> --contract <PROTOCOL> --fn admin_fn \
  --expect-blocked
# recorded at run time: topics [event_auth_checked, blocked, function_not_allowed]; broadcast: no
```

- 7c deny (unknown contract - no deployment needed, any address outside
`assets` and `protocols` exercises the path):

```bash
# Hidden prompt keeps the secret out of shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx invoke --guard <GUARD> --contract <UNLISTED> --fn anything \
  --expect-blocked
# recorded at run time: topics [event_auth_checked, blocked, protocol_not_allowed]; broadcast: no
```

### 8. Pause gate (pending)

1. Admin installs `paused: true` (record the `set_policy` hash as a setup
entry).
2. Agent transfer blocked pre-broadcast. Pause is decision-table gate 4, ahead
of all classification, so no per-call reasoning applies:

```bash
# Hidden prompt keeps the secret out of shell history.
read -rsp "Agent secret: " AGENT_SECRET; echo; export AGENT_SECRET
agent-tx transfer --guard <GUARD> --token <TOKEN> --to <RECIPIENT> \
  --amount 10 --expect-blocked
# recorded at run time: topics [event_auth_checked, blocked, paused]; broadcast: no
```

3. Admin restores `paused: false` (hash recorded); the same transfer succeeds
(recorded at run time: submitted hash, ledger, created_at, topics
`[event_auth_checked, allowed]`).

## Machine-readable index (`index.json`)

[`index.json`](index.json) is the same evidence in a stable shape — **scenario →
tx hash → ledger → expected reason → contract ID** — so tooling never has to
scrape this prose. This README stays the human narrative; the index is the
machine contract, and `schema_version` is what a consumer checks first.

### Schema (`schema_version: 1`)

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | int | Breaking-change marker. Bumped only when a field changes meaning or disappears; consumers must reject versions they don't know. |
| `network` | object | `name`, `protocol`, `passphrase`, `rpc`, `horizon`, `recorded_on`, `ledger_range_note` — the chain this evidence was captured on. |
| `contracts` | object | `guard` (the deployed custom-account address) and `token` (the SAC address) from the table above. |
| `accounts[]` | array | `role`, `address`, `key_alias` for each fixture account. |
| `setup_transactions[]` | array | The Phase 1 setup table: `step` (stable key), `label` (prose), `tx`, and `ledger` (`null` — setup ledgers were not recorded individually). |
| `scenarios[]` | array | Exactly five entries with `id` 1–5 matching the headings below. |
| `scenarios[].outcome` | `"allowed"` \| `"blocked"` | Verdict of the recorded run. |
| `scenarios[].expected_reason` | string | `allowed` when admitted, otherwise the block reason symbol (`per_tx_cap_exceeded`, `window_cap_exceeded`, `recipient_not_allowed`, `heartbeat_expired`) — the same vocabulary as [`docs/reason-glossary.md`](../../docs/reason-glossary.md). |
| `scenarios[].guard` / `.token` / `.policy_tx` | string | Contract IDs the scenario ran against, plus the `set_policy` transaction that armed the policy in effect. |
| `scenarios[].recipient` / `.amount` | string \| null / int | Transfer shape as recorded; `recipient` is `null` where the command above elided it. |
| `scenarios[].tx` | string \| null | Confirmed transaction hash, or `null` — blocked scenarios are caught pre-broadcast and have no hash. |
| `scenarios[].ledger` | int \| null | Ledger index of `tx`; `null` when blocked or not recorded. |
| `scenarios[].recorded_utc` | string \| null | Horizon `created_at` time of `tx`, when recorded. |
| `scenarios[].event_topics` | array | Recorded auth_checked topics. The canonical full vocabulary, including the empty reason topic on allowed outcomes, is in [`auth-checked-vocabulary.json`](auth-checked-vocabulary.json). |
| `scenarios[].notes[]` | array | The caveats the prose carries for that scenario. |
| `scenarios[4].reversal` | object | DMS reversal: `action`, `by` (admin address), `tx`, `ledger`, `event_topics` (`[event_unfrozen]`). |
| `scenarios[4].post_reversal` | object | The transfer that succeeded after `unfreeze()`: `outcome`, `expected_reason`, `amount`, `tx`, `ledger`, `recorded_utc`, `notes`. |
| `supplemental_transactions[]` | array | Hashes recorded in prose outside the setup table and the five scenarios (the debug-era transfer), with `canonical_scenario: null` for non-canonical runs. |

### Planned extension (`schema_version: 2`, executing PR)

When scenarios 6-8 land, the index grows with them and consumers must see
`schema_version: 2`. The executing PR (which closes #49 and #5) does all of
the following together, so the drift ratchet never passes on a half-migrated
pair of files:

- `scenarios[]` gains ids 6, 7, and 8 (dense, so `SCENARIO_COUNT` in
  `tests/fixtures_index.rs` moves 5 to 8 in the same PR). Deny-runs nest the
  way scenario 5 nests its reversal: scenario 6 carries `old_key_rejected`
  and `restore` (rotate-back) objects; scenario 7 carries `deny_wrong_fn`
  and `deny_unknown`; scenario 8 carries `restore` (unpause hash plus the
  post-restore transfer).
- New nested shapes need test support, not just data: the old-key rejection
  is a host signature trap with no `auth_checked` topics, so
  `old_key_rejected` records a `simulation_error` string and empty
  `event_topics`; the scenario-7 admit is a protocol call, not a transfer,
  so `token`/`recipient`/`amount` are null there and the entry carries
  `protocol` and `fn_name` instead. `assert_scenario` must learn both shapes.
- Every new setup entry (`set_policy` installs, `rotate_agent_key` and
  rotate-back, unpause, the `<PROTOCOL>` deployment) goes in
  `setup_transactions` with its prose table row, and every new contract or
  account appears in `contracts`/`accounts` (the protocol contract ID is only
  known at run time).

### Consistency guarantee

[`tests/fixtures_index.rs`](../fixtures_index.rs) runs as part of `cargo test`,
so it is part of the required `ci` check. It fails the build when the two files
drift:

- every 64-digit transaction hash in this README must appear in `index.json`
  **and** every hash in `index.json` must appear in this README;
- every truncated hash reference in this README (e.g. `6f17c570…`) must
  resolve to a hash that `index.json` records;
- the setup table must keep one row per `setup_transactions` entry;
- the scenario list must stay ids 1–5 with coherent `outcome`,
  `expected_reason`, `tx`, `ledger`, and `event_topics`.

## Canonical `auth_checked` event vocabulary

[`auth-checked-vocabulary.json`](auth-checked-vocabulary.json) is the complete,
machine-readable matrix of the allowed path and every `Error` code/reason
symbol. Each entry pins its event topics, data map fields, and SPEC reference.
Allowed decisions carry an empty reason topic because the contract publishes a
`Symbol("")` when no block reason exists. The `auth_checked_vocabulary`
integration test deserializes this fixture and fails if it drifts from the
`Error` enum or its reason-symbol mapping.

The SDK and dashboard should load this file from the contracts repository in
their decoder tests rather than maintaining copied vocabularies. Their
companion tracking issues are [SDK #263](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk/issues/263)
and [dashboard #263](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-dashboard/issues/263).

> **Companion note for `stellar-agent-guard-sdk`:** consume `index.json`
> instead of scraping this markdown — parse `schema_version` first and treat an
> unknown version as "do not trust". Its `scripts/check-enforcement-evidence.ts`
> gate does not read this README today (it only checks which files a PR
> touched), so there is no scraper to migrate yet; file the follow-up in that
> repository if fixture evidence is ever wired into that gate.

## What an operator sees for each recorded scenario

The `→ BLOCKED (pre-broadcast, enforced simulation)` lines above are the CLI
surface; the `topics: [event_auth_checked, blocked, <reason>]` lines are the
on-chain surface, and they are the authoritative record of *why*. Both come from
the same `simulateTransaction` response — the failure arrives as `result.error`
(a string) with the base64 diagnostic events in `result.events`, not as a
JSON-RPC `error` object — and the reason symbol is always the **third topic**.
The complete mapping (including the post-broadcast and bad-signature surfaces)
is
[`docs/functions/check-auth.md`](../../docs/functions/check-auth.md#what-an-operator-sees-when-this-rejects-issue-425).

| Scenario | Exit code from `agent-tx` | Reason an operator can decode | Reversal |
|---|---|---|---|
| 1 allowed | `0` | `topics: [event_auth_checked, allowed, ""]` — the reason topic is empty on an allow ([`auth-checked-vocabulary.json`](auth-checked-vocabulary.json)) | none needed |
| 2 per-tx cap | `1` | `per_tx_cap_exceeded`, contract code 22 | lower the amount, or `set_policy` to raise `per_tx_cap` |
| 3 rolling window | `1` | `window_cap_exceeded`, code 23 | wait for the oldest spend to age out of the window; `set_policy` resets the ledger |
| 4 allowlist | `1` | `recipient_not_allowed`, code 21 | `set_policy` to add the recipient |
| 5 dead-man | `1` | `heartbeat_expired`, code 11 — note the heartbeat self-call is **also** blocked, so only the admin can reverse it | admin `unfreeze` (scenario 5 above) |

Two notes that matter when these rows are used to triage a live incident:

- A block never changes state. Scenarios 2–4 consume nothing from the rolling
  window (SPEC §4 commits admissions only when *every* context passes), so
  replaying a blocked amount after a policy change behaves as if the failed
  attempt never happened. Scenario 3's "50 + 110" arithmetic only holds because
  scenario 1 was admitted.
- These five scenarios each present a **single** auth context, so the reported
  reason is that context's reason. A multi-context batch reports the first
  failing context in iteration order while every context still gets its own
  `auth_checked` event — worked through in SPEC §6.0 and pinned by
  `mixed_multi_context_batch_reports_the_first_failing_context` (`src/engine.rs`).

## How to re-run

1. `cargo build --release --target wasm32v1-none` (contract) and
   `cd tools/agent-tx && cargo build --release` (submission helper).
2. Fund fresh accounts via Friendbot, deploy the guard + token, mint, and
   `initialize` (see setup txs above).
3. Install the scenario policies (JSON in `--config`), then run the
   `agent-tx` invocations above. Use `--expect-blocked` for scenarios 2–5.

The five blocked/emitted events above are the contract's own
`event_auth_checked` topics — grep the enforced-simulation output for
`blocked, <reason>` to confirm each.

## Contributing to the proof plan: when a change needs a testnet proof entry

Per [`CONTRIBUTING.md` Coding Standard 6](../../CONTRIBUTING.md#coding-standards) and [`SPEC.md` §11](../../SPEC.md#11-testnet-proof-plan-scenarios-18-five-proven-three-planned), this directory records ground-truth on-chain evidence for contract behavior. To keep enforcement claims backed by real evidence without imposing unnecessary testnet runs on invisible changes, use the following guidelines:

### What requires a testnet proof entry ("user-visible enforcement change")

A change **requires** an on-chain testnet proof entry when it modifies externally observable authorization semantics:
- **Decision-table changes:** Any change altering what `__check_auth` admits or blocks, or changing the error code, event topics, or diagnostic data emitted on allow or deny.
- **Storage-layout or key-schema changes:** Changes to storage keys, data types, footprint, or TTL management (these probably require an entry because they alter on-chain state persistence, footprint, or contract upgrade/migration compatibility observable by callers).
- **Policy/guard rules:** Adding, modifying, or removing policy constraints, guards, or authorization paths.

### What does NOT require a testnet proof entry

A change **does not** require a testnet proof entry when observable contract behavior and state remain identical:
- **Gas / CPU / memory optimizations:** Internal performance improvements that preserve identical admit/block decisions, storage layouts, and emitted events.
- **Documentation changes:** Updates to markdown files, doc comments, specs, or diagrams.
- **Internal refactorings:** Restructuring internal helper functions, code cleanup, or modifying test harnesses and test-only code with zero external behavioral or state impact.

### Summary comparison

| Change category | Testnet proof entry required? | Examples / Notes |
|---|---|---|
| Decision-table change | Yes | Altering `__check_auth` admit/deny logic, error discriminants, event topics |
| Storage-layout change | Probably | Modifying storage key schemas, persistent footprint, TTL policies |
| Policy rule addition/removal | Yes | Adding new guard rules, allowlists, or authorization evaluation paths |
| Gas / performance optimization | No | Reducing CPU/instructions while preserving exact input/output and event behavior |
| Documentation update | No | Spec clarifications, README/diagram improvements, doc comments |
| Internal refactoring | No | Restructuring helper functions, cleaning up tests, renaming internal variables |

### Evidence bar and recording responsibility

- **Evidence bar:** A complete testnet proof entry requires the on-chain testnet transaction hash (`tx hash`) and the corresponding captured event/diagnostic output (`topics: [event_auth_checked, <outcome>, <reason>]`), formatted consistently with the scenarios in this README and mirrored in [`tests/fixtures/index.json`](index.json). Both files are cross-checked by [`tests/fixtures_index.rs`](../fixtures_index.rs).
- **Who records it:** The PR author proposing the user-visible enforcement change is responsible for executing the testnet scenario (using `tools/agent-tx` or standard Soroban CLI submission) and submitting the updated proof fixtures with their PR. When live testnet infrastructure or deployment keys are maintainer-managed during release/verification, the contributor provides the reproducible simulation command and rationale in the PR description, and maintainers record the live hashes upon verification.

### Impractical testnet changes (the fallback path)

When a change is enforcement-affecting (changes what `__check_auth` admits or blocks) but is impractical or non-deterministic to demonstrate on public testnet (such as extreme ledger-sequence/timestamp boundary conditions, complex time-warp states, specific host race conditions, or host resource-exhaustion limits):
1. **Deterministic local test:** Implement a comprehensive unit or host-routed integration test using the Soroban test environment (`Harness` / `GuardScenario` in [`src/integration_tests.rs`](../../src/integration_tests.rs)) that precisely exercises the boundary condition or failure path.
2. **Written rationale:** Include a clear written rationale in the PR description and proof plan documentation explaining why live testnet reproduction is impractical and how the local test suite conclusively guarantees the invariant.

