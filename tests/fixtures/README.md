# Testnet fixtures — Phase 1 ground-truth evidence

This directory records the **real, on-chain** testnet proof for Phase 1 of
`stellar-agent-guard-contracts`. Every transaction below was actually submitted
to Stellar testnet and verified via Horizon / the RPC at the time of writing.
Nothing here is simulated.

- Network: Stellar testnet (protocol 28, `Test SDF Network ; September 2015`)
- Date: 2026-09-08 (ledgers ~4565xxx–4566xxx)
- RPC used for submissions: `https://soroban-testnet.stellar.org`
- Horizon used for verification: `https://horizon-testnet.stellar.org`

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

Each invocation uses a fresh tx sequence as the auth nonce (the SAC's replay
protection records every consumed nonce on-chain; the guard's own `__check_auth`
ignores nonces, per SPEC §6).

## The five scenarios — real results

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
