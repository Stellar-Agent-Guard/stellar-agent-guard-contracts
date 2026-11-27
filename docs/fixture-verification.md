# Fixture re-verification contract (issue #156)

**Status: specification only.** No re-verification script exists in this repository
yet. This page defines what "verified" means for every claim recorded in
[`tests/fixtures/README.md`](../tests/fixtures/README.md) and
[`tests/fixtures/index.json`](../tests/fixtures/index.json), so that the future
script (tracked by
[issue #156](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/156))
implements this table 1:1 instead of inventing its own notion of "verified".

- The human narrative is [`tests/fixtures/README.md`](../tests/fixtures/README.md).
- The machine-readable twin is [`tests/fixtures/index.json`](../tests/fixtures/index.json).
- The live-verification page is [`docs/verification.md`](verification.md).
- The version scope of the security model is
  [`SECURITY.md` § Verified against](../SECURITY.md#verified-against).

Nothing on this page is a claim that a check has been run. The status column
records whether a claim **can** be checked from public remote data, not whether
it **was** checked when the fixtures were recorded.

---

## 1. What "verified" means

A fixture claim is **verified** when an unauthenticated, read-only query against
the recorded network's public endpoints returns data that satisfies every
machine-readable field backing that claim:

| Part of "verified" | Rule |
|---|---|
| Same network | The endpoint's network passphrase must equal `network.passphrase` (`Test SDF Network ; September 2015`). A response from any other network is never evidence. |
| Same object | The identifier in the response (`hash`, `sequence`, `account_id`, contract ID) must equal the identifier in the fixture. A lookup by some other key is not enough. |
| Same value | Every recorded value that the response exposes (success flag, ledger index, timestamp, topic list, amount, address) must compare equal under the rule named for that row. |
| Read-only | No verification step may submit a transaction, sign an auth entry, or write state. |
| No silent pass | A claim whose remote surface is absent, archived, or out of retention is reported as **indeterminate**, never as verified. |

Claims that have no remote surface at all are marked **not remotely verifiable**
in the tables below. They are *not* skipped: each carries the limitation and the
local evidence that does exist.

## 2. Shared inputs (from the fixture files, not hard-coded)

The script must read these from `tests/fixtures/index.json`; a value typed into
the script is a bug.

| Input | Source field | Used for |
|---|---|---|
| Network passphrase | `network.passphrase` | Rejecting responses from another network |
| Protocol version recorded | `network.protocol` (`28`) | Comparison against the ledger header / `getNetwork` |
| Recorded date | `network.recorded_on` (`2026-09-08`) | Timestamp sanity check on the recorded ledgers |
| Ledger range note | `network.ledger_range_note` (`ledgers ~4565xxx-4566xxx`) | Bounds for setup transactions, which have no recorded individual ledger |
| Horizon base URL | `network.horizon` (`https://horizon-testnet.stellar.org`) | Transactions, ledgers, operations, accounts |
| Soroban RPC base URL | `network.rpc` (`https://soroban-testnet.stellar.org`) | Contract events, transaction meta, read-only contract calls |
| Guard / token contract IDs | `contracts.guard`, `contracts.token` | Event filters, contract-state probes |
| Account addresses | `accounts[].address` | Existence checks, effect attribution |
| Transaction hashes | `setup_transactions[].tx`, `scenarios[].tx`, `scenarios[4].reversal.tx`, `scenarios[4].post_reversal.tx`, `supplemental_transactions[].tx` | Existence / success / ledger checks |
| Recorded ledgers and times | `*.ledger`, `*.recorded_utc` | Equality checks where present (`null` means "not recorded", so no equality check) |

### 2.1 What Horizon can and cannot answer

This distinction decides most rows below, so it is stated once:

- **Horizon** (`network.horizon`) serves transaction, ledger, operation and
  account resources. It is the source for `successful`, `ledger`, `created_at`,
  operation type/parameters, and account existence.
- **Soroban RPC** (`network.rpc`) is the only source for **contract events**
  (`getEvents`) and for the transaction's Soroban meta and diagnostics
  (`getTransaction` → `resultMetaXdr`, plus `diagnosticEventsXdr` where the
  response carries it). Horizon does not expose contract events, so any
  `event_topics` claim is an RPC claim.
- **RPC event retention is bounded.** `getEvents` only serves a recent ledger
  window. Fixtures recorded on a fixed date are therefore *partially* checkable:
  the transaction and its meta remain on Horizon, while the decoded contract
  events may have fallen out of retention.
- **No historical state snapshots.** Neither endpoint can return "the guard's
  storage as it was on 2026-09-08". Read entrypoints (`status`, `policy_hash`,
  `policy_version`, `check`) evaluate against the **current** ledger.

## 3. Verification dimensions, and which claims use them

Dimensions are applied per claim, not uniformly:

| Dimension | Applies to | Check that establishes it |
|---|---|---|
| Transaction existence | every recorded hash (setup, scenarios 1 and 5, reversal, post-reversal, supplemental) | Horizon `GET /transactions/{hash}` returns the resource |
| Ledger matching | the same set, where `ledger` is recorded | Response `ledger` equals the fixture `ledger`; where `ledger` is `null`, only presence is checked |
| Operation success | the same set | Response `successful` is `true` |
| Event topics | broadcast scenarios (1, 5 post-reversal), the `unfreeze` reversal, and the policy installs | RPC `getEvents` (or `getTransaction` meta) decoded to `[event_auth_checked, result, reason]`, compared to `event_topics` |
| Contract still holds the recorded state | no claim — the recorded state is historical | Not applicable; only a *drift report* against current state is possible (see §6) |
| Pre-broadcast denials (scenarios 2–4, 5 trigger, 7b/7c, 8) | — | **Not remotely verifiable**: no transaction exists, and a fresh simulation runs against today's state |
| Tooling and code properties (nonce handling, rolling-window pruning, CLI limitation) | — | **Not remotely verifiable**: code claims, pinned by local tests |

## 4. Claim → check table

Status vocabulary:

- **remote** — a public read-only query establishes the claim.
- **partial** — a public query establishes part of it; the remainder is named in
  *Limitations*.
- **none** — no remote surface; local evidence only.

### 4.1 Network and metadata claims

| Fixture / claim | Required remote check | Endpoint / query | Expected comparison | Remote verification status | Limitations |
|---|---|---|---|---|---|
| `network.passphrase` = `Test SDF Network ; September 2015` | Ask Horizon and the RPC which network they serve | Horizon `GET {horizon}/` → `network_passphrase`; RPC `getNetwork` → `passphrase` | Both equal the fixture passphrase | remote | None |
| `network.protocol` = `28` | Compare the recorded ledger header's protocol version with the fixture | RPC `getNetwork` → `protocolVersion` (current network only); Horizon `GET {horizon}/ledgers/{scenario_1_ledger}` and use `protocol_version` **if the response carries it** | Equal to `28` | partial | `getNetwork` reports the **current** protocol, so a later testnet upgrade makes it legitimately differ. Whether Horizon's ledger resource exposes `protocol_version` depends on the deployed Horizon version: if the field is absent, report indeterminate rather than passing. |
| `network.recorded_on` = `2026-09-08` with `ledger_range_note` = `ledgers ~4565xxx-4566xxx` | Check the recorded ledgers' close times and that setup transactions fall in the noted range | Horizon `GET {horizon}/ledgers/4566285`, `/ledgers/4566327` → `closed_at`; each setup `GET /transactions/{hash}` → `ledger` | `closed_at` date is `2026-09-08`; each setup ledger is inside the noted range | remote | The range is prose ("~4565xxx–4566xxx"), so the script must bound it explicitly (4565000–4566999) and say so in the report. |
| `network.horizon` endpoint reachable and serving the recorded network | Probe Horizon root | Horizon `GET {horizon}/` → `horizon_version`, `network_passphrase` | HTTP 200 and passphrase match | remote | An unreachable endpoint is **indeterminate**, not a failed claim. |
| `network.rpc` endpoint reachable | Probe RPC health | RPC `getHealth` → `status` | `"healthy"` | remote | Same: unreachable is indeterminate. |
| `contracts.guard` / `contracts.token` are deployed contract IDs on this network | Read-only invocation of the guard's permissionless read surface and the SAC's metadata | RPC `simulateTransaction` invoking `status` on `contracts.guard`; `symbol` on `contracts.token` | `status` returns a policy snapshot (non-error); SAC `symbol` returns the fixture asset code `GUARD` | partial | This proves the contracts exist **now**, not that they are the same instances recorded in 2026-09 (no deployment-time field is recorded for comparison). The `GUARD:GD5S5…` code:issuer claim additionally needs the SAC's contract-data asset entry (`getLedgerEntries` with a constructed ledger key); the fixture does not record that key, so it is out of scope for the first script. |
| `accounts[]` (admin, agent, allowed recipient, non-allowlisted recipient) exist and are funded | Fetch each account | Horizon `GET {horizon}/accounts/{address}` | HTTP 200 and `account_id` equals the requested address | remote | Existence only. Balances are current, not as-of-recorded, so no balance claim is made or checked. |

### 4.2 Setup transactions (`setup_transactions[]`, nine rows)

`setup_transactions[].ledger` is `null` for every row — individual setup ledgers
were never recorded — so ledger **equality** is not checkable; the range in
`network.ledger_range_note` is the substitute. The step-specific expectation
column states what the script should assert beyond that once it has confirmed the
field spelling against a live response; this specification does not assert
unverified field names as facts.

| Fixture / claim | Required remote check | Endpoint / query | Expected comparison | Remote verification status | Limitations |
|---|---|---|---|---|---|
| `upload_guard_wasm` (tx exists, succeeded, in range) | Fetch transaction, then its operations | Horizon `GET /transactions/{hash}`, `GET /transactions/{hash}/operations` | `successful: true`; `ledger` inside the noted range; one operation of Soroban contract-invocation type | partial | Horizon exposes no WASM bytecode hash for this step, and the fixture records none, so "the deployed code is the code this repo builds" is **not** checkable. |
| `create_guard_contract` | Same | Same | `successful: true`; in range; contract-creation host function | partial | The created contract ID is checked through `contracts.guard` (§4.1), not by parsing this operation. |
| `create_token_sac` | Same | Same | `successful: true`; in range | partial | The fixture does not record which asset the operation created; that comes from the `contracts.token` check. |
| `mint_to_guard` | Same, plus the minted amount | `GET /transactions/{hash}/operations` → operation parameters | `successful: true`; in range; a mint of `100000` to `contracts.guard` | partial | Requires ScVal decoding of the operation parameters (SPEC §3.2 encoding). If Horizon's deployed version omits `parameters` for host-function operations, fall back to the RPC `getTransaction` meta, and report indeterminate if neither carries the argument. |
| `initialize_guard` | Same, plus the registered agent key | `GET /transactions/{hash}/operations` → parameters | `successful: true`; in range; argument is the agent address (its registered Ed25519 key fingerprint) | partial | Same decoding caveat. The fixture records the agent **address**, so a fingerprint comparison is against `accounts[role=agent]`, not a raw key. |
| `policy_scenarios_1_to_4` | Same, plus the policy values | Operations → parameters, decoded per SPEC §3.2 | `successful: true`; in range; `per_tx_cap` 1000, `window_cap` 150, `window_secs` 60, `assets` = [token], `recipients` = [allowed recipient], empty `blocked_recipients`, `dms_grace_secs` 0 | partial | The policy values exist only in this README's prose (inside the fenced block), not in `index.json`; the script must therefore either parse the prose (fragile) or keep these expectations in its own reviewed constant table, and the fixture should gain structured policy fields before the script claims to verify them. |
| `trustline_recipient` | Fetch transaction and operations | `GET /transactions/{hash}/operations` | `successful: true`; in range; a `change_trust` operation whose trustor is the allowed recipient | partial | The asset code/issuer on that operation is checkable from the operation resource; the fixture does not record it, so the script compares against the `contracts.token` asset. |
| `policy_dms_grace_60s` | Same as the scenarios 1–4 policy row | Same | `successful: true`; in range; same policy with `dms_grace_secs` 60 | partial | Same prose-only-policy limitation. |
| `unfreeze_dms_reversal` | Fetch transaction and operations | `GET /transactions/{hash}/operations` | `successful: true`; in range; invocation of `unfreeze` | partial | Also recorded again as `scenarios[4].reversal.tx`; the script must report it **once** and cross-reference both fixture locations. |

### 4.3 Scenarios, reversal, and supplemental transactions

| Fixture / claim | Required remote check | Endpoint / query | Expected comparison | Remote verification status | Limitations |
|---|---|---|---|---|---|
| Scenario 1 — allowed transfer exists, succeeded, at ledger 4566285, created 08:10:12Z | Transaction lookup | Horizon `GET /transactions/{hash}` | `successful: true`; `ledger` = 4566285; `created_at` time = `08:10:12Z` | remote | `recorded_utc` stores a time only; compare the time component of `created_at` and assert the date against `network.recorded_on`. |
| Scenario 1 — `event_topics` = `[event_auth_checked, allowed]` | Decode the guard's contract events for that transaction | RPC `getEvents` with `filters: [{type: "contract", contractIds: [guard]}]`, `startLedger` = recorded ledger (paged forward); or the `diagnosticEventsXdr`/`resultMetaXdr` of `getTransaction(hash)` | An `event_auth_checked` event whose second topic is `allowed`, matching the fixture array | partial | Only decodable while the ledger is inside RPC event retention; beyond that, report indeterminate. An allowed outcome carries **no** third topic in the fixture (`["event_auth_checked","allowed"]`) while the prose says the contract publishes an empty reason symbol — the script must compare against `auth-checked-vocabulary.json`, not assume the array length. |
| Scenario 1 — "SAC `transfer` event fired on-chain" | Decode token contract events for the same ledger | RPC `getEvents` with `contractIds: [token]`, topics filtered to the transfer symbol | A transfer event from `contracts.guard` to the recorded recipient | partial | Retention-limited, and the event's amount encoding must be decoded before comparing to `amount: 50`. |
| Scenario 1 — "funds moved from the guard account to the allowed recipient" | Historical balance delta | Not available | — | none | Neither Horizon nor RPC exposes a balance snapshot at a past ledger for contract accounts. The transfer is evidenced by the operation/event arguments above; a *current* balance read is not evidence of the historical movement. |
| Scenario 2 — per-tx cap violation blocked pre-broadcast with `per_tx_cap_exceeded` | None possible | — | — | none | No transaction was broadcast and `tx`/`ledger` are `null`, so there is nothing on-chain to query. Re-simulating the transfer today would evaluate **today's** window and heartbeat state, not the recorded state; a fresh simulation is therefore not a re-verification. Local evidence: `event_topics` in `index.json` and the README block, plus the engine unit tests for `per_tx_cap_exceeded`. |
| Scenario 3 — rolling-window violation blocked pre-broadcast with `window_cap_exceeded` | None possible | — | — | none | Same as scenario 2, plus the window arithmetic ("50 + 110 = 160 > 150") depends on scenario 1 having been admitted in the same 60 s window; that historical window content cannot be recovered. Local evidence: `index.json`, README block, `src/window.rs` tests. |
| Scenario 4 — allowlist violation blocked pre-broadcast with `recipient_not_allowed` | None possible | — | — | none | Same as scenario 2. The *policy* that refused the recipient is checkable as an installation argument (§4.2), which is why the claim is recorded as a row rather than dropped. |
| Scenario 5 — DMS trigger blocked pre-broadcast with `heartbeat_expired` | None possible | — | — | none | Same as scenario 2. The "65 s after policy install, no heartbeat" timing cannot be reconstructed from chain data. |
| Scenario 5 reversal — `unfreeze` tx exists and succeeded, `event_topics` = `[event_unfrozen]` | Transaction lookup plus event decode | Horizon `GET /transactions/{hash}`; RPC `getEvents` (or meta) filtered to the guard | `successful: true`; an `event_unfrozen` event; `by` attribute equals the admin address when the event payload carries it | partial | `reversal.ledger` is `null`, so no ledger equality is possible (existence and success still are). Event decode is retention-limited. |
| Scenario 5 post-reversal — allowed transfer, ledger 4566327, created 08:13:42Z, outcome `allowed` | Transaction lookup plus event decode | Horizon `GET /transactions/{hash}`; RPC `getEvents` | `successful: true`; `ledger` = 4566327; time = `08:13:42Z`; an `auth_checked`/`allowed` event | partial | Same retention limit as scenario 1's event check. `post_reversal.event_topics` is not recorded in the index — the script must not require a comparison the fixture does not make. |
| Supplemental — debug-era transfer, ledger 4565852, outcome `allowed` | Transaction lookup | Horizon `GET /transactions/{hash}` | `successful: true`; `ledger` = 4565852 | remote | Non-canonical by definition (`canonical_scenario: null`); the report must label it as supplemental so it is never counted as one of the five scenarios. |

### 4.4 Narrative, state, and tooling claims

| Fixture / claim | Required remote check | Endpoint / query | Expected comparison | Remote verification status | Limitations |
|---|---|---|---|---|---|
| "The contract still holds the recorded state" (any scenario's policy, window, heartbeat, freeze flag) | None possible for the recorded point in time | RPC `simulateTransaction` invoking `status` / `policy_hash` / `policy_version` returns **current** state only | — | none | Newest and strongest limitation on this page. The fixture records no ledger-key snapshot, so historical storage cannot be compared. Current-state reads are a drift report (§6), deliberately kept out of the pass/fail verdict. |
| "Policies installed: `per_tx_cap` 1000, `window_cap` 150, `window_secs` 60, assets/recipients as listed, `dms_grace_secs` 0 then 60" | Read the `set_policy` installation arguments | Operations/parameters of `6f17c570…` and `1ddad388…` (see §4.2) | Decoded `PolicyConfig` equals the prose values | partial | Prose-only values; requires the structured policy fields noted in §4.2 before the script can claim this automatically. |
| "Each invocation draws a fresh auth nonce … the guard's `__check_auth` ignores nonces (SPEC §6)" | None possible | — | — | none | A code property. Local evidence: `tools/agent-tx/src/main.rs` collision argument and the auth-path tests. A live run would show one nonce, not the freshness property. |
| "The window is genuinely rolling (SPENT entries carry `spent_ts`; expired entries pruned at evaluation time)" | None possible | — | — | none | Code property. Local evidence: `src/window.rs` and its tests (SPEC §3.1). |
| "The `stellar` CLI cannot sign contract-address auth entries, so submissions used `tools/agent-tx`" | None possible | — | — | none | A tooling limitation, not a chain fact. Local evidence: `tools/agent-tx/README.md` and the recorded command blocks. |
| "`transfer_from` builds the guard as spender … no allowance transaction was run or verified" | None possible | — | — | none | An explicit non-claim in the fixture prose; the correct re-verification outcome is "nothing to check", reported as such. |
| "Scenarios 6–8 are pending live execution" | None possible (absence of evidence is not a query) | — | — | none | Checked locally instead: `tests/fixtures_index.rs` (`SCENARIO_COUNT = 5`) and `index.json` scenario IDs 1–5. The report must state that scenarios 6–8 are outside the verified set. |
| "README ↔ `index.json` describe the same run" | None possible remotely | — | — | none | Already a local CI gate: `tests/fixtures_index.rs` (hashes, prefixes, setup-row count, scenario shape). The re-verification script must not duplicate it; it consumes the index and reports on remote data. |
| "Horizon reported `successful: true`" for scenarios 1 and 5 post-reversal | Covered by the scenario rows above | — | — | remote | The recorded status is directly comparable, which is why these two scenarios carry the strongest remote evidence. |

## 5. Claims the script must report as unverifiable

The following set is closed and must appear in every report, even when empty of
mismatches. It exists so that a green report cannot be read as "everything on
this page was checked":

1. Scenarios 2, 3, 4 and the scenario-5 DMS trigger (pre-broadcast denials, no
   transaction, no historical state).
2. Historical contract state (policy, window, heartbeat, freeze flag) at any
   recorded point in time.
3. Balance movement at a past ledger.
4. Deployed WASM identity for `upload_guard_wasm`.
5. Tooling and code properties: nonce freshness, rolling-window pruning, CLI
   signing limitation.
6. Contract events outside the RPC retention window (indeterminate, reported
   with the requested ledger range).
7. Scenarios 6–8, which are not part of the recorded evidence yet.

## 6. Current-state drift report (allowed, separate from the verdict)

The script may additionally read **current** chain state through the guard's
permissionless read entrypoints (`status`, `policy_hash`, `policy_version`, and
`check`) via RPC `simulateTransaction`. That data is a *drift report*: it says
what the deployed contract looks like now. It must be rendered in its own
section, must never be compared to the historical fixture values as if they
described the same moment, and must never change the exit code that the
historical checks produce.

## 7. Implementation subtasks for the future script

No component below exists in this PR. The script must implement the table in §4
1:1; the acceptance criteria name the table sections it is responsible for.

### 7.1 Fixture loader and claim model

- **Responsibility:** load `tests/fixtures/index.json` plus
  `tests/fixtures/auth-checked-vocabulary.json` into a typed model; expose one
  claim object per row in §4.
- **Inputs:** the two JSON files, and the prose-derived policy expectations as a
  reviewed constant table until §4.2's structured fields land.
- **Outputs:** an ordered list of claims with stable IDs matching this page's row
  names (for example `setup.upload_guard_wasm`, `scenario.1.tx`,
  `scenario.5.reversal.event`).
- **Remote queries:** none.
- **Comparison rules:** reject an `index.json` whose `schema_version` is not the
  expected one; reject unknown fields in a scenario entry instead of ignoring
  them.
- **Error behaviour:** malformed or unknown-version fixture → exit `2` with the
  offending path, never a partial pass.
- **Acceptance criteria:** every row in §4 has exactly one claim ID; a fixture
  field added or removed without a matching claim update fails the build of the
  claim list.
- **Tests required:** unknown `schema_version`; missing required field; a fixture
  with an extra scenario; claim-ID uniqueness.

### 7.2 Network and endpoint probe

- **Responsibility:** confirm both endpoints answer and serve the recorded
  network before any claim is evaluated.
- **Inputs:** `network.horizon`, `network.rpc`, `network.passphrase`.
- **Outputs:** a resolved endpoint pair plus a passphrase verdict.
- **Remote queries:** Horizon `GET /`; RPC `getHealth`, `getNetwork`.
- **Comparison rules:** passphrase equality only (case-sensitive).
- **Error behaviour:** unreachable or wrong-network endpoint → every dependent
  claim is **indeterminate**, exit `2`, and the report says which endpoints
  failed. Wrong network is never retried silently against another URL.
- **Acceptance criteria:** §4.1 network rows implemented; no hard-coded URL.
- **Tests required:** passphrase mismatch; HTTP 5xx; timeout.

### 7.3 Horizon transaction and ledger verifier

- **Responsibility:** evaluate every claim that names a transaction hash, and the
  ledger/date claims.
- **Inputs:** `setup_transactions[]`, `scenarios[].tx`, `scenarios[4].reversal`,
  `scenarios[4].post_reversal`, `supplemental_transactions[]`, `network.*`.
- **Outputs:** per-hash verdict (`verified`, `mismatch`, `indeterminate`) with the
  compared fields and both values.
- **Remote queries:** `GET /transactions/{hash}`, `GET /ledgers/{sequence}`,
  `GET /transactions/{hash}/operations`, `GET /accounts/{address}`.
- **Comparison rules:** `successful === true`; `ledger` equality only when the
  fixture records one (`null` → presence-only, explicitly stated in the report);
  `created_at` time equality when `recorded_utc` is present; setup ledgers bounded
  by the noted range; operation-level assertions as listed in §4.2/§4.3.
- **Error behaviour:** 404 → `mismatch` (the fixture names a transaction that does
  not exist on this network); rate limit / 5xx / timeout after bounded retries →
  `indeterminate`; never `verified`.
- **Acceptance criteria:** §4.2 and the transaction rows of §4.3 implemented;
  `setup_transactions` with `ledger: null` do not silently pass a ledger check.
- **Tests required:** hash present with wrong ledger; hash absent (404);
  `successful: false`; `recorded_utc: null`; supplemental labelled non-canonical.

### 7.4 Soroban RPC event and meta verifier

- **Responsibility:** evaluate every `event_topics` claim for broadcast
  transactions and the `event_unfrozen` reversal.
- **Inputs:** guard and token contract IDs, recorded ledgers, expected topic
  arrays, `auth-checked-vocabulary.json`.
- **Outputs:** decoded topic arrays per transaction, compared topic by topic.
- **Remote queries:** RPC `getEvents` (`startLedger` = recorded ledger,
  `filters: [{type: "contract", contractIds: [...]}]`, paged); fallback
  `getTransaction` meta/diagnostics when `getEvents` cannot serve the range.
- **Comparison rules:** the reason symbol is the third topic on a block and there
  is no third topic on an allow; compare against the vocabulary file rather than
  assuming array length. Topic equality is exact and order-sensitive.
- **Error behaviour:** `startLedger` outside retention and no meta fallback →
  `indeterminate` with the attempted range; undecodable XDR → `indeterminate`
  with the raw base64 stored in the report; never guess a topic.
- **Acceptance criteria:** §4.3 event rows implemented; allowed vs blocked topic
  shapes both handled; retention failure reported as indeterminate.
- **Tests required:** allowed shape (`[event_auth_checked, allowed]`); blocked
  shape with reason; out-of-retention range; undecodable payload; unknown reason
  symbol (must surface as blocked-and-unknown, not as a pass).

### 7.5 Contract-state probe and drift report

- **Responsibility:** implement §4.1's contract-existence rows and §6's
  current-state section.
- **Inputs:** `contracts.guard`, `contracts.token`.
- **Outputs:** existence verdicts plus a clearly separated drift section.
- **Remote queries:** RPC `simulateTransaction` invoking `status` on the guard and
  `symbol` on the token.
- **Comparison rules:** a non-error simulation is existence; no historical
  comparison is permitted.
- **Error behaviour:** archived/TTL-expired entries → `indeterminate` naming the
  entry; a simulation error is a failed existence check, not a crash.
- **Acceptance criteria:** drift data is rendered separately and cannot alter the
  historical verdict or exit code.
- **Tests required:** successful read; contract error; archived entry; assertion
  that drift data does not change the exit code.

### 7.6 Unverifiable-claim registry and report renderer

- **Responsibility:** guarantee that §5's list is always printed, and render the
  verdicts.
- **Inputs:** every claim verdict plus the §5 registry.
- **Outputs:** a human-readable report (default) and a machine-readable JSON mode
  with one entry per claim ID.
- **Remote queries:** none.
- **Comparison rules:** exit `0` only when every claim is `verified` or listed in
  §5; exit `1` when any claim is `mismatch`; exit `2` when any claim is
  `indeterminate` or an endpoint failed.
- **Error behaviour:** an unknown claim ID or missing verdict is a hard failure —
  a claim must never disappear from the report.
- **Acceptance criteria:** the §5 list appears in every report; a report with no
  remote access cannot exit `0`.
- **Tests required:** all-verified; one mismatch; one indeterminate; no network;
  JSON schema stability.

### 7.7 CI wiring (opt-in, never in the required `ci` job)

- **Responsibility:** run the script on a schedule or by manual dispatch.
- **Inputs:** published endpoints only; no secrets.
- **Outputs:** a job log and the JSON report as an artifact.
- **Remote queries:** those of §7.2–§7.5.
- **Comparison rules:** the job fails on exit `1`; on exit `2` it reports
  "indeterminate" without failing the release gate, so a public-testnet outage
  cannot block development.
- **Error behaviour:** must not be added to the `ci` job, which is the required
  status check and must stay hermetic.
- **Acceptance criteria:** the required `ci` check does not depend on network
  access; the new job is documented in `CONTRIBUTING.md` when it lands.
- **Tests required:** workflow lint (the repository has no workflow linter today;
  at minimum a dry run against testnet before merging).

### 7.8 Explicit non-goals

- Re-running the Phase 1 scenarios against live testnet (that is a fixture
  *refresh*, governed by [`tests/fixtures/README.md`](../tests/fixtures/README.md),
  not a re-verification).
- Any write, submission, or auth-entry signing.
- Replacing `tests/fixtures_index.rs`, which stays the local README ↔ index gate.

## 8. Relationship to the existing gates

| Gate | Kind | What it proves |
|---|---|---|
| `tests/fixtures_index.rs` (part of `cargo test` / required `ci`) | local, hermetic | README and `index.json` describe the same run |
| [`auth-checked-vocabulary.json`](../tests/fixtures/auth-checked-vocabulary.json) + `auth_checked_vocabulary` test | local, hermetic | The recorded topic vocabulary matches the `Error` enum |
| Re-verification script (not implemented) | remote, opt-in | The public chain still contains what the fixtures say it contains, for the claims marked `remote`/`partial` above |

## 9. Cross-references

- [`tests/fixtures/README.md`](../tests/fixtures/README.md) — the human narrative
  and the claim blocks this table enumerates.
- [`tests/fixtures/index.json`](../tests/fixtures/index.json) — the machine
  contract the script reads.
- [`docs/verification.md`](verification.md) — the published verification page.
- [`SECURITY.md` § Verified against](../SECURITY.md#verified-against) — the
  protocol/SDK scope the fixtures back.
- [`SPEC.md` §11](../SPEC.md#11-testnet-proof-plan-scenarios-18-five-proven-three-planned)
  — the normative proof plan, including the evidence bar.
- [`docs/audit-pack.md`](audit-pack.md) — audit inventory item 13 tracks the
  script.
