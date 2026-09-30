## Summary

The contract's `auth_checked` events (and `check`/`check_detailed` results) carry `reason` symbols; the SDK ships a human-readable `explainReason` map keyed by the same symbols. Until now **nothing failed CI** when a new contract reason landed without an SDK entry — the exact gap `CreateContractNotAllowed` exposed when it was added after the SDK vocabulary was written. This PR adds the concrete parity gate: a committed SDK vocabulary file, a Rust parity test inside `cargo test`, a standalone script with a human-readable diff, and a CI step.

Closes #41

## What lands where

### 1. `tests/fixtures/sdk-reasons.json` — the committed SDK vocabulary (new)

The shared parity artifact: `schema_version: 1`, with a `reasons` object of `"<symbol>": "<human-readable explanation>"` entries — **21 reasons**, matching today's `Error::reason()` exactly (including `create_contract_not_allowed` and `protocol_call_rate_exceeded`). Its `$comment` and `source` block state the contract: the SDK repository asserts **its own shipped map** against this same file, so both repos move together on one committed artifact.

### 2. `tests/reason_parity.rs` — the gate inside `cargo test` (new)

Three tests, so drift fails even where only cargo runs:

- **`contract_reasons_match_the_committed_sdk_vocabulary`** — parses the `Self::Variant => "symbol"` arms straight out of `src/types.rs` (parsing the source rather than a second fixture means a new `Error` variant *cannot land unseen*) and fails with an itemized diff on missing/stale/renamed entries.
- **`fixture_blocked_reasons_use_the_contract_vocabulary`** — every blocked `expected_reason` recorded in `tests/fixtures/index.json` must be a real contract reason; the fixtures' documented `allowed` verdict is whitelisted (it is not an `Error` reason).
- **`every_parsed_reason_round_trips_through_the_compiled_error_enum`** — every parsed symbol must round-trip through `Error::from_block_reason` back to exactly the variant that declares it. This catches a stale arm, a typo, a duplicate symbol across variants, and a variant added to `Error::reason()` but forgotten in `from_block_reason`'s list (verified: each of those fails here with a message naming the symbol).

### 3. `scripts/check-reason-parity.sh` — the standalone CI gate (new)

The same parity with a **human-readable diff** and no Rust toolchain needed. Fails on missing/extra/renamed reasons and on fixture values the contract never emits; exit codes follow the repo's existing `scripts/check-spec-coverage.sh` convention (0 = parity, 1 = violations, 2 = usage/internal). Output sample (verified on the real negative path):

```
Contract reasons (src/types.rs :: Error::reason): 21
SDK vocabulary entries (tests/fixtures/sdk-reasons.json):            20
Fixture expected_reason values (tests/fixtures/index.json):  4

✗ Parity FAILURE: contract reasons vs SDK vocabulary (tests/fixtures/sdk-reasons.json)

  --- Contract reasons missing from the SDK vocabulary (SDK must add an entry) ---
    - create_contract_not_allowed

  --- SDK vocabulary entries that no contract reason produces (stale/renamed?) ---
    (none)

  Fix: add/remove/rename on BOTH sides in the same PR:
    - contract: src/types.rs :: Error::reason()  (and the Error variant itself)
    - SDK copy: tests/fixtures/sdk-reasons.json (the SDK repo asserts its own copy against this file)
    - docs: docs/reason-glossary.md + docs/research/wire-format.md reason tables
```

### 4. `.github/workflows/ci.yml` — wired into the `ci` job **after tests**

New step `Reason parity check (contract ↔ SDK vocabulary ↔ fixtures)` runs `./scripts/check-reason-parity.sh` directly after `cargo test`, per the acceptance criteria. The job name stays `ci` (the `main-protection` ruleset requires it).

### 5. Docs + fixture cross-check

- **`tests/fixtures/README.md`** — the `expected_reason` schema row now documents the cross-check against the contract's reason list and `sdk-reasons.json` (acceptance criterion: "fixture README reason vocabulary cross-checked"; `tests/fixtures_index.rs` already keeps README ↔ `index.json` hashes/fields in sync, and this gate now also pins its reason vocabulary to the contract).
- **`SPEC.md` §9** — after the event table, a paragraph pins the three-sided vocabulary gate and names the SDK companion gate.
- **`docs/reason-glossary.md`** — "Parity gate (issue #41)" note added to the vocabulary blockquote.
- **`docs/research/wire-format.md`** — the `Blocked` reason table gains the missing `protocol_call_rate_exceeded` row (present in code and glossary but absent here — found by building this gate) and a parity note.

### 6. Companion SDK issue

Per the issue's out-of-scope rule, the SDK-side work is tracked in its own repository. **`docs/issues/sdk-reason-parity-gate.md`** contains the filing-ready issue (title + full body: acceptance criteria for asserting the SDK's `explainReason` against the shared file, SHA-pinned fetch guidance, suggested implementation ported from this gate). Note: filing from this environment was rejected — the `GITHUB_TOKEN` here is integration-scoped with read-only org access (`Resource not accessible by integration (createIssue)` on `gh issue create --repo Stellar-Agent-Guard/stellar-agent-guard-sdk`) — so the ready-to-paste text is committed in-repo; nothing else in this PR depends on that issue existing first.

## Acceptance criteria (issue #41)

| Criterion | Status |
|---|---|
| Script fails on missing/extra/renamed reasons with a human-readable diff | ✅ All three negative paths verified (see output above); plus unknown fixture reasons |
| Wired into the `ci` job after tests | ✅ `.github/workflows/ci.yml`, step directly after `cargo test` |
| Vocabulary file committed in this repo; SDK issue filed to assert its side against the same file | ✅ `tests/fixtures/sdk-reasons.json` committed; SDK issue text committed at `docs/issues/sdk-reason-parity-gate.md` (org CI token cannot create cross-repo issues — `createIssue` rejected — so it is filing-ready in-repo; please transfer/paste it into the SDK tracker) |
| Fixture README reason vocabulary cross-checked | ✅ `expected_reason` row in `tests/fixtures/README.md` documents the gate; blocked values pinned to the contract vocabulary by `tests/reason_parity.rs` |
| Lint, type-check, and tests all pass locally | ✅ See below |
| PR description references this issue with `Closes #` | ✅ `Closes #41` |

## Repo checks (all green locally)

- `cargo fmt --check` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean (including the new test target)
- `cargo test` — 131 passed, 0 failed across all targets (was 128; +3 reason-parity tests)
- `./scripts/check-reason-parity.sh` — `✓ Reason parity OK` (21 reasons on all three sides)

## Design notes for review

- **Parse the source, not a copy.** The Rust test reads `Error::reason()` match arms from `src/types.rs`; a second committed list of contract reasons would itself be a drift vector. The shell script greps the same shape (`Self::X => "y"`), so both gates see a new reason the moment the source changes.
- **One shared artifact.** The SDK asserts against *this repo's* committed `sdk-reasons.json` (SHA-pinned on its side), not against a scraped copy of `explainReason` — one file, two consumers, no third copy to sync.
- **No contract code changes.** Reason symbols, event data, and the ABI snapshot are untouched; this is purely a CI/test/docs/vocabulary change, so no snapshot update is needed.

## Out of scope (per the issue)

- `stellar-agent-guard-sdk` and `stellar-agent-guard-dashboard` changes — tracked in their own repositories (companion text: `docs/issues/sdk-reason-parity-gate.md`).

🤖 Generated with Codebuff
