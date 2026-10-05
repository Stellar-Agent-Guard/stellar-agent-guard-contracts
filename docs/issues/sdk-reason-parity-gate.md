# Companion SDK issue (to be filed in `stellar-agent-guard-sdk`)

**Status:** filing from this environment was rejected — the `GITHUB_TOKEN` here
is an integration-scoped token with read-only access to the
`Stellar-Agent-Guard` org repos (`GraphQL: Resource not accessible by
integration (createIssue)` on `gh issue create --repo
Stellar-Agent-Guard/stellar-agent-guard-sdk`). The issue body below is complete
and ready to paste into the SDK repository by someone with issue access;
per issue #41's out-of-scope note, the cross-repo work is tracked in the SDK's
own tracker. Nothing else in this PR (vocabulary file, script, test, CI
wiring, docs) depends on that issue existing first.

---

## Title

`Assert explainReason vocabulary against the contracts repo's committed sdk-reasons.json (reason parity gate)`

## Body

### Summary

The contracts repository has landed a **reason-symbol parity gate**
(Stellar-Agent-Guard/stellar-agent-guard-contracts#41): its CI keeps the
contract's `Error::reason()` symbols, a committed copy of **this SDK's**
human-readable reason map, and its on-chain fixture evidence in lockstep. This
repo must now assert **its own shipped vocabulary** against that same committed
file, so the two sides cannot drift.

**The shared file:**
[`tests/fixtures/sdk-reasons.json`](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/blob/main/tests/fixtures/sdk-reasons.json)
in stellar-agent-guard-contracts — `schema_version: 1`, a `reasons` object of
`"<symbol>": "<human-readable explanation>"` entries (currently 21, including
`create_contract_not_allowed` and `protocol_call_rate_exceeded`).

**Why:** the SDK's `explainReason` map is exactly the kind of thing that rots —
the contracts repo adds a new `Error` variant (as `CreateContractNotAllowed`
was added after the fact, the original gap in #41), the SDK map silently lacks
an entry, and users get raw symbols instead of explanations. The contracts side
already fails CI when its own list and the committed copy disagree; this repo
needs the matching assertion so its *shipped* map is also pinned.

### Acceptance criteria

- [ ] The SDK's reason vocabulary (the `explainReason` map, wherever it ships —
  e.g. `src/reasons.ts`) is asserted at build/CI time against the contracts
  repo's `tests/fixtures/sdk-reasons.json`:
  - every symbol in the shared file has an `explainReason` entry (missing = fail);
  - every `explainReason` key exists in the shared file (stale/renamed = fail);
  - failure output is a human-readable diff naming the offending symbols and
    pointing at the shared file.
- [ ] The shared file is fetched pinned (commit SHA — the contracts repo's
  `main` may move; do not track a mutable ref in CI) with a comment recording
  the pinned SHA and how to update it.
- [ ] When the contracts repo adds a reason (the shared file changes), the SDK
  PR must add the vocabulary entry and the human-readable copy in the same PR —
  the gate failing is the intended friction.
- [ ] Symbol set matches the shared file's `reasons` object exactly.

### Suggested shape

A small script (TS/Vitest test both fit) reading the pinned `sdk-reasons.json`
and the SDK's own map, diffing the key sets, and exiting nonzero with an
itemized diff — the contracts repo's `scripts/check-reason-parity.sh` /
`tests/reason_parity.rs` are the reference implementation and can be ported in
minutes. Wire it into this repo's CI job after the test step.

### Out of scope

- Changing the reason symbols themselves — they are owned by the contracts repo
  (its `Error::reason()` is the source of truth; the shared file only mirrors it).
- `stellar-agent-guard-dashboard` decode work, if any — tracked in its own
  repository.

### References

- Contracts-side gate: Stellar-Agent-Guard/stellar-agent-guard-contracts#41
- Shared vocabulary file: `tests/fixtures/sdk-reasons.json` in
  stellar-agent-guard-contracts (pin by SHA when consumed here)
