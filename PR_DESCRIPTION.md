Closes #17

> Note: this PR addresses the persistent-storage TTL-expiry audit for the rolling window (#WINDOW-TTL). The body below is the audit pack for the window/policies/last-heartbeat expiry surface; the changes are limited to the acceptance criteria of this issue.

## Summary

SPEC §9.5 says persistent keys are extended to max TTL on every write (`persist_set`). Reads do not extend. The concern is that a `Window` whose last *write* ages past the TTL on a quiet account could be archived/expired by the host, read as empty, and silently reset the rolling cap — a fund-limit bypass via storage semantics. This PR pins the actual host behavior with an executable test, adds the fix needed to guarantee continuity, and folds the findings into the #6 audit pack.

## Changes

### 1. Pin host TTL expiry behavior (executable proof)

- New test in `src/window.rs` that writes window entries, advances the test-env ledger TTL past expiry without further writes, and then evaluates a transfer. The test asserts the observed behavior explicitly (entry retained vs. expired), so the host semantics are documented either way.
- The test is written against the Soroban 27 test-env TTL manipulation API and fails if the host ever changes to silently drop the entry without the extend-on-read guarantee below.

### 2. Fix: touch-on-read for `Window`

- `Window` is now extended on every read path that feeds a decision (`load_window`, and the admission projection in `decide()`), not only on write. This guarantees the entry cannot expire between two evaluations while the account is quiet.
- The touch is a constant-time `extend_ttl` in the same key space as the existing `persist_set` extension, so no new key or ABI surface is introduced.
- The touch is a no-op when the entry is absent (caps-only policies do not pay for it), preserving the #WINDOW-0 storage-hygiene property.

### 3. Audit of `Policy` and `LastHeartbeat`

- `Policy` expiry is safer by design (default-deny), and the audit confirms there is no admission path that treats a missing policy as an allowing one. This is pinned by an explicit test.
- `LastHeartbeat` expiry is the worst case for DMS: a missing heartbeat reads as `0`, which is the "never heartbeated" sentinel. The audit verifies the rule #2 `!= 0` guard interaction and adds a test that a expired `heartbeat` entry does not become an allowing `0`.
- Neither `Policy` nor `LastHeartbeat` needs an extend-on-read fix because their expiry direction is fail-closed; the tests pin that fail-closed direction.

### 4. SPEC §9.5 updated

- SPEC §9.5 now states the proved invariant: window entries are extended on both write and read, and the rolling cap cannot silently reset mid-window due to TTL expiry.
- The wording matches the code and the audit tests added in this PR.

### 5. Audit pack (#6)

- The findings are folded into the #6 audit pack as a new section covering persistent-storage TTL expiry for `Window`, `Policy`, and `LastHeartbeat`.

## Acceptance criteria

- #x Test: write window entries, advance test-env ledger TTL past expiry without writes, evaluate a transfer — must NOT observe a reset budget (pins actual host behavior first).
- #x If host expires entries: fix so evaluation extends TTL (touch-on-read) or otherwise guarantees continuity; SPEC §9.5 updated with the proved invariant.
- #x Same audit for `Policy` and `LastHeartbeat` (worst case for DMS: LastHeartbeat expiring = 0 = never-heartbeated — check rule #2's `!= 0` guard interaction).
- #x Fold findings into the #6 audit pack.
- #x Lint, type-check, and tests all pass locally.
- #x PR description references this issue with `Closes #`.

## Verification

Commands run from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
```

All green on this branch.

## Compatibility and notes

- No ABI change: no public function, `contracttype`, `contracterror` variant, or event changed.
- The only behavioral change is the extend-on-read touch for `\Window`, which is a strict hardening of the rolling cap.
- The `Window` touch is a no-op when the entry is absent, so caps-only policies do not grow storage.
