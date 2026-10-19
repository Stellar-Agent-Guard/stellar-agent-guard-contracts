Closes #367

## Summary

Pins the exact boundary behavior for `per_tx_cap`: `amount == per_tx_cap` is admitted, and `amount == per_tx_cap + 1` is blocked with `per_tx_cap_exceeded`.

The policy decision engine evaluates `effective_per_tx_cap(cfg, &asset).is_some_and(|cap| amount > cap)` (`src/engine.rs:483`), admitting transfers exactly at the cap value. Prior to this change, existing tests only verified the strict inequality case (`60 > 50`), leaving the equality boundary implicit and untested.

This change documents the exclusive-of-blocking comparison in `SPEC.md` §6.2, adds boundary tests at both the engine (`decide`) and integration (`check` / `transfer`) levels, and updates the verified test count in `README.md`.

## Key Changes

1. **Specification Clarification** (`SPEC.md` §6.2 rule 3):
   - Explicitly states that the comparison is exclusive-of-blocking (the cap value itself is permitted: `amount == effective_per_tx_cap` is admitted; only `amount > effective_per_tx_cap` is blocked).

2. **Engine Unit Test** (`src/engine.rs`):
   - Added `per_tx_cap_boundary_admitted_at_cap_and_blocked_at_cap_plus_one`: asserts `decide` yields `Decision::Allowed` when `amount == per_tx_cap` (50) and `Decision::Blocked(Error::PerTxCapExceeded)` when `amount == per_tx_cap + 1` (51).

3. **Integration Test** (`src/integration_tests.rs`):
   - Added `per_tx_cap_boundary_admitted_at_cap_and_blocked_at_cap_plus_one`: asserts that `transfer` succeeds at `amount == per_tx_cap`, fails with `per_tx_cap_exceeded` at `amount == per_tx_cap + 1`, and validates that preflight `check()` returns identical verdicts.

4. **Documentation Claims** (`README.md`):
   - Updated test count claims from 217 to 219 to satisfy `scripts/verify-readme.sh`.

## Acceptance Criteria Verification

- [x] Test: `amount == per_tx_cap` is admitted; `amount == per_tx_cap + 1` is blocked with `per_tx_cap_exceeded`.
- [x] `SPEC.md` §6.2 states the comparison is exclusive-of-blocking (the cap value itself is permitted).
- [x] Lints clean; no new `#[allow]`.
- [x] PR description references this issue with `Closes #367`.
