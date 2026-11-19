# test(window): automate SPEC §11 scenario 3's window rollover (drop the 60 s wait)

## Summary

Closes #122. SPEC §11 scenario 3 ends with "then a window rollover restores spending,
proving it is rolling". Demonstrating that on testnet required waiting out a 60-second
fixture window in wall-clock time, and the existing unit coverage of the rollover is split
between raw-ledger tests (`src/window.rs`) and a long multi-scenario lifecycle simulation —
nothing walked the scenario end-to-end through the contract boundary. This PR adds that one
focused test, with the wait replaced by a ledger-timestamp jump.

No contract code changed; this is test + spec cross-reference only.

## What changed

- **`src/integration_tests.rs`** — new test
  `spec_11_scenario_3_window_rollover_restores_spending`, using the fixture's own window
  (`window_secs = 60`, `window_cap = 150`) with `per_tx_cap = 150` (see the reviewer note
  below; no transfer trips it):
  1. spend 50 → admitted;
  2. spend 110 → blocked `WindowCapExceeded` (160 > 150), and `status().window_remaining`
     still shows the full 100 headroom — a denied attempt never consumes budget (§6.0);
  3. at `t0 + window_secs - 1` → still blocked (the admission is retained inside the window);
  4. at `t0 + window_secs + 1` → the same 110 is admitted (rollover restored spending —
     this is the step the testnet run waited 60 real seconds for);
  5. one second before the new admission's boundary → 41 is blocked (retained);
     at exactly `admitted_at + window_secs` → the entry is expired (§3.1) and the full 150
     cap is available again.
- **`SPEC.md` §11 scenario 3** — notes that the rollover half is automated by that test,
  and that it pins the §3.1 exact-boundary membership rule.
- **`README.md`** — the audited test count moves from 250 to 251 in both places
  (`scripts/verify-readme.sh` sums `test result: ok. N passed` across binaries and fails if
  the README claim disagrees).

## Sequence note (deduplication with the boundary-pinning and lifecycle issues)

This test does **not** re-derive timestamps a third time:

- **Boundary arithmetic** stays owned by the `src/window.rs` unit fixtures —
  `exact_boundary_semantics` (entry at `ts + window_secs == now` is exactly expired) and
  `prune_boundary_is_addition_form_at_zero_timestamp` (addition form at low timestamps, no
  saturating underflow). The new test asserts the same rule only as an observable at the
  contract boundary.
- **Multi-rollover budget recovery** stays owned by
  `agent_runtime_lifecycle_simulation_continuous_heartbeat_loop_and_spends`; this is the
  dedicated minimal scenario-3 case requested by the issue.
- Timestamps start at `1_000_000` so the boundary is exercised away from zero, matching the
  lifecycle simulation rather than introducing a new low-timestamp convention.

## Testing & CI (local, pinned `1.99.0`)

```bash
cargo fmt --check                                            # exit 0
cargo clippy --all-targets --all-features -- -D warnings     # exit 0
cargo test                                                   # 251 passed; 0 failed
scripts/verify-readme.sh                                     # README test count is 251
scripts/verify-docs-reachability.sh                          # 0 failed
```

`scripts/check-spec-coverage.sh` is unrelated and fails identically on the base commit
(`ebd5090`); it is not wired into CI.

## Files

- `src/integration_tests.rs` — the new scenario-3 test.
- `SPEC.md` — §11 scenario 3 cross-reference.
- `README.md` — audited test count 250 → 251.
- `PR_DESCRIPTION_window_scenario3_rollover.md` — this file.

## Notes for reviewers

- **Fixture `per_tx_cap` is stale.** `tests/fixtures/README.md` records the live policy as
  `per_tx_cap: 1000, window_cap: 150`, but current §8 validation rejects
  `per_tx_cap > window_cap` (`PerTxCapExceedsWindowCap`), so that config can no longer be
  installed. The test therefore keeps only the window numbers that scenario 3 is about and
  uses `per_tx_cap = 150` (the largest permitted value). The fixture README is untouched —
  correcting the recorded historical policy is out of scope for this issue.
- The pre-existing `229 passed; 0 failed` sentence in README Testing & CI is handled by the
  separate #115 PR; it is deliberately untouched here so the branches stay independently
  rebasable.
- Enforcement behavior is unchanged, so no testnet-proof fixture entry is required
  (SPEC §11.1 item 2: test-only assertions).

Closes #122
