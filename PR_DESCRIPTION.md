Closes #17
Closes #18
Closes #19
Closes #20

## Summary

This PR hardens the rolling-window ledger (`src/window.rs`) and the decision engine
(`src/engine.rs`) in one focused pass over four related window-accounting issues:

1. **#17** — the running-total projection in `decide()` is now **overflow-checked**;
   a sum that would exceed `i128` becomes a deliberate, stable `WindowCapExceeded`
   block instead of a silent saturating clamp (or an accidental trap).
2. **#18** — the **exact prune boundary** is pinned by a test that proves the
   addition-form expiry (`ts + window_secs <= now`) is in use, and SPEC §3.1 is
   reworded to match the code (and `docs/concepts/spend-limits.md`).
3. **#19** — the **MAX_WINDOW_ENTRIES merge-forward backstop** at the exact 8192
   boundary is now driven by tests: structure/merge semantics, plus a
   property-style assertion that the merge can only tighten, never loosen,
   admission.
4. **#20** — tests pin that `window_cap = 0` **writes no spend rows at all**
   (storage hygiene for caps-only policies), and that a window-only policy
   (`per_tx_cap = 0`) still accrues and enforces.

No public ABI, no error variant, and no on-wire type changed. The only behavioral
change is at the `i128` overflow boundary (#17); #18–#20 are behavioral pinning
plus one SPEC-wording fix.

## Changes by issue

### #17 — checked arithmetic for window total accumulation

**Problem.** `WindowState.total` and the per-recipient totals are `i128`. Caps are
validated `>= 0` and individual amounts `> 0`, but nothing stopped
`total + staged + amount` from overflowing `i128` when a large amount reaches the
engine with `per_tx_cap = 0` and the effective window cap is at/near `i128::MAX`.
The previous projection used `saturating_add`, which clamped to `i128::MAX` and —
for a cap of exactly `i128::MAX` — could **admit spend past the cap**. The release
profile is `overflow-checks = true` with `panic = "abort"`, so a raw `+` would
instead be an accidental trap on the auth path, which CONTRIBUTING rule 1 forbids.

**Fix (`src/engine.rs`).**

- New helper `checked_window_projection(base, staged, amount) -> Option<i128>`
  computes `base + staged + amount` with `checked_add`.
- In `decide()`, both the **global** and the **per-recipient** projections use it.
  `None` (overflow) is treated as over-cap and reported as the existing stable
  reason `WindowCapExceeded` — the true sum necessarily exceeds any `i128` cap, so
  this is exact, not conservative-by-accident.
- `src/window.rs`'s `admit_to_ledger` keeps its non-trapping `saturating_add` as a
  defense-in-depth backstop (documented), while the engine becomes the layer that
  turns the case into a deliberate error.

**Tests.**

- `engine::tests::accumulated_total_at_i128_ceiling_blocks_overflow_stably` —
  drives the total to `i128::MAX - 5`, asserts `+5` is admitted (lands exactly on
  the ceiling), asserts `+6` and `+1` are blocked with `WindowCapExceeded`, and
  asserts the ledger is byte-for-byte unchanged on each rejection.
- `engine::tests::recipient_accumulated_total_at_i128_ceiling_blocks_overflow_stably`
  — same for a per-recipient override with the global window disabled.
- `engine::tests::caps_disabled_huge_amount_is_allowed_and_leaves_window_empty` —
  an `i128::MAX` amount with all caps disabled neither traps nor leaves accounting.
- `window::tests::admit_saturates_rather_than_trapping_near_i128_max` — pins the
  ledger helper's non-trapping (saturating) backstop.

### #18 — pin the pruning boundary (`ts + window_secs <= now`)

**Problem.** SPEC §3.1 described pruning in subtraction form
(`entries[0].ts <= now - window_secs`) while the code implements the algebraically
equivalent addition form (`entry.ts + window_secs <= now`). They differ at low
timestamps: `now - window_secs` saturates to `0`, which would wrongly expire an
entry recorded at ts `0`. No test stated whether an entry exactly at
`now - window_secs` is retained or pruned, so flipping `<=` to `<` could silently
double the effective window.

**Fix.**

- `SPEC.md` §3.1 now states the **addition form** for both the prune loop and the
  membership invariant, matching the code and the already-addition-form
  `docs/concepts/spend-limits.md` (no downstream wording drift).
- No code change was needed — the code was already correct; this is the SPEC/word
  alignment the issue asked for plus an explicit pinning test.

**Test.**

- `window::tests::prune_boundary_is_addition_form_at_zero_timestamp` — at `now = 0`
  an entry at ts `0` (window `1`) must be **retained** (`0 + 1 <= 0` is false);
  at the exact boundary `now = 1` the same entry is **expired**. This test fails
  under the subtraction form, which is the point.

### #19 — MAX_WINDOW_ENTRIES merge-forward at the exact 8192 boundary

**Problem.** The boundedness backstop (merge the two oldest entries forward, keeping
the newer `ts`, over-counting conservatively) is a documented safety property, but
no test drove the ledger to exactly `MAX_WINDOW_ENTRIES` and one past it, and none
asserted the conservative direction of the over-count.

**Tests.**

- `window::tests::max_window_entries_merges_forward_at_exact_bound` — fills exactly
  8192 distinct-second entries and asserts **no merge** occurs (length 8192, total
  8192, ts range `0..=8191`); pushing the 8193rd distinct second yields
  `first().ts == 1` (the **newer** of `{0, 1}`), `first().amount == 2` (the sum),
  length back to 8192, ascending order and tail intact. `MAX_WINDOW_ENTRIES`
  remains the single named const (no numeric literals introduced in code).
- `engine::tests::backstop_merge_never_admits_what_true_rolling_sum_would_reject` —
  property-style: after driving to the bound, triggering the merge, and pruning at
  the point where the true (un-merged) ts-0 spend has expired, asserts
  `total >= true_rolling_sum` and, over a set of candidate amounts,
  `merged_admits(amount) => true_rolling_sum_admits(amount)` under the same cap —
  i.e. the over-count can only make admission stricter, never permit an amount the
  true policy would reject.

### #20 — verify window accounting is skipped entirely when `window_cap = 0`

**Problem.** `window_cap = 0` disables the window, but this was not pinned: does a
caps-only policy still append `SpendEntry` rows on every allowed transfer
(unbounded persistent-storage growth) even though no cap exists?

**Finding.** The engine already skips both pruning and global admission when
`window_cap = 0` (and no per-recipient/protocol accounting is active), and
`__check_auth` only re-persists an empty ledger. There was no test pinning it.

**Tests.**

- `integration_tests::disabled_window_cap_writes_no_window_entries` — a
  `per_tx_cap = 100, window_cap = 0` policy, five allowed transfers, then asserts
  the persisted `WindowState` is absent or has `total == 0`, **empty `entries`**,
  and empty `recipients`.
- `integration_tests::enabled_window_cap_accrues_with_per_tx_cap_disabled` — the
  converse (`per_tx_cap = 0, window_cap = 100`): two same-second allowed transfers
  coalesce to one entry with `total == 70`, and a 31-unit transfer is blocked
  (`70 + 31 > 100`).

## Acceptance criteria

### #17
- [x] All window additions use checked/saturating arithmetic with a deliberate
      stable error path (engine: `checked_add` → `WindowCapExceeded`; ledger:
      non-trapping saturating backstop).
- [x] Tests cover an amount near `i128::MAX` with caps disabled and an accumulated
      total near `i128::MAX`.
- [x] Lint, type-check, and tests pass locally.

### #18
- [x] Test at the exact boundary timestamp: the entry is pruned iff SPEC says
      expired (matches §3.1 exactly; SPEC updated to the addition form).
- [x] Test uses the addition form (no subtraction underflow) at `now = 0`.
- [x] Lint, type-check, and tests pass locally.

### #19
- [x] Test builds 8192 distinct-second entries, verifies structure, pushes the
      8193rd, asserts merge semantics, and asserts `total >= true sum`.
- [x] Property-style assertion: post-merge admission never admits an amount the
      pre-merge policy would reject.
- [x] `MAX_WINDOW_ENTRIES` stays a single named const.
- [x] Lint, type-check, and tests pass locally.

### #20
- [x] `window_cap = 0` with `per_tx_cap` set: N allowed transfers leave
      `WindowState.entries` empty.
- [x] `per_tx_cap = 0` with `window_cap` set: the window still accrues.
- [x] Lint, type-check, and tests pass locally.

## Verification

Run from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features
cargo test
cargo build --release --target wasm32v1-none
```

Results on this branch:

- `cargo fmt --check` — clean.
- `cargo clippy --all-targets --all-features` (`clippy::all` + `clippy::pedantic`
  denied) — clean, no warnings.
- `cargo test` — **99 passed; 0 failed** in the main suite, plus
  `abi_snapshot` (1), `fixtures_index` (5), `policy_hash_encoding` (11), and
  `policyconfig_scval_encoding` (6) all green. Nine new tests were added:
  `accumulated_total_at_i128_ceiling_blocks_overflow_stably`,
  `recipient_accumulated_total_at_i128_ceiling_blocks_overflow_stably`,
  `caps_disabled_huge_amount_is_allowed_and_leaves_window_empty`,
  `backstop_merge_never_admits_what_true_rolling_sum_would_reject`,
  `max_window_entries_merges_forward_at_exact_bound`,
  `prune_boundary_is_addition_form_at_zero_timestamp`,
  `admit_saturates_rather_than_trapping_near_i128_max`,
  `disabled_window_cap_writes_no_window_entries`,
  `enabled_window_cap_accrues_with_per_tx_cap_disabled`.
- `cargo build --release --target wasm32v1-none` — successful contract WASM build.

## Compatibility and notes

- **No ABI change.** No public function, `contracttype`, `contracterror` variant,
  or event changed; the committed ABI snapshot test still passes. The stable reason
  vocabulary is untouched — the new overflow path reuses `window_cap_exceeded`.
- **Testnet proof plan (CONTRIBUTING rule 6).** The only enforcement change (#17)
  is reachable solely with an effective window cap within ~5 units of `i128::MAX`
  (`0x7fff…ffffffff`), which is not expressible as a realistic on-chain operator
  policy; the five Phase-1 testnet scenarios in `tests/fixtures/` are unchanged and
  still pass their drift checks. #18–#20 change no `__check_auth` admission decision
  (they are tests plus a SPEC-wording correction).
- **Scope.** The protocol-call counter (`u32`) was intentionally left as-is; this
  PR addresses the `i128` window totals named in #17.
