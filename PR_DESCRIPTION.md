Closes #

## Summary

Provides an end-to-end, contributor-facing how-to guide and checklist for adding a new `Error` variant and denial reason across the repository.

Adding a denial reason touches at least five distinct places — the enum, the `reason()` mapping, the decision site & `decision-table.json`, the `SPEC.md` §4/§6/§7 tables, and the consumer event vocabulary (`auth-checked-vocabulary.json` and `docs/reason-glossary.md`). While the consistency requirement is enforced in CI via the deny-list check (`scripts/check-spec-coverage.sh`), the decision-table drift test, and the ABI snapshot test, the end-to-end workflow was previously undocumented. This checklist makes the requirement executable by hand, turning potential review rejections into first-pass successes.

## Key Additions

1. **The Discriminant-Freeze Rule & 'Append, Never Insert' Convention**:
   - Explicitly documents that numeric error discriminants are permanently frozen on testnet and mainnet (`Error(Contract, #N)`).
   - Documents the three designated numerical groups:
     - Generic & Lifecycle: `1..=9` (next free: `7`)
     - Account-Level Gates: `10..=19` (next free: `15`)
     - Per-Call Decisions & Context Classification: `20..=39` (next free: `34`)
   - Details the 'append, never insert' convention: always allocating the next free integer at the tail of the appropriate group.

2. **Step-by-Step End-to-End Checklist**:
   - Step 1: Declare the variant in `src/types.rs` (`pub enum Error`) with doc comments and next free discriminant.
   - Step 2: Implement string mappings in `src/types.rs` (`Error::reason()` and `all_errors` in `Error::from_block_reason()`).
   - Step 3: Implement decision site (`src/engine.rs` / `src/lib.rs`) and update `decision-table.json`.
   - Step 4: Update `SPEC.md` §4 decision table and §6 classification semantics.
   - Step 5: Update `SPEC.md` §7.1 error mapping table and §7 `pub enum Error` code block.
   - Step 6: Update consumer event vocabulary in `tests/fixtures/auth-checked-vocabulary.json` and `docs/reason-glossary.md` (with no-evasion agent guidance).
   - Step 7: Update tests (pin discriminant in `error_code_discriminant_stability_spec_7`, engine test, and host-routed integration test in `src/integration_tests.rs`).

3. **Verification Commands**:
   - Deny-list CI check: `./scripts/check-spec-coverage.sh`
   - Decision-table drift test: `cargo test --test decision_table`
   - Vocabulary fixture test: `cargo test --test auth_checked_vocabulary`
   - Discriminant stability assertion: `cargo test error_code_discriminant_stability_spec_7`
   - ABI snapshot gate: `UPDATE_SNAPSHOTS=1 cargo test --test abi_snapshot`
   - Standard test and lint suite: `cargo fmt --check && cargo clippy --all-targets --all-features && cargo test`

4. **Cross-Linking & Documentation Stability**:
   - Added Rule 9 and section in `CONTRIBUTING.md`.
   - Added Rule 8 and full section in `docs/contributing.md`.
   - Linked from `src/types.rs` (`Error` enum doc comments and `error_code_discriminant_stability_spec_7` doc comments).
   - Linked from `SPEC.md` §7.1 and `docs/reason-glossary.md`.

## Verification

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features`
- `cargo test`
- `./scripts/check-spec-coverage.sh`
- `./scripts/verify-docs-reachability.sh`
