## Why

<!--
Describe the problem this PR solves and what the change accomplishes:
- What was broken, missing, or wrong?
- What does this fix/feature/doc change do?
-->

## Enforcement Impact Declaration

<!--
Every policy change must update SPEC.md and tests together (CONTRIBUTING rule 2).
Declare whether this PR alters __check_auth admission behavior or policy evaluation.
-->

- [ ] **No enforcement change**: This PR does not change `__check_auth` admission behavior, policy engine logic, or storage keys.
- [ ] **Enforcement change**: This PR modifies `__check_auth` admission behavior, policy evaluation, or storage keys:
  - **SPEC section updated**: `SPEC.md §...` <!-- e.g., §4 Decision Table, §8 Validation -->
  - **Associated tests**: `src/integration_tests.rs::...` <!-- or unit tests in src/engine.rs / src/window.rs -->
  - **Testnet evidence**: `tests/fixtures/README.md` <!-- Required if user-visible enforcement change per CONTRIBUTING rule 6 -->

## Contributor Checklist

- [ ] **One commit per logical unit**: No batching of unrelated changes into one commit (`CONTRIBUTING.md` Commit Discipline rule 1).
- [ ] **Conventional commit format**: Follows `type(scope): description` (e.g., `fix(window): ...`, `docs(tests): ...`).
- [ ] **Local gates passed**:
  - [ ] `cargo fmt --check`
  - [ ] `cargo clippy --all-targets --all-features`
  - [ ] `cargo test`
- [ ] **Rebased onto latest `main`**.
