Closes #

## Summary

Documents how the integration test harness (`src/integration_tests.rs`) constructs Soroban authorization entries and switches between mocking and enforcing modes, turning a previously non-obvious copy-and-hope exercise into a clear, guided process for contributors.

## Motivation & Background

Writing a host-routed test is the most valuable test a contributor can add to this repository and previously the highest-friction. Because `src/integration_tests.rs` replicates the host's `HashIdPreimage::SorobanAuthorization` hashing, constructs `SorobanAuthorizationEntry` records by hand, and manages the test environment's mode switches, auth construction was non-obvious and prone to subtle errors (stale nonces, expired ledger limits, mismatched invocation trees, or accidental testing under `mock_all_auths`).

This PR provides comprehensive documentation both in code and in the contributing guides so contributors can confidently add host-routed tests and declarative scenario tests.

## Changes

1. **`src/integration_tests.rs` (Module Doc Header)**:
   - Walkthrough of Soroban host authorization mechanics:
     - The preimage the host hashes: `HashIdPreimage::SorobanAuthorization` (`network_id`, `nonce`, `signature_expiration_ledger`, and `invocation`).
     - Why the signature covers it: SHA-256 hashing of the XDR-encoded preimage and Ed25519 signature verification against the registered agent key inside `__check_auth`.
     - The role of the nonce in replay protection and monotonic tracking.
     - How `Harness::enforce()` flips the `Env` from mocking to enforcing mode via `env.set_auths()`.
   - In-depth explanation of the `mock_all_auths()` vs `set_auths()` distinction and when each is correct (preventing the common pitfall of false passes under mock mode).
   - Invocations and sub-invocation tree structure (`SorobanAuthorizedInvocation`).
   - Comprehensive reference table of reusable `Harness` helpers (setup, invocations, auth entries, execution).
   - Step-by-step minimal worked example of adding a new host-routed test.
   - Cross-reference to the declarative `GuardScenario` builder (issue #63) and the shared scenario matrix (`docs/scenario-matrix.md` and `decision-table.json`).
   - Documentation for `MockAsset`, `MockAdmin`, and `MockDeployer`.

2. **`docs/contributing.md`**:
   - Added rule 7 to Coding Standards requiring real host-routed tests for enforcement changes.
   - Added new section `## Writing host-routed integration tests` with the full conceptual walkthrough, mechanics, helper table, minimal worked example, and scenario matrix cross-reference.

3. **`CONTRIBUTING.md`**:
   - Added rule 8 to Coding Standards pointing contributors to the host-routed integration test walkthrough in `docs/contributing.md` and `src/integration_tests.rs`.

## Verification

- `cargo fmt --check`: Clean (passed)
- `cargo clippy --all-targets --all-features`: Clean with `-D warnings` (passed)
- `cargo test`: All tests pass locally
