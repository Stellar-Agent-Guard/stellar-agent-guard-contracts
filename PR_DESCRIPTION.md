Closes #365

## Summary

Adds integration tests asserting that all policy and key management functions are strictly admin-gated in enforcing authorization mode.

Previously, the test harness registered `MockAdmin` and relied on `mock_all_auths()` for setup, authorizing admin calls via blanket mocking. No test asserted that a non-admin principal (such as the agent key or an unauthorized external address) cannot invoke policy or key management functions. A regression in admin gating would have silently permitted non-admin accounts to alter policy or rotate keys while tests remained green.

This change adds explicit enforcing-mode tests for every admin-gated function and verifies that authorization entries from non-admin principals are rejected and fail closed.

## Key Changes

1. **Harness Extensions** (`src/integration_tests.rs`):
   - Added `h.non_admin_entry(account, &root)` to build valid Soroban authorization entries for arbitrary custom accounts.
   - Added invocation helper methods on `Harness`: `set_policy_invocation`, `revoke_policy_invocation`, `rotate_agent_key_invocation`, and `cancel_admin_invocation`.
   - Updated `set_policy_enforcing` to reuse `set_policy_invocation`.

2. **Admin-Gating Integration Tests** (`src/integration_tests.rs`):
   - `admin_gating_set_policy_rejects_non_admin`: asserts that `set_policy` rejects entries from both non-admin accounts and the agent key, maintaining policy and revision invariants.
   - `admin_gating_revoke_policy_rejects_non_admin`: asserts that `revoke_policy` rejects non-admin and agent-key auth entries, ensuring policy remains active.
   - `admin_gating_freeze_rejects_non_admin`: asserts that `freeze` rejects non-admin and agent-key auth entries, leaving account unfrozen.
   - `admin_gating_unfreeze_rejects_non_admin`: asserts that `unfreeze` rejects non-admin and agent-key auth entries on a frozen account, while legitimate admin unfreeze succeeds.
   - `admin_gating_rotate_agent_key_rejects_non_admin`: asserts that a non-admin cannot call `rotate_agent_key` to bind an attacker key, proves that an attacker who failed to bind cannot authorize operations as the agent, and verifies the registered agent key remains valid.
   - `admin_gating_propose_admin_rotation_rejects_non_admin`: asserts that `propose_admin_rotation` rejects non-admin and agent auth entries, leaving the pending admin slot empty.
   - `admin_gating_cancel_admin_rotation_rejects_non_admin`: asserts that `cancel_admin_rotation` rejects non-admin and agent auth entries, preserving the pending rotation.

3. **Documentation on `catch_unwind` vs `try_*`**:
   - Explicitly documented in tests and module documentation that unit-returning contract functions (`()`) have no `try_*` client methods in the SDK for host-level auth rejection, and host `require_auth` traps are caught via `std::panic::catch_unwind` + `std::panic::AssertUnwindSafe`.

## Acceptance Criteria Verification

- [x] One test per admin function showing that an authorization entry from a non-admin principal is rejected.
- [x] Include `rotate_agent_key` specifically: a non-admin cannot bind their own key and then authorize as the agent.
- [x] Documented why `catch_unwind` is the available mechanism where `try_*` is not generated for unit returns.
- [x] Lints clean; no new `#[allow]`.
- [x] PR description references this issue with `Closes #365`.
