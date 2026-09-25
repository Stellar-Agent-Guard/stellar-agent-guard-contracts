# Description

Closes #142

This PR adds a `policy_revision` counter to the policy engine to enable cheap change detection. Dashboards and SDKs that already poll the `status()` endpoint will now receive this counter for free, allowing them to easily detect drift or policy updates without needing to poll the full `policy()` read or listen to events.

### Changes
*   **State:** Added `PolicyRevision` to persistent storage (`DataKey`).
*   **Status Struct:** Added `policy_revision: u64` to the `Status` struct returned by the `status()` read function.
*   **Engine:** `set_policy` and `revoke_policy` now retrieve, increment, and persist the new revision counter.
*   **Specification:** Updated `SPEC.md` §7 to reflect the new `Status` field.
*   **Tests:** Added `policy_revision_increments_across_set_and_revoke` to integration tests to verify the counter starts at 0 and increments exactly as specified.

### Acceptance Criteria Checklist
- [x] `Status` struct carries `policy_revision: u64` (0 = never set).
- [x] Tests: 0 pre-first-set, increments across set→revoke→set visible via status.
- [x] Lint, type-check, and tests all pass locally.
- [x] PR description references the issue (Closes #142).

### Reviewer Note
The issue description mentioned the possibility of `PolicyRevision` already being implemented in events by a concurrent issue. Since it was not present in the codebase, the full incrementing logic and state storage was implemented here.
