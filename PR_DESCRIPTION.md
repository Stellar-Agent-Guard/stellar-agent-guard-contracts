# Description

Closes #21

This PR verifies that rejected SAC transfers never mutate rolling-window state, including invalid amounts rejected in per-context enforcement.

### Changes
* **Tests:** Added zero and negative amount cases that assert `InvalidAmount` and compare the complete ledger against its pre-call snapshot.
* **Regression coverage:** Reused full-ledger snapshot assertions for per-transaction cap, rolling-window cap, and recipient-denied rejections.

### Acceptance Criteria Checklist
- [x] Amounts 0 and < 0 return `InvalidAmount` without changing window state.
- [x] Cap-exceeded and recipient-denied cases assert unchanged ledger state.
- [ ] Formatting, lint, type-check, and tests pass locally.
- [x] PR description references the issue (Closes #21).
