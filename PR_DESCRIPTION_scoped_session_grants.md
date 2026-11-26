Closes #308

## Summary

Records the decision record for scoped session grants: should the admin be
able to mint a short-lived, amount-capped capability the agent consumes between
policy edits, instead of rewriting the account-global policy to adjust a
routine budget?

**Decision: do not build in v1; build in v2 as a contract-stored grant keyed by
a monotonic nonce.** The off-chain signed-grant representation is rejected for
v2 (it requires changing `CustomAccountInterface::Signature`, adds a second
admin trust root, and still needs on-chain consumption state to prevent replay).

Documentation only — no contract code, storage keys, error variants, events, or
`__check_auth` behavior changed.

## What the change contains

- [`SPEC.md`](SPEC.md) — new **Appendix A**, explicitly non-normative for v1,
  with the decision and the bounded v2 shape.
- [`docs/research/scoped-session-grants.md`](docs/research/scoped-session-grants.md)
  — the full ADR:
  - Representation A (contract-stored grant + nonce) and Representation B
    (signed off-chain grant in `__check_auth`), each analysed for replay,
    expiry, and revocation.
  - Cap interaction: eligibility gates **intersect** policy; monetary caps
    **substitute on policy overflow** (`PerTxCapExceeded` / `WindowCapExceeded`
    only). Grant spend is tracked separately from `WindowState`.
  - Explicit revocation story with no background process: lazy predicates,
    per-grant `revoke_grant`, and implicit global revocation via the
    `policy_revision` / `agent_key` bindings.
  - Illustrative (non-compiled) engine decision shape for `src/engine.rs`.
- [`docs/README.md`](docs/README.md) — SPEC ↔ GitBook cross-reference row.
- [`docs/.summary-allowlist`](docs/.summary-allowlist) — the research note is
  intentionally outside `docs/SUMMARY.md` navigation.

## Motivation correction

The issue's premise that "every policy change resets the window" no longer
holds at this revision: `set_policy` preserves the rolling window and DMS clock
(issue #289) and `increase_window_cap` raises the cap in place (issue #349).
The remaining gap — a budget that is *scoped*, *time-boxed*, and *revocable*
without an account-wide rewrite — is what the v2 shape addresses.

## Verification

- `cargo fmt --check` — pass
- `cargo clippy --all-targets --all-features -- -D warnings` — pass
- `cargo test` — pass
- `scripts/verify-docs-reachability.sh` — 64 passed, 0 failed

No testnet proof is needed: no contract behavior changed.
