<!-- PR: Clarify ambiguous "window" wording across docs -->

# docs: clarify "window" → distinguish active window vs rolling spend window

Summary
-------
This PR clarifies ambiguous uses of the word "window" across the repository so readers and integrators cannot confuse the account-level "active window" (`active_from` / `active_until`) with the asset-transfer "rolling spend window" (the `window_secs` / `window_cap` ledger used for spend accounting). The wording changes make enforcement boundaries explicit and avoid overstating protections for non-SAC (non-asset-contract) calls.

What I changed
--------------
- Reworded explanatory text to explicitly say "active window" where the gating is time-based account activation (`active_from` / `active_until`).
- Called out that rolling-window spend accounting and per-call amount/recipient limits apply only to SAC token transfers (`transfer` / `transfer_from`).

Files modified
--------------
- `SPEC.md` — clarified the enforcement boundary paragraph to name the account-level "active window" and to state rolling-window accounting is limited to SAC transfers.
- `README.md` — made the same clarification in the Enforcement Scope section.
- `docs/enforcement-scope.md` — disambiguated "window" → "active window" and clarified what is enforced for non-SAC calls.
- `docs/concepts/spend-limits.md` — clarified that rolling-window accounting applies only to SAC transfers and that the active window still gates all calls.

Why
---
The repository previously used the bare word "window" in multiple places. That wording risked readers conflating two distinct concepts: (1) the account-level active window that gates whether the account may be used at all, and (2) the rolling spend-window that caps aggregate transfers over `window_secs`. The edits make this distinction explicit so reviewers, auditors, and integrators understand which protections apply to which kinds of calls.

Testing & checks
----------------
- The edits are documentation-only; no contract code was changed.
- Please run the usual format/lint checks and docs build in CI (suggested commands):

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
# (optional) build the documentation site if you use the GitBook toolchain / mdbook
```

How to review
-------------
- Confirm the prose now clearly differentiates "active window" (account gating) from "rolling window" (spend accounting).
- Ensure the SPEC references still align with the contract storage fields and decision table (§3 and §4).
- Suggest further improvements if any other docs should reference the canonical phrasing.

Related
-------
Closes: #437
