# feat(engine): CAP-71 delegated signers — research spike + decision record (v2 gate)

## Summary

Closes #80. Adds the decision record that was gating #2 (v2 multi-key work): what CAP-71
delegation actually enables for this design, how it interacts with `__check_auth`, the exact
soroban-sdk 27 API surface, three concrete options for scoped sub-keys, and one explicit
decision. No contract code changes.

## Decision

- **Adopting CAP-71 in v1:** no change — `Signature = BytesN<64>`, no delegate credentials,
  storage/errors untouched.
- **Building #2's multi-sig on top of delegation: rejected.** `delegate_auth` aborts on
  failure and has no `try` variant, so delegation can only express *AND* (all attached
  delegates must authorize). It cannot count approvals, so it cannot express M-of-N.
- **Adopting CAP-71 in v2: deferred with trigger conditions** (T1 concrete external-approver
  requirement, T2 testnet proof incl. nesting/sorting/exhaustion/scope rejection, T3
  sub-contract tests + TTL + audit note).
- **#2 is unblocked** and proceeds with in-account N-key threshold logic, per
  `docs/research/multi-sig-threshold-models.md`.

## What the record establishes (verified against pinned sources)

- The host still routes every authorization through the guarded account's `__check_auth`;
  delegation is an outbound call made *inside* it (`AuthenticationFrame` forwards the same
  `signature_payload` and the same flattened `auth_contexts`). Policy gates are never
  bypassed by attaching delegates, and `auth_contexts` is unchanged.
- `env.custom_account().get_delegated_signers()` returns **unsanitized** user input;
  `delegate_auth()` panics unless the address is a non-exhausted delegate that authorized the
  invocation. Both are callable only within `__check_auth`.
- Delegate trees must be strictly ascending by address, duplicate-free, nested within a depth
  limit, and each signer is single-use. `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` plus
  `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` bind the signature to the top-level
  account, preventing cross-account replay.
- G-address delegates are authenticated with classic account thresholds/weights, so one
  delegate address can already be a classic multisig account — outside our audit surface.
- Delegation is unsupported in recording auth mode, so simulation never emits delegate
  credentials; clients assemble them.

Three options are compared (delegate allowlist / sub-account contract with its own policy /
in-account keys), with scoping, threshold capability, audit surface, per-auth cost and
integration-fit columns.

## Files

- `docs/research/cap71-delegated-signers.md` — new decision record (the deliverable).
- `SPEC.md` §1.1 — the CAP-71 sentence now links the record and states the decision.
- `docs/README.md` — §1.1 cross-reference row links the new research page.
- `docs/.summary-allowlist` — registers the new research page as intentionally outside
  `SUMMARY.md` navigation (same treatment as the other research notes).
- `docs/research/multi-sig-threshold-models.md` — points #2 readers at the delegation gate.
- `PR_DESCRIPTION_cap71_delegated_signers_decision_record.md` — this file.

## Testing & CI

Docs-only change, no Rust touched; the full local gate set was run anyway on the pinned
`1.99.0` toolchain:

```bash
cargo fmt --check                                            # exit 0
cargo clippy --all-targets --all-features -- -D warnings     # exit 0
cargo test                                                   # 250 passed; 0 failed (9 binaries)
scripts/verify-readme.sh                                     # 3 passed, 0 failed
scripts/verify-docs-reachability.sh                          # 64 passed, 0 failed
```

`scripts/check-spec-coverage.sh` was also run: it fails on 3 variants (`Unauthorized` and two
others) — **identically on the base commit before this change**, and it is not wired into CI.
This PR does not touch the `Error` enum or the SPEC §4/§6 tables, so the failure is
pre-existing and left alone.

## Issue #2 (post-merge comment)

> #80 is resolved: delegation is **not** a viable basis for the threshold model
> (`delegate_auth` is AND-only — it aborts on failure, so approvals cannot be counted). #2 is
> unblocked and should proceed with in-account N-key threshold/role logic as described in
> `docs/research/multi-sig-threshold-models.md`. CAP-71 itself stays deferred with trigger
> conditions in `docs/research/cap71-delegated-signers.md`.

## Notes for reviewers

- Nothing in this PR changes contract behaviour; the "no code" outcome is deliberate and is
  what the issue asked for.
- The record is written against the *pinned* versions (`soroban-sdk 27.0.6`,
  `soroban-env-host 27.0.1`, `stellar-xdr 27.0.0`); if the SDK is bumped, re-verify the
  `custom_account.rs` / `auth.rs` line references when touching SPEC §1.1.

Closes #80
