## Why

<!-- Required by CONTRIBUTING.md → Pull Request Process: what was broken/wrong,
     what the fix does, and — for enforcement changes — how it was verified
     (tests, and testnet evidence where applicable). -->

## What changed

<!-- Summarize the change and link each issue it addresses below. -->

## Verification

- [ ] `cargo fmt --check`
- [ ] `cargo clippy --all-targets --all-features`
- [ ] `cargo test`

## Enforcement impact

- [ ] `__check_auth` admission behavior did **not** change, **or**
- [ ] `__check_auth` admission behavior changed. Named SPEC section(s):
      ____________________. Named test(s): ____________________.
      Testnet evidence (rule 6) is attached or explicitly waived with a
      written rationale in the PR body: ____________________.

## Checklist

- [ ] One commit per logical unit (bug fix, feature, doc change, and test change
      are not batched together).
- [ ] SPEC.md and the tests changed together for any policy or decision-table
      change (CONTRIBUTING coding standard 2).
- [ ] `Closes #` is present for every issue this PR fully resolves; use
      `Refs #` when the issue is only related.

Closes #<issue>
