---
name: "Bug report"
description: "Report something broken or unexpected"
title: "[bug]: "
labels: []
---

<!-- Maintainers: tag one `complexity: trivial|small|medium|large` label per CONTRIBUTING.md ("Issue backlog"). -->

## Summary

<!-- What is broken, in one or two sentences. -->

## Acceptance Criteria

<!-- What "fixed" looks like, as checkable boxes. Example:
- [ ] ...
- [ ] Regression test added
- [ ] `cargo fmt --check`, `cargo clippy --all-targets --all-features`, and `cargo test` pass locally
-->

- [ ]
- [ ] Lint and tests pass locally (`cargo fmt --check`, `cargo clippy --all-targets --all-features`, `cargo test`)

## Tech Stack

<!-- Toolchain versions: `rustc --version`, `stellar --version`, `soroban-sdk` version, OS. -->

- rustc:
- stellar CLI:
- soroban-sdk:
- OS:

## Reproduction

### Exact commands

```sh
# Paste the exact commands run, including contract invocations and flags.
```

### Expected vs actual

<!-- What did you expect to happen? What happened instead? Paste output / tx hashes where applicable. -->

- Expected:
- Actual:

### Enforcement path involved?

<!-- Security triage signal: does this touch `__check_auth`, the policy decision table, the rolling window, or fund movement? If yes, say so plainly and do NOT post secrets. See SECURITY.md for disclosure of live vulnerabilities. -->

- [ ] Yes — this involves the enforcement path (`__check_auth` / policy / window / fund movement)
- [ ] No
- [ ] Unsure
