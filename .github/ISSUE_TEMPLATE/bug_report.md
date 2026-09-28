---
name: Bug report
about: Report a reproducible defect in the contracts, tooling, or docs.
title: "fix(scope): short problem statement"
labels: ["type: bug"]
assignees: []
---

<!--
Maintainer note: after triage, apply exactly one
`complexity: trivial | small | medium | large` label
per CONTRIBUTING.md ("Issue backlog").
-->

## Summary

<!-- What is broken, in one or two sentences. -->

## Acceptance Criteria

<!-- What "fixed" means. Checkable statements, e.g.:
- [ ] Given <setup>, when <action>, then <expected outcome>.
-->

## Tech Stack

<!-- e.g. contract (`src/`), `tools/agent-tx`, docs/SPEC, CI. Name the area. -->

## Reproduction

### Exact commands

```bash
# Paste the exact commands you ran, e.g.:
# cargo test
# cargo build --release --target wasm32v1-none
```

### Toolchain versions

```text
# Paste output of:
# rustc --version; cargo --version; stellar --version
```

### Expected vs actual

- Expected:
- Actual:

### Enforcement path involved?

<!-- Security triage signal: does this touch `__check_auth`, the decision table
(`src/engine.rs`), the rolling window (`src/window.rs`), admin controls
(freeze/unfreeze), or the dead-man switch? Yes / No. If Yes, explain and see
SECURITY.md before posting secrets or keys. -->

- [ ] Yes — enforcement path involved (describe below)
- [ ] No

### Logs / output

```text
# Paste relevant test output, CLI output, or transaction simulation errors.
```

## Context

- Network (if on-chain): <!-- e.g. local / testnet / futurenet, contract ID if relevant -->
- Related SPEC section: <!-- e.g. SPEC §4, §6, §8, §11 -->
