# SPEC §11 Exit Criteria Checklist

| Gate / Check | Command | Evidence Link / Fixture | Verified By | Status |
|---|---|---|---|---|
| Code Formatting | `cargo fmt --check` | CI Workflow Run | Contributor / CI | [ ] |
| Clippy Lints | `cargo clippy --all-targets --all-features` | CI Workflow Run | Contributor / CI | [ ] |
| Unit & Integration Tests | `cargo test` | CI Workflow Run | Contributor / CI | [ ] |
| Fixture Parity | Checked via test suites | `tests/fixtures/` | Contributor | [ ] |
| README & Spec Synchronized | Manual review | `SPEC.md`, `README.md` | Maintainer | [ ] |
