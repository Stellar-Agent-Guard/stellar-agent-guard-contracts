Closes #399

## Summary

Enforce the repository's formatting and Clippy standards for the standalone
`tools/agent-tx` crate. CI runs its format and lint checks; this adds the
matching `clippy::all` and `clippy::pedantic` deny policy, includes all features
in the CI lint command, and documents the standalone commands for contributors.

## Verification

- `cargo fmt --manifest-path tools/agent-tx/Cargo.toml --check`
- `cargo clippy --manifest-path tools/agent-tx/Cargo.toml --all-targets --all-features -- -D warnings`
- `cargo test --manifest-path tools/agent-tx/Cargo.toml`
