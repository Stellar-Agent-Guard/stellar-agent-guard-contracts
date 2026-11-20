Closes #403

## Summary

Scan the release WASM for panic/unwrap diagnostic strings after the contract
build. An exact-string allowlist is available for reviewed legitimate matches.
The scan is a backstop for Coding Standard 1, not proof that no panic path
exists or a replacement for code review.

## Verification

- Synthetic scanner tests: clean, unallowlisted match, and exact allowlist.
- Rust lint, type-check, and test gates run in CI; Cargo and the real WASM artifact are unavailable locally.
