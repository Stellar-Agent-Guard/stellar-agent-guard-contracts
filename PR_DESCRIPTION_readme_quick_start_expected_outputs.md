# docs(tests): README Quick Start — add expected-output assertions (copy-paste verifiable)

## Summary

The README's Quick Start listed commands but, apart from the `status` read, never showed
what success looks like. A contributor could not distinguish "works on my machine" from
"silently did nothing", and the test count was stated in two places with two different
numbers (`250 tests` in Quick Start vs. `229 passed` in Testing & CI).

This PR makes every Quick Start command verifiable and makes the test-count claim
self-auditing instead of hand-maintained.

## What changed

- **Quick Start expected outputs.** `cargo build --release --target wasm32v1-none` now
  shows the `Finished `release` profile [optimized]` line and the artifact path, and
  `cargo test` shows the shape of its output (`test result: ok. <N> passed; 0 failed; …`,
  one line per test binary) plus the summed total. The `status` read gains an explicit
  statement that an empty/erroring response is a failure, not a quiet no-op.
- **`set_policy` expectation surfaced.** Quick Start now points at the existing,
  copy-pasteable `set_policy` example whose expected output is
  `Event: EventPolicySet (event_policy_set)`.
- **Stale number fixed.** The Testing & CI paragraph claimed `229 passed; 0 failed` while
  the same section claimed 250 tests. It now reports the measured result,
  **250 passed; 0 failed** (summed across all test binaries, 9 binaries today), and names
  the toolchain and commands it was verified with.
- **Count kept honest mechanically, not by memory.** Both sections note that
  `scripts/verify-readme.sh` runs `cargo test`, sums the `passed` counts, and fails CI if
  the README's `N tests` claim disagrees — so adding tests means updating the number in
  the same PR rather than letting it rot. The number is therefore kept (the audit check
  requires it) rather than reworded away.
- **CONTRIBUTING.md.** The local-gate block's `cargo test` step now says to update the
  README count when tests change, and why CI will catch it.
- **Numeric-claim audit.** Grepped the touched docs for `30`, `31`, `229`, `N/N` and
  `N tests`-style claims; no other stale counts remained.

## Testing & CI

Run locally on the pinned `1.99.0` toolchain, all passing:

```bash
cargo fmt --check                                            # exit 0
cargo clippy --all-targets --all-features -- -D warnings     # exit 0
cargo test                                                   # 250 passed; 0 failed (9 binaries)
cargo build --release --target wasm32v1-none                 # Finished `release` profile
scripts/verify-readme.sh                                     # 3 passed, 0 failed — "README test count is 250"
scripts/verify-docs-reachability.sh                          # 63 passed, 0 failed
```

## Related

Closes #115
