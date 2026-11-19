# fix(tests): CI: run the suite with `--release` once (behavioral drift between debug/release)

## Summary

Closes #121. CI only ran `cargo test`, i.e. the **dev** profile, while the artifact
that ships is built with `--release`. Release codegen is not debug codegen:
optimizations change panic paths and unwinding behaviour, and release builds do
**not** check arithmetic overflow by default (the project's checked-arithmetic
issue mitigates the rolling window specifically, but not arithmetic elsewhere).
A regression that only manifests in release could therefore pass every gate and
only surface in the deployed wasm.

This PR adds one release-mode test run to the required `ci` job and documents the
profile flags and the cost. No contract code changed.

## What changed

- **`.github/workflows/ci.yml`** — new step `Unit + integration tests (release
  profile)` running `cargo test --release`, immediately after the existing debug
  test step. It is inside the required `ci` job (not a separate informational
  job), so a release-only failure blocks the merge instead of being advisory. The
  `ci` job key is untouched, so the `main-protection` required status check still
  resolves.
- **`Cargo.toml`** — `[profile.release]` already set `overflow-checks = true`;
  this is the "both" half of the acceptance criteria and needed no behavior
  change, so the PR documents it in place (a comment explaining why it must stay,
  tied to the new release test run). Profile flags, unchanged:
  `opt-level = "z"`, `lto = true`, `codegen-units = 1`, `panic = "abort"`,
  `debug = 0`, `strip = "symbols"`, `debug-assertions = false`,
  `overflow-checks = true`.
- **`CONTRIBUTING.md`** — the local-gate block gains step `4b`, `cargo test
  --release`, with the reason and the cost, so a contributor runs what CI runs.
- **`README.md`** — the "commands CI runs" block gains `cargo test --release`,
  and the Testing & CI prose now states why the suite runs twice (release wasm,
  panic paths, overflow checks) and what the step costs.
- **`docs/contributing.md`** — the mirrored gate list gains the same command; its
  stale "224 unit + integration tests" parenthetical was replaced with a
  profile-neutral label (the suite is 250 tests; the count is audited against
  `README.md` by `scripts/verify-readme.sh`, not here).

## Profile semantics relied on

`cargo test --release` compiles the test binaries with the `[profile.release]`
settings above (Cargo's `bench` profile inherits `release`). Because
`overflow-checks = true` is set there, an overflow now traps identically in the
debug and release test runs instead of passing in debug and trapping only in the
shipped build. `panic = "abort"` governs the wasm build; Cargo still builds the
test harness with unwinding, so `#[should_panic]` tests and the harness itself run
normally — confirmed by the release run below, which passes the same 250 tests.

## Wall-time delta (honest numbers, measured on the pinned `1.99.0` toolchain)

| Run | Warm `target` | Cold `target` |
|---|---|---|
| `cargo test` (debug) | ~5 s | — |
| `cargo test --release` | ~2 s | ~120 s (of which `Finished release profile ... in 1m 58s` is dependency + crate compilation) |

So the steady-state cost of the new step is about **2 seconds** on a warm cache —
it re-runs already-built binaries, and release test execution is *faster* than
debug (4.5 s → 1.7 s for the unit-test binary). The one-off cost is the cold
release dependency graph, which the existing `actions/cache` step already covers:
its `path` list includes `target`, so `target/release` artefacts are cached and
restored on later pushes (keyed by `Cargo.lock`). Worst case is a `Cargo.lock`
change, which recompiles release dependencies once for that key — roughly the
same order as the existing `cargo build --release --target wasm32v1-none` step
that already runs in the same job.

## Release-only failures found

**None.** `cargo test --release` passes 250 tests, 0 failed (216 unit + 9
integration binaries: `abi_snapshot` 1, `auth_checked_vocabulary` 1,
`decision_table` 8, `fixtures_index` 5, `policy_hash_encoding` 11,
`policy_schema` 1, `policy_vectors` 1, `policyconfig_scval_encoding` 6). No test
needed adjusting, so nothing was "fixed to make release green".

## Testing & CI (local, pinned `1.99.0`)

```bash
cargo fmt --check                                            # exit 0
cargo clippy --all-targets --all-features -- -D warnings     # exit 0
cargo test                                                   # 250 passed; 0 failed
cargo test --release                                         # 250 passed; 0 failed
scripts/verify-readme.sh                                     # 3 passed, 0 failed
scripts/verify-docs-reachability.sh                          # 63 passed, 0 failed
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"   # workflow parses
```

`scripts/check-spec-coverage.sh` is not part of this change and is not wired into
CI; it fails identically on the base commit (`ebd5090`).

## Files

- `.github/workflows/ci.yml` — release-profile test step.
- `Cargo.toml` — comment pinning the `overflow-checks = true` rationale (no
  behavior change).
- `CONTRIBUTING.md` — local gate step `4b`.
- `README.md` — CI command list + Testing & CI prose (profile flags, wall time).
- `docs/contributing.md` — mirrored gate list; stale test-count parenthetical
  removed.
- `PR_DESCRIPTION_ci_release_tests.md` — this file.

## Notes for reviewers

- Chose the required `ci` job over a separate informational job: the issue allows
  either, and an advisory job can go red indefinitely without anyone noticing,
  which is the failure mode this issue is about.
- The pre-existing `229 passed; 0 failed` sentence in README Testing & CI is fixed
  by the separate PR for #115; it is deliberately not touched here so the two
  branches stay independently rebasable.
- Nothing under `src/` changed, so no testnet-proof fixture entry is required.

Closes #121
