# Contributing to stellar-agent-guard-contracts

We welcome contributions! Here's how to get started.

> **Heads up:** this is a **security contract that gates fund movement**. Changes
> to policy semantics, the decision table, or the auth path have real financial
> blast radius. Small changes deserve as much care as big ones.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/aigbagbobila/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts

# The toolchain is pinned in rust-toolchain.toml (channel + wasm32v1-none target
# + clippy/rustfmt). rustup applies it automatically from this directory, so
# every cargo command below runs on the pinned compiler — install it once with
# `rustup toolchain install`, or just run a cargo command and let rustup do it.

# Run tests (31 unit + integration tests, no network needed)
cargo test

# Audit numeric, hash, transaction, and contract-ID claims before README PRs
scripts/verify-readme.sh

# Lint (clippy all + pedantic are denied via [lints.clippy])
cargo clippy --all-targets --all-features

# Format check
cargo fmt --check

# Build the contract wasm (Soroban 27 targets wasm32v1-none)
cargo build --release --target wasm32v1-none

# Prove the wasm build is deterministic (builds twice, diffs SHA-256);
# this is the same check CI's `wasm-reproducible` job runs.
./scripts/check-wasm-reproducible.sh

# Build the agent-tx submission helper
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

The pin is what makes the released WASM hash verifiable: a `stable` toolchain
would move and change the bytes without any change to the repository. Bumping
`channel` in `rust-toolchain.toml` changes the released artifact hash, so do it
in its own commit (issue #67).

The `stellar` CLI cannot sign Soroban authorization entries whose address is a
contract. Heartbeat testing uses the guard contract's own address, so the CLI
cannot submit a heartbeat; use `agent-tx` for this path. See the
[`agent-tx` usage guide](tools/agent-tx/README.md) for commands and options.

## Clean Build Artifacts

```bash
# Clean root workspace (contract + all members)
cargo clean

# Clean agent-tx tool specifically
cargo clean --manifest-path tools/agent-tx/Cargo.toml
```

This removes all `target/` directories and `*.wasm` artifacts. The `.gitignore` is configured to exclude these from version control.

## Coding Standards

1. **No `unwrap()` / `expect()` / indexing without bounds in contract code** —
   the contract runs in the host with `panic = "abort"`; failures on the
   authorization path must be deliberate `panic_with_error!` calls that surface
   as stable `Error` reasons (SPEC §7), never accidental traps.
2. **Every policy change must update SPEC.md and the tests together** — the
   decision table (SPEC §4/§6) and the enforcement-scope statement (SPEC §2)
   must stay word-for-word consistent with the code; that consistency is
   a review requirement, not a nicety. Scope *wording* itself is single-sourced:
   edit the canonical paragraph in SPEC §2 only — the README and
   `docs/enforcement-scope.md` carry short excerpts plus a
   `full statement: SPEC §2` link that auto-follows (re-sync an excerpt only if
   the quoted sentence itself changes). Copies in sibling repositories
   (`stellar-agent-guard-sdk`, `stellar-agent-guard-dashboard`) are out of scope
   here; they are tracked in their own issue trackers.

   The decision table is single-sourced too, and mechanically so (issue #76):
   [`decision-table.json`](decision-table.json) is the source of truth, the SPEC
   §4 table is rendered from it, and `tests/decision_table.rs` fails `cargo test`
   — therefore CI — when the JSON, the SPEC §4 table, the README walkthrough, the
   `Error` enum, and `src/engine.rs` drift apart. When you change what a call can
   be blocked with, the order is: `src/engine.rs` → `decision-table.json` (row,
   reason, and the test that pins it) → paste the rendered row into SPEC §4 →
   run `cargo test`. Adding an `Error::` branch without a JSON row fails the
   build on purpose.
3. **`clippy::all` and `clippy::pedantic` clean** — enforced in CI with
   `-D warnings`.
4. **`cargo fmt` clean** — enforced in CI.
5. **Doc comments on every public function** stating what it authorizes or
   changes, and which storage keys it touches.
6. **Testnet-proof pattern:** behavior that changes what `__check_auth` admits
   or blocks should add a unit/integration test **and**, where it is a user-
   visible enforcement change, be recorded in the testnet proof plan
   (`tests/fixtures/README.md` **and** its machine-readable twin
   `tests/fixtures/index.json`) per the Phase-1 exit-criteria pattern. The two
   files are cross-checked by `tests/fixtures_index.rs`, so editing one without
   the other fails `cargo test`.
7. **Denial-reason messages:** `docs/reason-glossary.md` is the canonical
   message-content source for SDK/UI work — map new user-facing denial text to
   its agent/operator/auditor columns instead of inventing new phrasing.

## Commit Discipline (strict)

`PolicyConfig` changes must update `policy.schema.json` and its conformance test in the same
PR. The Rust contract remains authoritative; the schema is the tooling/editor fast-feedback
layer and must not silently diverge.

1. **One commit per logical unit.** A bug fix, a feature, a doc change, a test
   change — each is its own commit. Do **not** batch unrelated fixes into one
   commit "because they're small" — `git log` must be able to distinguish one
   logical fix from a pile of incidental changes. This is a standing project
   rule (see the Phase 1 review, item A2).
2. Conventional commit format: `type(scope): description`
   (e.g. `fix(window): use addition-form expiry to avoid low-timestamp underflow`).
3. Rebase onto the latest `main` before pushing.
4. Ensure CI passes (fmt, clippy, tests, both builds).

## Pull Request Process

1. Open the PR against `main`. The `ci` status check is required to merge
   (branch protection).
2. One reviewer approval required (branch protection).
3. Describe the *why* in the PR body: what was broken/wrong, what the fix does,
   and — for enforcement changes — how it was verified (tests, and testnet
   evidence where applicable).

## Keeping your PR mergeable

This repo has a security-sensitive backlog and several PRs touching `engine.rs` in parallel; merge conflicts pile up fast. Keep your branch cheap to rebase:

- **One logical unit per PR.** A bug fix, a doc change, a workflow --- each its own branch and PR. Small branches have a small conflict surface.
- **Rebase onto `main` early and often**, not just once before opening the PR.
- **Draft PRs get a nudge, not a close.** A draft that hasn't moved in 14 days gets a warning comment; if it's still stalled 7 days later it's closed (see `.github/workflows/stale.yml`). Issues are never auto-closed --- the backlog is curated by maintainers.

## Project Structure

```
src/
  lib.rs             # Contract: lifecycle, admin, __check_auth (CustomAccount)
  engine.rs          # Pure decision table over auth Contexts (SPEC §4/§6)
  window.rs          # Genuinely rolling spend window (lazy prune, bounded)
  types.rs           # Policy model, storage keys, errors, parsed-call enum
  integration_tests.rs # Host-routed tests incl. real Ed25519 auth signatures
examples/
  agent_pubkey.rs    # Derive raw Ed25519 pubkey (hex) from a Stellar secret key,
                     #   off-chain only: deterministic SEP-0023/RFC 8032
                     #   derivation, but it does NOT prove the agent runtime
                     #   signs with that key (see the file's trust-boundary docs)
  agent-loop.md      # Narrative example of the 24/7 agent runtime loop
                     #   (heartbeat, pre-flight, blocked-reason handling, DMS)
tools/
  agent-tx/          # Sign+submit helper for the custom-account address
tests/fixtures/      # Real testnet evidence (tx hashes, contract IDs, events)
tests/decision_table.rs  # Drift gate: SPEC §4 ↔ decision-table.json ↔ engine
decision-table.json  # Machine-readable source of truth for the SPEC §4 table
rust-toolchain.toml  # Pinned toolchain: reproducible WASM hashes (issue #67)
SPEC.md              # Architecture specification (mechanism is settled)
```

## Issue backlog

Scoped issues with Summary / Acceptance Criteria / Tech Stack live in the
[issue tracker](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues);
each carries one `complexity: trivial|small|medium|large` label. Good first
tasks for the Drips Stellar Wave contributor sprints.

## Dependency drift check

When bumping `soroban-sdk` version in `Cargo.toml`, you **must** re-verify
SPEC §1.1 quotes against the new SDK source (`src/auth.rs`, `src/custom_account.rs`).
Update the version comment in `Cargo.toml` and the SPEC §1.1 header accordingly.
This is the mechanical ratchet preventing silent auth-semantics drift.

Dependabot (`.github/dependabot.yml`, weekly, Cargo + GitHub Actions) files
update PRs against `main` the same as any contributor PR: they must pass the
full `ci` gate (`cargo fmt --check`, clippy with `-D warnings`, `cargo test`,
both builds) — branch protection on `main` requires the `ci` check, so a
dependabot PR cannot merge green-skipped. `soroban-sdk` majors are isolated in
their own group because they can break the ABI; review those with the SPEC §1.1
re-verification above.
