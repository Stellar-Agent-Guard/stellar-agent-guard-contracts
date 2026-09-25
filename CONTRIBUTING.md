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

# Run tests (32 unit + integration tests, no network needed)
cargo test

# Audit numeric, hash, transaction, and contract-ID claims before README PRs
scripts/verify-readme.sh

# Lint (clippy all + pedantic are denied via [lints.clippy])
cargo clippy --all-targets --all-features

# Format check
cargo fmt --check

# Build the contract wasm (Soroban 27 targets wasm32v1-none)
cargo build --release --target wasm32v1-none

# Build the agent-tx submission helper
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

## Coding Standards

1. **No `unwrap()` / `expect()` / indexing without bounds in contract code** —
   the contract runs in the host with `panic = "abort"`; failures on the
   authorization path must be deliberate `panic_with_error!` calls that surface
   as stable `Error` reasons (SPEC §7), never accidental traps.
2. **Every policy change must update SPEC.md and the tests together** — the
   decision table (SPEC §4/§6) and the enforcement-scope statement (SPEC §2 /
   README) must stay word-for-word consistent with the code; that consistency is
   a review requirement, not a nicety.
3. **`clippy::all` and `clippy::pedantic` clean** — enforced in CI with
   `-D warnings`.
4. **`cargo fmt` clean** — enforced in CI.
5. **Doc comments on every public function** stating what it authorizes or
   changes, and which storage keys it touches.
6. **Testnet-proof pattern:** behavior that changes what `__check_auth` admits
   or blocks should add a unit/integration test **and**, where it is a user-
   visible enforcement change, be recorded in the testnet proof plan
   (`tests/fixtures/README.md`) per the Phase-1 exit-criteria pattern.

## Commit Discipline (strict)

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

## Project Structure

```
src/
  lib.rs             # Contract: lifecycle, admin, __check_auth (CustomAccount)
  engine.rs          # Pure decision table over auth Contexts (SPEC §4/§6)
  window.rs          # Genuinely rolling spend window (lazy prune, bounded)
  types.rs           # Policy model, storage keys, errors, parsed-call enum
  integration_tests.rs # Host-routed tests incl. real Ed25519 auth signatures
examples/
  agent_pubkey.rs    # Derive raw Ed25519 pubkey from a Stellar secret key
tools/
  agent-tx/          # Sign+submit helper for the custom-account address
tests/fixtures/      # Real testnet evidence (tx hashes, contract IDs, events)
SPEC.md              # Architecture specification (mechanism is settled)
```

## Issue backlog

Scoped issues with Summary / Acceptance Criteria / Tech Stack live in the
[issue tracker](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues);
each carries one `complexity: trivial|small|medium|large` label. Good first
tasks for the Drips Stellar Wave contributor sprints.