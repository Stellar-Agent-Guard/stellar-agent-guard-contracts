# Contributing to stellar-agent-guard-contracts

We welcome contributions! Here's how to get started.

> **Heads up:** this is a **security contract that gates fund movement**. Changes
> to policy semantics, the decision table, or the auth path have real financial
> blast radius. Small changes deserve as much care as big ones.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts.git
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

### Minimum supported Rust version (MSRV)

`Cargo.toml` declares `rust-version = "1.91.0"`, and the `msrv` job in
`.github/workflows/ci.yml` installs exactly that release — including the
`wasm32v1-none` target — and runs clippy, `cargo test`, and the wasm build on
it. The job reads the field from `Cargo.toml`, so changing that one value is
what changes what CI proves; there is no second hardcoded version to forget.
`cargo fmt` deliberately stays on the pinned channel in the `ci` job: rustfmt
output is version-sensitive, and one formatter authority avoids two
contradictory definitions of "formatted" (issue #410).

The floor comes from the dependency graph, not from preference: `soroban-sdk`
27.0.6 itself declares `rust-version = "1.91.0"`. If a dependency bump needs a
newer compiler:

1. Raise `rust-version` in the same PR as the bump — never as a drive-by — and
   say why in the PR body.
2. Update every version claim: the `README.md` badge, `docs/installation.md`,
   and this section.
3. Update [`SECURITY.md` § Verified against](SECURITY.md#verified-against),
   because the security model is verified against a specific toolchain and
   SDK, not against "Rust" in general.
4. Let the `msrv` CI leg prove the new floor before merging.

Do **not** declare a lower MSRV than the graph supports. Before issue #410 this
repository declared 1.85 while `soroban-sdk` required 1.91, so a contributor's
first `cargo build` failed on a version the README called supported.

### Documentation site (GitBook)

The published docs at
<https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/> are
synced from this repository by GitBook Git Sync — there is no build or deploy
workflow in `.github/workflows/`. What gets synced, what triggers a sync, how
to preview a change, who can publish, and which file wins between
`gitbook-docs.yaml` and `docs/SUMMARY.md` are documented in
[`docs/README.md`](docs/README.md). Read that before adding, moving, or renaming
a page; after any such change, run `scripts/verify-docs-reachability.sh`.

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
8. **Host-routed integration tests:** When testing policy enforcement, write
   tests that exercise the real Soroban host authorization pipeline in
   `src/integration_tests.rs` rather than testing under blanket mock auth.
   Tests asserting enforcement must use `Harness::enforce()` or `GuardScenario`
   (`set_auths`) so `__check_auth` is genuinely exercised. See the full
   walkthrough in [`docs/contributing.md`](docs/contributing.md#writing-host-routed-integration-tests)
   and the module header of [`src/integration_tests.rs`](src/integration_tests.rs).
9. **Adding a new Error variant:** Adding a denial reason touches at least five
   places — the enum, the `reason()` mapping, the decision site & `decision-table.json`,
   the SPEC §4/§6/§7 tables, and the event vocabulary (`auth-checked-vocabulary.json`
   and `docs/reason-glossary.md`). Discriminants are frozen on mainnet/testnet and
   strictly follow the 'append, never insert' convention. See the
   [end-to-end checklist](#how-to-add-a-new-error-variant-end-to-end) below and the
   comprehensive walkthrough in
   [`docs/contributing.md`](docs/contributing.md#how-to-add-a-new-error-variant-end-to-end).

## How to read this codebase

Start with the policy model, then follow an authorization from its decision
logic through the ledger to the contract boundary:

1. [`src/types.rs`](src/types.rs) — Shared policy and ledger types, parsed
   calls, storage keys, bounds, and stable error codes. `PolicyConfig`'s
   canonical policy hash uses ScVal XDR with sorted symbol keys, so changing a
   policy field changes its hash; keep numeric `Error` discriminants stable as
   well (see the [Error variant checklist](#how-to-add-a-new-error-variant-end-to-end),
   [`tests/policy_hash_encoding.rs`](tests/policy_hash_encoding.rs), and the
   `error_code_discriminant_stability_spec_7` test in this module).
2. [`src/engine.rs`](src/engine.rs) — Pure evaluation of the host's auth
   contexts against policy and account state. It classifies calls and applies
   fail-closed gates, allowlists, caps, and staged window/rate-limit checks;
   `SPEC.md` §§4 and 6 describe the decision rules.
3. [`src/window.rs`](src/window.rs) — In-memory rolling spend and protocol-call
   ledgers: pruning, admission, bounded entry merging, and state conversion.
   Its rolling-boundary behavior is covered by
   `ledger_second_changes_window_membership_at_boundary` in this module.
4. [`src/lib.rs`](src/lib.rs) — The Soroban contract shell: lifecycle and
   storage, loading the authorization snapshot, calling the engine, and
   persisting successful ledger changes. Keep policy decisions in the engine
   and ledger mechanics in the window module; this boundary also implements
   the host-facing custom-account interface.

Two invariants deserve particular care. Authorization is fail-closed: a
missing policy blocks, and the host-facing signature verification precedes
policy evaluation; see `no_policy_is_default_deny_on_chain` and
`auth_verification_order_initialized_account_valid_signature_no_policy_yields_no_policy`
in [`src/integration_tests.rs`](src/integration_tests.rs). Window admissions
are staged and committed only if every context passes, so a rejected batch
cannot consume spend budget; see
`failed_multi_context_batch_never_commits_staged_window_admissions` in
[`src/engine.rs`](src/engine.rs) and
[`src/integration_tests.rs`](src/integration_tests.rs).

`__check_auth` is not a project-designed endpoint: the Soroban host calls the
`CustomAccountInterface` method with its required shape. Here,
`Self::Signature = BytesN<64>` and `Self::Error = Error`; the method is:

```rust
fn __check_auth(
   env: Env,
   signature_payload: soroban_sdk::crypto::Hash<32>,
   signatures: Self::Signature,
   auth_contexts: soroban_sdk::Vec<Context>,
) -> Result<(), Error>
```

The `Context` enum is also defined by the SDK and includes contract calls and
host-function contract-creation contexts. Do not casually change this ABI or
assume the project can redefine the SDK's context types. See the exact
implementation in [`src/lib.rs`](src/lib.rs) and the SDK contract recorded in
[SPEC §1.1](SPEC.md#11-sdk-and-host-surface-this-is-built-on-soroban-sdk-27).
Host exposure of both contract-creation context variants is exercised by
`contract_creation_denied_through_real_host_path` in
[`src/integration_tests.rs`](src/integration_tests.rs).

## How to add a new Error variant end-to-end

Adding a new denial reason touches at least five places across the repository: the enum, the `reason()` mapping, the decision site & `decision-table.json`, the `SPEC.md` §4/§6/§7 tables, and the consumer event vocabulary. Forgetting any one of these breaks CI.

### The Discriminant-Freeze Rule & 'Append, Never Insert' Convention
- **Frozen discriminants:** Numeric error codes (`Error(Contract, #N)`) are consumed by off-chain tooling, indexing pipelines, and SDKs (`stellar-agent-guard-sdk`). Once assigned, discriminants are permanently frozen on testnet and mainnet. Never renumber, repurpose, or delete an existing variant.
- **Group partitioning:**
  - `1..=9`: Generic & lifecycle errors (next free: `7`).
  - `10..=19`: Account-level gates (next free: `15`).
  - `20..=39`: Per-call decisions & context classification (next free: `34`).
- **'Append, never insert':** Always allocate the next free number in the appropriate group. Never insert between existing codes or shift discriminants down.

### End-to-End Checklist
1. **`src/types.rs` (`pub enum Error`)**: Declare the variant with doc comments and assign the next free discriminant in its group.
2. **`src/types.rs` (`reason()` and `from_block_reason`)**:
   - Map variant to its lower_snake_case symbol in `Error::reason()`.
   - Add variant to `all_errors` in `Error::from_block_reason()`.
3. **Decision site & `decision-table.json`**:
   - Return the error at its enforcement site (`src/engine.rs` or `src/lib.rs`).
   - If returned by the engine, add or update the row in `decision-table.json` under `"reasons"` with the pinning test name.
4. **`SPEC.md` §4 and §6**:
   - Paste the rendered table row from `decision-table.json` into the SPEC §4 table.
   - Document semantics, precedence, and argument parsing rules in SPEC §6.
5. **`SPEC.md` §7 and §7.1**:
   - Add a row in the SPEC §7.1 mapping table (`| Code | Variant | Reason Symbol | Reachable in check()? | Rationale |`).
   - Add the variant into the `pub enum Error` code block in SPEC §7.
6. **Event vocabulary & glossary**:
   - Add outcome entry to `tests/fixtures/auth-checked-vocabulary.json` (topics: `["event_auth_checked", "blocked", symbol]`).
   - Add entry to `docs/reason-glossary.md` with agent guidance (no evasion!), operator action, and auditor note.
7. **Tests**:
   - In `src/types.rs`, add variant to `all_errors` and the match arm in `error_code_discriminant_stability_spec_7()`.
   - Add unit test for the decision site in `src/engine.rs`.
   - Add host-routed integration test in `src/integration_tests.rs` asserting the exact reason string.

### Verification Commands
- **Deny-list CI check**: `./scripts/check-spec-coverage.sh` (validates coverage in SPEC §4/§6 and §7 enum).
- **Decision-table drift check**: `cargo test --test decision_table` (ensures `decision-table.json`, SPEC §4, and engine agree).
- **Auth-checked vocabulary check**: `cargo test --test auth_checked_vocabulary` (verifies `auth-checked-vocabulary.json` coverage).
- **Discriminant stability check**: `cargo test error_code_discriminant_stability_spec_7`.
- **ABI snapshot check**: Update the committed baseline with `UPDATE_SNAPSHOTS=1 cargo test --test abi_snapshot`, then inspect with `git diff tests/snapshots/abi_snapshot.txt`.
- **Local build & lints**: `cargo fmt --check && cargo clippy --all-targets --all-features && cargo test`.

For the full detailed walkthrough, see [`docs/contributing.md`](docs/contributing.md#how-to-add-a-new-error-variant-end-to-end).

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
[issue tracker](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues);
each carries one `complexity: trivial|small|medium|large` label. Good first
tasks for the Drips Stellar Wave contributor sprints.

## Dependency drift check

When bumping `soroban-sdk` version in `Cargo.toml`, you **must** re-verify
SPEC §1.1 quotes against the new SDK source (`src/auth.rs`, `src/custom_account.rs`).
Update the version comment in `Cargo.toml` and the SPEC §1.1 header accordingly.
Also update the SDK row in
[`SECURITY.md` § Verified against](SECURITY.md#verified-against), which names
the protocol and SDK the security model was actually verified against — a bump
without that update leaves a security document claiming a version that is no
longer the one in `Cargo.lock`. This is the mechanical ratchet preventing
silent auth-semantics drift.

Dependabot (`.github/dependabot.yml`, weekly, Cargo + GitHub Actions) files
update PRs against `main` the same as any contributor PR: they must pass the
full `ci` gate (`cargo fmt --check`, clippy with `-D warnings`, `cargo test`,
both builds) — branch protection on `main` requires the `ci` check, so a
dependabot PR cannot merge green-skipped. `soroban-sdk` majors are isolated in
their own group because they can break the ABI; review those with the SPEC §1.1
re-verification above.
