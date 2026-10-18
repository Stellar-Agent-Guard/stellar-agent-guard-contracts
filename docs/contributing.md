# Contributing

We welcome contributions. Here's how to get started.

> **Heads up:** this is a **security contract that gates fund movement**. Changes to policy semantics, the decision table, or the auth path have real financial blast radius. Small changes deserve as much care as big ones.

## Development setup

```bash
# Clone the repo
git clone https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts

# Run tests (33 unit + integration tests, no network needed)
cargo test

# Lint (clippy all + pedantic are denied via [lints.clippy])
cargo clippy --all-targets --all-features

# Format check
cargo fmt --check

# Build the contract WASM (Soroban 27 targets wasm32v1-none)
cargo build --release --target wasm32v1-none

# Build the agent-tx submission helper
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
```

## Coding standards

1. **No `unwrap()` / `expect()` / indexing without bounds in contract code** — the contract runs in the host with `panic = "abort"`; failures on the authorization path must be deliberate `panic_with_error!` calls that surface as stable `Error` reasons, never accidental traps.

2. **Every policy change must update SPEC.md and the tests together** — the decision table and the enforcement-scope statement must stay word-for-word consistent with the code; that consistency is a review requirement, not a nicety.

3. **`clippy::all` and `clippy::pedantic` clean** — enforced in CI with `-D warnings`.

4. **`cargo fmt` clean** — enforced in CI.

5. **Doc comments on every public function** stating what it authorizes or changes, and which storage keys it touches.

6. **Testnet-proof pattern:** behavior that changes what `__check_auth` admits or blocks should add a unit/integration test **and**, where it is a user-visible enforcement change, be recorded in the testnet proof plan (`tests/fixtures/README.md` **and** its machine-readable twin `tests/fixtures/index.json` — the two are cross-checked by `tests/fixtures_index.rs`).

7. **Host-routed integration tests:** When testing policy enforcement, write tests that exercise the real Soroban host authorization pipeline in `src/integration_tests.rs` rather than testing under blanket mock auth. Tests asserting enforcement must use `Harness::enforce()` or `GuardScenario` (`set_auths`) so `__check_auth` is genuinely exercised. See [Writing host-routed integration tests](#writing-host-routed-integration-tests) below.

## Writing host-routed integration tests

Writing a host-routed test in `src/integration_tests.rs` is the most valuable test a contributor can add and traditionally the highest-friction, because Soroban custom-account authorization construction is non-obvious and easy to get subtly wrong (wrong nonce, stale expiration, mismatched invocation tree).

Unlike unit tests in `src/engine.rs` (which directly invoke `decide()` over mock contexts), integration tests exercise the real Soroban host authorization pipeline: calling `from.require_auth()`, having the host route into `PolicyEngine::__check_auth`, verifying cryptographic signatures, evaluating policy rules, and enforcing ledger updates.

### 1. How Soroban host authorization works

When a contract call (such as `MockAsset::transfer(from, to, amount)`) executes `from.require_auth()`, the Soroban host validates authority for `from`:

1. **Host constructs the preimage**: The host creates a `HashIdPreimage::SorobanAuthorization` struct with four fields:
   - `network_id`: SHA-256 digest of the Stellar network passphrase (e.g. `Test SDF Network ; September 2015`). Prevents signatures created for testnet from being valid on mainnet.
   - `nonce`: An `i64` sequence number tracked per address. Prevents replaying an authorization payload on the same network.
   - `signature_expiration_ledger`: A `u32` ledger sequence after which the authorization entry expires (`ledger.sequence() + max_ttl` in our harness).
   - `invocation`: A `SorobanAuthorizedInvocation` representing the exact function call tree (contract address, function name, arguments as `ScVal`, and child `sub_invocations`).
2. **Host computes payload hash**: The host encodes the preimage to XDR and takes the SHA-256 digest (`[u8; 32]`).
3. **Host routes to `__check_auth`**: The host invokes `PolicyEngine::__check_auth(signature_payload, signatures, auth_contexts)`.
4. **Guard verifies signature and policy**:
   - The contract verifies the Ed25519 signature against `signature_payload` using the registered agent public key.
   - The contract evaluates policy rules via `engine::decide()` on `auth_contexts`.
   - If either check fails, `__check_auth` returns an error (or traps) and the host aborts the transaction with an authorization error.

### 2. `mock_all_auths()` vs `set_auths()`: The critical distinction

Soroban's test environment (`Env`) operates in one of two auth modes:

| Mode | Behavior | When to Use |
|---|---|---|
| **`env.mock_all_auths()`** (Mock Mode) | All `require_auth()` calls succeed unconditionally. Signature verification is bypassed and `__check_auth` is **never executed**. | **Test setup only**: initializing contracts, setting up policies (`initialize`, `set_policy`, `revoke_policy`). |
| **`env.set_auths(&[entries])`** (Enforcing Mode) | Blanket mocking is disabled. The host matches invocations against the provided `SorobanAuthorizationEntry` records, verifies nonces/expiration, and calls `__check_auth`. | **Guarded operations**: any test asserting that a transaction is permitted or blocked by policy. |

> [!WARNING]
> **Common pitfall**: Never assert that a policy blocks or admits an operation while `mock_all_auths()` is active! Because `__check_auth` is bypassed under `mock_all_auths()`, `require_auth()` will always succeed, creating false passes.
>
> Once `enforce()` or `set_auths()` is called, the environment remains in enforcing mode. Any subsequent admin call in the same test must either provide an admin auth entry (via `Harness::set_policy_enforcing`) or explicitly re-enable mocking via `h.env.mock_all_auths()`.

### 3. Reusable test helpers in `Harness`

New tests should reuse the helpers provided by `Harness` (`src/integration_tests.rs`):

| Category | Helper | Purpose |
|---|---|---|
| **Setup & Lifecycle** | `Harness::new()` | Initializes env, registers `MockAdmin`, `MockAsset`, `PolicyEngine`, generates agent keypair, runs `initialize()`. |
| | `Harness::base_policy()` | Returns a standard baseline policy with `MockAsset` and allowed recipient `h.recv`. |
| | `h.install_policy(&cfg)` | Installs policy in mock mode. |
| | `h.set_policy_enforcing(&cfg)` | Updates policy when already in enforcing mode. |
| **Invocations** | `h.transfer_invocation(from, to, amount)` | Constructs `SorobanAuthorizedInvocation` for `MockAsset::transfer`. |
| | `h.heartbeat_invocation()` | Constructs invocation for `heartbeat()`. |
| | `h.invocation(contract, fn, args)` | Low-level invocation builder for arbitrary contracts/methods. |
| **Auth Entries** | `h.guard_entry(&root)` | Hashes preimage, signs with agent key, bumps nonce, returns `SorobanAuthorizationEntry`. |
| | `h.guard_entry_with(key, &root)` | Signs with an arbitrary key (for testing wrong or rotated keys). |
| | `h.admin_entry(&root)` | Builds auth entry for `MockAdmin` (void signature). |
| **Execution** | `h.enforce(entry)` | Calls `env.set_auths(&[entry])`, activating enforcing mode. |
| | `h.transfer(to, amount)` | High-level: builds entry, enforces, executes transfer, asserts success. |
| | `h.transfer_expect_blocked(to, amount)` | High-level: builds entry, enforces, executes transfer, asserts panic. |
| | `h.transfer_blocked_reason(to, amount)` | High-level: executes and returns panic string containing `Error::reason()`. |
| | `h.heartbeat()` / `h.heartbeat_expect_blocked()` | High-level heartbeat runners in enforcing mode. |
| | `h.unfreeze()` | Admin unfreeze in enforcing mode. |

### 4. Minimal worked example

Here is how to write a new host-routed test from scratch:

```rust
#[test]
fn example_host_routed_cap_test() {
    // 1. Initialize harness (starts in mock mode for setup)
    let mut h = Harness::new();

    // 2. Configure policy while in mock mode
    let mut policy = h.base_policy();
    policy.per_tx_cap = 500;
    h.install_policy(&policy);

    // 3. Construct the authorized invocation the host will route
    let root = h.transfer_invocation(&h.guard, &h.recv, 600);

    // 4. Build signed auth entry (hashes HashIdPreimage, signs with agent key, bumps nonce)
    let entry = h.guard_entry(&root);

    // 5. Flip the environment from mocking to enforcing mode with the signed entry
    h.enforce(entry);

    // 6. Execute the guarded call and assert host rejection
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &h.recv, &600);
    }));
    assert!(res.is_err(), "expected transfer exceeding per_tx_cap to be blocked");
}
```

Or using the concise helper:

```rust
#[test]
fn example_host_routed_concise() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.per_tx_cap = 500;
    h.install_policy(&policy);

    let log = h.transfer_blocked_reason(&h.recv, 600);
    assert!(log.contains(GuardError::PerTxCapExceeded.reason()));
}
```

### 5. High-level scenario testing and the scenario matrix

When adding tests that correspond to the policy decision table (SPEC §4), prefer the declarative `GuardScenario` builder (`src/integration_tests.rs`):

```rust
GuardScenario::new()
    .policy(|p| p.per_tx_cap = 500)
    .expect_transfer(&recv, 200)
    .expect_block(GuardError::PerTxCapExceeded, &recv, 600);
```

Before adding new test cases, cross-reference [Scenario Matrix](scenario-matrix.md) and [`decision-table.json`](../decision-table.json) to see which cells are already covered and which gaps need coverage.

## Commit discipline (strict)

1. **One commit per logical unit.** A bug fix, a feature, a doc change, a test change — each is its own commit. Do **not** batch unrelated fixes into one commit "because they're small" — `git log` must be able to distinguish one logical fix from a pile of incidental changes.

2. **Conventional commit format:** `type(scope): description`
   (e.g. `fix(window): use addition-form expiry to avoid low-timestamp underflow`)

3. **Rebase** onto the latest `main` before pushing.

4. **Ensure CI passes** (fmt, clippy, tests, both builds).

## Pull request process

1. Open the PR against `main`. The `ci` status check is required to merge (branch protection).
2. One reviewer approval required (branch protection).
3. Describe the *why* in the PR body: what was broken/wrong, what the fix does, and — for enforcement changes — how it was verified (tests, and testnet evidence where applicable).

## Project structure

```
src/
  lib.rs               # Contract: lifecycle, admin, __check_auth (CustomAccount)
  engine.rs            # Pure decision table over auth Contexts
  window.rs            # Genuinely rolling spend window (lazy prune, bounded)
  types.rs             # Policy model, storage keys, errors, parsed-call enum
  integration_tests.rs # Host-routed tests incl. real Ed25519 auth signatures
examples/
  agent_pubkey.rs      # Derive raw Ed25519 pubkey from a Stellar secret key
tools/
  agent-tx/            # Sign+submit helper for the custom-account address
tests/fixtures/        # Real testnet evidence (tx hashes, contract IDs, events)
docs/                  # GitBook documentation site
SPEC.md                # Architecture specification (mechanism is settled)
```

## Issue backlog

Scoped issues with Summary / Acceptance Criteria / Tech Stack live in the [issue tracker](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues); each carries one `complexity: trivial|small|medium|large` label.
