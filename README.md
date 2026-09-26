<p align="center">
<img src="Gemini_Generated_Image_mvimg2mvimg2mvim.jpeg" alt="Stellar Agent Guard" width="700"/>
</p>
<p align="center">
<a href="https://github.com/aigbagbobila/stellar-agent-guard-contracts/actions/workflows/ci.yml">
<img src="https://github.com/aigbagbobila/stellar-agent-guard-contracts/actions/workflows/ci.yml/badge.svg" alt="CI"/>
</a>
<a href="LICENSE-MIT">
<img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License: MIT OR Apache-2.0"/>
</a>
<a href="https://www.rust-lang.org/">
<img src="https://img.shields.io/badge/rust-1.85%2B-blue" alt="Rust 1.85+"/>
</a>
<a href="https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/">
<img src="https://img.shields.io/badge/docs-GitBook-blue" alt="Documentation"/>
</a>
</p>

# Stellar Agent Guard — Contracts

📚 **[Documentation](https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/)**

**Non-custodial, account-level spending firewall for autonomous AI agents on Stellar.**

An autonomous agent holding a wallet has a single point of failure: one prompt-injection
or one buggy loop can drain it. Stellar Agent Guard makes that impossible on-chain — the
agent's funds stay in its own smart account, and *every* transaction the account must
authorize is intercepted by the contract's `__check_auth` and rejected pre-broadcast unless
it satisfies a policy the operator installed: per-transaction spend caps, a genuinely
rolling window cap, recipient/asset allowlists, a protocol/function allowlist, a pause
switch, and a dead-man switch (heartbeat with admin-attested reversal).

**Status: Phase 1 complete.** All five enforcement scenarios were proven against live
Stellar testnet (protocol 28) with real contract IDs and transaction hashes — evidence is
recorded in [`tests/fixtures/README.md`](tests/fixtures/README.md), and the deployed
contract's read functions were cross-checked live during this README pass (below).

## 🎯 What makes this different

Enforcement happens **inside the account itself**, via Soroban's native Custom Account
Abstraction — not in a wrapper contract in front of funds, not in an off-chain service.
The guard is a Soroban contract implementing the `CustomAccountInterface`; the agent's
Ed25519 public key is registered at `initialize`, and from then on the agent's address
*is* the contract's address. Any transaction that requires the agent's authorization is
routed by the host through `__check_auth`, which verifies the agent's signature over the
transaction auth payload and then evaluates the policy decision table over every auth
context. Funds never leave the agent's own account — there is no deposit step, no vault,
no `top_up`.

This is the mechanism the rest of the Soroban spend-guard ecosystem is converging on,
not a niche choice:

- [SpendGuard](https://github.com/deegalabs/stellar-402-spendguard) ("the spending-policy
  contract that was missing for x402 agents on Stellar") and
  [stellarspend-contracts](https://github.com/stellarspend/stellarspend-contracts)
  (automated budgets / spending limits) enforce limits around specific apps and payment
  rails, not at account-authorization time.
- [AgentGuard](https://github.com/Cowrie-Labs/agentguard) is a policy contract agents
  call into — a guard the agent must choose to route through, rather than the host
  intercepting every authorization.
- [Watchdog](https://github.com/leticarolina/watchdog) holds funds in a vault contract
  the agent never directly owns — custodial by design, with a one-time deposit step.
  Its own README names the smart-account model as the unbuilt future direction:
  > "Roadmap > smart-account model: move enforcement into the agent's own wallet via a
  > custom Soroban account contract (`__check_auth`), so the wallet itself won't sign a
  > transaction unless Watchdog's rules pass, no deposit step required, funds never leave
  > the agent's own custody."

Stellar Agent Guard **is** that model, built and proven: `__check_auth` enforcement,
non-custodial, no proxy wrappers, tested end-to-end on testnet.

> ⚠️ **Disclaimer:** This is unaudited security tooling that gates real fund access. Do
> not deploy to mainnet without an independent audit. See [SECURITY.md](SECURITY.md).

## Enforcement scope — read this before relying on the caps

Full recipient/amount enforcement — spend caps, allowlists, per-transaction limits — is native and automatic for SAC token transfers (`transfer`/`transfer_from`), since these are the calls whose arguments the Soroban auth context exposes for inspection. For other Soroban contract calls made by the guarded account (arbitrary DEX/lending/protocol calls), the policy engine still enforces window and pause state, but per-call amount/recipient limits are not yet enforced — extending fine-grained enforcement to arbitrary calls is tracked as a v2 item, not implied as already covered.

This boundary is an inherent property of the platform (the auth context does not expose arbitrary call arguments generically), not a gap this project hides or overclaims. The classification that produces this boundary (`AssetTransfer` vs `Protocol` vs `Unknown` default-deny) is spelled out in SPEC §6.

## Quick Start

```bash
# Build the contract and run the test suite
git clone https://github.com/aigbagbobila/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts
cargo build --release --target wasm32v1-none   # → target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm
cargo test                                      # 30 tests, isolated (no network)

# Read live state from the Phase-1 testnet deployment (no auth, simulation only)
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → {"admin_frozen":false,"has_policy":true,"heartbeat_expired":true,"last_heartbeat":1788855212,"now":1788863857}
```

## Public functions

All signatures below are pulled from the deployed source; the write-path examples were
re-verified this session by simulating each call against the live Phase-1 testnet
deployment (no transaction submitted). The Phase-1 fixture policy is
`per_tx_cap: 1000, window_cap: 150, window_secs: 60, assets: [token], recipients: [GDUYLF…],
dms_grace_secs: 60`.

### `initialize`
```rust
pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>)
```
One-time setup, `require_auth(admin)`. Stores the policy `admin` and the agent's Ed25519
public key (32 bytes) in instance storage, and initializes `AdminFrozen = false`,
`LastHeartbeat = 0`. Until `set_policy` runs, the account is **default-deny** — every
authorization is rejected with `not_initialized`/`no_policy`.

Called twice, it fails with `AlreadyInitialized` — verified live:
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  initialize --admin GD5S5O2MZ6FSMFH6QILG37KSQNRVR3RPSWBTTV4JOUJ7J6TWLLL5LAVS \
  --agent_pubkey 1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05
# → ❌ transaction simulation failed: HostError: Error(Contract, #2)   (AlreadyInitialized)
```
The Phase-1 deployment's real `initialize` transaction:
`cb17b7b1c65bff74b6bc99f67fe3cf1070c7a28f14bdd71527ba60c9d4a81264`.

### `set_policy`
```rust
pub fn set_policy(env: Env, config: PolicyConfig)
```
Admin-only (`require_auth(Admin)`). Replaces the policy, resets the rolling window, and
starts the dead-man-switch clock at install time (a fresh policy gets full grace). The
`PolicyConfig` fields:

| Field | Type | Meaning |
|---|---|---|
| `per_tx_cap` | `i128` | per asset-transfer call cap; `0` = disabled |
| `window_secs` | `u64` | rolling window width in seconds (default 86_400) |
| `window_cap` | `i128` | rolling cap within `window_secs`; `0` = disabled |
| `assets` | `Vec<Address>` | SAC token contracts whose transfers get parsed and enforced |
| `protocols` | `Vec<ProtocolRule>` | allowlisted non-asset contracts (`contract` + optional `fns: Option<Vec<Symbol>>`) |
| `recipients` | `Vec<Address>` | allowed SAC transfer destinations |
| `allow_any_recipient` | `bool` | escape hatch: skip the recipient allowlist (caps still apply) |
| `active_from` / `active_until` | `u64` | active window (unix seconds); `0` = unrestricted |
| `paused` | `bool` | admin kill switch |
| `dms_grace_secs` | `u64` | dead-man grace in seconds; `0` = disabled |

Config is validated **before** anything is written; invalid config fails with
`InvalidConfig` and the policy is left unchanged (fail-closed). Verified live — the
fixture policy installs cleanly (emits `EventPolicySet`), and an invalid active window
(`active_until <= active_from`) is rejected with `Error(Contract, #4)`:
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- set_policy --config '{
    "active_from": 0, "active_until": 0, "allow_any_recipient": false,
    "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
    "dms_grace_secs": 60, "paused": false, "per_tx_cap": "1000",
    "protocols": [], "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
    "window_cap": "150", "window_secs": 60 }'
# → Event: EventPolicySet (event_policy_set)
```
Other validation rules (SPEC §8): negative caps, `window_cap > 0` with `window_secs == 0`,
duplicate assets/recipients/protocol contracts, empty per-protocol fn lists, or the
self-address in `assets`/`protocols` all fail with `InvalidConfig`.

### `revoke_policy`
```rust
pub fn revoke_policy(env: Env)
```
Admin-only. Removes the policy and the rolling window → the account is immediately
default-deny. Verified live (simulation): emits `EventPolicyRevoked`.

### `rotate_agent_key`
```rust
pub fn rotate_agent_key(env: Env, new_pubkey: BytesN<32>)
```
Admin-only. Re-binds the agent's Ed25519 public key. The admin never gains fund-moving
power — it can only replace the key the account will authenticate. Verified live
(simulation): emits `EventAgentRotated`.

### `heartbeat`
```rust
pub fn heartbeat(env: Env)
```
The only self-call the policy allows. A valid caller is the **registered agent key and
nothing else**: `heartbeat` does `require_auth` on the contract itself, so it routes
through `__check_auth`, which verifies the agent's Ed25519 signature over the auth
payload. It records `LastHeartbeat = now` and emits `EventHeartbeat`. A heartbeat arriving
after the grace window expired is rejected (`heartbeat_expired`) — silence cannot
self-revive; only the admin's `unfreeze` restores the account.

The `stellar` CLI cannot invoke it, because it cannot sign Soroban auth entries whose
address is a contract. Use the repo's submission helper instead:
```bash
cd tools/agent-tx && cargo build --release
./target/release/agent-tx heartbeat \
  --guard CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --agent-secret S...   # the registered agent's Ed25519 secret (AGENT_SECRET env also works)
```

For the full steady-state loop an agent must run (heartbeat cadence, per-transfer
pre-flight, blocked-reason handling, DMS stop conditions), see
[`examples/agent-loop.md`](examples/agent-loop.md).
The TypeScript equivalent is the SDK's
[agent-runtime guide issue](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk/issues/74).

### `freeze` / `unfreeze`
```rust
pub fn freeze(env: Env)      // admin only — sets AdminFrozen = true
pub fn unfreeze(env: Env)    // admin only — clears AdminFrozen, LastHeartbeat = now
```
`freeze` is the immediate admin kill switch (blocks even a live, heartbeating agent);
`unfreeze` is the admin's liveness attestation that revives a dead-man-frozen account.
Both are admin-only (`require_auth(Admin)`). Verified live (simulation): `freeze` emits
`EventFrozen`, `unfreeze` emits `EventUnfrozen`.

The real Phase-1 unfreeze — the DMS-reversal transaction verified on-chain (tx
`dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5`):
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source guard_admin --send=yes -- unfreeze
# → ✅ Transaction submitted successfully!  tx=dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5
```

### `policy` (read)
```rust
pub fn policy(env: Env) -> Option<PolicyConfig>
```
No auth. Returns the current policy, or `None` (default-deny). Verified live against the
deployed contract — this is the real installed fixture policy:
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- policy
# → {"active_from":0,"active_until":0,"allow_any_recipient":false,
#    "assets":["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
#    "dms_grace_secs":60,"paused":false,"per_tx_cap":"1000","protocols":[],
#    "recipients":["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
#    "window_cap":"150","window_secs":60}
```

### `status` (read)
```rust
pub fn status(env: Env) -> Status
```
No auth. Returns `{ has_policy, admin_frozen, heartbeat_expired, last_heartbeat, now }`.
Verified live:
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- status
# → {"admin_frozen":false,"has_policy":true,"heartbeat_expired":true,"last_heartbeat":1788855212,"now":1788863857}
```
Note the deployed account now reads `heartbeat_expired: true` — the 60s DMS grace lapsed
after the Phase-1 fixture runs, exactly as the design specifies: a silent account freezes
itself with zero transactions.

### `check` (read / pre-flight)
```rust
pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult
```
No auth, no writes. A pure pre-flight replica of the SAC-transfer decision path: lets
agents/SDKs simulate a transfer *before* signing, emitting the same `auth_checked` events
as an in-path decision so telemetry sees one vocabulary. Verified live (this account is
DMS-frozen, so the honest answer today is blocked):
```bash
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  check --asset CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
# → {"Blocked":"heartbeat_expired"}
```

### `__check_auth` (host-invoked — not callable by anyone)
```rust
fn __check_auth(env: Env, signature_payload: Hash<32>, signatures: BytesN<64>,
                auth_contexts: Vec<Context>) -> Result<(), Error>
```
This is the enforcement entrypoint, and it is **not** a user-callable function: the Soroban
host invokes it automatically on every authorization the account must approve. Step by step:

1. Load the registered agent pubkey from instance storage — missing means
   `NotInitialized` (default-deny until `initialize`).
2. Verify the agent's Ed25519 signature over `signature_payload` via
   `env.crypto().ed25519_verify` — a wrong key or bad signature traps the frame before any
   policy evaluation.
3. Snapshot policy state: `PolicyConfig` (missing → `NoPolicy`), `AdminFrozen`,
   `LastHeartbeat`, ledger time.
4. Run the decision table (`decide`) — account-level gates first, then a per-context
   decision loop, then commit window admissions only if every context passed.
5. Return `Ok(())` to approve the transaction, or `Err(reason)` to reject it — and emit
   the `auth_checked` event either way.

See [How it works](#how-it-works) below for the full flow through `parse_call`/`decide`.

## Installation

### Prerequisites
- **Rust 1.85+** with the `wasm32v1-none` target (Soroban 27 targets `wasm32v1-none`,
  not `wasm32-unknown-unknown`):
  `rustup target add wasm32v1-none`
- **Soroban CLI** (`stellar` / `stellar-cli` 22+ — verified against 27.1.0) for deployment
  and admin invocations
- **Network access** to a Soroban RPC endpoint for anything on-chain

| Network | Endpoint |
|---|---|
| `testnet` | `https://soroban-testnet.stellar.org` |
| `mainnet` | `https://soroban.stellar.org` |
| `futurenet` | `https://rpc-futurenet.stellar.org` |

### Build from source
```bash
git clone https://github.com/aigbagbobila/stellar-agent-guard-contracts.git
cd stellar-agent-guard-contracts

# contract wasm (the artifact to deploy)
cargo build --release --target wasm32v1-none
# → target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm

# submission helper (agent-tx: signs auth entries for the guard address; the
# stellar CLI cannot — see "heartbeat" above)
cargo build --release --manifest-path tools/agent-tx/Cargo.toml
# → target/release/agent-tx

# full gate suite (see Testing & CI)
cargo test
cargo clippy --all-targets --all-features
cargo fmt --check
```
Both builds and all three gates were re-run green on this machine during the README pass.

## How it works

```
┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
│ Transaction requires │─────▶│ __check_auth         │─────▶│ Verify agent Ed25519 │
│ the account's auth   │      │ (host-invoked)       │      │ signature over auth  │
└──────────────────────┘      └──────────────────────┘      │ payload (bad sig ⇒  │
                                                             │ host trap)          │
                                                             └──────────┬───────────┘
                                                                        ▼
┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
│ Load PolicyConfig,   │◀─────│ Account-level gates  │◀─────│ Load instance +      │
│ AdminFrozen,         │      │ (order: admin frozen │      │ persistent state     │
│ LastHeartbeat, now   │      │ → DMS → paused →     │      │ (agent key, policy,  │
└──────────┬───────────┘      │ active window)       │      │ window, heartbeat)   │
           │                  └──────────────────────┘      └──────────────────────┘
           ▼
┌──────────────────────┐      ┌──────────────────────┐      ┌──────────────────────┐
│ Per-context decision │─────▶│ parse_call: classify │─────▶│ Enforce per kind:    │
│ loop — every context │      │ each auth context    │      │ • AssetTransfer →    │
│ must pass            │      │ (SelfCall /          │      │   recipient allowlist│
└──────────────────────┘      │  CreateContract /    │      │   + per-tx cap +     │
                              │  Unknown / AssetOther│      │   rolling window     │
                              │  / AssetTransfer /   │      │ • Protocol → contract│
                              │  Protocol)           │      │   + fn allowlist     │
                              └──────────────────────┘      │ • anything else →    │
                                                             │   default-deny       │
                                                             └──────────┬───────────┘
                                                                        ▼
                              ┌────────────────────────────────────────────────────┐
                              │ All contexts admissible?  Yes → commit staged      │
                              │ window admissions → Ok(()).  No → Err(reason) —     │
                              │ the whole transaction is rejected pre-broadcast.   │
                              └────────────────────────────────────────────────────┘
```

Walkthrough, matching the real code path in `src/lib.rs` / `src/engine.rs`:

1. **Signature verification.** `__check_auth` loads the registered agent pubkey and calls
   `env.crypto().ed25519_verify` over the transaction auth payload. This runs before any
   policy logic, so a compromised-but-unregistered key never reaches the decision table.
2. **Policy snapshot.** The current `PolicyConfig`, `AdminFrozen`, `LastHeartbeat`, and
   ledger time are loaded. No policy stored ⇒ `NoPolicy` — the account is default-deny.
3. **Account-level gates** (in this order): admin freeze, dead-man switch (grace elapsed
   since last heartbeat), pause, active window. Any one firing rejects the transaction
   regardless of what the call is.
4. **Per-context classification.** `parse_call` turns each `Context` into a typed call:
   `SelfCall` (only `heartbeat` is allowed), `CreateContract` (denied in v1),
   `Unknown`/`AssetOther` (denied), `AssetTransfer` (a known SAC transfer with parsed
   recipient and amount), or `Protocol` (a call to an allowlisted contract).
5. **Per-kind enforcement.** Asset transfers get the full treatment — recipient
   allowlist, per-tx cap, and the rolling-window projection (existing total + amounts
   staged earlier in the same request). Protocol calls get contract + per-function
   allowlisting. Everything else is denied by default.
6. **All-or-nothing commit.** Window admissions are staged and only committed to storage
   if *every* context passes — a partially-validating batch can never spend. `Ok(())`
   approves; `Err(reason)` rejects the entire transaction, and the `auth_checked` event
   records the outcome either way.

## Storage

On-chain state, keyed per the `DataKey` enum in `src/types.rs` (SPEC §3):

| Key | Type | Kind | Purpose |
|---|---|---|---|
| `Initialized` | `bool` | instance | one-time flag for `initialize` |
| `Admin` | `Address` | instance | policy admin; set once at `initialize` |
| `AgentPubkey` | `BytesN<32>` | instance | the registered agent's Ed25519 public key |
| `Policy` | `PolicyConfig` | persistent | current policy (`None` = default-deny) |
| `Window` | `WindowState` | persistent | rolling spend ledger (`total` + chronological `entries`) |
| `LastHeartbeat` | `u64` | persistent | unix seconds of the last agent heartbeat (`0` = never) |
| `AdminFrozen` | `bool` | persistent | admin-initiated freeze flag |

Instance keys auto-refresh TTL on every invocation; persistent keys are extended to the
maximum TTL on every write (`persist_set`). The `Window` ledger is bounded at
`MAX_WINDOW_ENTRIES = 8192` — beyond that, the two oldest entries merge *forward*
(conservative over-count), so the `window_cap` ceiling is never exceeded (SPEC §3.1).

## Architecture

Stellar Agent Guard operates across three dedicated repositories:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Operator (Browser / Freighter)                     │
│                                     │                                   │
│                                     ▼                                   │
│              stellar-agent-guard-dashboard (Next.js / UI)               │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                   AI Agent Runtime (LangChain / ElizaOS)                │
│                                     │                                   │
│                                     ▼                                   │
│                stellar-agent-guard-sdk (TypeScript / RPC)               │
│               • Pre-flight policy check  • Cost pre-checks              │
│               • Agent-auth tx signing    • Event telemetry              │
└─────────────────────────────────────┬───────────────────────────────────┘
                                      │
                                      ▼ Soroban RPC
┌─────────────────────────────────────────────────────────────────────────┐
│               stellar-agent-guard-contracts (Soroban / Rust)             │
│            • CustomAccount interface (`__check_auth`)                   │
│            • Spend caps, rolling window, allowlists, dead-man switch    │
└─────────────────────────────────────────────────────────────────────────┘
```

| Repository | Role | Documentation |
|---|---|---|
| [**stellar-agent-guard-contracts**](https://github.com/aigbagbobila/stellar-agent-guard-contracts) (this repo) | Soroban smart contracts implementing Custom Account Abstraction and spending policy firewall | [GitBook Docs](https://soroban-cost-estimator.gitbook.io/stellar-agent-guard-contracts/) |
| [**stellar-agent-guard-sdk**](https://github.com/aigbagbobila/stellar-agent-guard-sdk) | TypeScript SDK for pre-flight interception, simulation pricing, and AI agent framework integration | [GitHub](https://github.com/aigbagbobila/stellar-agent-guard-sdk) |
| [**stellar-agent-guard-dashboard**](https://github.com/aigbagbobila/stellar-agent-guard-dashboard) | Client-side operator dashboard for policy deployment, inspection, and emergency panic-button freeze | [GitHub](https://github.com/aigbagbobila/stellar-agent-guard-dashboard) |

## Repository layout

- `src/` — contract: `__check_auth` (CustomAccount), policy engine, rolling window,
  dead-man switch, admin controls, events.
- `src/integration_tests.rs` — contract-level tests that exercise the real
  `__check_auth` path, including Ed25519 auth-signature verification (SPEC §11).
- `tools/agent-tx/` — submission helper that signs Soroban auth entries for the guard
  (custom-account) address and submits real testnet transactions. The `stellar` CLI
  cannot sign auth entries whose address is a contract, so this tool fills that gap; it
  is the prototype of the Phase 2 SDK's signing path.
- `examples/agent-loop.md` — the steady-state **24/7 agent runtime loop**: heartbeat
  cadence formula (`interval ≤ grace / 3`), pre-flight `check()`, blocked-reason
  handling table, and stop conditions, with tested `agent-tx` commands.
- `tests/fixtures/README.md` — the real testnet evidence for the five scenarios.
- `SPEC.md` — the full architecture specification.

## ✅ Verified against live testnet

Phase 1 was proven end-to-end against a **real deployed contract** on Stellar testnet
(protocol 28, `Test SDF Network ; September 2015`), cross-checked on-chain:

- **Guard (custom account) contract ID**:
  `CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7`
- **SAC token**: `CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7`
- **Allowed transfer** (scenario 1), ledger 4566285, `successful: true`:
  `4c5759298c0364b01d386a5935b964532b04978ea595d96d904d9011f58d64b8`
- **Post-unfreeze transfer** (scenario 5 reversal), ledger 4566327:
  `b39457afa59f20d6ac90cd137e917c7efd51e27af4913c6c6308a6e5d0eff512`
- **Admin unfreeze** (DMS reversal):
  `dd327d32b18bfc6cebdf6c956503fe5318e28f8a8bc86a88cb7ee42c5d46b5e5`

The five scenarios — allowed transfer, per-tx cap block, rolling-window cap block,
recipient-allowlist block, and dead-man trigger + reversal — plus the setup transaction
hashes, the event output from the contract's own `auth_checked` topics, and full
reproduction steps live in
[`tests/fixtures/README.md`](tests/fixtures/README.md). During this README pass the
deployed contract's `status`/`policy`/`check` functions were invoked live again (results
pasted in the function reference above) — the account is still on-chain and readable,
and honestly reports the DMS has since expired, exactly as designed.

## Project Status

| Feature | Status |
|---|---|
| Custom-account `__check_auth` enforcement | ✅ |
| Per-transaction spend cap | ✅ |
| Rolling window spend cap | ✅ |
| Recipient allowlist (SAC transfers) | ✅ |
| Protocol/function allowlist (any call) | ✅ |
| Dead-man switch (freeze on missed heartbeat) | ✅ |
| Admin unfreeze | ✅ |
| Verified against live testnet (cross-checked) | ✅ |
| Fine-grained amount/recipient enforcement for non-SAC calls | 🔲 (v2, tracked as [issue #1](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues/1)) |

## Testing & CI

30 tests (unit + integration) cover the policy decision engine — including the regression
for the rolling-window prune underflow at low timestamps, the per-tx-cap arithmetic that
proves blocked transactions never consume the window, and dead-man-switch timeline edge
cases — plus `__check_auth` Ed25519 signature verification and the full enforcement
scenario matrix (SPEC §11). Verified green this session: `30 passed; 0 failed`.

```bash
cargo test
cargo clippy --all-targets --all-features   # clippy `all` + `pedantic` denied via Cargo.toml lints
cargo fmt --check
```

Every push runs these gates on GitHub Actions (`.github/workflows/ci.yml`, job `ci`):
format → clippy (`-D warnings`) → unit + integration tests → contract wasm build →
`agent-tx` build. `main` is protected by a branch ruleset — the `ci` check must be green
and a review approved for changes to merge.

## Topics

`stellar`, `soroban`, `smart-contracts`, `rust`, `ai-agents`, `security`,
`custom-account`, `spending-limits`

## Community

- [Telegram](https://t.me/+EzSusj-2vVhhNmI0) — Stellar Agent Guard community group
- [Discord](https://discord.gg/Z766vsgjg) — Stellar Agent Guard community server

## Maintainers

| Name | GitHub | Telegram |
|---|---|---|
| Hybrid | [@aigbagbobila](https://github.com/aigbagbobila) | [@aigbagbobila](https://t.me/+EzSusj-2vVhhNmI0) |

## Socials

- [Telegram](https://t.me/+EzSusj-2vVhhNmI0)
- [Discord](https://discord.gg/Z766vsgjg)

## Contact

- GitHub issues: <https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues>
- Maintainer (GitHub): [@aigbagbobila](https://github.com/aigbagbobila)
- Security disclosures: see [SECURITY.md](SECURITY.md) (Telegram, the Stellar ecosystem norm)

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on coding standards, PR process, and
project structure — including the strict one-commit-per-logical-unit rule.

Looking for something to work on? The
[issue backlog](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues)
holds scoped issues with Summary / Acceptance Criteria / Tech Stack — good first tasks for
the Drips Stellar Wave contributor sprints.

![Contributors](https://contrib.rocks/image?repo=aigbagbobila/stellar-agent-guard-contracts)