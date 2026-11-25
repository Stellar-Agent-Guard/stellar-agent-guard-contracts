# stellar-agent-guard-contracts — Architecture Specification (Phase 1)

Status: **implemented against this spec; testnet proofs recorded in `tests/fixtures/README.md`.**
Mechanism is settled: **Soroban native Custom Account Abstraction.** This document specifies the
smart-wallet policy contract, every public signature with auth-placement reasoning, the policy
model (per-transaction cap, genuinely rolling window cap, recipient + protocol/function
allowlists, pause, dead-man switch), and the exact enforcement scope.

Documentation mapping: this specification is the **normative** source of truth for contract behavior.
For corresponding explanatory guides, tutorials, and concept walkthroughs on the GitBook documentation
site, see the [SPEC ↔ GitBook Cross-Reference Map](docs/README.md#spec--gitbook-cross-reference-map).

Sibling context: this project builds on the research and reasoning of `agent-spend-policy` (a
related but distinct project). Mechanism conclusions are shared; code, policy math (rolling, not
fixed-bucket), and the product split (contracts / SDK / dashboard) are this project's own.

---

## 1. Mechanism and non-custodial guarantee

The guarded agent's Ed25519 public key is registered inside a smart-wallet contract that
implements the Soroban `CustomAccountInterface`. From then on, the agent's **address is the
contract's address**: any transaction that needs the agent to authorize an action (any
`require_auth` on that address) is routed by the host through the contract's `__check_auth`
before the action can touch a target protocol. `__check_auth` is the single enforcement vector.
The mechanism choice and the alternatives rejected are recorded in
[ADR-0001](docs/adr/0001-custom-account-abstraction-over-wrapper-contract.md).

- **Non-custodial.** Funds live in the agent's own smart account (balances held at the contract
  address by Stellar Asset Contracts). There is no third-party vault, no `top_up`, no deposit
  step. The policy admin holds **no fund-moving authority of any kind**: admin functions change
  policy and freeze state only. Only the registered agent key can move funds, and only within
  the policy enforced in `__check_auth`.
- **No per-protocol proxy wrapper contracts.** The account calls target protocols directly; the
  policy contract is the account itself, not a wrapper in front of anything.
- A contract account cannot perform classic Stellar operations (its address has no Ed25519 key
  of its own), so every action of the account is a Soroban invocation and therefore passes
  through `__check_auth`. There is no classic-op enforcement gap to configure.

**Why non-custodial, concretely.** The guarantee is about reachability, not only about where
the balance sits. The contract exposes no sweep, withdraw, or arbitrary-transfer admin
entrypoint: no admin function moves value, and only the registered agent key can authorize a
transfer, under the policy evaluated in `__check_auth`. Two consequences are part of the same
statement and must be read with it:

- **An admin-key attacker is a control attacker, even though no admin entrypoint moves
  funds.** The admin can rewrite policy (§8), pause/resume, freeze/unfreeze, and re-bind the
  agent key (§7). Those powers let a hostile admin install a permissive policy and rotate the
  agent key to one it controls, so describing admin-key compromise as "cannot touch funds"
  would understate it. Admin compromise is out of scope by design (§10); the mitigation is
  custody of the admin key, not a contract check.
- **The enforcement boundary is distinct from the custody boundary.** Custody is
  non-custodial for every authorized call; *amount and recipient* enforcement is complete
  only for SAC transfers. Arbitrary protocol calls are bound by contract/function
  allowlisting and the account-level gates, not by per-call caps (§2).

What infrastructure can and cannot reach (SDK, RPC, third-party contracts) is summarized
with the actor table in the README's
[Why non-custodial, concretely](README.md#why-non-custodial-concretely) subsection; the
exclusions are §10.

### 1.1 SDK and host surface this is built on (soroban-sdk 27)

Verified against `soroban-sdk 27.0.6` source (`src/auth.rs`, `src/custom_account.rs`). The SDK
version is pinned in `Cargo.toml`; the host is not a library dependency, so this section also
records the host contract that the contract depends on:

```rust
pub trait CustomAccountInterface {
    type Signature;
    type Error: Into<Error>;
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,   // digest the presented signature must verify against
        signatures: Self::Signature,
        auth_contexts: Vec<Context>,   // every call this account must authorize, with args
    ) -> Result<(), Self::Error>;
}

pub enum Context {
    Contract(ContractContext),                     // a call: contract, fn_name, args
    CreateContractHostFn(..),                      // account-authorized contract creation
    CreateContractWithCtorHostFn(..),
}
pub struct ContractContext {
    pub contract: Address,   // the contract being called (an SAC token, a protocol, ...)
    pub fn_name: Symbol,
    pub args: Vec<Val>,      // raw arguments of that call — the thing we inspect
}
```

The host invokes `__check_auth` once per authorization the account must approve, supplying the
contexts of the calls being authorized. `auth_contexts` is the flattened invocation tree for
this account: a nested `require_auth` performed by an allowlisted protocol appears as its own
context, in tree order — measured and pinned in §2.1 (issue #340). `type Signature = BytesN<64>` (single registered agent
Ed25519 key; a `Vec` of keys / threshold signatures is a v2 item — see [Multi-Sig Threshold Models](docs/research/multi-sig-threshold-models.md)). Signature verification:
`env.crypto().ed25519_verify(registered_pubkey, signature_payload (32B), presented_sig)`, then
policy evaluation. CAP-71 delegation (`env.custom_account().get_delegated_signers()` /
`delegate_auth`) is available but **out of v1 scope**.

**Research note (v2):** Verifiable off-chain policy attestation is explored in [Policy Attestation](docs/research/policy-attestation.md) — admin signs `policy_hash()` output; agent verifies before bootstrap. Current conclusion: deferral (direct chain read is stronger for typical deployments).

---

## 2. Enforcement scope — SAC token calls vs. every other Soroban call (REQUIRED FRAMING)

`auth_contexts` exposes `contract`, `fn_name`, and raw `args` for **every** call the account
authorizes. The Stellar Asset Contract interface is fixed and known, so for SAC token calls the
arguments are meaningful to us: `transfer(from, to, amount)` and `transfer_from(from, spender,
to, amount)` lay out recipient and amount at known positions. No other Soroban contract exposes
a fixed, knowable argument schema, and per-call value moved is frequently a return value or an
internal effect that is not readable at authorization time.

Therefore the scope is:

**Full recipient/amount enforcement — spend caps, allowlists, per-transaction limits — is
native and automatic for SAC token transfers (`transfer`/`transfer_from`), since these are the
calls whose arguments the Soroban auth context exposes for inspection. For other Soroban
contract calls made by the guarded account (arbitrary DEX/lending/protocol calls), the policy
engine still enforces account-level gates — admin freeze, dead-man switch, pause, and the
active window (`active_from` / `active_until`) — but per-call amount/recipient limits and
rolling-window spend accounting are not applied to non-SAC calls; extending fine-grained
enforcement to arbitrary calls is tracked as a v2 item, not implied as already covered.**

*Canonical statement: the paragraph above is the single source of truth for the scope
wording. The README and `docs/enforcement-scope.md` quote the same paragraph word for
word and link back here; `scripts/check-enforcement-scope.sh` fails CI if the three
copies diverge (CONTRIBUTING rule 2).*

What "window and pause state" means for non-SAC calls is made exact in §6.4: the account is a
**default-deny** environment — every call must match the protocol allowlist (contract, and
optionally function) — and the active-window / pause / dead-man-freeze checks gate every context
equally, SAC or not. What *is* applied to non-SAC calls as of v1 is **call count rate limiting**
(rolling-window cap on the number of protocol calls; see §6.3), which is fully observable and
addresses runaway-loop attacks. What is *not* applied to non-SAC calls is per-call amount capping
and rolling-window spend accounting, because the amount is not available in the context in any
trustworthy way.

This boundary is an inherent property of the platform (an independent current confirmation:
OpenZeppelin's Soroban `spending_limit` plugin likewise only meters transfer contexts and
rejects non-transfer calls outright), **not** a gap this project hides or overclaims. The README
and `docs/enforcement-scope.md` quote this section briefly and link here as canonical. The
deny-by-default classification that produces this boundary is recorded in
[ADR-0004](docs/adr/0004-deny-by-default-classification.md).

**Contract creation contexts:** Host-function contract creation contexts (`CreateContractHostFn`
and `CreateContractWithCtorHostFn`) are surfaced by the host to `__check_auth` when contract deployment
is authorized by the guarded custom account (e.g. via `deployer().with_address(...)`). The
policy engine evaluates these contexts under default-deny and denies all contract creation
attempts fail-closed with `CreateContractNotAllowed` (code 28), verified end-to-end through
the real host authorization path (`contract_creation_denied_through_real_host_path`).

**Research note (v2):** The decomposition of "fine-grained non-SAC enforcement" into honest sub-strategies (protocol-specific parsers, declared-max, return-value commitments) is documented in [Non-SAC Enforcement](docs/research/non-sac-enforcement.md). Count-based protocol call rate limiting (v1) is now implemented; opt-in protocol parsers remain a secondary track.

### 2.1 Nested / sub-invocation authorizations (issue #340)

**The question.** v1 evaluates the contexts it is given. The v2 fine-grained enforcement question
(for non-SAC protocol calls) depended on whether a protocol's own nested `require_auth` on the
account is delivered to `__check_auth` as a separate context, collapsed into the parent, or not
surfaced at all. If nested authorizations were invisible, an allowlisted protocol could pull a
further authorization from the account that the guard never evaluated — a materially sharper
statement of this section's enforcement boundary.

**The answer (recorded finding): nested authorizations are visible, not collapsed and not
absent.** When an allowlisted protocol performs a nested `require_auth` on the guarded account,
the nested call arrives in `auth_contexts` as its own entry, in invocation-tree order (parent
first, then each nested call), and the guard classifies and evaluates it exactly like a top-level
context. The host requires the nested call to be declared in the transaction's
authorization tree (`SorobanAuthorizedInvocation.sub_invocations`); a nested authorization that
is **not** declared fails host authorization rather than reaching the guard unexamined. So there
is no path by which a protocol obtains an approval the guard did not evaluate.

**Evidence (reproducible, not a one-off trace).** The committed host-routed tests
`nested_authorization_is_delivered_as_a_separate_auth_context` and
`nested_authorization_is_evaluated_against_policy` (`src/integration_tests.rs`) drive the real
host authorization path: a `MockNestedRouter` protocol call is authorized as the root context and
performs a nested SAC `transfer` from the same account, declared as a sub-invocation. The first
test observes **two** separate `auth_checked` events (one per context — a collapsed or hidden
context would produce one), and the second observes the guard rejecting the whole authorization
with `recipient_not_allowed` when only the nested transfer violates the recipient allowlist. The
experiment was run against `soroban-env-host` 27.0.1 (the host line pinned by the SDK, i.e. the
same auth-assembly code testnet protocol 28 runs). It is pinned as a test rather than a one-off
testnet transaction so CI re-checks it on every change; exercising it on a live network would
require deploying a probe protocol and a custom-account auth entry for an account whose agent key
is not held by this repository.

**Consequence for the scope claim above — scope is unchanged, one reassurance is added.** v1
still does not apply per-call amount/recipient limits to **non-SAC** calls (the arguments of an
arbitrary protocol call are not a trustworthy description of value moved). But nesting is not a
bypass for the limits it *does* enforce: a nested SAC `transfer` is classified as an asset
transfer and is fully enforced (allowlists, caps, rolling window), as the second test demonstrates.
A protocol that wants to move an allowlisted asset out of the account must therefore do so through
a context the guard evaluates; the honest statement of the boundary is "amount/recipient
enforcement is per SAC-transfer context, wherever that context appears in the tree", not "a
protocol can spend invisibly". This strengthens, and does not widen, the §2 paragraph — the v2
work (protocol-specific parsers, declared-max, return-value commitments) remains open, and the
v2 issue is referenced there rather than designed here.

---

## 3. Storage model

Persistent storage with explicit TTL management (all policy/state keys are extended to a target
TTL on every write; see §9.5).

| Key | Type | Kind | Notes |
|---|---|---|---|
| `Initialized` | `bool` | instance | one-time flag for `initialize` |
| `Admin` | `Address` | instance | policy admin; set once at `initialize`, rotated via §7.2 |
| `PendingAdmin` | `Address` | instance | proposed admin awaiting `confirm_admin_rotation`; absent = no rotation pending |
| `AgentPubkey` | `BytesN<32>` | instance | the agent's Ed25519 public key |
| `PolicyVersion` | `u32` | instance | policy-model format version written at `initialize` (`POLICY_FORMAT_VERSION`, issue #339); absent before initialization. Read via `policy_version()` (never moved by `set_policy`, `revoke_policy`, or a pause) |
| `Policy` | `PolicyConfig` | persistent | current policy (`None` = default-deny) |
| `Window` | `WindowState` | persistent | rolling spend ledger for asset transfers (global + per-recipient) |
| `LastHeartbeat` | `Option<u64>` | persistent | unix seconds of the last agent heartbeat: `Some(t)` = last attestation (may be `0`), `None` = never heartbeated (issue #295). The `Option` is what keeps "never" distinct from a heartbeat at ledger timestamp 0 — `Some(0)` arms the dead-man switch, `None` never does |
| `AdminFrozen` | `bool` | persistent | admin-initiated freeze flag |
| `PolicyRevision` | `u64` | persistent | policy sequence number; incremented on every `set_policy`/`revoke_policy` and on a `pause()`/`resume()` that actually flips `paused` (issues #289/#290), stamped into `policy_set`/`policy_revoked`/`paused`/`resumed`/`auth_checked` events (§9, issue #38) |

```rust
#[contracttype]
pub struct PolicyConfig {
    pub per_tx_cap: i128,                    // per asset-transfer call; 0 = disabled
    pub window_secs: u64,                    // rolling window width in seconds (default 86_400)
    pub window_cap: i128,                    // rolling cap within window_secs; 0 = disabled
    pub assets: Vec<Address>,                // SAC token contracts whose transfers get parsed/enforced
    pub protocols: Vec<ProtocolRule>,        // allowlisted non-asset contracts the account may call
    pub recipients: Vec<Address>,            // allowed SAC transfer destinations
    pub asset_caps: Vec<AssetCap>,           // per-asset cap overrides; empty = global behavior unchanged
    pub recipient_window_caps: Vec<RecipientCap>, // per-recipient rolling cap overrides; 0 = fall back to global
    pub blocked_recipients: Vec<Address>,    // denied SAC transfer destinations (checked first)
    pub allow_any_recipient: bool,           // escape hatch: skip recipient allowlist (still capped)
    pub active_from: u64,                    // unix seconds; 0 = no restriction
    pub active_until: u64,                   // unix seconds; 0 = no restriction
    pub paused: bool,                        // admin kill switch
    pub dms_grace_secs: u64,                 // dead-man switch grace; 0 = disabled
    pub protocol_calls_per_window: u32,      // max protocol calls per rolling window; 0 = disabled
}

#[contracttype]
pub struct ProtocolRule {
    pub contract: Address,                // contract permitted for non-SAC calls
    pub fns: Option<Vec<Symbol>>,         // None = any function; Some = function allowlist
    pub paused: bool,                     // if true, the protocol entry is blocked even if allowlisted
}

#[contracttype]
pub struct AssetCap {
    pub asset: Address,                   // must be a member of `assets`; unknown-asset overrides rejected
    pub per_tx_cap: i128,                 // per-asset per-tx cap; 0 = fall back to global per_tx_cap
    pub paused: bool,                     // if true, the asset is blocked even if allowlisted
}

#[contracttype]
pub struct RecipientCap {
    pub recipient: Address,
    pub cap: i128,                        // per-recipient rolling cap within window_secs; 0 = disabled / global fallback
}

#[contracttype]
pub struct WindowState {
    pub total: i128,                      // observability/ABI only: never read for enforcement;
                                          // recomputed from `entries` on every load (fail-safe)
    pub entries: Vec<SpendEntry>,         // chronological global spend entries; pruned lazily on access
    pub recipients: Vec<RecipientWindowState>, // per-recipient rolling ledgers for recipients with override caps
    pub protocol_call_entries: Vec<ProtocolCallEntry>, // rolling protocol call count entries; pruned lazily
}

#[contracttype]
pub struct RecipientWindowState {
    pub recipient: Address,
    pub total: i128,                      // observability/ABI only: never read for enforcement;
                                          // recomputed from `entries` on every load (fail-safe)
    pub entries: Vec<SpendEntry>,          // chronological entries for this recipient
}

#[contracttype]
pub struct SpendEntry { pub ts: u64, pub amount: i128 }

#[contracttype]
pub struct ProtocolCallEntry { pub ts: u64, pub count: u32 }  // coalesced call count per second
```

**`WindowState.total` / `RecipientWindowState.total` are write-only for enforcement
(issue #346).** The stored `total` is never used for enforcement: it is recomputed from
`entries` on every load, so a corrupted cache can never admit spend. The field is kept in
the persisted shape for ABI stability and introspection only — removing it would change the
`Window` wire encoding (and every off-chain decoder) without strengthening the guard. The
same wording is used in the `Ledger::from_state` / `ledger_from_entries` doc comments in
`src/window.rs`.

**Field names and declaration order are part of the on-chain wire format.** These are
`#[contracttype]` shapes: Soroban encodes a struct as an `ScVal` map keyed by the field
names, its generated decoder reads entries positionally against the sorted field list, and
its XDR shape follows declaration order. Renaming, reordering, inserting, or removing a
field is therefore a wire-format change — it changes the bytes hashed by `policy_hash`, the
persisted `Window` encoding, and the shape every off-chain decoder sees — even though the
Rust code still compiles. Treat such an edit as breaking, regenerate
`tests/snapshots/abi_snapshot.txt`, and review the diff
(`git diff <last-release-tag> HEAD -- tests/snapshots/abi_snapshot.txt`). The encoding is
pinned by §3.2 and `tests/policyconfig_scval_encoding.rs`; the contributor rule is
CONTRIBUTING coding standard 10.

**`0` means disabled — normative helper definitions.** The sentinel convention used by
`per_tx_cap`, `window_cap`, and `dms_grace_secs` (and `0` = no limit for
`protocol_calls_per_window`) is defined once, in code, by the `PolicyConfig` accessors
`per_tx_cap_enabled()`, `window_cap_enabled()`, `dms_enabled()`, and
`protocol_calls_enabled()` in `src/types.rs`. `decide`, `status()`, and policy validation
read the sentinel through those helpers; any off-chain reimplementation (SDK, dashboard)
should match them rather than comparing the raw field, so the contract and its consumers
cannot drift on what `0` means.

Tooling-facing JSON shape is maintained in [`policy.schema.json`](policy.schema.json).
Treat it as normative-adjacent: the contract's `validate_config` implementation is authoritative
if a conflict exists, but changes to `PolicyConfig` or its validation rules must update this
schema and its conformance tests in the same change.

### 3.1 The window is genuinely rolling — not a fixed bucket

**Clock and pre-flight freshness.** `now` is the Soroban ledger's unix timestamp
(`env.ledger().timestamp()`), not the submitter's wall clock. The host supplies that
timestamp when the transaction executes; the contract cannot select or backdate it. Ledger
timestamps have one-second granularity, so events whose execution timestamps fall in the same
second are tied for window membership and are ordered by the host's transaction execution,
not by a sub-second wall-clock ordering. A policy or pre-flight `check()` result therefore
describes the ledger-time snapshot used by that invocation; it is advisory, not a reservation
of capacity. Between simulation and execution, another transaction may consume the remaining
cap or the ledger timestamp may advance across an active/window boundary. Re-run `check()`
immediately before signing/broadcasting if more than one ledger has elapsed, and always handle
the authoritative execution result (which can still differ if state changes afterward).

A test-env boundary example is covered by `window::tests::ledger_second_changes_window_membership_at_boundary`:
a spend admitted at second `t` remains live at `t`, then expires at `t + window_secs`.

A fixed 86,400-second bucket (reset-at-midnight style) is a **different guarantee** from a
rolling window and is rejected here. Under a fixed bucket, spend at 23:59 and spend at 00:01
are never counted together even though they are two minutes apart; under a rolling window, any
two spends within any 86,400-second span are counted together. The two guarantees diverge in
exactly the burst-boundary cases a spend guard exists to catch. The decision, its rejected
alternatives, and the conditions that would reopen it are recorded in
[ADR-0002](docs/adr/0002-rolling-window-over-fixed-bucket.md).

Implementation (exact, lazy, bounded):

- Entries are append-ordered by unix ledger time (`env.ledger().timestamp()`, 1s granularity).
- On every evaluation: the global and per-recipient spend ledgers bulk-prune their expired
  prefix using binary search over the timestamp-sorted entries to find the first live entry,
  dropping the prefix in O(log n) time instead of sequential O(k) pops. Expiry is tested as
  `entry.ts + window_secs <= now` — the addition form, not the algebraically equivalent
  `entry.ts <= now - window_secs` — because the subtraction form underflows (saturates to 0)
  at low ledger timestamps and would wrongly expire a still-live entry. Protocol-call entries
  apply the same predicate in a front-to-back loop. The low-timestamp regression is pinned by
  `window::tests::prune_keeps_recent_entries_at_low_timestamps`, which keeps an entry recorded
  at ts 0 that is only 50 seconds old in a 100-second window. Evaluation is lazy — no cron, no
  background writes; the O(expired) pruning cost amortizes over accesses.
- A new spend coalesces into the trailing entry when it shares the same second
  (`entries.last().ts == now`), so dense bursts in one second stay one entry.
- **Boundedness backstop:** `MAX_WINDOW_ENTRIES = 8192`. If a write would exceed it, the two
  oldest entries are merged into one whose `ts` is the **newer** of the two and whose `amount`
  is the sum. Merging forward over-counts (the older amount then expires later than it truly
  should), which can only make enforcement stricter than policy — it can never admit spend that
  policy would reject. The exact guarantee ("window_cap is a hard ceiling over any
  `window_secs` span") is preserved in all cases; in the pathological region of ≥8192 distinct
  spend seconds within one window the engine is conservative until density drops. This is
- **Merge telemetry:** each successful admission that triggers this backstop emits one
  `event_window_merged` event. Topic 1 identifies `global_spend`, `recipient_spend`, or
  `protocol_calls`; data is the compact tuple `(merged_ts, merged_value)`, where `merged_ts`
  is the retained newer timestamp and `merged_value` is the merged spend amount or call count.
  Events are emitted only when all auth contexts pass and the corresponding ledger changes
  are committed. No event is emitted below the bound.
- **Measured worst case (single lazy prune burst):** the real bench measurement for the pathological
  case of 8192 stale entries being pruned in one authorization is `worst_case_prune_cpu_cost=86925434`
  CPU instructions (`cargo test prune_worst_case_measured_cost -- --nocapture`). That is a
  real worst-case cost and is over the per-call host budget; the fix is tracked in
  [issue #113](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/113)
  (bulk-prune / sorted search), not a false all-clear. The bounded `MAX_WINDOW_ENTRIES` cap
  also interacts with storage rent/TTL because each persisted window entry is a ledger item that
  must remain live; see [issue #85](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/85)
  for the long-lived-account rent/TTL model.

**Per-asset caps and shared rolling total (v1 decision).** The rolling window total is
shared across all assets listed in `policy.assets`. `window_cap` is enforced against
`ledger.total` (`WindowState.total`), which sums `SpendEntry` amounts across all assets
listed in `policy.assets` (src/engine.rs). The rolling window does not segregate budget
by asset: with two listed tokens, 100 spent on one consumes the exact same rolling
budget as 100 on the other (the total is an aggregated, unit-less amount).

Per-asset overrides (`asset_caps`) change only the *per-transaction cap* compared
against, not the window ledger. There remains exactly one global rolling ledger
(`WindowState.total` / `entries`); a transfer's effective per-tx cap is resolved from
`asset_caps` (matching the transfer's asset) with fallback to the global `per_tx_cap`.
The rolling `window_cap` stays global and shared across all assets.

**Worked two-asset example:**
Suppose a policy lists two SAC assets `[AssetA, AssetB]` with `window_cap = 100`, `window_secs = 3600`, and `per_tx_cap = 100`:
1. Spend 60 on `AssetA`: the running rolling window total increases from `0` to `60` (`<= 100`), so the transfer is admitted.
2. Spend 60 on `AssetB`: even though zero `AssetB` has been transferred so far, the shared window total is already `60`. The projected aggregate total is `60 + 60 = 120 > 100`, so the second transfer is blocked with `WindowCapExceeded`.

**V2 direction:** Full per-asset rolling ledgers (independent window caps and running totals per asset) are the v2 direction and are tracked in [issue #56](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/56). Until then, this cross-asset aggregation is the actual semantics: operators who require isolated rolling budgets across different tokens should deploy separate guard accounts with single-asset policies.

This keeps the window invariant (§3.1) unchanged: the global `total` is still the sum of all admitted asset spends in the window across all listed assets, and admission requires `total + amount <= window_cap`.

**Invariant (window):** for every authorization decision, the global `total` after any admission equals the
sum of `entries[i].amount` over global entries whose addition-form predicate `ts + window_secs > now`
holds — the exact predicate `prune` applies, never the subtraction form `ts > now - window_secs` — and a
new asset transfer is admitted only if the running total (plus amounts already staged in the same
request) ≤ the effective cap for that transfer. Per-recipient overrides maintain the same invariant in their own
`RecipientWindowState`; recipients without an override use the global cap. Both the global cap
and any matching per-recipient cap must be satisfied.

**Corrupted persisted entries (issue #347).** No current admission path can persist a
non-positive `SpendEntry`: `decide` rejects `amount <= 0` before admission, and the merge-backstop
only sums two positive amounts. `ledger_from_entries` nevertheless filters `amount <= 0` when
rebuilding from storage as a corruption-only backstop, and the discard is pinned by
`window::tests::from_entries_drops_non_positive_corrupted_entries`. This branch cannot fire
through normal contract use. If corruption changed a real positive spend into a non-positive
amount, dropping it makes the recomputed total smaller than the true spend — the direction that
weakens enforcement — so the filter is a backstop, not an enforcement guarantee. The cached
`total` is always discarded and recomputed, so a corrupted cache can never admit spend (§3).

**Mid-window cap extension (`increase_window_cap`, issue #349).** Companion to `set_policy`'s
window-preserving edit semantics and explicit `reset_window` ([issue #289](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/289),
[issue #305](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/305),
[issue #303](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/303)):
an admin can top up `window_cap` mid-window via `increase_window_cap(new_cap)` without rewriting
the full `PolicyConfig` or resetting `DataKey::Window`. The call prunes the loaded ledger against
`now` and `window_secs` in memory to compute the live rolling total, rejects any `new_cap` that is
not strictly greater than the current `window_cap` (`new_cap <= cfg.window_cap`, which also rejects
`<= 0`) or that falls below the live pruned total (`new_cap < ledger.total`) with `InvalidConfig`,
and re-validates the updated config against §8 (`window_secs > 0`, `per_tx_cap <= new_cap`).
Rejecting a value below the current total is deliberate: silently setting a cap below already-spent
live volume would leave the account blocked with no recourse until entries roll off or the admin
calls `reset_window`. Existing window entries and `LastHeartbeat` are preserved untouched;
`PolicyRevision` increments and `event_window_cap_increased` is emitted with `by`, `old_cap`,
`new_cap`, and `revision` (§7, §9).

### 3.2 Exact ScVal encoding of `PolicyConfig` (for non-TypeScript consumers)

The SDK's `policyToScVal` is the corresponding TypeScript encoder. This section pins the on-wire
`ScVal` layout so Go/Python/Rust integrators (or a future CLI) can
implement encoders without reverse-engineering TS source. The layout below was derived from the
soroban-sdk 27 `#[contracttype]` derives (the host is the ultimate referee) and is locked by
`tests/policyconfig_scval_encoding.rs` and the shared vectors in
[`tests/fixtures/policy-vectors.json`](tests/fixtures/policy-vectors.json). The Rust vector test
decodes and round-trips each XDR value; [SDK issue #260](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-sdk/issues/260)
references this same file for the `policyToScVal` encoder assertion.

**Top level:** `ScVal::Map` with exactly **14 entries**, one per field. The map keys are the
field names as `ScVal::Symbol`.

**Sort order is mandatory.** The entries below are listed in **ascending symbol-key order**
(ASCII), which is the order the wire map must use. soroban-sdk generates struct decoders that
read map entries positionally against the sorted field list — a decoder is **order-sensitive**:
an encoder that emits declaration order instead of sorted order will silently misbind fields
(e.g. `window_cap` decoded as `window_secs`) rather than fail loudly. Emit keys sorted; never
rely on the struct's declaration order. The contract itself does not re-validate key order —
§8 validates policy *semantics* — so sorted emission is entirely the encoder's responsibility.

| # | Symbol key | Rust type | ScVal type | Notes |
|----|--------------------|--------------------|------------|-------|
| 1 | `active_from` | `u64` | `U64` | 0 = unrestricted |
| 2 | `active_until` | `u64` | `U64` | 0 = unrestricted |
| 3 | `allow_any_recipient` | `bool` | `Bool` | |
| 4 | `assets` | `Vec<Address>` | `Vec` | elements are `ScVal::Address`; SAC token contracts are contract addresses |
| 5 | `blocked_recipients` | `Vec<Address>` | `Vec` | denied destinations (checked first); account or contract addresses |
| 6 | `dms_grace_secs` | `u64` | `U64` | 0 = DMS disabled |
| 7 | `paused` | `bool` | `Bool` | |
| 8 | `per_tx_cap` | `i128` | `I128` | `Int128Parts { hi: i64, lo: u64 }`, two's complement |
| 9 | `protocol_calls_per_window` | `u32` | `U32` | 0 = disabled |
| 10 | `protocols` | `Vec<ProtocolRule>` | `Vec` | elements are 2-entry maps, see below |
| 11 | `recipient_window_caps` | `Vec<RecipientCap>` | `Vec` | elements are 2-entry maps, see below |
| 12 | `recipients` | `Vec<Address>` | `Vec` | account addresses |
| 13 | `window_cap` | `i128` | `I128` | 0 = disabled |
| 14 | `window_secs` | `u64` | `U64` | |

**`ProtocolRule` sub-encoding:** each element of `protocols` is itself a `ScVal::Map` with
exactly 2 entries, keys sorted:

| # | Symbol key | Rust type | ScVal type | Notes |
|---|-----------|--------------------|------------|-------|
| 1 | `contract` | `Address` | `Address` | contract address |
| 2 | `fns` | `Option<Vec<Symbol>>` | `Vec` or `Void` | `Some(list)` → `ScVal::Vec` of `ScVal::Symbol`; `None` → `ScVal::Void` |

**`RecipientCap` sub-encoding:** each element of `recipient_window_caps` is itself a
`ScVal::Map` with exactly 2 entries, keys sorted:

| # | Symbol key | Rust type | ScVal type | Notes |
|---|-----------|------------|------------|-------|
| 1 | `cap` | `i128` | `I128` | rolling cap within `window_secs`; 0 = disabled / fall back to global |
| 2 | `recipient` | `Address` | `Address` | account address |

**Primitive rules (apply everywhere, including nested values):**

- `u64` → `ScVal::U64`; `protocol_calls_per_window: u32` → `ScVal::U32`.
- `i128` → `ScVal::I128(Int128Parts { hi, lo })` — the 128-bit two's-complement value split into
  a signed 64-bit high word and unsigned 64-bit low word. Example: `-1234567` encodes as
  `hi: -1, lo: 18446744073708317049` (= 2⁶⁴ − 1234567). Non-negative values always have
  `hi: 0`. §8 validation rejects negative caps, but integrators must still encode them
  correctly to receive meaningful decode errors rather than garbage.
- `Vec<T>` → `ScVal::Vec(Some(ScVec))`. An **empty vec stays an empty vec** — it must NOT be
  encoded as `Void`.
- `Option<T>` → `Some(v)` encodes as `v`; `None` encodes as **`ScVal::Void`** (this is why
  `ProtocolRule.fns` is `Void` when any function is allowed). Do not confuse the two: an empty
  `Vec` is a list with zero elements, `None` is the absence of the value.
- `bool` → `ScVal::Bool`.
- `Address` → `ScVal::Address` — `ScAddress::Contract(ContractId(Hash))` for contract IDs
  (assets, protocol contracts) and `ScAddress::Account(AccountId(PublicKey::KeyTypeEd25519
  (Uint256)))` for account IDs (recipients).
- Serializing the tree above with Stellar XDR is deterministic (fixed-width big-endian fields,
  `VecM` length prefixes), so byte equality is a valid equality test for policies.

**Worked example — the Phase-1 fixture policy** (same values as the example in
`docs/functions/set-policy.md`):

JSON accepted by the CLI (`per_tx_cap`/`window_cap` quoted because they are `i128`):

```json
{
  "active_from": 0, "active_until": 0, "allow_any_recipient": false,
  "asset_caps": [],
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "blocked_recipients": [],
  "dms_grace_secs": 60, "paused": false, "per_tx_cap": "1000",
  "protocols": [], "recipient_window_caps": [],
  "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
}
```

The same policy as a structural `ScVal` tree (keys in mandatory sorted order):

```text
ScVal::Map(Some(vec![
  ("active_from",         U64(0)),
  ("active_until",        U64(0)),
  ("allow_any_recipient", Bool(false)),
  ("asset_caps",          Vec([])),                                  // empty vec, NOT Void
  ("assets",              Vec([Address(Contract(CBLQ…JC7))])),      // 1 element
  ("blocked_recipients",  Vec([])),                                  // empty vec, NOT Void
  ("dms_grace_secs",      U64(60)),
  ("paused",              Bool(false)),
  ("per_tx_cap",          I128(Int128Parts { hi: 0, lo: 1000 })),
  ("protocols",           Vec([])),                                  // empty vec, NOT Void
  ("recipient_window_caps", Vec([])),                            // empty vec, NOT Void
  ("recipients",          Vec([Address(Account(GDUY…RRX))])),        // 1 element
  ("window_cap",          I128(Int128Parts { hi: 0, lo: 150 })),
  ("window_secs",         U64(60)),
]))
```

Note the two address shapes: `assets` holds contract (C…) addresses →
`ScAddress::Contract`, while `recipients` holds account (G…) addresses →
`ScAddress::Account`.

---

## 4. Policy semantics — decision table

### 4.0 Pre-decision authentication and snapshot pipeline (`__check_auth`)

Before any policy gate or classification rule is evaluated, `__check_auth` executes a strict 3-step authentication sequence:

1. **Agent key registration check:** `DataKey::AgentPubkey` must exist in instance storage (set during `initialize`). If missing, `__check_auth` returns contract error `Error::NotInitialized` (code #3). Crucially, this check precedes cryptographic verification, so an uninitialized account returns `NotInitialized` even when provided arbitrary or invalid signature bytes.
2. **Ed25519 signature verification:** `env.crypto().ed25519_verify(&agent, &signature_payload, &signatures)`. If verification fails (wrong signer key or corrupted signature bytes), the host crypto function traps the execution frame (`InvokeError::Abort`). Crucially, this host trap occurs before policy snapshot loading, so an unauthorized or wrong-key signature aborts the frame immediately and never proceeds to return `Error::NoPolicy` or leak whether a policy is installed.
3. **Policy snapshot loading:** `AuthSnapshot::load(&env)`. If `DataKey::Policy` is missing (never set or revoked), `__check_auth` returns contract error `Error::NoPolicy` (code #12).

This 1→2→3 ordering is a stated security guarantee, not an implementation detail: see
§10.2 for the guarantee, the named tests that pin it, and the refactor warning that goes with
it.

Once authentication succeeds and the policy snapshot is loaded, the decision table below is evaluated over every auth context:

Before any account gate or context classification, `decide` checks the authorization's context
count. More than `MAX_AUTH_CONTEXTS = 64` returns one aggregate `TooManyAuthContexts` block;
exactly 64 continues through the ordinary gates and per-context rules. The aggregate rejection does
not prune or stage window admissions.

**Empty `auth_contexts` (issue #368).** If `auth_contexts` is empty (`len == 0`), `__check_auth`
still enforces the §4.0 pre-decision pipeline fail-closed (`NotInitialized` if no `AgentPubkey`,
host trap on bad `ed25519_verify`, `NoPolicy` if no `Policy` is installed). Once a policy is
installed and the signature verifies, `decide` returns an empty verdict list (vacuously allowed —
zero blocking verdicts, zero spend/call admissions) and `__check_auth` returns `Ok(())`. Approving
an empty context list authorizes zero contract invocations and zero host functions, so it grants no
capability and moves no funds. Zero `event_auth_checked` events are emitted because `auth_checked`
is a per-context telemetry record (`1:1` with contexts, carrying `context_index`, `contract`, and
`fn_name`). Pinned by `engine::tests::empty_auth_contexts_yields_vacuously_allowed` and
`integration_tests::empty_auth_contexts_approves_without_emitting_auth_checked`.

Evaluation order inside `__check_auth` (first match wins; all states below are evaluated against
ledger time, which Soroban code cannot forge). The order is stated **once**, here; §5, §5.1,
§6.4 and the README walkthrough reference these row numbers instead of restating them.

| # | Condition | Result |
|---|---|---|
| 0 | authorization contains more than `MAX_AUTH_CONTEXTS` contexts | **Block** (`Reason::TooManyAuthContexts`) before evaluating any context |
| 1 | no `Policy` stored (revoked or never set) | **Block** (`Reason::NoPolicy`) — default deny |
| 2 | `AdminFrozen` is set (admin `freeze`, or agent `self_lock`; §5) | **Block** (`Reason::AdminFrozen`) |
| 3 | dead-man switch enabled AND `LastHeartbeat != 0` AND `now - LastHeartbeat > dms_grace_secs` | **Block** (`Reason::HeartbeatExpired`) — automatic freeze, derived lazily, no background write |
| 4 | `paused` | **Block** (`Reason::Paused`) |
| 5 | `active_from != 0 && now < active_from`, or `active_until != 0 && now > active_until` | **Block** (`Reason::OutsideActiveWindow`) |
| 6 | context is a call to this account's own administrative/self functions (`heartbeat`, `self_lock`) | allow `heartbeat` (§5 state update) or `self_lock` (§5 agent-initiated freeze); any other self-function is blocked (`Reason::SelfFunctionNotAllowed`) |
| 7 | per-context classification (§6) applies all allowlist / cap / window rules | allow or **Block** (`Reason::AssetNotAllowed`, `Reason::RecipientNotAllowed`, `Reason::PerTxCapExceeded`, `Reason::WindowCapExceeded`, `Reason::ProtocolNotAllowed`, `Reason::FunctionNotAllowed`, `Reason::UnknownContract`) |

Three §7.1 variants are deliberately outside this decision table, and their absence is
by design rather than drift: `Unauthorized` (code 1) is reserved and never emitted — a bad
agent signature is a host `ed25519_verify` trap, not a returned error (§4.0 step 2, §7.1);
`AlreadyInitialized` (code 2) is the one-shot `initialize` guard and never arises while
authorizing a call; and `DecisionInvariantViolation` (code 31) is an internal engine
consistency guard, not a policy outcome. `scripts/check-spec-coverage.sh` reads this
paragraph as their semantic documentation.

**Machine-readable twin: [`decision-table.json`](decision-table.json).** The table above is
rendered from it (one JSON row per line, verbatim), and it also records which `Error` variants the
engine can actually return for each row and which test pins each one. `tests/decision_table.rs`
fails `cargo test` — and therefore CI — if this table, the JSON, the `README` walkthrough, the
`Error` enum, and the engine's branches disagree. Edit a decision row in `decision-table.json`
first, then paste the rendered line back into the table above; never edit only the SPEC side.
Where this table and the engine still disagree — SPEC row 7 names `Reason::AssetNotAllowed`, which
the v1 engine never emits — the JSON records the engine's behavior in its `note` and points at the
audit (see [`docs/scenario-matrix.md`](docs/scenario-matrix.md) findings F-2/F-3); correcting this
prose is a semantics call for a maintainer, not a doc-generation side effect.

Note the dead-man auto-freeze (`#3`) applies even to `heartbeat` from the registered key: a
heartbeat arriving after the grace window expired cannot revive the account — revival is the
admin's `unfreeze` (§7). This is the precise freeze/reversal boundary. The dead-man gate is evaluated against the pre-transaction heartbeat for every context in the transaction, including the heartbeat self-call.

**One pause flag, two entry points (issues #289/#290).** Rule #4 reads `paused` from the
stored `PolicyConfig` — there is no second pause flag anywhere in storage. The flag can be
flipped two ways: an admin `set_policy` carrying `paused: true|false` (a policy edit; §7 —
the window and the DMS clock are preserved), or the dedicated `pause()` / `resume()` entry
points (§7), which flip the flag **in place** on the stored config without rewriting the rest
of the policy, without touching the rolling window, and without touching the DMS clock. The
emergency admin brake remains `AdminFrozen` (rule #2): `freeze` binds even a policyless
account, while `paused` exists only while a policy is installed. The agent's `self_lock`
(§5) sets that same `AdminFrozen` flag through the self-call path.

### 4.1 Gate cost order (measured)

After the row 0 context bound, the decision table's policy gates remain ordered **semantically
first** (policy snapshot → admin freeze / self-lock → dead-man → pause → active window →
classification), not cost-optimized. Benchmarks on the Soroban test environment (see
`benches/denial_path_gas.rs`) show the following CPU instruction costs for a blocked
authorization at each gate:

The fixed context-count check is a constant-time length comparison before the listed gates. On an
oversized batch it returns one aggregate block, so result allocation and event emission do not
scale with the oversized context count.

| Gate | Condition | Approx. Instructions |
|------|-----------|---------------------|
| 1 | `NoPolicy` | ~8,750 |
| 2 | `AdminFrozen` | ~8,750 |
| 3 | `HeartbeatExpired` | ~8,750 |
| 4 | `Paused` | ~8,750 |
| 5 | `OutsideActiveWindow` | ~8,750 |
| 6 | `SelfFunctionNotAllowed` | ~10,600 |
| 7a | `AssetNotAllowed` (unlisted asset) | ~16,300 |
| 7b | `RecipientNotAllowed` | ~17,700 |
| 7c | `PerTxCapExceeded` | ~14,200 |
| 7d | `WindowCapExceeded` | ~14,300 |
| 7e | `ProtocolNotAllowed` | ~8,200 |
| 7f | `FunctionNotAllowed` | ~10,500 |
| 7g | `UnknownContract` | ~11,800 |

For comparison, an **allowed** transfer with window pruning costs ~14,800 instructions, while an allowed transfer without window costs ~17,800 instructions.

**Observation:** The early gates (#1–#5) are consistently the cheapest (~8.7k instructions) because they only check simple boolean/int flags (row 1 short-circuits on the missing policy snapshot before any gate flag is read). The classification gates (#7a–#7g) are more expensive because they require parsing the auth context, looking up allowlists, and evaluating caps. The semantic ordering therefore *accidentally* aligns with cost ordering: the cheapest gates run first. Reordering for cost would not yield meaningful savings and would weaken the semantic clarity of the snapshot/freeze/reversal boundaries (the policy snapshot must remain first because every later gate is defined in terms of it). The delta between semantic and cost-optimal ordering is immaterial (<2x on the fast path).

### 4.2 Admin freeze and policy pause

`AdminFrozen` and `PolicyConfig.paused` are independent controls stored separately; changing one
does not change the other. When a policy is installed, both deny the account's `__check_auth`
authorization contexts (including agent heartbeat authorization), but they have different
activation, reversal, and state effects. Neither flag disables the admin-authorized management
entry points.

| Topic | `AdminFrozen` | `PolicyConfig.paused` |
|---|---|---|
| Activation | Admin calls `freeze()`, which sets the persistent `AdminFrozen` flag. | Admin calls `set_policy()` with the complete policy and `paused: true`. |
| What it blocks | The first decision gate rejects each authorization context with `AdminFrozen`, including heartbeat authorization. | The policy gate rejects each authorization context with `Paused`, including heartbeat authorization. |
| Reversal | Admin calls `unfreeze()`, which clears `AdminFrozen`. It also sets `LastHeartbeat = now`. | Admin calls `set_policy()` again with the complete policy and `paused: false`. |
| Side effects | `freeze()` changes no persistent state besides `AdminFrozen` and emits `EventFrozen`. `unfreeze()` also resets `LastHeartbeat` to now and emits `EventUnfrozen`, re-arming the dead-man clock when its timestamp changes (see §5). | A `set_policy()` that **edits** an installed policy replaces the policy and increments `PolicyRevision`, but leaves the rolling window and the `LastHeartbeat` clock untouched ([issue #289](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/289)): accumulated spend stays counted and a DMS-expired account stays expired. A **first** install (no policy stored, including an install after `revoke_policy`) seeds an empty window and stamps `LastHeartbeat = now`. Both emit `policy_set`, and both apply even when only `paused` was intended to change. The explicit, admin-attested budget reset is `reset_window()` (§7). |
| Incident-response use | Use `freeze()` for an immediate administrative halt when the installed policy and spend window should remain unchanged. Plan for `unfreeze()` to re-arm the dead-man clock. | Use `set_policy()` when intentionally replacing policy as well as changing pause state; do not treat it as a pause-only operation. It does **not** refund accumulated window spend or restart the dead-man grace — an edit preserves both (issue #289); only a `revoke_policy` → `set_policy` cycle, which is a first install, starts from a fresh window and a fresh grace. For a pause-only change prefer `pause()`/`resume()` (§7), which flip the flag in place. |

The controls are not interchangeable: clearing one does not clear the other, and the remaining
gate can continue to deny authorization.

---

## 5. Dead-man switch — precise definition

- **Purpose:** if the agent stops operating (lost key, dead process, operator disappearance),
  the account must not remain spendable forever. It guards against *silence*; it does not guard
  against a live attacker who keeps heartbeating (spend caps do that — see threat model §10).
- **Heartbeat:** `heartbeat()` — callable only by the registered agent key (enforced because the
  function does `require_auth` on the account itself, so it routes through `__check_auth`, which
  verifies the agent's signature, and then records `LastHeartbeat = now`). No fund movement, no
  window accounting.
- **Redundant heartbeats are skipped (gas optimization).** A heartbeat that arrives in the same
  ledger second as the previous one (`now == LastHeartbeat`) is a true no-op: no persistent write,
  no TTL extension, and no `heartbeat` event. The stored value is already `now`, and the first
  heartbeat of that second already extended the entry's TTL, so the duplicate carries no new
  information and only burns fees. Distinct-second heartbeats (the normal case) always write and
  emit. Measured: see `redundant_same_second_heartbeat_is_a_measured_no_op` (CPU instruction delta
  between a fresh and a redundant heartbeat).
- **Grace:** `dms_grace_secs` in the policy (0 disables). Recommended default on testnet proofs:
  small (e.g. 60s) so the freeze is observable; production guidance ≥ several days.
- **Freeze mechanism:** automatic and *lazy*. There is no stored "auto-frozen" flag for the enforcement itself — rule #3 (§4)
  derives it from `LastHeartbeat` and ledger time on every authorization, so the account is
  frozen the moment the grace elapses, with zero transactions and zero background writes
  required, and can never be "unfrozen by time passing."
- **Freeze visibility / Telemetry:** `refresh_deadman()` (permissionless). Because the freeze is lazy, it natively produces no on-chain event. This helper explicitly records `AutoFrozenAt` and emits a `dms_auto_frozen` event if the grace has elapsed. It does not weaken the freeze semantics: the authorization path still derives the decision lazily regardless of this flag (rule #3). It is permissionless because it only records an already-true fact (the account is already frozen).
- **Manual freeze:** `freeze()` (admin) sets `AdminFrozen = true` — immediate, and blocks even a
  live, heartbeating agent.
- **Agent-initiated self-lock (issue #306):** `self_lock()` is a fixed §6.1 self-call that sets
  the same `AdminFrozen` flag through the account's own authorization path. It exists for the
  case `freeze()` cannot cover — the admin key is on another machine, in another org, or lost —
  and lets a runaway agent stop its own spending. It is deliberately a **capability reduction**:
  the agent can only *add* the lock (no funds move, no policy change, no key change), it cannot
  clear it, and revival is the admin's `unfreeze`. A compromised agent that calls `self_lock`
  locks itself out; that is an availability outcome, not a fund-safety one. Like any
  authorization, it is subject to rows 1–5 of §4: it cannot lock an account whose grace already
  expired or whose active window has passed, but in those states the account is already blocked
  for every call, so no spend can slip through. Emits a dedicated `self_locked` event (§9).
- **Reversal path (explicit):** `unfreeze()` (admin only) clears `AdminFrozen` **and** sets
  `LastHeartbeat = now`. The admin's signature is the liveness attestation that revives the
  account; a subsequently-heartbeating agent keeps it alive from there. Admin freeze and
  heartbeat-expiry are separate conditions; `unfreeze` clears the former, rule #3 keeps
  evaluating the latter.
- **Recorded decision (dual semantics kept, event enriched).** `unfreeze` performs two distinct
  jobs in one call — the admin brake release and the liveness attestation — and this is
  intentional: when the DMS grace had already elapsed, an operator unfreezing an admin-frozen
  account silently re-arms the liveness clock on the admin's authority. Splitting the call into
  `unfreeze` plus an explicit heartbeat-equivalent was considered and rejected: it changes the
  deployed ABI, complicates the reversal runbook (a two-call sequence risks the operator issuing
  only the brake release and leaving the account DMS-frozen — the worst possible post-reversal
  state), and buys no additional safety since the semantics below are already auditable.
  Rationale: deployed ABI stability matters more than purity, so the semantics stay and the
  behavior is made louder:
  - **Event:** `event_unfrozen` data gains `rearmed_dms: bool` — `true` when the call changed
    `LastHeartbeat` (the DMS clock was re-armed; the typical DMS-expired reversal), `false` when
    `LastHeartbeat` already equaled `now` (DMS fresh; only the brake was released). Telemetry
    (SDK/dashboard) can therefore surface exactly when an admin action extended the grace window.
  - **Docs:** the README freeze/unfreeze section and
    `docs/functions/freeze-unfreeze.md` state the re-arm behavior explicitly, so an operator
    cannot be surprised by it.
  - **Tests:** both paths are asserted — `dead_man_switch_freeze_and_admin_reversal` covers the
    DMS-expired unfreeze (`rearmed_dms: true`) and
    `unfreeze_while_dms_fresh_emits_rearmed_dms_false` covers the DMS-fresh unfreeze
    (`rearmed_dms: false`).
  - **No API change:** `unfreeze`'s signature, storage writes, and authorization are unchanged;
    this is purely additive event data (see §9).
- **Executable specification.** `dms_timeline_edge_matrix` (`src/integration_tests.rs`) is the
  table-driven walk of rule #3 and is normative for its edges: the first install arms the clock at `LastHeartbeat = now` (a later policy edit leaves the window and the clock untouched — issues #289/#290; `reset_window`/`unfreeze` are the explicit levers), the 80% warn band is reached while spend is still admissible (`> grace`,
  not `>= grace`), expiry blocks the transfer *and* the heartbeat, a blocked heartbeat leaves the
  clock untouched, and `unfreeze` re-arms it so the new window expires on its own terms. It also
  pins the two degenerate encodings: `dms_grace_secs == 0` (switch disabled — no amount of silence
  expires the account, `dms_health` returns `Ok` without consulting the clock) and
  `LastHeartbeat == 0` (never armed — rule #3's `!= 0` clause means the gate can never fire on the
  sentinel, while `dms_health` reports `Expired`; a first heartbeat replaces the sentinel and the
  grace binds from then on). Read that asymmetry as intended: the gate defaults to *not* freezing an
  account it holds no attestation for, and the advisory view is where the missing attestation is
  surfaced. Measured: see `dms_timeline_edge_matrix` (scenario B).

### 5.1 Reversal boundaries — which gate is cleared by what

The guard enforces several account-level and per-context gates (§4). When an account becomes blocked, the reversal path depends strictly on which gate fired:

| Gate / Reason | Cleared by `unfreeze`? | Cleared by `set_policy`? | Cleared by time / neither? |
|---|---|---|---|
| **No policy** (`NoPolicy`, rule #1) | **No** | **Yes** (installs a valid policy) | No |
| **Admin freeze / agent self-lock** (`AdminFrozen`, rule #2) | **Yes** (`AdminFrozen = false`) | **No** (leaves `AdminFrozen` unchanged) | No |
| **Dead-man switch** (`HeartbeatExpired`, rule #3) | **Yes** (stamps `LastHeartbeat = now`) | **Only on first install** (`set_policy` stamps `LastHeartbeat = now` and starts fresh grace when no policy is stored — including after `revoke_policy`; a policy *edit* leaves the clock untouched, issue #289) | No (time progression can never unfreeze silence) |
| **Paused** (`Paused`, rule #4) | **No** | **Yes** (installs a policy with `paused: false`; or call `resume()` (§7), which flips the flag in place without touching the window) | No |
| **Outside active window** (`OutsideActiveWindow`, rule #5) | **No** | **Yes** (installs a policy with renewed `active_until` or `0`) | Before `active_from`: cleared naturally when ledger time advances into `[active_from, active_until]`. After `active_until`: **neither** time nor `unfreeze` can clear it; only `set_policy` revives the account. |
| **Window cap exceeded** (`WindowCapExceeded`, rule #7d) | **No** | **Only explicitly** — `set_policy` preserves the window across edits (issue #289); the admin-attested zeroing is `reset_window()` (§7) | **Yes** (rolling window entries expire naturally as time advances past `window_secs`) |
| **Context classification rules** (unlisted asset/recipient, per-tx cap, protocol/function) | **No** | **Yes** (if policy configuration updates allowlists or caps) | No |

**Key asymmetry — dead-man switch vs. active window:**
An operator who observes an account blocked after inactivity might expect `unfreeze` to restore operation in all cases. The two freeze mechanisms look symmetric from the outside and are not:
- `unfreeze()` performs only two state transitions: it sets `AdminFrozen = false` and `LastHeartbeat = now`. It never mutates `PolicyConfig`.
- When an account passes `active_until`, it is blocked at gate #5 (`OutsideActiveWindow`). Because gate #5 is an account-level check evaluated before per-context classification, it blocks **all** contexts — including the `heartbeat` self-call.
- Calling `unfreeze()` does not advance `active_until`. The account remains blocked (`outside_active_window`), and even the agent's heartbeat cannot be executed.
- Only an administrator calling `set_policy` with a renewed active window (`active_until >= now` or `active_until = 0`) can revive an account whose active window has expired.

### 5.2 When two transaction-level gates fire at once (issue #426)

§5 and §5.1 describe each gate's reversal path on its own. The **combinations are not derivable
from either section**, and they are the case an operator actually meets: `HeartbeatExpired`
(rule 2) and `OutsideActiveWindow` (rule 5) are independent conditions — an agent that went
silent *and* an account whose declared activity window has closed are both true of the same
account at the same instant — and `unfreeze` clears exactly one of them.

**The order the engine reports reasons in.** Inside `decide()` (`src/engine.rs`), the §4 row 0
`MAX_AUTH_CONTEXTS` bound is tested first and returns a single aggregate verdict before anything
else is evaluated, so it never appears as one of the combinations below. Among the account-state
gates, `state.admin_frozen` is checked first and returns for every context; the remaining three
transaction-level gates are then tested in a single `if / else if / else if` chain —
dead-man grace, then `paused`, then the active window — and the **first** gate that matches
becomes the only reason returned, for every context in the transaction. So:

- `admin_frozen` outranks everything else the engine evaluates;
- `heartbeat_expired` outranks `paused` and `outside_active_window`;
- `paused` outranks `outside_active_window`.

This matches §4's row numbering for rules 2, 4 and 5. It says nothing about rule 3
(`no_policy`): `decide()` reads the freeze flag before the policy load, so `admin_frozen`
outranks a revoked policy, and [finding F-1](docs/scenario-matrix.md#f-1-rule-order-adminfrozen-precedes-no_policy-and-is-unpinned)
tracks that the combination is still unasserted. It is out of scope here; on the
`__check_auth` path a missing policy is rejected by the snapshot load (§4.0 step 3) before
`decide()` runs at all.

Because only one reason surfaces, the reason an operator sees is **not** a list of what is
wrong with the account — it is the first of possibly several bindings. Reversal has to be read
off the combination, not off the reason:

| Gates true at once | Reason reported | `unfreeze` clears | `set_policy` clears | Trap when only one half is applied |
|---|---|---|---|---|
| dead-man + active window | `heartbeat_expired` | the dead-man leg only | both legs (renewed window **and** `LastHeartbeat = now`) — only via `revoke_policy` → `set_policy`, since a first install stamps `LastHeartbeat` and an edit does not (issue #289); `unfreeze` + an edit also covers both | `unfreeze` alone leaves the account blocked, now reporting `outside_active_window` |
| admin freeze + dead-man | `admin_frozen` | both legs (`unfreeze` clears `AdminFrozen` **and** stamps `LastHeartbeat`) | neither (an edit preserves the clock; `revoke_policy` → `set_policy` re-arms it) | `set_policy` alone leaves it reporting `admin_frozen`; `unfreeze` is the call that ends this pair |
| admin freeze + active window | `admin_frozen` | the freeze leg only | the window leg (an edit moves `active_until` and preserves the dead-man clock) | `unfreeze` alone leaves it reporting `outside_active_window`; `set_policy` alone leaves `admin_frozen` |
| `paused` + active window | `paused` | neither (`unfreeze` never mutates `PolicyConfig`) | both, in one call (`paused: false` + renewed window) | `unfreeze` changes nothing observable: the account still reports `paused` |
| dead-man + `paused` | `heartbeat_expired` | the dead-man leg only | the `paused` leg only — an edit installs `paused: false` but preserves the expired clock (issue #289) | `set_policy` alone leaves it reporting `heartbeat_expired`; the dead-man leg still needs `unfreeze` |

Two structural facts produce every row above, and both are stated in §5.1 but worth restating
in combination form because they are the trap:

- `unfreeze()` performs exactly two state transitions — `AdminFrozen = false` and
  `LastHeartbeat = now`. It cannot touch `paused`, `active_from`, or `active_until`, because
  those live in `PolicyConfig` and it never writes one.
- `set_policy()` writes the whole `PolicyConfig` but, on an **edit**, preserves both the window
  and `LastHeartbeat` (`src/lib.rs`, `set_policy`, issue #289). It therefore revives an account
  bound by the active window but **not** one bound by the dead-man switch: an expired clock stays
  expired through an edit, and the reversal path for expiry remains `unfreeze` (§5.1). Only a
  first install — no policy stored, including an install after `revoke_policy` — seeds an empty
  window and stamps `LastHeartbeat = now`; see §7.

Pinned by `heartbeat_expiry_and_active_window_both_firing_reports_heartbeat_expired`
(`src/engine.rs`), which walks the first row in both directions: with a stale `LastHeartbeat`
and `now < active_from`, a `[transfer, heartbeat]` batch reports `HeartbeatExpired` for **both**
contexts (so the agent cannot even record a heartbeat to escape, §5); applying only the
`unfreeze` half (`LastHeartbeat = now`) leaves the same batch blocked, now reporting
`OutsideActiveWindow`; applying the `set_policy` half (window bounds opened) admits it. Both
blocked rounds leave the window ledger untouched (§4 all-or-nothing); only the third round, where
every context passes, spends the transfer's amount.

The on-chain half is pinned by `unfreeze_does_not_clear_outside_active_window_until_set_policy`
(`src/integration_tests.rs`): with `active_until` in the past, a transfer *and* a `heartbeat` are
both refused, `unfreeze` leaves both refused, and only `set_policy` with a renewed `active_until`
revives the account — rows two and three of the table above, run through the real host auth flow.

**Operational reading.** Facing `outside_active_window` after a successful `unfreeze` is not a
bug and not a second incident: it is the second gate becoming visible for the first time. The
incident runbook is therefore two checks, not one — `status()` reports `paused`,
`outside_active_window` and `window_remaining`, and `dms_health()` reports the heartbeat leg —
and an account whose reversal needs both must be given both `set_policy` (window bounds) and,
if the freeze flag was involved, `unfreeze`. Cross-reference the operator column of
[`docs/reason-glossary.md`](docs/reason-glossary.md) for the per-reason remediation, the
incident variant of [`docs/key-rotation.md`](docs/key-rotation.md#incident-variant-suspected-agent-key-leak)
for the runbook that sequences those calls against a live incident, and
[`docs/functions/freeze-unfreeze.md`](docs/functions/freeze-unfreeze.md) for the `rearmed_dms`
telemetry that distinguishes the two halves of an `unfreeze`. What each rejection looks like on
the operator's own interfaces — RPC diagnostics, Horizon, the CLI — is mapped in
[docs/functions/check-auth.md](docs/functions/check-auth.md#what-an-operator-sees-when-this-rejects-issue-425).

### 5.3 Clock basis for the grace — timestamp, not ledger sequence (issue #341)

Rule #2 compares `dms_grace_secs` against `env.ledger().timestamp()`. Ledger **sequence** is the
quantity the host orders by and contract code can forge neither, so this section records why the
timestamp basis is kept, what each basis does under the failure modes that matter, and what a
future switch would cost.

| Condition | Timestamp basis (current) | Ledger-sequence basis (rejected) |
|---|---|---|
| **Missed close** (one or more ledgers skipped) | Close time advances to real time on the next close, so the grace can elapse across the gap: the account freezes even though the agent could not have submitted a heartbeat. Fail-closed. | Sequence does not advance across the gap, so the grace pauses. The account stays live through the outage. Fail-open. |
| **Long close / slow cadence** | Grace is fixed in wall-clock time, independent of how often ledgers close. Predictable for operators. | A grace expressed in ledgers stretches in wall-clock terms when closes are slow; the same configured value means different real durations on different networks. |
| **Network partition from the agent's perspective** (the network keeps closing; the agent cannot reach it) | Grace elapses and the account freezes. This is the intended meaning of silence. | Ledgers keep closing, so the grace also elapses. No practical difference. |
| **Operator misconfiguration of the grace value** | Seconds are the policy model's native unit (`window_secs`, `active_from`/`active_until`), so a value is readable and comparable at a glance. `MAX_DMS_GRACE_SECS` rejects nonsense above ~10 years. | Requires cadence arithmetic (≈5 s/ledger). A small value is catastrophic in a way seconds are not: a dozen ledgers of grace freezes the account on a single missed close. The existing `MAX_DMS_GRACE_SECS` bound would also no longer be the right unit. |

**Recorded decision: keep the timestamp basis.** Both bases fail under some condition; the choice
is which way to fail. The dead-man switch exists to bound *silence*, and wall-clock silence is the
threat model: a network outage in which the agent cannot transact is, for the account's users,
indistinguishable from a dead agent, and freezing is the safe answer (the admin `unfreeze` path
already exists and is documented in §5.1). A sequence basis would let downtime silently extend
availability, which is the wrong default for a spend guard. The secondary reasons are structural:

- **One clock in the policy model.** `window_secs`, `active_from`, `active_until`, `status()`'s
  `now`/`last_heartbeat`/`heartbeat_expires_at`, `status_at(as_of)`, and the `heartbeat` event's
  `expires_at` are all unix seconds. A sequence-based DMS would introduce a second clock and make
  `status_at` unable to project the DMS gate without a new ledger-sequence parameter.
- **Storage and events stay intelligible.** `LastHeartbeat` holds a unix timestamp (an
  `Option<u64>` whose `Some` value is the timestamp, per §3) and the
  heartbeat event records `at + dms_grace_secs` as a deadline. A sequence basis would change the
  meaning of both fields, and a bare `u64` could no longer be interpreted without knowing which
  basis wrote it.
- **Validation remains in the same unit as the rest of the policy.** `dms_grace_secs` shares
  `MAX_WINDOW_SECS`; a sequence basis would need a new bound and a new name.

**If it ever changes, the migration cost is a format-version change, not a field edit.** A switch
would add a distinct storage key (for example `LastHeartbeatLedger`) rather than reinterpreting
`LastHeartbeat`, because an existing timestamp and a ledger sequence are both `u64` and
indistinguishable; it would change the meaning of `PolicyConfig.dms_grace_secs` (a breaking
semantic change, so `POLICY_FORMAT_VERSION` bumps per §7.4), the `heartbeat` event payload, the
`status` fields, and every SDK/dashboard projection. Doing it in place without a version would
silently reinterpret live state — the exact failure the §7.4 version exists to prevent. **This
decision closes the clock-basis question for v1; it does not close the dead-man design.** The
remaining dead-man items (multi-key liveness, heartbeat delegation, and richer telemetry) are
unchanged and tracked separately.

**Interaction with `window_secs` if the two bases diverge.** Today both use the same clock, so a
heartbeat and a rolling-window prune agree on "now". If a future change moved only the DMS to
ledger sequence, the two would advance independently: a slow-close period would age the spend
window at a different rate than the DMS grace, and an account could be admissible for spending
while its liveness clock says expired (or vice versa). Any such change must move both or
explicitly document the split; this section records that keeping them on one clock is the
reason the question is closed in favor of the timestamp.

---

## 6. Per-context classification and rule application

Each `Context` in `auth_contexts` is classified independently; every context must pass or the
whole authorization fails (`__check_auth` returns an error → transaction rejected).

Before classification, the engine enforces the fixed `MAX_AUTH_CONTEXTS = 64` bound. It is not
operator-configurable: auth contexts are transaction input, not policy configuration, and adding a
policy field would expand the policy wire/storage API. Exactly 64 contexts are evaluated normally;
65 or more return the single aggregate reason `TooManyAuthContexts` without parsing any context,
pruning the rolling window, or staging a `SpendEntry`. The aggregate `auth_checked` event uses
`context_index = 0`. This is fail-closed and cannot commit a prefix of an oversized batch.

The value targets router workloads rather than matching policy-list sizes. A single transfer or
multihop swap commonly needs only a handful of SAC transfer contexts; 64 allows a large router batch
of 64 transfers while bounding more adversarial batches. At the existing maximum recipient-list
cardinalities, the measured worst-case decision path is 338,315 CPU instructions per context
(§6.2); 64 such contexts project to 21,652,160 instructions, about 22% of the documented
100,000,000 per-invocation CPU budget. At most 64 global `SpendEntry` admissions and 64 staged
per-recipient entries can be held for one authorization. Existing per-policy list limits remain 256
and bound each context's scans independently; they are not authorization-context limits.

### 6.0 Worked example: a mixed multi-context batch (issue #423)

A transaction can present several contexts at once — an allowlisted protocol call bundled with a
capped transfer, or two transfers against different assets. Row-for-row the rule is stated in
§6 and §4; what an auditor actually needs is the *partially-valid* case worked through, because
that is the case where all-or-nothing is either real or a slogan. The batch below is the fixture
of `mixed_multi_context_batch_reports_the_first_failing_context` (`src/engine.rs`): the numbers
are the test's, so every claim in this section is checkable by running it.

Policy (the test's `base_policy`, with the §4 transaction-level gates 1–5 all clear):

| field | value |
|---|---|
| `assets` | `[addr(1)]` — one allowlisted SAC, called `A` below |
| `recipients` | `[addr(2)]` — `R1`; `addr(4)` (`R2`) is deliberately **not** listed |
| `protocols` | `[addr(3)]` with `fns = None` — `P`, any function |
| `per_tx_cap` | 80 |
| `window_secs` / `window_cap` | 86,400 / 100 |
| `now` | 1,000 |

Auth contexts, in the order the host supplies them:

| index | context | gate it reaches | verdict |
|---|---|---|---|
| 0 | `P::deposit` | §6.3 protocol allowlist — contract listed, `fns = None` | **Allowed** |
| 1 | `A.transfer(guard → R1, 40)` | §6.2 in order: recipient allowed, `40 ≤ 80` per-tx, `0 + 40 ≤ 100` window | **Allowed**, 40 staged |
| 2 | `A.transfer(guard → R1, 90)` | §6.2 rule 3 — `90 > per_tx_cap 80` | **Blocked**, `per_tx_cap_exceeded` (22) |

What each observer is left with:

- **Authorization.** `decide()` returns exactly one verdict per context —
  `[Allowed, Allowed, Blocked(PerTxCapExceeded)]` — and `__check_auth` returns
  `Err(PerTxCapExceeded)`, code 22 (§7.1). One blocked context is enough; the two admissible
  ones authorize nothing.
- **The window records no admission at all.** Context 1 cleared its caps and staged its 40, but
  the commit is guarded by `all_passed` in `decide()`, so the staged entry is dropped and
  `Window` is never written. The same guard covers the per-recipient ledger and the
  protocol-call counter, and it drops the up-front `ledger.prune(now, window_secs)` too: a
  denied batch leaves no spend accounting, no merged entries, and no `event_window_merged`
  records (§9). Even the read-side TTL refresh that `AuthSnapshot::load` performs rolls back
  with the failed transaction (§9.5). The test closes the loop: a later
  `A.transfer(guard → R1, 70)` is **Allowed** and takes the total to 70, whereas a committed 40
  would have made `40 + 70 = 110 > 100` a `window_cap_exceeded`. The rejected batch spent
  neither funds nor budget, so `status().window_remaining` is unchanged by an attack that only
  generates denials (threat model §10).
- **Events.** One `auth_checked` per context, including `allowed` for indices 0 and 1, each
  stamped with its own `context_index` and the live `revision` (§9). The event stream is where
  the *whole* batch is visible: it shows the two admissible contexts that storage did not
  commit and the third that failed. Subject to the rollback caveat of §9 — the transaction
  failed, so these events exist only in simulation diagnostics and dual-stream telemetry, never
  as committed ledger events (see also [docs/functions/check-auth.md](docs/functions/check-auth.md)).

**Which reason is reported when several contexts fail.** `__check_auth` reports the first
blocked verdict **in auth-context iteration order** — the order the host handed over — not a
"most severe" reason and not one chosen per call kind. Reordering the batch so that the
recipient violation comes first (`[A.transfer(guard → R2, 5), A.transfer(guard → R1, 90)]`)
reports `recipient_not_allowed` (21) even though `per_tx_cap_exceeded` is equally true of the
other context; putting those two contexts back in the other order reports
`per_tx_cap_exceeded` again. Both directions are asserted by the same test.

That is acceptable, because the returned reason answers "why was this authorization refused"
rather than "what is wrong with this transaction":

- Any blocked context refuses the whole transaction, so whichever one is reported is a true and
  sufficient cause. There is no partial approval that could be misattributed.
- Nothing is lost. Every context is still evaluated (the loop does not short-circuit; the only
  batch that is not walked at all is the oversized one, which §4 row 0 refuses as a single
  aggregate verdict before parsing), so every
  denial emits its own `auth_checked` event with its own `context_index`, and an operator
  holding the diagnostics can enumerate *all* failing contexts instead of trusting one code.
- It is deterministic. The order is part of the transaction before the call, and the whole
  invocation is inside the signature digest (§10.1), so two observers of the same transaction
  see the same reason.
- Short-circuiting at the first failure was the rejected alternative: it would make the emitted
  event stream depend on where the first failure happened to fall — weakening exactly the audit
  trail above — while buying no cost, since the bounded worst case (§6.2's measured figure) is
  charged for the full loop either way.

Cross-reference: [`docs/scenario-matrix.md`](docs/scenario-matrix.md) tabulates the
single-context cells (the §4 rules 1–7 against the six call kinds) that this example composes,
and §6.4's
boundary paragraph explains why contexts refused by the transaction-level gates never reach
this per-context loop at all. When two of those transaction-level gates fire together the
reported reason is decided by §5.2, not by this section.

### 6.1 Self-calls

Context whose `contract == env.current_contract_address()`. Allowed function set:
`heartbeat` and `self_lock` (§5). Any other self-function is blocked
(`SelfFunctionNotAllowed`). No spend rules apply; `self_lock` only sets `AdminFrozen` and moves
no funds, which is why it is safe to admit inside the policy engine at all.

### 6.2 Asset (SAC) calls — fully enforced

`contract ∈ policy.assets` **and** `fn_name ∈ { "transfer", "transfer_from" }`. These are the
calls whose semantics and arguments are known:

- `transfer` args: `(from, to, amount)` — the account is `from`; recipient = args[1], amount = args[2].
- `transfer_from` args: `(from, spender, to, amount)` — the account is `from`; recipient = args[2], amount = args[3].

**Asset identity is load-bearing for the per-tx cap.** The classified asset is what resolves the
effective per-tx cap in rule 3 below (a matching `asset_caps` entry, otherwise the global
`per_tx_cap`), so two listed assets with different overrides decide the same amount differently.
The rolling window (rule 4) remains a unit-less sum across every asset in `assets`: per-asset caps
are a per-transaction limit only, and operators who need per-asset *window* isolation should use
separate policies. (Removing `ParsedCall::AssetTransfer.asset` would therefore change behaviour;
issue #294 kept it and pinned that with `asset_identity_selects_the_per_asset_cap`.)

**Exact arity required; extra args deny -- we do not partially parse.** A call whose argument list does not match the SAC schema exactly (`transfer` = 3, `transfer_from` = 4) is rejected with `UnknownContract` and never reaches the cap/allowlist evaluation. We only enforce what we fully understand; a context carrying extra trailing values is treated as a call we cannot reason about (conservative default-deny).

Rules applied (in order; the denylist is checked before the allowlist/escape hatch):

1. **Recipient denylist:** if `recipient ∈ policy.blocked_recipients`, block
   `RecipientBlocked`. The denylist wins over both the allowlist and
   `allow_any_recipient`.
2. **Recipient allowlist:** if `allow_any_recipient == false`, `recipient ∈ policy.recipients`
   or block `RecipientNotAllowed`.
3. **Per-tx cap:** resolve the effective per-tx cap for the transfer's asset — the matching
   `asset_caps` entry's `per_tx_cap` when non-zero, otherwise the global `per_tx_cap`. If the
   effective cap is non-zero, `amount <= effective_per_tx_cap` or block `PerTxCapExceeded`.
   The comparison is exclusive-of-blocking (i.e. the cap value itself is permitted:
   `amount == effective_per_tx_cap` is admitted; only `amount > effective_per_tx_cap` is blocked).
4. **Rolling window (§3.1):**
   - Global window: if `window_cap != 0`, prune expired entries, then
     `total + amount <= window_cap` or block `WindowCapExceeded`.
   - Per-recipient window: if `recipient` has an entry in `policy.recipient_window_caps` with
     `cap > 0`, use that cap against the recipient's own rolling ledger; otherwise fall back to
     the global window cap. If the effective cap is exceeded, block `WindowCapExceeded`.
   - On admission, update the global ledger and, when a per-recipient cap applies, the
     recipient's ledger.
5. Amount validity: `amount > 0` or block `InvalidAmount`.

An asset contract listed in `assets` invoked with any other function — in particular the
administrative and custody-altering functions `mint`, `burn`, `clawback`, `set_admin`, `pause`,
and `unpause`, none of which the account should ever call as authorizer — is blocked with the
single dedicated reason `AssetFnNotAllowed` (one code for the whole class, so a compromised agent
probing token custody is one alertable signal rather than several). The same function names on a
contract that is *not* listed in `assets` are never parsed as asset calls and stay `UnknownContract` — an agent cannot silently move balances on an unregistered SAC. This keeps
the "we know what we're enforcing" promise exact.

**Measured worst case: evaluation ≈ 338,315 CPU instructions per context.** Rules 1 and 2 are the only
steps whose cost depends on a policy list length, and §8 caps every recipient list at
`MAX_RECIPIENT_ENTRIES = 256`, so the decision path is bounded by construction. Measured in the
Soroban test environment with both `recipients` and `blocked_recipients` filled to exactly 256
entries and the transfer destination deliberately in **neither** — the configuration that makes
the linear sweeps the dominant term:

| Configuration | Instructions | % of the 100,000,000 per-invocation CPU budget |
|---|---|---|
| `allow_any_recipient = false` — full 2×256 scan, miss on the last element of each | **338,315** | 0.34% |
| `allow_any_recipient = true` — denylist swept, rule 2 skipped | 179,674 | 0.18% |

The escape hatch saves 158,641 instructions by skipping the 256-entry allowlist, which is
precisely what it buys: under the escape hatch the remaining linear work is a single sweep, not
two. Reproduce with `cargo test worst_case_decision_path_measured_cost -- --nocapture`, which
also asserts both figures fit one invocation's budget, or
`cargo run --manifest-path benches/Cargo.toml --bin worst_case_decision_path`. Both drive the
same `testutils` fixtures (`worst_case_transfer_policy` / `worst_case_transfer_target`), so the
table and the assertion cannot drift apart. As elsewhere in §3.1/§4.1 these are test-environment
instruction counts; on-chain cost also carries host overhead, metering, and fee accounting.

This bound covers the *allowlist* worst case only. The rolling window has its own, much larger
one — a single lazy prune of 8192 stale entries — which is measured separately in §3.1 and
tracked in [issue #113](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/113).

### 6.3 Protocol calls — allowlist only (window/pause state still enforced)

`contract ∈ policy.protocols` (each with optional per-function allowlist). `parse_call` checks
`assets` before `protocols`, and §8 rejects a contract listed in **both**, so an asset can never
silently shadow a `ProtocolRule` (including its `fns` allowlist) — issue #296. Allowed calls are
authorized; per-call amount/recipient limits do **not** apply to individual call values because
the arguments of an arbitrary protocol are not interpretable (§2). However, the **count of
protocol calls is fully observable** — the engine loops over contexts and can meter them — so
a rolling-window rate limit on call count (`policy.protocol_calls_per_window`; 0 = disabled)
is enforced: if the cumulative count of protocol contexts within `window_secs` would exceed the
cap, the call is blocked with `ProtocolCallRateExceeded`. This count-based throttling is
defensible v1 enforcement that does not overclaim — it directly addresses runaway loops
(the threat case this project exists to stop) within what the host actually exposes. Functions
not in a rule's `fns` allowlist (when present) are blocked `FunctionNotAllowed`.

### 6.4 Anything else — blocked

A context whose contract is not the account itself, not in `assets`, and not in `protocols`
is blocked (`UnknownContract`). Host-function contract creation contexts (`CreateContractHostFn`
and `CreateContractWithCtorHostFn`) are mapped by `parse_call` to `ParsedCall::CreateContract`
and blocked with `CreateContractNotAllowed` (code 28). The account is **default-deny**: adding
a protocol is an explicit policy act, and contract creation by the agent is disallowed. The
classification rule and the rejected allow-by-default alternatives are recorded in
[ADR-0004](docs/adr/0004-deny-by-default-classification.md).

**Boundary stated exactly:** no-policy (#1), admin freeze / agent self-lock (#2),
dead-man (#3), pause (#4), and active-window (#5) are *transaction-level* gates applied before
classification, so they bind every call the
account makes, SAC or protocol. Spend caps and rolling-window accounting bind SAC asset
transfers only. Recipient allowlists bind SAC asset transfers only. Contract creation is
denied unconditionally.

---

### 6.5 Scenario matrix — decision rows × call kinds

The §4 decision table and the §6 classifications above are two halves of one truth table:
7 decision rows × 6 call kinds (self, asset transfer, asset other-fn, protocol,
create-contract, unknown). That table is written out in full, cell by cell, in
[`docs/scenario-matrix.md`](docs/scenario-matrix.md), together with a **coverage map** that
names the test pinning each cell and enumerates the cells that no test pins yet (currently
the entire `outside_active_window` row, the `AssetOther` and `CreateContract`
classification arms, and most of the transaction-level gates × non-SAC kinds).

Read it before changing anything under §4 or §6: it is the shortest path from "I am
touching this gate" to "which test will catch me", and it is the shortest path from
"is this tested?" to a citation instead of a guess. Note that the two `parse_call`-time
outcomes `CreateContractNotAllowed` and the `AssetOther` → `function_not_allowed` arm are
classified here but are **not** listed in §4 rule 7's inline reason list; §4.1's cost table
does list gate 6 (`SelfFunctionNotAllowed`) but has no row for contract creation.

### 6.6 Admin-rotation errors live outside the per-context path

`propose_admin_rotation` / `confirm_admin_rotation` / `cancel_admin_rotation`
(§7.2) are direct admin entrypoints, not authorizations evaluated by `decide`:
they never produce per-context verdicts and never emit `auth_checked`. Two
errors belong to them alone. `InvalidConfig` is raised when the current admin
proposes itself (a no-op handover that would emit a misleading event trail).
`NoPendingAdmin` is raised when `confirm_admin_rotation` or
`cancel_admin_rotation` runs with no `PendingAdmin` stored. Neither error is
reachable via `check()` pre-flight or `__check_auth` (see the §7.1 mapping);
both fail the transaction frame that raised them, leaving admin, policy, and
revision unchanged.

---

## 7. Public surface — exact signatures and auth placement

Auth placement rule used throughout: **the authority that can change a thing is the authority
named by the change.** Admin (classic or contract address) governs policy and freeze; the
registered agent key (verified through the account's own `__check_auth`) may only heartbeat and
transact within policy. No function moves funds; funds move only through the agent's own
authorized transactions.

`__check_auth` itself enforces the ordering stated in §10.2: the agent's signature is verified
before any policy state is read, so an unverifiable signature never reaches the decision table
below. The single-key choice and the rejected multi-sig / delegated-signer alternatives are
recorded in [ADR-0003](docs/adr/0003-ed25519-single-key-over-multisig-v1.md).

```rust
// ── Lifecycle ─────────────────────────────────────────────────────────────
pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>)
    // require_auth(admin). Exactly once (AlreadyInitialized otherwise). Stores
    // Admin, AgentPubkey, and PolicyVersion = POLICY_FORMAT_VERSION (§7.4); no
    // policy yet -> account is default-deny until set_policy.

### 7.1 Error code ↔ CheckResult variant ↔ reason symbol mapping

To close the CheckResult/Error duality gap, every contract `Error` variant maps 1:1 to a block-reason `Symbol` emitted in `CheckResult::Blocked` and `auth_checked` events. There is no separate `BlockReason` Rust type: `CheckResult::Blocked` carries a `Symbol`, and that symbol is always one of the `Error::reason()` strings in the table below (the exhaustive vocabulary). The table records the complete correspondence, including auth-only or admin-only variants that are unreachable via `check()` pre-flight reads and their rationale.

**Discriminant stability & frozen codes:** Contract error codes (`Error(Contract, #N)`) are permanently frozen on testnet and mainnet (`1..=9` for generic/lifecycle, `10..=19` for account-level gates, and `20..=39` for per-call decisions). The numbers are public ABI, not an implementation detail: raw codes appear in published evidence (`tests/fixtures/README.md`), operator docs, the SDK's `REASON_CODES`, and telemetry, so renumbering any code breaks SDK/telemetry decoders and invalidates published evidence. When introducing a new variant, contributors must adhere to the 'append, never insert' convention — **append at the end of the variant's numeric group; never insert between existing codes** — and execute the end-to-end checklist in [`docs/contributing.md`](docs/contributing.md#how-to-add-a-new-error-variant-end-to-end). Renumbering is only permissible with an explicit version note in this section recording the date, the reason, and the old → new mapping for every consumer, together with the corresponding SDK change.

The rule has three enforcement mechanisms, so a slip is caught rather than reviewed by memory: `tests/abi_snapshot.rs` pins every code/variant/reason triple in the committed `tests/snapshots/abi_snapshot.txt`, `error_code_discriminant_stability_spec_7` in `src/types.rs` asserts each numeric discriminant against this table, and `scripts/check-spec-coverage.sh` (the deny-list coverage check documented in CONTRIBUTING) reports when this enum and the table drift apart.

| Error Code | Error Variant | Reason Symbol (`CheckResult::Blocked`) | Reachable via `check()`? | Rationale for Unreachable Direction |
|---|---|---|---|---|
| 1 | `Unauthorized` | `unauthorized` | No | **Reserved, never emitted** (issue #292): a bad agent signature is rejected by `ed25519_verify`'s host trap (`InvokeError::Abort`) before any policy state is read, and admin ops enforce `require_auth(Admin)` at the host level, so no code path returns #1. `Unauthorized` stays in the ABI error enum (code 1) so the published table and off-chain `REASON_CODES` mappings remain wire-stable. |
| 2 | `AlreadyInitialized` | `already_initialized` | No | Admin lifecycle op: initialize is run once during deployment setup, not a check parameter. |
| 3 | `NotInitialized` | `not_initialized` | Yes | Pre-activation guard check. |
| 4 | `InvalidConfig` | `invalid_config` | No | Admin op: `set_policy` validation error; policies are not passed into `check()`. |
| 5 | `InvalidAmount` | `invalid_amount` | Yes | Checked directly in `check()` input arguments. |
| 6 | `NoPendingAdmin` | `no_pending_admin` | No | Admin op: `confirm_admin_rotation` / `cancel_admin_rotation` with no `PendingAdmin` stored; rotation state is never a `check()` parameter. |
| 10 | `AdminFrozen` | `admin_frozen` | Yes | Account-level gate evaluated in `check()`. |
| 11 | `HeartbeatExpired` | `heartbeat_expired` | Yes | Account-level dead-man switch gate evaluated in `check()`. |
| 12 | `NoPolicy` | `no_policy` | Yes | Account-level gate evaluated in `check()`. |
| 13 | `Paused` | `paused` | Yes | Account-level gate evaluated in `check()`. |
| 14 | `OutsideActiveWindow` | `outside_active_window` | Yes | Account-level gate evaluated in `check()`. |
| 20 | `AssetNotAllowed` | `asset_not_allowed` | Yes | Evaluated in `check()` asset parameter validation. |
| 21 | `RecipientNotAllowed` | `recipient_not_allowed` | Yes | Evaluated in `check()` recipient parameter validation. |
| 22 | `PerTxCapExceeded` | `per_tx_cap_exceeded` | Yes | Evaluated against `check()` amount parameter. |
| 23 | `WindowCapExceeded` | `window_cap_exceeded` | Yes | Evaluated against rolling window ledger in `check()`. |
| 24 | `ProtocolNotAllowed` | `protocol_not_allowed` | No | Auth-path only: non-SAC protocol calls do not use `check()`. |
| 25 | `FunctionNotAllowed` | `function_not_allowed` | No | Auth-path only: restricted functions apply to auth contexts, not `check()`. |
| 32 | `AssetFnNotAllowed` | `asset_fn_not_allowed` | No | Auth-path only: non-transfer functions on listed SAC contracts. |
| 26 | `UnknownContract` | `unknown_contract` | No | Auth-path only: unlisted contracts are encountered in auth contexts. |
| 27 | `SelfFunctionNotAllowed` | `self_function_not_allowed` | No | Auth-path only: self-calls are part of `__check_auth` context dispatch. |
| 28 | `CreateContractNotAllowed` | `create_contract_not_allowed` | No | Auth-path only: contract creation host functions occur in auth contexts. |
| 29 | `RecipientBlocked` | `recipient_blocked` | Yes | Recipient is on the explicit denylist. |
| 30 | `ProtocolCallRateExceeded` | `protocol_call_rate_exceeded` | No | Auth-path only: protocol-call rate limits apply to auth contexts. |
| 31 | `DecisionInvariantViolation` | `decision_invariant_violation` | No | Internal invariant guard: the policy engine returned inconsistent verdict data. |
| 33 | `TooManyAuthContexts` | `too_many_auth_contexts` | No | Auth-path only: more than `MAX_AUTH_CONTEXTS` (64) contexts; classified as one aggregate block before the context loop. |

// ── Policy management (admin only) ────────────────────────────────────────
pub fn set_policy(env: Env, config: PolicyConfig)
    // require_auth(Admin). Validates config (§8). Replaces Policy. The
    // rolling window and the dead-man-switch clock are PRESERVED across
    // edits of an installed policy (issue #289): pausing or tightening a
    // policy no longer hands the agent a fresh budget or a fresh grace
    // period. A first install (no policy stored — including an install
    // after revoke_policy) seeds an empty Window and stamps
    // LastHeartbeat = now (a fresh policy gets full grace). The explicit
    // window zeroing is reset_window (below).
pub fn reset_window(env: Env)
    // require_auth(Admin). Removes the Window entry — the explicit,
    // admin-attested zeroing set_policy no longer performs implicitly
    // (issue #289). Idempotent (an absent/empty window is a no-op that
    // still records the admin action); does not touch Policy,
    // PolicyRevision, or LastHeartbeat. Emits window_reset { by }.
pub fn increase_window_cap(env: Env, new_cap: i128)
    // require_auth(Admin). Raises the installed policy's global window_cap
    // IN PLACE without resetting DataKey::Window or touching LastHeartbeat
    // (issue #349; companion to set_policy / reset_window in issues #289
    // and #305). NoPolicy when no policy is installed. Prunes the loaded
    // window in memory against `now` to compute the live total; rejects
    // with InvalidConfig when `new_cap <= cfg.window_cap` (not an increase,
    // including <= 0), when `new_cap < live_total` (silently setting a cap
    // below current spend would block the account with no recourse), or
    // when the resulting policy violates §8 (e.g. window_secs == 0 or
    // per_tx_cap > new_cap). Increments PolicyRevision and emits
    // window_cap_increased { by, old_cap, new_cap, revision } (§9).
pub fn revoke_policy(env: Env)
    // require_auth(Admin). Removes Policy and Window -> default-deny immediately.
pub fn rotate_agent_key(env: Env, new_pubkey: BytesN<32>)
    // require_auth(Admin). Re-binds AgentPubkey. Admin never gains fund-moving
    // power; it can only replace the key the account will authenticate. For the
    // operational recovery runbook (lost/compromised keys and DMS unfreeze
    // interaction), see docs/key-rotation.md.
pub fn propose_admin_rotation(env: Env, new_admin: Address)
    // require_auth(Admin). Stores PendingAdmin; the current admin stays
    // authoritative until confirmation. Self-proposal -> InvalidConfig.
pub fn confirm_admin_rotation(env: Env)
    // require_auth(PendingAdmin). Only the proposed admin can confirm: the
    // confirmation is proof the new key is live (see §7.2). Sets Admin,
    // clears PendingAdmin; no policy revision bump (policy unchanged).
    // No pending rotation -> NoPendingAdmin.
pub fn cancel_admin_rotation(env: Env)
    // require_auth(Admin). Clears PendingAdmin. No pending rotation ->
    // NoPendingAdmin.
pub fn pause(env: Env)
    // require_auth(Admin). Flips the stored PolicyConfig.paused to true IN
    // PLACE (issue #290): the rolling window, the DMS clock, and every other
    // field are untouched. Idempotent (pausing a paused account is not an
    // error; the event still records the admin action). NoPolicy when no
    // policy is installed. Emits paused { by, revision }; PolicyRevision
    // advances only when the flag actually flips, so same revision <=> same
    // effective policy (§9).
pub fn resume(env: Env)
    // require_auth(Admin). Mirror of pause: sets paused = false in place,
    // again preserving the window — resuming restores admissibility, not
    // budget. Same idempotency/NoPolicy rules. Emits resumed { by, revision }.

// ── Dead-man switch (see §5) ──────────────────────────────────────────────
pub fn heartbeat(env: Env)
    // require_auth(env.current_contract_address()) — i.e., routes through
    // __check_auth, which verifies the registered agent key. Records LastHeartbeat.
    // Blocked when AdminFrozen or grace already expired.
pub fn refresh_deadman(env: Env)
    // permissionless. Explicitly records AutoFrozenAt and emits an event if
    // the grace has elapsed, for telemetry visibility. No effect on enforcement.
pub fn freeze(env: Env)      // require_auth(Admin); sets AdminFrozen = true
pub fn unfreeze(env: Env)    // require_auth(Admin); clears AdminFrozen, LastHeartbeat = now
pub fn self_lock(env: Env)
    // require_auth(current_contract_address()) — routes through __check_auth,
    // which verifies the registered agent key and admits `self_lock` as a fixed
    // §6.1 self-call. Sets AdminFrozen = true (capability reduction only; no
    // funds move) and emits `self_locked`. Only admin `unfreeze` reverses it.
    // Blocked by the §4 account gates like any other authorization.

// ── Read / advisory (no auth; non-confidential state; TTL effects in §9.5) ──
pub fn policy(env: Env) -> Option<PolicyConfig>       // current policy
pub fn policy_version(env: Env) -> u32                // policy-model format version (issue #339);
                                                      // 0 before initialize, never traps
pub fn status(env: Env) -> Status                     // operational snapshot (see Status block below):
                                                      // paused / window_remaining / outside_active_window
                                                      // / admin_frozen / heartbeat_expired / revision
pub fn status_at(env: Env, as_of: u64) -> Status      // same snapshot projected at a supplied unix timestamp
pub fn dms_health(env: Env) -> DmsHealth                  // ok, warn (>=80%), or expired
pub fn validate_policy(env: Env, config: PolicyConfig) -> ValidationOutcome
    // Dry-run §8 validation over the *candidate* `config` (issue #35):
    // `Valid`, or `Invalid(rule)` naming the first failing §8 rule in
    // evaluation order. Read-only preflight so SDKs/dashboards can pinpoint
    // the offending field before submission; the on-chain rejection path is
    // unchanged (`set_policy` still fails with the single `InvalidConfig`
    // code).
pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult
    // Preflight / simulate a transfer (doc alias; ABI frozen as `check`):
    // pure pre-flight replica of the §6.2 decision path: it does not change
    // spend accounting, but a submitted call may refresh TTLs under §9.5.
    // Simulation before signing does not persist those rent bumps.
    //
    // INVARIANT — `check` writes no ledger data. Its in-memory prune and its
    // staged admission are local copies that are discarded before returning:
    // the persisted `Window`, `LastHeartbeat`, and `AdminFrozen` values are
    // byte-identical before and after, and the `status()` snapshot is
    // unchanged apart from ledger time. Agents and SDKs call `check` freely
    // before deciding whether to sign, so persisting a read call's accounting
    // would be a silent side effect on a fund-holding account. Enforced by
    // `check_is_pure_and_writes_nothing_to_storage` (src/integration_tests.rs).
    //
    // Exact synthetic context it constructs and hands to `decide` (one per
    // call; `check_batch` builds one per transfer, in order):
    //   Context::Contract(ContractContext {
    //       contract: asset,                            // the SAC being debited
    //       fn_name:  "transfer",
    //       args:     [ env.current_contract_address(), // SAC `from`,   args[0]
    //                   to,                             // SAC `to`,     args[1]
    //                   amount ],                       // SAC `amount`, args[2]
    //   })
    // i.e. `args = [from, to, amount]` with `from` = `env.current_contract_address()`
    // — byte-for-byte the shape the host hands `__check_auth` for the real
    // transfer, so pre-flight and on-chain authorization score the same context
    // (issue #317). The decision table reads only `args[1]`/`args[2]` today;
    // `args[0]` is pinned for the `from`-is-the-guarded-account validation
    // (issue #10), which must land after this shape is correct.
pub fn check_detailed(env: Env, asset: Address, to: Address, amount: i128) -> CheckDetail
  // Same zero-write pre-flight, with remaining_window and effective cap metrics.
pub fn check_batch(env: Env, asset: Address, transfers: Vec<BatchTransfer>) -> BatchCheckResult
  // Zero-write payment-run pre-flight. Evaluates transfers in order, staging each
  // allowed admission in memory so later items see earlier admissions. Returns one
  // verdict per item and `admissible: false` if any item is blocked.

// ── Enforcement (host-invoked; not callable by anyone) ────────────────────
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;
    fn __check_auth(env, signature_payload: Hash<32>, signatures: BytesN<64>,
                    auth_contexts: Vec<Context>) -> Result<(), Error>;
    // 1. Agent pubkey registered (initialize done) -> Error::NotInitialized (#3) if absent.
    // 2. ed25519_verify(AgentPubkey, signature_payload, signatures) -> host crypto trap (InvokeError::Abort) on bad signature / wrong key.
    // 3. Policy snapshot load (AuthSnapshot::load) -> Error::NoPolicy (#12) if absent / revoked.
    // 4. Decision table §4 + classification §6 over every context.
    // 5. Events (§9) + TTL refreshes (§9.5); spend-accounting writes only on admission.
}
```

**`set_policy` — what a policy edit does to the window and the dead-man clock (issue #289).**
An operator-visible statement of the guarantee, not merely the mechanics. `set_policy` on an
**installed** policy is an *edit*: it replaces `PolicyConfig` and increments `PolicyRevision`,
and it **preserves the rolling window and the dead-man-switch clock**. The accumulated spend
stays counted and a DMS-expired account stays expired, so a routine edit — adding a recipient,
extending the protocol allowlist, changing `per_tx_cap` — never hands the agent a fresh budget
or a fresh grace period. Caps are therefore **continuous across a policy edit**: the cap in
force after an edit is the same cap, measured against the same spend ledger.

Continuity is broken in exactly two admin-attested ways, and an operator should read both as
budget resets rather than as edits:

1. **Editing `window_cap` itself moves the ceiling without resetting the ledger.** The preserved
   running total is re-compared against the new number, so raising `window_cap` (directly, or via
   `increase_window_cap`, §3.1) admits spend the old cap would have blocked; lowering it can
   block an account whose live total already exceeds the new value. The spend history survives;
   the budget does not.
2. **`revoke_policy` → `set_policy` is a first install.** `revoke_policy` removes `Policy`
   *and* `Window`, so the next `set_policy` takes the first-install path: it seeds an empty
   window and stamps `LastHeartbeat = now`. The agent starts with a full budget and full grace.
   Anything that must survive a revoke/reinstall cycle has to be re-asserted by the admin.

Only a first install (no policy stored, including an install after `revoke_policy`) seeds an
empty window and arms the dead-man clock at install time. The explicit, admin-attested zeroing
of the window is `reset_window()` (below), which touches neither the policy, `PolicyRevision`,
nor `LastHeartbeat`, and then only when a fresh budget is actually intended. Whether an edit
*should* reset the window — the behaviour documented here is the resolution of that question —
is tracked in [issue #289](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/289),
with the surrounding semantics in [issue #305](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/305)
and [issue #303](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/303).

`Status` / `CheckResult` / `CheckDetail` / reasons:

**Wire format:** Exact JSON serialization for non-Rust consumers (SDK, dashboard) is documented in [Wire Format](docs/research/wire-format.md) — includes field names, enum tagging convention (`Allowed` bare vs `{"Blocked":"reason"}`), and decoder-breakage warning.

```rust
#[contracttype]
pub struct Status { pub admin_frozen: bool, pub heartbeat_expired: bool,
                   pub last_heartbeat: u64, pub now: u64, pub has_policy: bool,
                   pub policy_revision: u64,
                   pub paused: bool, pub window_remaining: Option<i128>,
                   pub outside_active_window: bool,
                   pub dms_grace_secs: u64,
                   pub heartbeat_expires_at: Option<u64> }
// Operational fields (additive; SDK/dashboard decoders must tolerate new keys):
// - paused: the installed policy's admin kill switch (§3 `PolicyConfig.paused`);
//   false when no policy is installed (default-deny has nothing to pause).
// - window_remaining: global headroom `window_cap - spent` over the *pruned*
//   rolling ledger (expired entries never count) — the same number
//   `check_detailed` reports as `remaining_window` for a recipient without a
//   per-recipient override; None when the global cap is disabled (0), including
//   the no-policy case. Per-recipient override headroom is recipient-targeted
//   and not projected here (use `check_detailed` per recipient).
// - outside_active_window: whether `now` sits outside the policy's active
//   window (`active_from`/`active_until`, both bounds inclusive; §4 account
//   gate) — false with no policy or an unrestricted window (either bound 0).
// - dms_grace_secs: configured dead-man grace in seconds; zero when disabled.
// - heartbeat_expires_at: last_heartbeat + dms_grace_secs, or None when grace
//   is disabled or no heartbeat has been recorded. Enforcement marks the
//   heartbeat expired strictly after this timestamp.

// `status_at(env, as_of)` evaluates `heartbeat_expired`, `now`,
// `outside_active_window`, and window headroom using `as_of`; it does not
// change the existing `status()` signature or mutate spend accounting.

#[contracttype]
pub enum DmsHealthStatus { Ok, Warn, Expired }

#[contracttype]
pub struct DmsHealth {
    pub status: DmsHealthStatus,
    pub elapsed_secs: u64,
    pub grace_secs: u64,
    pub threshold_secs: u64,
}

#[contracttype]
pub enum PolicyRuleId { AmountSign, WindowRequiresWidth, ActiveWindowOrder,
                        SelfAddressInList, DuplicateAddressInList,
                        DuplicateRecipientCap, RecipientListTooLong,
                        RecipientCapSign, RecipientAllowAndBlocked,
                        ProtocolContractDuplicate, ProtocolFnListInvalid,
                        DurationExceedsBound, AssetListTooLong,
                        ProtocolListTooLong, PerTxCapExceedsWindowCap,
                        AssetCapListTooLong, AssetCapUnknownAsset, DuplicateAssetCap,
                        AssetProtocolOverlap }

#[contracttype]
pub enum ValidationOutcome { Valid, Invalid(PolicyRuleId) }

#[contracttype]
pub enum CheckResult { Allowed, Blocked(Symbol) }
// Blocked carries a `Symbol`, not a dedicated enum type. Its value is always
// one of the `Error::reason()` strings enumerated in the §7.1 mapping table
// above (e.g. `heartbeat_expired`, `window_cap_exceeded`) — the same string
// used as the `reason` topic of `auth_checked`. Consumers can therefore treat
// that table as the exhaustive block-reason vocabulary; an unrecognized symbol
// is still a denial and must be handled fail-closed (§9.1).

#[contracttype]
pub struct CheckDetail {
  pub result: CheckResult,
  pub remaining_window: Option<i128>,
  pub per_tx_cap: Option<i128>,
  pub effective_per_tx_cap: Option<i128>,
  pub effective_window_cap: Option<i128>,
}

#[contracterror] #[repr(u32)]
pub enum Error {            // values stable; see tests/fixtures
    // #1 `Unauthorized` is RESERVED and never emitted (issue #292): bad agent
    // signatures die in the ed25519_verify host trap (§4.0/§10.2) and admin
    // ops fail at require_auth — see §7.1 row 1. Do not add a check returning it.
    Unauthorized = 1, AlreadyInitialized = 2, NotInitialized = 3,
    InvalidConfig = 4, InvalidAmount = 5,
    NoPendingAdmin = 6,
    AdminFrozen = 10, HeartbeatExpired = 11, NoPolicy = 12, Paused = 13,
    OutsideActiveWindow = 14,
    AssetNotAllowed = 20, RecipientNotAllowed = 21, PerTxCapExceeded = 22,
    WindowCapExceeded = 23, ProtocolNotAllowed = 24, FunctionNotAllowed = 25,
    UnknownContract = 26, SelfFunctionNotAllowed = 27,
    CreateContractNotAllowed = 28,
    RecipientBlocked = 29, ProtocolCallRateExceeded = 30,
    DecisionInvariantViolation = 31,
    AssetFnNotAllowed = 32,
    TooManyAuthContexts = 33,
}
```

`check_detailed` loads and prunes only an in-memory copy of the rolling ledger;
it does not change spend accounting. A submitted invocation may refresh persistent
entry TTLs under §9.5 and emits the same `auth_checked` event, with the same
`allowed`/`blocked` result and reason, as `check`. `remaining_window` is the
capacity available before the requested transfer; it is `None` when no effective
window cap applies to the queried recipient (no global `window_cap` and no
per-recipient override). The configured and effective caps are `None` when
disabled. `effective_per_tx_cap` reflects the resolved per-asset override for
the queried asset when one is configured, otherwise the configured global
`per_tx_cap`. `effective_window_cap` reflects the queried recipient's
per-recipient override when one is configured, otherwise the global `window_cap`.

### 7.2 Preflight / simulate a transfer (doc alias for `check`)

`check(asset, to, amount)` is the permissionless **preflight** / **simulate**
entrypoint: a pure pre-flight replica of the §6.2 SAC-transfer decision path
for agents and SDKs to call before signing. Search for "preflight",
"simulate", or `simulate_transfer` to find it.

**Purity invariant.** `check` never writes spend accounting. It loads the
rolling-window ledger, prunes and stages admissions on an in-memory copy, and
discards that copy before returning — so an account that would prune on a real
transfer still reports the same stored `Window`, `LastHeartbeat`, and
`AdminFrozen` after a `check`, and callers may simulate as often as they like
without consuming budget. TTL refreshes from the read are host-level (§9.5),
not data writes. `check_detailed` and `check_batch` share the same guarantee.
`check_is_pure_and_writes_nothing_to_storage` (`src/integration_tests.rs`)
pins it.

These are documentation aliases only: the on-chain ABI is frozen as `check`
(and `check_detailed`); there is no `simulate_transfer` function to invoke,
and no contract change ships with this alias. Canonical behavior is the §6.2
path above; the live testnet invocation mirrored in the `check` rustdoc is:

```text
stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
  --network testnet --source-account guard_admin --send=no -- \
  check --asset CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
  --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
# → {"Blocked":"heartbeat_expired"}
```

### 7.3 Policy hash — cheap drift detection (`policy_hash`)

Operators and the dashboard need to answer *"has the installed policy changed since I last
looked?"* without shipping the full `PolicyConfig` each poll and diffing client-side.
`policy_hash()` provides that check as one value, and doubles as a tamper-evident log anchor
when recorded alongside `auth_checked` events (see [Policy
Attestation](docs/research/policy-attestation.md) for the related admin-signature workflow).

```rust
pub fn policy_hash(env: Env) -> BytesN<32>         // no auth; event-free; write-free
```

- **No policy case — defined, never a trap.** Before `initialize`, when `revoke_policy()` has
  removed the policy, or in any other no-policy state, `policy_hash()` returns
  `NO_POLICY_DIGEST` = `sha256("")`
  = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` — the SHA-256 of the
  empty marker. Off-chain implementers reproduce it trivially; the value is exported by the
  crate and asserted by `tests/policy_hash_encoding.rs`. The all-zero "nothing enabled"
  policy is a *real* policy and never collides with this sentinel.
- **Determinism.** The same policy value yields the same hash across contract instances,
  deployments, and ledger advances; `set_policy` with an unchanged value keeps the hash
  stable (the `PolicyRevision` changes; the hash does not). Any change to **any** field —
  including `paused`, the active window, list membership, or a per-protocol fn list —
  changes the hash. Reverting a policy restores its previous hash exactly.

**Canonical encoding.** The hash is `SHA-256` over the **ScVal XDR serialization of the
policy map** — the same bytes an SDK produces when it passes the policy as the `set_policy`
argument. Determinism rests on two wire-stable invariants:

1. `#[contracttype]` structs encode as `ScVal::Map` with entries in **ascending symbol-key
   order** — the host map invariant, and the same order §3.2 pins for manual encoders.
2. ScVal XDR is a canonical byte format: each field has a single XDR type (`i128` → `I128`,
   `u64` → `U64`, `bool` → `Bool`, `Address` → `ScAddress`, `Option::None` → `Void`,
   `Vec<Address>` → `ScVec` of `ScAddress`, …), so two conforming encoders never disagree.

Field order is therefore the sorted key order of §3.2's table (`active_from`, `active_until`,
`allow_any_recipient`, `asset_caps`, `assets`, `blocked_recipients`, `dms_grace_secs`, `paused`,
`per_tx_cap`, `protocol_calls_per_window`, `protocols`, `recipient_window_caps`, `recipients`,
`window_cap`, `window_secs`). An off-chain reproducer builds the policy value it already
constructs for `set_policy`, XDR-encodes it, and SHA-256s the bytes — no custom serialization
exists to drift. Notes:

- XDR `Vec`s are **ordered**: two allowlists with equal members in different order are
  different policies and hash differently (allowlist scan order is policy semantics, §6).
- `i128` fields carry the standard two's-complement big-endian XDR form (caps are validated
  `>= 0` by §8, but the encoding itself is defined for negatives).
- `policy_hash` is a pure read: no auth, no event, no storage mutation (like every persistent
  read it may refresh entry TTLs under §9.5).
- Out of scope: sibling repositories. The SDK/dashboard drift-check flow is tracked in its
  own repository.

### 7.4 Policy format version — migration hook (issue #339)

`policy_version()` returns the `POLICY_FORMAT_VERSION` constant recorded in instance storage at
`initialize` (SPEC §3, `DataKey::PolicyVersion`). It is a pure read — no auth, no event, no
write — and it reports `0` before initialization, a value that is never a valid format version.

Why it exists: before this read, nothing on-chain recorded which `PolicyConfig` model a
deployed guard implements. Two deployments built from different contract versions were
indistinguishable to an operator or indexer unless it decoded every storage entry and inferred
the shape. A single instance-storage write at `initialize` makes version-gated tooling possible
at the cheapest possible cost: an SDK can refuse to construct a policy the deployed contract
would reject, and a migration runbook can assert the starting state before touching it.

**Version policy (recorded decision).** The format version is a **single monotonic integer**,
written once at `initialize` and never changed after deployment (a policy edit, revoke, pause,
resume, or key rotation does not touch it — those change policy *content*, not the *model*).

- **Any change to the shape or meaning of `PolicyConfig` bumps it by one** — additive fields
  included. Additive-only changes keep the contract ABI compatible (older callers that omit a
  field need not break, when the new field has a defined default), but they still bump the
  version because an older consumer cannot know the field exists. This is what keeps an
  upgraded deployment distinguishable from the one it replaced.
- **A breaking change** (renaming, removing, retyping, or changing the meaning of a field;
  changing an enum's wire ordinals) also bumps it by one **and** ships as a new contract
  release with an explicit migration note. The version is never reused and never decremented.
- **A pure implementation change** — bug fix, gas optimization, refactor, or a change that
  leaves the `PolicyConfig` shape and semantics untouched — does **not** bump it.
- **Consumers must treat an unknown higher version as an unknown policy model.** Refusing to
  submit a policy, flagging the account for review, and logging the observed version is the
  graceful path; silently editing a policy whose model you do not know is the unsafe one.

The constant is asserted in the test suite (`policy_format_version_is_recorded_at_initialize`),
so bumping it is a deliberate act that also forces this section and the §3 storage row to be
reviewed in the same change.

### 7.5 Why `check()` stays permissionless — disclosure analysis (issue #343)

**Decision (recorded): keep `check()`, `check_detailed()`, and `check_batch()`
unauthenticated.** They are advisory reads over state that is already public. Gating them
would break the SDK's pre-flight-before-signing path without actually hiding anything.

**What an unauthenticated caller can learn today.** `check(asset, to, amount)` returns
`Allowed` or `Blocked(reason)` for an arbitrary hypothetical transfer;
`check_detailed` adds `remaining_window`, `per_tx_cap`, `effective_per_tx_cap`, and
`effective_window_cap`; `check_batch` adds one verdict per hypothetical transfer and an
aggregate `admissible` flag. Comparing that with the rest of the permissionless surface:

| Permissionless read | Discloses |
|---|---|
| `policy()` | The full `PolicyConfig`: all caps and window width, asset/recipient/protocol allowlists and blocks, active-window bounds, DMS grace, protocol rate limit, and the pause flag. |
| `status()`, `status_at()`, `dms_health()` | Admin freeze and pause, last heartbeat and its expiry/health, current ledger time, policy revision, global window headroom (pruned), and whether the active window is open. |
| `check()`, `check_detailed()`, `check_batch()` | Whether a *caller-supplied* `(asset, recipient, amount)` would pass the §4/§6 gates right now, plus per-call cap/headroom metrics. This is a derived answer: policy plus the public headroom already determine it for anyone willing to do the arithmetic. |
| `policy_hash()`, `policy_version()`, `validate_policy()` | Policy drift signal, the implemented policy model, and whether a candidate policy would pass §8 validation. |

The marginal disclosure is therefore a **convenience oracle for a hypothetical**, not a new
capability: no key material, secret, or private state is involved, and everything the verdict
depends on is already readable via `policy()` and `status()` (both unauthenticated by design).
The design is internally consistent, and the sibling SDK depends on the unauthenticated form
for pre-flight.

**Options considered, with SDK compatibility cost.**

- **Keep as-is (chosen).** No SDK or dashboard change; agents can pre-flight with
  `simulateTransaction` / `--send=no` before signing, and the same advisory read remains
  available to operators triaging a denial. No new storage keys or rotation paths.
- **Gate behind caller authentication** (`require_auth` on `check*`). Breaks the core
  "simulate before you sign" workflow: the agent cannot produce a valid auth entry for a
  hypothetical transfer it has not decided to submit, and the admin key should never be
  needed to read state. Requires a coordinated SDK/dashboard change and still leaves the same
  facts available through `policy()`/`status()`.
- **Shared secret / read-only caller check.** An on-chain secret is public by definition;
  an off-chain one needs a new persistent key, an admin rotation path, an ABI change, and
  secret distribution in every SDK consumer — to conceal nothing that was not already public.
- **On-chain rate limiting.** Soroban provides no per-caller read throttle; implementing one
  would turn a read into a write (mutable counters, rent, footprint, a shared counter that a
  griefer can inflate). If probe throttling is needed, it belongs at the RPC/gateway/operator
  layer, outside consensus state.

**Proof that `check()` cannot influence state.** `check` delegates to `check_detailed`;
`check_detailed` and `check_batch` call `AuthSnapshot::load` (whose only storage operations
are `persist_get` reads), evaluate `decide` against a **local copy** of the rolling ledger, and
emit `auth_checked` diagnostic events. None of these paths calls `persist_set`, `save_ledger`,
`increment_revision`, `freeze`, `heartbeat`, or any other mutator: the loaded snapshot is
discarded and no window write is staged. The only possible ledger-side effect of a *submitted*
read is the §9.5 TTL refresh, which changes rent metadata, not any value a decision consults;
RPC simulation (`send=no`) does not persist even that. Events are telemetry, not contract
state, and cannot feed back into a later decision. Consequently no caller of `check` can
change policy, spend accounting, freeze/DMS state, or any other stored value. Re-open this
decision only if a future read path starts writing state or if a genuinely private input is
introduced into the decision table.

---

## 8. Config validation (`set_policy`)

> **Starter configs.** Copy-paste `PolicyConfig` presets for common operator personas
> (day-trader, payments bot, watch-only, max security) — each with rationale, explicit
> "what it does NOT protect against", and unaudited/mainnet/DMS-grace warnings — are in
> [`docs/policy-templates.md`](docs/policy-templates.md). A CI test installs every preset
> documented there, so the examples cannot rot into invalid configs.

Every candidate `PolicyConfig` is validated before storage is written. Any rejected rule fails
`set_policy` with `Error::InvalidConfig`, leaving the installed policy unchanged (fail-closed,
never partially applied). Rules are evaluated in the order shown below so `validate_policy` (§8.1)
reports a deterministic first failing `PolicyRuleId`. Empty-list and dormant-window rows are
explicitly listed as **Accepted** with their operational consequences so reviewers can audit the
entire validation surface at a glance (issue #353).

### Validation rules and accepted-but-inert configurations

| Precondition | Behaviour (`set_policy` / `validate_policy`) | Code location | Covering test(s) |
|---|---|---|---|
| `assets.len() > MAX_POLICY_ASSETS` (256) | **Rejected** — `InvalidConfig` / `AssetListTooLong` | `src/lib.rs` (`first_failing_rule`) | `policy_asset_protocol_and_recipient_limits_are_inclusive_and_fail_closed` (`src/integration_tests.rs`) |
| `protocols.len() > MAX_POLICY_PROTOCOLS` (256) | **Rejected** — `InvalidConfig` / `ProtocolListTooLong` | `src/lib.rs` (`first_failing_rule`) | `policy_asset_protocol_and_recipient_limits_are_inclusive_and_fail_closed` (`src/integration_tests.rs`) |
| `recipients.len() > 256`, `recipient_window_caps.len() > 256`, or `blocked_recipients.len() > 256` (`MAX_RECIPIENT_ENTRIES`) | **Rejected** — `InvalidConfig` / `RecipientListTooLong` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_recipient_list_too_long`, `policy_asset_protocol_and_recipient_limits_are_inclusive_and_fail_closed` (`src/integration_tests.rs`) |
| `asset_caps.len() > MAX_ASSET_CAP_ENTRIES` (256) | **Rejected** — `InvalidConfig` / `AssetCapListTooLong` | `src/lib.rs` (`first_failing_rule`) | *(uncovered — no dedicated over-256 `asset_caps` test yet)* |
| `per_tx_cap < 0` or `window_cap < 0` (`window_secs` and `dms_grace_secs` are `u64`, so negatives are unrepresentable) | **Rejected** — `InvalidConfig` / `AmountSign` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_amount_sign` (`src/integration_tests.rs`) |
| `window_cap > 0 && window_secs == 0` | **Rejected** — `InvalidConfig` / `WindowRequiresWidth` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_window_requires_width` (`src/integration_tests.rs`) |
| `per_tx_cap > 0 && window_cap > 0 && per_tx_cap > window_cap` (issue #33) | **Rejected** — `InvalidConfig` / `PerTxCapExceedsWindowCap`; equal caps and either cap `== 0` are **Accepted** | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_per_tx_cap_exceeds_window_cap`, `validate_policy_accepts_equal_per_tx_and_window_caps`, `validate_policy_skips_cap_comparison_when_either_is_zero`, `validate_policy_accepts_per_tx_cap_less_than_window_cap` (`src/integration_tests.rs`) |
| `active_until != 0 && active_until <= active_from` | **Rejected** — `InvalidConfig` / `ActiveWindowOrder` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_active_window_order` (`src/integration_tests.rs`) |
| `active_until` already elapsed or `active_from` in the past/future (with valid order) | **Accepted** — parks the account in a dormant/pre-active state; authorizations evaluate to `OutsideActiveWindow` until ledger time enters `[active_from, active_until]` | `src/lib.rs` (`first_failing_rule` — no wall-clock check at install) | `expired_at_install_policy_results_in_outside_active_window` (`src/integration_tests.rs`) |
| Contract's own address (`env.current_contract_address()`) in `assets`, `protocols[i].contract`, `recipients`, `blocked_recipients`, `recipient_window_caps[i].recipient`, or `asset_caps[i].asset` | **Rejected** — `InvalidConfig` / `SelfAddressInList` | `src/lib.rs` (`first_failing_rule`, `first_failing_recipient_cap_rule`, `first_failing_asset_cap_rule`) | `validate_policy_reports_self_address_in_list`, `self_address_rejected_in_every_list` (`src/integration_tests.rs`) |
| Duplicate address within `assets`, `recipients`, or `blocked_recipients` | **Rejected** — `InvalidConfig` / `DuplicateAddressInList` | `src/lib.rs` (`first_failing_rule`, `has_dup`) | `validate_policy_reports_duplicate_address_in_list` (`src/integration_tests.rs`) |
| Duplicate `recipient` within `recipient_window_caps` | **Rejected** — `InvalidConfig` / `DuplicateRecipientCap` | `src/lib.rs` (`first_failing_recipient_cap_rule`) | `validate_policy_reports_duplicate_recipient_cap`, `invalid_duplicate_recipient_window_cap_rejected` (`src/integration_tests.rs`) |
| `recipient_window_caps[i].cap < 0` | **Rejected** — `InvalidConfig` / `RecipientCapSign` | `src/lib.rs` (`first_failing_recipient_cap_rule`) | `validate_policy_reports_recipient_cap_sign`, `invalid_recipient_window_cap_rejected` (`src/integration_tests.rs`) |
| `recipient_window_caps[i].cap > 0 && window_secs == 0` | **Rejected** — `InvalidConfig` / `WindowRequiresWidth` | `src/lib.rs` (`first_failing_recipient_cap_rule`) | `validate_policy_reports_window_requires_width`, `invalid_recipient_window_cap_rejected` (`src/integration_tests.rs`) |
| `asset_caps[i].per_tx_cap < 0` | **Rejected** — `InvalidConfig` / `AmountSign` | `src/lib.rs` (`first_failing_asset_cap_rule`) | `invalid_negative_per_asset_cap_rejected` (`src/integration_tests.rs`) |
| `asset_caps[i].asset` absent from `assets` | **Rejected** — `InvalidConfig` / `AssetCapUnknownAsset` (never silently ignored) | `src/lib.rs` (`first_failing_asset_cap_rule`) | `invalid_unknown_asset_override_rejected` (`src/integration_tests.rs`) |
| Duplicate `asset` within `asset_caps` | **Rejected** — `InvalidConfig` / `DuplicateAssetCap` | `src/lib.rs` (`first_failing_asset_cap_rule`) | `invalid_duplicate_per_asset_cap_rejected` (`src/integration_tests.rs`) |
| Non-empty intersection between `recipients` and `blocked_recipients` | **Rejected** — `InvalidConfig` / `RecipientAllowAndBlocked` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_recipient_allow_and_blocked`, `blocked_recipients_contradiction_rejected_at_set_policy` (`src/integration_tests.rs`) |
| Duplicate `protocols[i].contract` | **Rejected** — `InvalidConfig` / `ProtocolContractDuplicate` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_protocol_contract_duplicate` (`src/integration_tests.rs`) |
| `protocols[i].fns == Some(list)` where `list.is_empty()` or `list` has duplicate `Symbol`s | **Rejected** — `InvalidConfig` / `ProtocolFnListInvalid` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_protocol_fn_list_invalid` (`src/integration_tests.rs`) |
| Non-empty intersection between `assets` and `protocols[i].contract` (issue #296) | **Rejected** — `InvalidConfig` / `AssetProtocolOverlap`; asset-first classification must never silently shadow a `ProtocolRule` | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_asset_protocol_overlap` (`src/integration_tests.rs`) |
| `window_secs > MAX_WINDOW_SECS` or `dms_grace_secs > MAX_DMS_GRACE_SECS` (`315_360_000` s ≈ 10 years; issue #34) | **Rejected** — `InvalidConfig` / `DurationExceedsBound`; `0` (disabled) and `MAX_*` boundary are **Accepted** | `src/lib.rs` (`first_failing_rule`) | `validate_policy_reports_duration_exceeds_bound`, `window_and_dms_upper_bounds_rejected`, `window_and_dms_upper_bounds_accept_boundary` (`src/integration_tests.rs`) |
| Empty `assets` (`assets.is_empty()`) | **Accepted (inert for SAC transfers)** — no SAC token is allowlisted, so every SAC `transfer`/`transfer_from` classifies as `UnknownContract` and is never allowed (useful for watch-only / heartbeat-only accounts) | `src/lib.rs` (`first_failing_rule` — no non-empty check); `src/engine.rs` (`parse_call_inner`) | `empty_assets_policy_blocks_sac_transfers_but_allows_protocol_calls`, `empty_assets_policy_is_recoverable_by_adding_an_asset` (`src/integration_tests.rs`); `every_documented_preset_installs_and_round_trips` (`src/policy_preset_tests.rs`, Watch-only preset); `audit_event_payloads_and_topics` (`src/event_audit_tests.rs`) |
| Empty `recipients` with `allow_any_recipient == false` | **Accepted (inert for SAC transfers)** — no destination is allowlisted and the escape hatch is off, so every SAC transfer is blocked with `RecipientNotAllowed`. Accepted in v1 unless changed by companion [issue #351](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/351) | `src/lib.rs` (`first_failing_rule` — no non-empty check); `src/engine.rs` (`decide`) | `every_documented_preset_installs_and_round_trips` (`src/policy_preset_tests.rs`, Watch-only preset); companion policy-rejection decision tracked in [issue #351](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/351) |
| Empty `recipients` with `allow_any_recipient == true` | **Accepted** — recipient allowlist is skipped by the escape hatch; `blocked_recipients`, `per_tx_cap`, and `window_cap` still apply | `src/lib.rs` (`first_failing_rule`); `src/engine.rs` (`decide`) | `allow_any_recipient_with_empty_list_still_enforces_both_caps` (`src/integration_tests.rs`) |
| Empty `protocols` (`protocols.is_empty()`) | **Accepted (inert for protocol calls)** — no non-asset external protocol is allowlisted; every non-asset, non-self call is blocked with `UnknownContract` | `src/lib.rs` (`first_failing_rule`); `src/engine.rs` (`parse_call_inner`) | `validate_policy_accepts_valid_config_and_ignores_installed_policy` (`src/integration_tests.rs`), `unlisted_asset_is_unknown_contract` (`src/engine.rs`) |
| `protocols[i].fns == None` | **Accepted** — wildcard: any function on that allowlisted protocol contract is allowed (contrasts with `Some([])`, which is rejected as `ProtocolFnListInvalid`) | `src/lib.rs` (`first_failing_rule`); `src/engine.rs` (`decide`) | `protocol_allowlist_is_enforced_through_real_host_authorization` (`src/integration_tests.rs`) |
| Empty `blocked_recipients` (`blocked_recipients.is_empty()`) | **Accepted (no-op denylist)** — no recipient is explicitly denied; allowlist / `allow_any_recipient` applies normally | `src/lib.rs` (`first_failing_rule`); `src/engine.rs` (`decide`) | `empty_blocked_recipients_list_is_no_op` (`src/engine.rs`) |
| Empty `recipient_window_caps` | **Accepted** — no per-recipient overrides; all recipients use global `window_cap` | `src/lib.rs` (`first_failing_recipient_cap_rule`); `src/engine.rs` (`effective_window_cap`) | `per_recipient_window_cap_falls_back_to_global` (`src/integration_tests.rs`) |
| Empty `asset_caps` | **Accepted** — no per-asset overrides; all allowlisted assets use global `per_tx_cap` | `src/lib.rs` (`first_failing_asset_cap_rule`); `src/engine.rs` (`effective_per_tx_cap`) | `per_asset_cap_falls_back_to_global_when_absent` (`src/integration_tests.rs`) |

**Key design rationales:**
- **Cap ordering (`per_tx_cap <= window_cap`, issue #33):** if `per_tx_cap > window_cap` when both are nonzero, every transfer above `window_cap` is double-rejected and transfers between the two values pass per-tx only to fail on window — an operator error caught at install time. Disabled caps (`0`) skip this check; equal caps are allowed.
- **Duration upper bounds (issue #34):** `window_secs` and `dms_grace_secs` are `u64`, so a seconds/milliseconds mix-up (e.g. a 90-day window passed as `7_776_000_000` ms) or `u64::MAX` would silently disable pruning (unbounded storage growth) or disable the dead-man switch (§5). Capping both at `315_360_000` s (86_400 × 3_650 ≈ 10 years) catches accidental units while affecting no realistic policy; `0` remains legal (feature disabled).
- **Self-address rejection:** `env.current_contract_address()` is known at deployment (pre-`initialize`), and `set_policy` only runs post-initialize. Self-calls are governed by the fixed §6.1 rule rather than `assets`/`protocols`, a self-recipient is a no-op loop signaling a mis-pasted address, and self-entries in `recipient_window_caps`/`asset_caps` cannot be meaningful overrides.
- **Cardinality bounds:** list bounds (`256` entries each) are checked before content and duplicate scans so validation work, authorization scans, and per-recipient storage stay strictly bounded.

Invalid config → `InvalidConfig`, policy unchanged (fail-closed, never partially applied).

### 8.1 Identifying the failing rule: `validate_policy` (issue #35)

The on-chain rejection surface is deliberately stable: any rule above fails
`set_policy` with the single `InvalidConfig` code, and the policy is left
uninstalled. To make the *reason* identifiable without exploding the on-chain
error enum, the contract exposes a read-only dry run:

```rust
pub fn validate_policy(env: Env, config: PolicyConfig) -> ValidationOutcome
```

It evaluates the *candidate* `config` argument — never the installed policy —
against the same rules, in the same order, as `set_policy`, and returns
`Valid` or `Invalid(PolicyRuleId)`, where the payload names the **first** rule
that failed. `PolicyRuleId` variants map to the rejected rows above in evaluation
order:

| `PolicyRuleId` | §8 rule |
|---|---|
| `AssetListTooLong` | `assets` over `MAX_POLICY_ASSETS` |
| `ProtocolListTooLong` | `protocols` over `MAX_POLICY_PROTOCOLS` |
| `RecipientListTooLong` | `recipients` / `recipient_window_caps` / `blocked_recipients` over `MAX_RECIPIENT_ENTRIES` |
| `AssetCapListTooLong` | `asset_caps` over `MAX_ASSET_CAP_ENTRIES` |
| `AmountSign` | `per_tx_cap`, `window_cap`, or `asset_caps[i].per_tx_cap` negative |
| `WindowRequiresWidth` | `window_cap != 0` (or a per-recipient cap `> 0`) with `window_secs == 0` |
| `PerTxCapExceedsWindowCap` | `per_tx_cap > window_cap` when both are enabled (`> 0`; issue #33) |
| `ActiveWindowOrder` | `active_until != 0 && active_until <= active_from` |
| `SelfAddressInList` | the contract's own address in `assets`, `protocols`, `recipients`, `blocked_recipients`, `recipient_window_caps`, or `asset_caps` |
| `DuplicateAddressInList` | duplicate address in `assets` / `recipients` / `blocked_recipients` |
| `DuplicateRecipientCap` | the same recipient twice in `recipient_window_caps` |
| `RecipientCapSign` | a per-recipient cap negative |
| `AssetCapUnknownAsset` | an `asset_caps` entry for an asset not present in `assets` |
| `DuplicateAssetCap` | the same asset appears twice in `asset_caps` |
| `RecipientAllowAndBlocked` | a recipient in both `recipients` and `blocked_recipients` |
| `ProtocolContractDuplicate` | the same contract in two protocol rules |
| `ProtocolFnListInvalid` | a protocol rule's fn list empty or containing duplicates |
| `AssetProtocolOverlap` | the same contract appears in both `assets` and `protocols` (evaluated after the per-protocol rules, before the duration bounds; issue #296) |
| `DurationExceedsBound` | `window_secs` or `dms_grace_secs` over `MAX_WINDOW_SECS` (`315_360_000` s ≈ 10 years; evaluated last so the other variant ordinals stay wire-stable) |

`validate_policy` is a read: no auth, no events, no state writes (read-path
TTL effects in §9.5 still apply). The `InvalidConfig` code itself is
unchanged — every decoder matching on it keeps working; surfacing
`ValidationOutcome` in the SDK/dashboard is a cross-repo follow-up tracked in
those repositories.

---

## 9. Events and telemetry

Events are the contract's audit trail and Phase-2 telemetry vocabulary. This
section is the indexer contract: it states the exact **encoded shape** of every
event — topic positions and data layout — not just the conceptual payload. A
listener can be written from this section alone, and a field reorder is called
out as the breaking change it is (§9.4).

### 9.1 Encoding rules (`#[contractevent]`)

Events are declared as Rust structs with `#[contractevent]`. The macro's
encoding is the on-chain API:

1. `topic[0]` is always the event-name symbol: `event_` followed by the struct
   name converted to `lower_snake_case` (`EventAuthChecked` →
   `event_auth_checked`). It is prepended by the macro; it is not declared as a
   field.
2. Every field marked `#[topic]` follows in **declaration order**: `topic[1]`,
   `topic[2]`, and so on.
3. Fields not marked `#[topic]` become the event data — an `ScVal::Map` keyed
   by the field names as `ScVal::Symbol`. Soroban maps are canonically ordered
   by key, so the encoded entries are **sorted by field name, not by declaration
   order**. Always decode data by key.

Consequences an indexer must rely on:

- Topic positions are meaningful. For `auth_checked`, `result` is `topic[1]`
  and `reason` is `topic[2]`; `src/integration_tests.rs` filters on exactly
  those positions.
- An event with no `#[topic]` fields still has one topic: the prepended name.
- Data is a map, not a tuple. Decode by key and ignore unknown keys; that is
  what makes additive fields backward-compatible (an added `#[topic]` field is
  not additive — it shifts every later position, §9.4).
- `Option<T>` data fields encode as `ScVal::Void` when `None` and as the inner
  value when `Some`; `BytesN<N>` encodes as `ScVal::Bytes` of length `N`.

### 9.2 Event catalogue

The table is normative. `topic[0]` is shown explicitly so no reader has to
infer the prepended name. Data keys are listed in encoded (sorted-key) order;
read them by key regardless.

| Event symbol | Topics | Data (encoded key order) | Emitted when |
|---|---|---|---|
| `auth_checked` | event-name topic `event_auth_checked`, then `result: Symbol` (`allowed`/`blocked`) and `reason: Symbol` (`ok` on allow, the `Error` reason on block) | Map: `context_index: u32`, `revision: u64`, `contract: Option<Address>`, `fn_name: Option<Symbol>` | every `__check_auth` / `check` decision |
| `heartbeat` | (none) | `at: u64`, `expires_at: u64` — the attested DMS deadline as it stood at emission time, `at + dms_grace_secs` of the policy current at that moment; `0` when the dead-man switch is disabled (`dms_grace_secs == 0`, or no policy) | on agent heartbeat (skipped when `now == LastHeartbeat`; §5) |
| `dms_auto_frozen` | (none) | `at: u64` — ledger time at which the elapsed dead-man grace was explicitly recorded | permissionless `refresh_deadman()` records an **already-true** expiry for the first time (`AutoFrozenAt` was unset); a no-op when not expired or already recorded (§5) |
| `initialized` | (none) | `by: Address` | contract initialization |
| `frozen` | (none) | `by: Address` | admin freeze |
| `self_locked` | (none) | `at: u64`, `revision: u64` — lock timestamp and the `PolicyRevision` in force | agent `self_lock` |
| `unfrozen` | (none) | `by: Address`, `rearmed_dms: bool` — whether `LastHeartbeat` was changed (DMS clock re-armed; §5) | admin unfreeze |
| `policy_set` / `policy_revoked` | (none) | `by: Address`, `revision: u64` — the `PolicyRevision` this call produced | admin policy changes |
| `paused` / `resumed` | (none) | `by: Address`, `revision: u64` — the `PolicyRevision` this call produced; the counter advances only when the call actually flips `paused`, so a redundant double-pause emits the event with an unchanged revision | admin `pause()` / `resume()` (issues #289/#290) |
| `window_reset` | (none) | `by: Address` — the admin that explicitly zeroed the rolling window (`set_policy` preserves it across edits, issue #289) | admin `reset_window()` (issue #289) |
| `window_cap_increased` | (none) | `by: Address`, `old_cap: i128`, `new_cap: i128`, `revision: u64` — the admin that raised `window_cap` in place without resetting the ledger, plus the incremented `PolicyRevision` | admin `increase_window_cap(new_cap)` (issue #349) |
| `agent_rotated` | (none) | `by: Address`, `old_fingerprint: BytesN<8>`, `new_fingerprint: BytesN<8>` | admin agent-key rotation (`rotate_agent_key`) |
| `admin_rotation_proposed` | (none) | `by: Address`, `proposed: Address` — the current admin that proposed and the pending admin | admin `propose_admin_rotation(new_admin)`; a self-proposal is rejected before emission |
| `admin_rotated` | (none) | `old: Address`, `new: Address` — the outgoing and incoming admins | `confirm_admin_rotation()`; only the pending admin can confirm, and the old admin loses authority immediately |
| `admin_rotation_cancelled` | (none) | `by: Address`, `cancelled: Address` — the admin that cancelled and the pending admin whose proposal was discarded | admin `cancel_admin_rotation()` while a proposal is pending |
| `event_window_merged` | `ledger_kind: Symbol` (`global_spend`, `recipient_spend`, `protocol_calls`) | `(merged_ts: u64, merged_value: i128)` â€” retained newer timestamp and merged spend amount or call count | successful admission engages the 8192-entry backstop |

**Policy revision join key (issue #38).** `PolicyRevision` is a persistent
instance-stored counter (`DataKey::PolicyRevision`, §3) incremented by every
`set_policy`, `revoke_policy`, and `increase_window_cap` (issue #349), and by a `pause()` / `resume()` that
actually flips the `paused` flag (a redundant pause leaves the counter
untouched; issues #289/#290) — starting at 1 after the first `set_policy`
and never reset by a revoke. `status()` exposes it as `policy_revision`, and
the `policy_set`, `policy_revoked`, `paused`, `resumed`, `window_cap_increased`, and `auth_checked`
events stamp it as
additive `revision` data. Telemetry consumers can therefore join "which policy
was in force when this transfer was admitted" on the counter instead of
wall-clock joins, which are wrong the instant an admin makes two `set_policy`
calls within one ledger. The fields are additive data on unchanged topics, so
decoders that ignore unknown map keys keep working; SDK/dashboard decoders
surfacing the new field are cross-repo follow-ups. Two `auth_checked` events
sharing a revision were evaluated under the same policy generation; the
`policy_hash` (§7.3) distinguishes *which* policy that generation installed.

Reason symbols mirror `BlockReason`/`Error` naming so off-chain code maps one vocabulary.
Every decision publishes a non-empty `reason` topic: an allowed decision carries `ok`
(issue #300), so a listener filters on a real symbol and never special-cases a zero-length one.

**Heartbeat expiry (`heartbeat.expires_at`).** `expires_at` is the deadline the heartbeat was
actually attested under, derived from the `dms_grace_secs` of the policy *current at the moment
the heartbeat is emitted* — not a value the consumer recomputes from `at` using whatever grace
the policy carries later. A `set_policy` that changes `dms_grace_secs` after a heartbeat does not
retroactively change that heartbeat's recorded deadline, so a listener replaying the log derives
the same expiry the contract enforced instead of a drifting recomputation. When the dead-man
switch is disabled the event carries `expires_at == 0` rather than `at + 0`, so `0` unambiguously
means "no deadline was attested" and never a real timestamp (ledger timestamps are far above `0`).
Reads `Policy` at emission time to obtain the grace; a missing policy reads as disabled.

**Agent fingerprint (`initialized.agent_fingerprint`).** The `initialized` event
carries the first 4 bytes of the registered Ed25519 public key, rendered as 8
lowercase hex characters off-chain, so an auditor or incident responder can
answer "which key was this account bound to at setup?" from telemetry alone
instead of replaying the initialize transaction or reading instance storage.
This is a **correlation prefix, not a security fingerprint**: 32 bits collide by
the birthday bound at roughly 77,000 keys, so it must never be used to prove key
identity or to authorize anything. It reveals nothing new — the full key is
already public in instance storage. `agent_rotated` uses a different, longer
fingerprint (below); the two are intentionally not comparable.

**Key fingerprints (`agent_rotated`).** A fingerprint is `sha256(pubkey)[0..8]` — the first
8 bytes of the SHA-256 digest of the agent public key, rendered as 16 lowercase hex characters
off-chain. Rotations record both endpoints (outgoing and incoming) so an auditor can reconstruct
"when did key K stop being authoritative" from the append-only event log; the full public key is
never repeated in event data (it is already public at `initialize`). SDK/dashboard decoders must
render the `BytesN<8>` data fields as hex — a cross-repo follow-up tracked in those repositories.

### 9.1 Reason-symbol vocabulary — compatibility policy (issue #342)

Reason symbols are the contract's most depended-upon **string** surface: they are published as the
`reason` topic of every `auth_checked` event, as the payload of `CheckResult::Blocked`, and in the
SPEC §7.1 table. SDKs, dashboards, and operator runbooks key off them. This section records what
is promised, because nothing else on-chain commits to it.

**Recorded decision: the vocabulary is a *published, additive-first compatibility surface* — not a
separately versioned API, and not a free-to-change string.** In practical terms:

- **Additive changes are non-breaking and expected.** A new `Error` variant / reason symbol may
  appear in a release (the error enum already follows "append, never insert", and the
  discriminants are frozen — §7.1). Consumers must accept a reason they have never seen.
- **Removing or renaming an existing reason is breaking**, as is changing *which condition* emits
  an existing reason (a consumer that alerts on `window_cap_exceeded` must not silently start
  receiving it for a different gate). A breaking vocabulary change ships with a contract release
  and an updated `tests/fixtures/auth-checked-vocabulary.json`; it is **not** versioned per event.
- **There is no per-event vocabulary version field.** Adding one would cost bytes on every
  decision and break the topic-filtering contract that makes `auth_checked` cheap to consume. The
  version a consumer is talking to is the deployed contract release (and, for the policy model
  specifically, `policy_version()` — §7.4). The canonical snapshot a consumer can pin is the
  committed vocabulary fixture plus the §7.1 table, not a value in event data.
- **`ok` means allowed; every other reason means blocked.** `ok` is reserved for the allow
  path and is never emitted for a denial. A consumer that filters `reason == ok` sees exactly
  the admitted decisions; no outcome publishes an empty-symbol reason topic (issue #300).
- **Unknown reason = treat as blocked.** This is the one required consumer behavior: fail closed,
  log the raw symbol, and surface it for review; never crash, never treat an unrecognized symbol
  as `allowed`, and never assume the reason set is finite or that an enum mirror is exhaustive.
  The numeric `Error(Contract, #N)` code in diagnostics is stable and can be matched when the
  symbol is unfamiliar; §7.1 is the mapping.

This is deliberately "in between" the two options the issue names: consumers get a real
compatibility promise (no silent renames; additive growth), but they are not handed a version
number they could gate on, because the cost of carrying it on every event outweighs the benefit
when the release already identifies the vocabulary. Consumers that need a hard gate should pin
the fixture and the contract release they were built against.

The operator-facing consequence — an unknown symbol is still a denial, and the diagnostic event
is where it is legible — is cross-referenced from SECURITY.md.

### 9.5 Persistent storage TTL liveness

`Policy`, `Window`, `LastHeartbeat`, `AdminFrozen`, and `PolicyRevision` are persistent ledger
entries. A successful write extends its entry to `env.storage().max_ttl()` ledgers. A successful
read refreshes the accessed entry to that same TTL when its remaining TTL is below half of
`max_ttl()`. The extension target is a TTL duration relative to the current ledger sequence, not
an absolute sequence number. This thresholded read refresh avoids paying rent on every read while
keeping frequently accessed guard state away from archival. Because of this refresh, submitting a
read call such as `policy`, `status`, or `check` can write TTL metadata and charge rent when the
threshold is crossed; an RPC simulation (`send=no`) does not persist that change. A rejected
authorization transaction rolls back its TTL updates along with its other state changes.

This is an activity-based liveness policy, not a promise that untouched state never expires. If
an entry is left untouched for its full maximum TTL, Soroban archives it. A transaction that
accesses archived persistent data must restore that entry in its footprint before contract
execution; RPC simulation normally supplies the restore footprint. If restoration is not
included or its rent cannot be funded, the transaction fails before a guard decision can approve
the spend. Once restored, a successful read refreshes the entry. Operators requiring liveness
through inactivity longer than the maximum TTL must arrange a keeper/restore transaction before
expiry; the contract cannot run a background extension itself.

The executable TTL regression test shortens the test ledger's persistent TTL, advances ledger
sequence past expiry, and verifies that archived `Policy`, `Window`, `LastHeartbeat`, and
`AdminFrozen` entries restore with their original values. It also checks that a pre-expiry spend
still counts against `window_cap` after restoration and that an expired dead-man clock remains
expired. See [issue #43](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/43)
and the operator [rent/TTL guide](docs/rent-and-ttl.md).

---

## 10. Threat model (what this does and does not do)

Guarded against, on-chain and unbypassable (a compromised agent key cannot exceed policy —
spend caps, allowlists, freeze, default-deny all execute inside `__check_auth` before any value
moves):
- runaway/overspend loops (per-tx + global/per-recipient rolling window caps)
- payment to unauthorized recipients (recipient allowlist on asset transfers)
- per-recipient overspend (per-recipient rolling window caps)
- calls to unauthorized protocols/functions (protocol allowlist + default-deny)
- agent disappearance (dead-man switch) and operator-initiated halt (freeze/pause)
- a runaway agent stopping itself via `self_lock` even when the admin key is unavailable
  (issue #306) — a halt path that gives the agent no fund-moving power

Not guarded by v1 (documented, not hidden):
- fine-grained amount/recipient limits on non-SAC protocol calls (§2, v2 item)
- a live attacker who keeps the agent key heartbeating and never calls `self_lock` (caps still
  bind them; the switch only fires on silence). `self_lock` closes the *honest runaway* half of
  this gap, not the compromised-key half: an attacker holding the key simply does not call it.
- `self_lock` as a fund-safety control: an agent (or a compromised agent) can lock itself — and
  therefore the account — out. That is an availability outcome, not a loss-of-funds outcome; the
  call cannot move funds, change policy, or rotate keys, and only admin `unfreeze` reverses it.
- admin compromise (admin can freeze and rewrite policy/keys — that is its function; it still
  cannot move funds)
- **admin-key loss while the dead-man switch is armed** — arming `dms_grace_secs > 0` makes
  the admin key a liveness dependency for the entire balance. The grace freeze is reversed
  only by an admin `unfreeze` (§5, §5.1), and `propose_admin_rotation` requires the current
  admin's signature, so a lost admin key cannot be replaced. Once the grace has lapsed the
  balance is unspendable: the agent's heartbeat is rejected and no other actor can authorize
  a transfer. Recognise it with `status()` (`admin_frozen: false`,
  `heartbeat_expired: true`) and treat admin-key custody as a precondition of arming the
  switch; see the
  [incident playbook](docs/operations/incident-playbook-admin-key-lost.md).
- **availability griefing by a holder of the agent key** — see §10.3
- DoS on the account by someone **without** the agent key is not possible (anyone may call read
  functions); policy writes are admin-only. The contract is unaudited; see `SECURITY.md`/README disclaimers.

### 10.1 Signature binding

**What the payload covers.** `__check_auth` step 2 is
`ed25519_verify(AgentPubkey, signature_payload, sig)` — a pure signature check over a
digest the **host** computes, never this contract:
`sha256(HashIdPreimage::SorobanAuthorization { network_id, nonce,
signature_expiration_ledger, invocation })`, where `invocation` is the complete root
invocation — every auth context (target contract, function, argument values) the
transaction will execute under this account. What the binding therefore covers:

| Payload field | Bound meaning | If altered |
|---|---|---|
| `network_id` | chain domain | a testnet signature verifies on no other network |
| `nonce` | single-use label, unique per address | host rejects reuse once consumed |
| `signature_expiration_ledger` | validity bound in ledgers | entry fails after that ledger passes |
| `invocation` (root) | contract + function + args of every context | digest changes ⇒ signature no longer verifies |

**Replay analysis.**

- *Across transactions: impossible by construction.* A signature captured for tx A
  verifies only against A's digest. Replaying it inside tx B's auth entry makes the
  host recompute B's digest — different invocation, nonce, or expiry ⇒ different bytes
  ⇒ `ed25519_verify` traps **before** any policy evaluation, so a replayed signature
  never reaches the decision table. Pinned by
  `captured_signature_cannot_authorize_different_tx` and
  `check_auth_binds_signature_to_the_exact_payload` (`src/integration_tests.rs`).
- *The same transaction twice: host-side.* A byte-identical resubmission reuses A's
  nonce (unique per address, rejected by the host after first consumption) and dies at
  `signature_expiration_ledger` regardless. Division of labor, stated plainly: nonce
  and expiry replay defense is **host** construction — this contract only ever checks
  the signature over the digest the host hands it.
- *Agent signature ≠ admin authority.* An agent signature clears verification only for auth
  entries whose credentials address is **this account**. The admin write path
  (`set_policy`, `revoke_policy`, `freeze`, `unfreeze`, `rotate_agent_key`) runs under
  `require_auth(Admin)` — a different address, a different auth entry, a different
  payload — and an agent-signed entry never satisfies it
  (`agent_signature_does_not_confer_admin_authority`). The converse is the
  admin-compromise bullet above: the admin cannot produce the agent's signature either,
  so it may widen policy but still cannot move funds.

**Leaked payload + sig, mid-flight.** Anyone holding `(payload, sig)` before inclusion
can submit **exactly** tx A themselves — front-running the already-authorized
invocation. That is not an escalation: amount, recipient, and function are inside the
digest, so nothing can be edited without invalidating the signature; policy is
re-evaluated at execution, so caps, allowlists, pause, and freeze still bind the
replayed transaction; the nonce is consumed on first use; and
`signature_expiration_ledger` bounds how long the leak stays usable. A leaked pair
cannot authorize a policy change, a different recipient, or a larger amount — those
are different digests, and the admin path never consults the agent's signature at all.

### 10.2 Verification ordering guarantee

**The guarantee.** `__check_auth` verifies the agent's Ed25519 signature over the host's auth
payload **before** any policy state is read and **before** any decision-table gate is evaluated.
Consequently an unverifiable signature — wrong signer key, corrupted signature bytes, or a
payload belonging to a different transaction (§10.1) — never reaches the decision table: there
is no path on which an unverified signature consults `PolicyConfig`, `AdminFrozen`,
`LastHeartbeat`, the rolling window, or any allowlist, and therefore no path on which it causes
a storage write. `env.crypto().ed25519_verify` traps the execution frame (`InvokeError::Abort`)
at the point of failure, so the transaction reverts with a host abort rather than a guard
verdict. This is what makes "a compromised-but-unregistered key cannot do anything" a property
of the code rather than a likelihood.

Two corollaries worth stating because they are the ones a reviewer can check:

- A wrong-key caller cannot learn whether a policy is installed. The abort precedes
  `AuthSnapshot::load`, so an account with a policy and an account without one are
  indistinguishable to that caller — both abort.
- A wrong-key caller cannot obtain a `Blocked` reason symbol. Reason symbols come from the
  decision table; reaching them requires a valid signature from the registered key.

**Enforcing tests** (all `src/integration_tests.rs`; the suite is what a refactor of the
ordering is measured against):

| Test | What it pins |
|---|---|
| `wrong_signature_is_rejected_by_host_crypto` | On an initialized account **with** policy installed, an entry signed by a different key aborts the call; the registered agent still authorizes afterwards |
| `auth_verification_order_initialized_account_wrong_signature_traps_as_host_abort` | The ordering case that matters: wrong key **and** corrupted bytes both trap with `InvokeError::Abort` on an account with **no policy installed**, i.e. verification precedes policy load rather than merely preceding the gates. If the snapshot were read first, these would return `NoPolicy` |
| `auth_verification_ordering_matrix_pins_exact_observables` | The full observable matrix: uninitialized + any signature → `NotInitialized`; initialized (no policy) + wrong signature → `InvokeError::Abort`; initialized (no policy) + valid signature → `NoPolicy`; initialized + policy + valid signature → `Ok(())` |
| `captured_signature_cannot_authorize_different_tx`, `check_auth_binds_signature_to_the_exact_payload` | The payload-binding side of the same property (§10.1): a signature verified only over the exact digest it was made for |

**Interaction with the not-initialized and no-policy paths.** Two early contract-error returns sit
either side of verification, and their relative order is a **separate documented concern** from
this guarantee — it is specified in §4.0 and pinned by its own tests:

- The registration check (`DataKey::AgentPubkey`) runs **before** verification
  (`auth_verification_order_uninitialized_account_rejects_with_not_initialized`). An
  uninitialized account returns `NotInitialized` even for arbitrary or invalid signature bytes,
  instead of an opaque host abort. That does not weaken this guarantee: with no key registered
  there is no signature that *can* verify, and the account is default-deny either way. It is a
  diagnosability choice, not an authorization one.
- Policy snapshot loading runs **after** verification
  (`auth_verification_order_initialized_account_valid_signature_no_policy_yields_no_policy`).
  `NoPolicy` is therefore reachable only by a caller holding the registered agent key, which is
  what keeps the first corollary above true.

**Refactor warning.** Do not move any policy or state read ahead of `ed25519_verify`, including
for gas: reading the policy first to "warm" the snapshot makes a wrong-key caller's `NoPolicy`
outcome reachable again and re-opens the information leak in the first corollary. §4.1 shows the
cost ordering is already aligned with the semantic ordering, so there is nothing to win. If the
sequence is reordered for any other reason, the matrix test above is the check that must fail —
a green suite after reordering means the tests were changed to match the code, which is the
outcome this section exists to prevent.

### 10.3 Availability: a compromised agent key can grief-block its own transactions (issue #424)

**The property.** Default-deny enforcement means *any* authorization the guard evaluates is
checked against the same policy that the agent itself must satisfy. Consequently, anyone holding
the registered agent key can construct transactions that fail policy on demand — a transfer one
unit over `per_tx_cap`, a recipient outside `recipients`, a call to an unlisted contract — and
have them refused. That is not a bug in enforcement; it is the same mechanism that makes
enforcement unbypassable, seen from the availability side. It is the fourth bullet of §10's
list rather than an extension of the third: the pre-existing "DoS is not possible" claim is
about *strangers*, who can neither move funds nor change policy, and it does not survive a key
holder.

**The bound — what the attacker does and does not get.**

- **No funds move.** A blocked context means `__check_auth` returns `Err` before the SAC call is
  authorized, so the token contract is never invoked (§6.2, §6.4). The attacker's power is the
  power to fail, not to spend.
- **No budget is consumed.** Denied batches never commit their staged window admissions
  (§6.0), so repeated failures do not drain `window_cap`, do not fill the window ledger, and do
  not lower `status().window_remaining`. Legitimate spend is unaffected by how many denials are
  generated. The same is true of the per-recipient ledger and the protocol-call counter, which
  share the `all_passed` guard.
- **No state is written and no storage grows.** A rejected authorization rolls back its TTL
  refreshes along with everything else (§9.5), so the attacker cannot inflate the account's
  rent footprint by failing on purpose.
- **Cost falls on the attacker, not the account.** A denial that is only *simulated* is free and
  requires no transaction at all; a denial that is *submitted* is paid for by the transaction
  source account, which must be a classic account the attacker funds — the guard's contract
  address cannot be a fee source. The attacker cannot make the guarded account pay for its own
  refusals.
- **The admin ends it with one call.** `rotate_agent_key` re-binds `AgentPubkey` (§7); from that
  transaction onward, the compromised key's signatures trap at `ed25519_verify` before any
  policy evaluation (§10.2), so the griefing stream stops and cannot even reach a denial reason.
  Rotation is the documented response in
  [`docs/key-rotation.md`](docs/key-rotation.md) and
  [`docs/functions/admin-rotation.md`](docs/functions/admin-rotation.md).

**What is actually lost** is the operator's ability to tell "the agent is misbehaving" from
"the agent's key is compromised and something is failing on purpose", plus the incident time
spent finding out. The account remains functional for policy-respecting spend throughout.

**Telemetry signature.** The denials are the only trace, and where they appear depends on how
the operator is watching:

- Each refusal is a `auth_checked` event with `result = blocked` and the specific reason symbol
  (§9). Read the reason, not the volume: `per_tx_cap_exceeded`, `recipient_not_allowed`,
  `recipient_blocked`, `unknown_contract`, `asset_fn_not_allowed` are per-call classification
  denials that a heartbeat-driven agent would produce rarely and predictably, while a
  `window_cap_exceeded` or `heartbeat_expired` stream points at liveness or budget, not at a
  constructed attempt. The per-reason remediation is in
  [`docs/reason-glossary.md`](docs/reason-glossary.md) — that table is the vocabulary this
  paragraph assumes.
- **Blocked decisions are not committed ledger events.** The transaction that carried them
  failed and rolled them back, so they surface in simulation diagnostics and in the SDK's
  dual-stream telemetry, never in a raw `getEvents` query over committed events (§9, README
  step 5 caveat, and the operator-visible error shapes in
  [docs/functions/check-auth.md](docs/functions/check-auth.md)). An operator whose pipeline
  indexes only committed events will see *nothing* for these attempts — which is itself the
  signature to look for: reports of a broken account, a stream of blocked decisions in the
  diagnostics, and no corresponding committed transaction or SAC `transfer` event.
- The positive control is the window: `status().window_remaining` unchanged across a burst of
  denials distinguishes griefing from a real overspend attempt, which would move that number
  when its transfers succeed.
- A live attacker can additionally keep heartbeating, so `dms_health()` staying `ok` is not
  evidence of an innocent agent — that is the pre-existing second bullet of this list, and it is
  why the denial reasons, not the liveness signals, are the discriminating evidence.

The asymmetry worth stating to a stakeholder: this is a *cheap* attack — no funds, no fees from
the account, no state — and a *bounded* one — it cannot escalate into a spend, a policy change,
or a locked budget. Its cost is measured in operator attention, and its remedy is one
`rotate_agent_key`.

---

## 11. Testnet proof plan (scenarios 1–8: five proven, three planned)

Scenarios 1–5 were executed against a real testnet deployment; evidence
(contract IDs, tx hashes, event output) is recorded in
`tests/fixtures/README.md` as required by Phase 1 exit criteria:

1. **Allowed transaction** — policy-respecting asset transfer succeeds.
2. **Per-tx cap violation** — transfer above `per_tx_cap` is blocked on-chain.
3. **Rolling-window cap violation** — cumulative spend across separate transactions inside one
   `window_secs` span exceeds `window_cap`; the later one is blocked (then a window rollover
   restores spending, proving it is rolling).
4. **Allowlist violation** — transfer to a recipient outside the allowlist is blocked.
5. **Dead-man switch trigger + reversal** — heartbeat stops past `dms_grace_secs`; a subsequent
   spend is blocked with `HeartbeatExpired`; admin `unfreeze` + fresh heartbeat restores it.

Scenarios 6–8 are defined below to the same evidentiary standard (reproduction
steps, contract ID, tx hash or diagnostic output, event topics) and are
**pending live execution** (tracked by issue #49; the executing PR records the
hashes in `tests/fixtures/README.md` + `index.json` and closes #49). Scenario 6
is the scope of issue #5 (agent-key rotation proof) — #5 is absorbed here, not
duplicated: the executing PR closes both. Until the hashes land, the fixture
index stays at scenarios 1–5 (`schema_version: 1`, `SCENARIO_COUNT = 5` in
`tests/fixtures_index.rs`); the executing PR bumps both to cover 6–8.

6. **Agent-key rotation + old-key rejection** (absorbs issue #5) — admin
   `rotate_agent_key(new_pubkey)` succeeds on-chain (`agent_rotated` event with
   the old/new fingerprints); a transfer signed with the **old** key is
   rejected (host signature-trap error in the enforced simulation — no
   `auth_checked` topics, since verification fails before policy evaluation);
   a transfer signed with the **new** key succeeds on-chain
   (`auth_checked`/`allowed` + ledger + hash). DMS interplay asserted:
   `status()` before/after shows `last_heartbeat` unchanged (rotation resets
   nothing) and the new key heartbeats within the existing grace. Precondition:
   the account must be live (unfrozen, inside DMS grace — `unfreeze` and/or a
   scenario policy install first, each hash recorded). Postcondition: rotate
   back to the canonical key and prove it spends again, so the shared fixture
   deployment ends exactly as it started.
7. **Protocol allowlist admit + deny** — policy installs a `protocols` rule for
   a freshly deployed minimal protocol contract (contract ID recorded at run
   time) allowlisting one function (e.g. `ping`) while another function on the
   same contract (e.g. `admin_fn`) stays denied:
   - **7a admit:** agent-signed call to the allowlisted function succeeds
     on-chain (`auth_checked`/`allowed` + ledger + hash). Requires the
     `invoke` subcommand in `tools/agent-tx` (the current tool only builds
     transfer/heartbeat auth entries) — specified in
     `tools/agent-tx/README.md`, implemented in the executing PR.
   - **7b deny (wrong fn):** agent-signed call to the non-allowlisted function
     on the same contract is blocked pre-broadcast (`auth_checked`/`blocked`/
     `function_not_allowed`, no hash).
   - **7c deny (unknown contract):** agent-signed call to a contract in
     neither `assets` nor `protocols` is blocked pre-broadcast
     (`auth_checked`/`blocked`/`protocol_not_allowed`, no hash). No deployment
     needed for 7c — any address not in the policy exercises the path.
8. **Pause gate** — admin installs `paused: true` (hash recorded); an
   agent-signed transfer is blocked pre-broadcast (`auth_checked`/`blocked`/
   `paused`, no hash — pause is decision-table gate #4, ahead of all
   classification); admin restores `paused: false` (hash recorded) and the
   same transfer succeeds on-chain (`auth_checked`/`allowed` + ledger + hash).

Unit + invariant tests (Soroban test env, real host semantics) cover the decision table, the
window invariant, auth-context parsing, signature verification, freeze/reversal, and default
deny. Gates: `cargo test` green, `cargo clippy --all-targets --all-features` clean with
`warnings`/`clippy::all`/`clippy::pedantic` deny, `cargo fmt --check` clean, CI (`ci` job) green
on `main`.

### 11.1 Testnet-proof criteria and fallback rationale

Per [`CONTRIBUTING.md` Coding Standard 6](CONTRIBUTING.md#coding-standards) and [`tests/fixtures/README.md`](tests/fixtures/README.md):

1. **User-visible enforcement changes (testnet proof entry required):**
   - Alterations to the decision table (SPEC §§4, 6) affecting what `__check_auth` admits or blocks, or changing error codes/events emitted on allow or deny.
   - Storage-layout, footprint, or key-schema changes affecting on-chain persistence, footprint, or contract upgrade/migration compatibility observable by callers.
   - Adding, modifying, or removing policy/guard rules or authorization checks.

2. **Changes not user-visible (no testnet proof entry required):**
   - Pure internal gas/CPU/memory optimizations that preserve identical admit/deny decisions, storage layout, and events.
   - Documentation, comments, or specification formatting updates.
   - Refactorings of internal helpers, test harnesses, or test-only assertions.

3. **Evidence bar & responsibility:**
   - A valid proof entry requires an on-chain testnet transaction hash (`tx hash`) and the emitted event output (`topics: [event_auth_checked, <outcome>, <reason>]`), structured per [`tests/fixtures/README.md`](tests/fixtures/README.md) and mirrored in [`tests/fixtures/index.json`](tests/fixtures/index.json).
   - The PR contributor proposing the change is responsible for capturing and recording the testnet proof.

4. **Impractical testnet scenarios (fallback path):**
   - If an enforcement change is impractical to demonstrate on live public testnet (e.g. extreme ledger-sequence/timestamp edge cases, complex multi-ledger rollbacks, or host resource exhaustion):
     - The change must provide a deterministic unit/integration test in the Soroban test environment ([`src/integration_tests.rs`](src/integration_tests.rs)) covering the exact enforcement path.
     - The PR description and proof documentation must include a written rationale explaining why testnet demonstration is impractical and how the deterministic test suite validates the invariant.


## Appendix A — Scoped session grants (research spike, issue #308)

**Status:** Decision recorded, **not implemented**. This appendix is
non-normative for v1: no storage key, decision row, error variant, event, or
`__check_auth` behavior described here exists on-chain. The full analysis is
[`docs/research/scoped-session-grants.md`](docs/research/scoped-session-grants.md).

**Question.** Should an admin be able to mint a short-lived, amount-capped
capability ("session grant") that the agent consumes between policy edits,
instead of editing the account-global policy to adjust a routine budget?

**Current state.** The motivating "every policy edit resets the window" premise
does not hold at this revision: `set_policy` preserves the rolling window and
DMS clock (issue #289), and `increase_window_cap` raises the global cap in place
without resetting the ledger (issue #349). The remaining gap is a budget that is
*scoped* (asset + recipient set), *time-boxed*, and *revocable* without an
account-wide policy rewrite.

**Decision.** Build in v2 as a **contract-stored grant keyed by a monotonic
nonce**. Reject the off-chain signed-grant representation for v2: `__check_auth`
has no side-channel for a grant, so it would require changing
`CustomAccountInterface::Signature` from `BytesN<64>`, adds a second admin trust
root, and still needs on-chain consumption state to prevent replay.

**v2 shape (bounded summary).**

- One live `SessionGrant` per account in persistent storage, plus a monotonic
  `LastGrantNonce`; admin-only `mint_grant` and `revoke_grant`.
- Bound to the contract, admin, `AgentPubkey`, `policy_revision`, asset,
  recipient scope, `per_tx_cap`, `total_cap`, and `expires_at`.
- **Eligibility intersects policy:** a grant cannot bypass `AdminFrozen`, DMS,
  `NoPolicy`, `paused`, the active window, asset/recipient allowlists, or call
  classification. It affects only monetary limits on an already-admissible SAC
  `transfer` / `transfer_from`.
- **Monetary caps substitute on overflow:** the policy path is evaluated first;
  a matching grant is consulted only when the policy blocks with
  `PerTxCapExceeded` or `WindowCapExceeded`. Grant-funded spend is tracked in
  the grant's `consumed` counter, **not** in `WindowState`; if the grant does not
  cover the call, the original policy denial reason is returned.
- **Revocation is lazy and explicit:** `revoke_grant` takes effect on the next
  authorization; any policy-mutating admin call, `revoke_policy`, or
  `rotate_agent_key` makes outstanding grants inert through the revision/key
  binding. Revocation never reverses an already-settled spend, and no
  background process exists or is needed. This is the same lazy model as §5 and
  §9.5.
- A compromised agent key can consume outstanding grants; short lifetimes, small
  caps, and key rotation bound that loss. Grants add no new signer or bearer
  authority.

**Out of scope here:** contract code, storage keys, error variants, events,
ABI snapshots, and testnet proofs. The v2 build requires the full Phase-1 gate
plus testnet evidence per §11.1.
