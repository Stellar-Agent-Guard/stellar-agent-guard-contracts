# stellar-agent-guard-contracts — Architecture Specification (Phase 1)

Status: **implemented against this spec; testnet proofs recorded in `tests/fixtures/README.md`.**
Mechanism is settled: **Soroban native Custom Account Abstraction.** This document specifies the
smart-wallet policy contract, every public signature with auth-placement reasoning, the policy
model (per-transaction cap, genuinely rolling window cap, recipient + protocol/function
allowlists, pause, dead-man switch), and the exact enforcement scope.

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
contexts of the calls being authorized. `type Signature = BytesN<64>` (single registered agent
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
engine still enforces window and pause state, but per-call amount/recipient limits are not yet
enforced — extending fine-grained enforcement to arbitrary calls is tracked as a v2 item, not
implied as already covered.**

What "window and pause state" means for non-SAC calls is made exact in §6.4: the account is a
**default-deny** environment — every call must match the protocol allowlist (contract, and
optionally function) — and the active-window / pause / dead-man-freeze checks gate every context
equally, SAC or not. What is *not* applied to non-SAC calls is per-call amount capping and
rolling-window spend accounting, because the amount is not available in the context in any
trustworthy way.

This boundary is an inherent property of the platform (an independent current confirmation:
OpenZeppelin's Soroban `spending_limit` plugin likewise only meters transfer contexts and
rejects non-transfer calls outright), **not** a gap this project hides or overclaims. The README
states the same scope in the same terms.

**Research note (v2):** The decomposition of "fine-grained non-SAC enforcement" into honest sub-strategies (protocol parsers, rate limiting, declared-max, return-value commitments) is documented in [Non-SAC Enforcement](docs/research/non-sac-enforcement.md). Recommended direction: protocol rate limiting (count-based) as core deliverable; opt-in protocol parsers as secondary.

---

## 3. Storage model

Persistent storage with explicit TTL management (all policy/state keys are extended to a target
TTL on every write; see §9.5).

| Key | Type | Kind | Notes |
|---|---|---|---|
| `Initialized` | `bool` | instance | one-time flag for `initialize` |
| `Admin` | `Address` | instance | policy admin; set once at `initialize` |
| `AgentPubkey` | `BytesN<32>` | instance | the agent's Ed25519 public key |
| `Policy` | `PolicyConfig` | persistent | current policy (`None` = default-deny) |
| `Window` | `WindowState` | persistent | rolling spend ledger for asset transfers |
| `LastHeartbeat` | `u64` | persistent | unix seconds of last agent heartbeat (0 = never) |
| `AdminFrozen` | `bool` | persistent | admin-initiated freeze flag |

```rust
#[contracttype]
pub struct PolicyConfig {
    pub per_tx_cap: i128,                 // per asset-transfer call; 0 = disabled
    pub window_secs: u64,                 // rolling window width in seconds (default 86_400)
    pub window_cap: i128,                 // rolling cap within window_secs; 0 = disabled
    pub assets: Vec<Address>,             // SAC token contracts whose transfers get parsed/enforced
    pub protocols: Vec<ProtocolRule>,     // allowlisted non-asset contracts the account may call
    pub recipients: Vec<Address>,         // allowed SAC transfer destinations
    pub allow_any_recipient: bool,        // escape hatch: skip recipient allowlist (still capped)
    pub active_from: u64,                 // unix seconds; 0 = no restriction
    pub active_until: u64,                // unix seconds; 0 = no restriction
    pub paused: bool,                     // admin kill switch
    pub dms_grace_secs: u64,              // dead-man switch grace; 0 = disabled
}

#[contracttype]
pub struct ProtocolRule {
    pub contract: Address,
    pub fns: Option<Vec<Symbol>>,         // None = any function; Some = function allowlist
}

#[contracttype]
pub struct WindowState {
    pub total: i128,                      // cached rolling total
    pub entries: Vec<SpendEntry>,         // chronological; pruned lazily on access
}
#[contracttype]
pub struct SpendEntry { pub ts: u64, pub amount: i128 }
```

### 3.1 The window is genuinely rolling — not a fixed bucket

A fixed 86,400-second bucket (reset-at-midnight style) is a **different guarantee** from a
rolling window and is rejected here. Under a fixed bucket, spend at 23:59 and spend at 00:01
are never counted together even though they are two minutes apart; under a rolling window, any
two spends within any 86,400-second span are counted together. The two guarantees diverge in
exactly the burst-boundary cases a spend guard exists to catch.

Implementation (exact, lazy, bounded):

- Entries are append-ordered by unix ledger time (`env.ledger().timestamp()`, 1s granularity).
- On every evaluation: while `entries[0].ts <= now - window_secs`, pop from the front and
  subtract from `total`. Evaluation is lazy — no cron, no background writes; the O(expired)
  pruning cost amortizes over accesses.
- A new spend coalesces into the trailing entry when it shares the same second
  (`entries.last().ts == now`), so dense bursts in one second stay one entry.
- **Boundedness backstop:** `MAX_WINDOW_ENTRIES = 8192`. If a write would exceed it, the two
  oldest entries are merged into one whose `ts` is the **newer** of the two and whose `amount`
  is the sum. Merging forward over-counts (the older amount then expires later than it truly
  should), which can only make enforcement stricter than policy — it can never admit spend that
  policy would reject. The exact guarantee ("window_cap is a hard ceiling over any
  `window_secs` span") is preserved in all cases; in the pathological region of ≥8192 distinct
  spend seconds within one window the engine is conservative until density drops. This is
  documented here and in the README, not hidden.
- **Measured worst case (single lazy prune burst):** the real bench measurement for the pathological
  case of 8192 stale entries being pruned in one authorization is `worst_case_prune_cpu_cost=86925434`
  CPU instructions (`cargo test prune_worst_case_measured_cost -- --nocapture`). That is a
  real worst-case cost and is over the per-call host budget; the fix is tracked in
  [issue #113](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/113)
  (bulk-prune / sorted search), not a false all-clear. The bounded `MAX_WINDOW_ENTRIES` cap
  also interacts with storage rent/TTL because each persisted window entry is a ledger item that
  must remain live; see [issue #85](https://github.com/Stellar-Agent-Guard/stellar-agent-guard-contracts/issues/85)
  for the long-lived-account rent/TTL model.

**Invariant (window):** for every authorization decision, `total` after any admission equals the
sum of `entries[i].amount` over entries with `ts > now - window_secs`, and a new asset transfer
is admitted only if that running total plus the transfer amount ≤ `window_cap`.

---

## 4. Policy semantics — decision table

Evaluation order inside `__check_auth` (first match wins; all states below are evaluated against
ledger time, which Soroban code cannot forge):

| # | Condition | Result |
|---|---|---|
| 1 | `AdminFrozen` is set | **Block** (`Reason::AdminFrozen`) |
| 2 | dead-man switch enabled AND `LastHeartbeat != 0` AND `now - LastHeartbeat > dms_grace_secs` | **Block** (`Reason::HeartbeatExpired`) — automatic freeze, derived lazily, no background write |
| 3 | no `Policy` stored (revoked or never set) | **Block** (`Reason::NoPolicy`) — default deny |
| 4 | `paused` | **Block** (`Reason::Paused`) |
| 5 | `active_from != 0 && now < active_from`, or `active_until != 0 && now > active_until` | **Block** (`Reason::OutsideActiveWindow`) |
| 6 | context is a call to this account's own administrative/self functions (`heartbeat`, `check`) | allow into §5 handling (heartbeat state update only) |
| 7 | per-context classification (§6) applies all allowlist / cap / window rules | allow or **Block** (`Reason::AssetNotAllowed`, `Reason::RecipientNotAllowed`, `Reason::PerTxCapExceeded`, `Reason::WindowCapExceeded`, `Reason::ProtocolNotAllowed`, `Reason::FunctionNotAllowed`, `Reason::UnknownContract`) |

Note the dead-man auto-freeze (`#2`) applies even to `heartbeat` from the registered key: a
heartbeat arriving after the grace window expired cannot revive the account — revival is the
admin's `unfreeze` (§7). This is the precise freeze/reversal boundary.

### 4.1 Gate cost order (measured)

The decision table above is ordered **semantically first** (admin freeze → dead-man → policy gates → classification), not cost-optimized. Benchmarks on the Soroban test environment (see `benches/denial_path_gas.rs`) show the following CPU instruction costs for a blocked authorization at each gate:

| Gate | Condition | Approx. Instructions |
|------|-----------|---------------------|
| 1 | `AdminFrozen` | ~8,750 |
| 2 | `HeartbeatExpired` | ~8,750 |
| 3 | `NoPolicy` | ~8,750 |
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

**Observation:** The early gates (#1–#5) are consistently the cheapest (~8.7k instructions) because they only check simple boolean/int flags on the account state. The classification gates (#7a–#7g) are more expensive because they require parsing the auth context, looking up allowlists, and evaluating caps. The semantic ordering therefore *accidentally* aligns with cost ordering: the cheapest gates run first. Reordering for cost would not yield meaningful savings and would weaken the semantic clarity of the freeze/reversal boundary (admin freeze must remain first). The delta between semantic and cost-optimal ordering is immaterial (<2x on the fast path).

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
- **Freeze mechanism:** automatic and *lazy*. There is no stored "auto-frozen" flag — rule #2
  derives it from `LastHeartbeat` and ledger time on every authorization, so the account is
  frozen the moment the grace elapses, with zero transactions and zero background writes
  required, and can never be "unfrozen by time passing."
- **Manual freeze:** `freeze()` (admin) sets `AdminFrozen = true` — immediate, and blocks even a
  live, heartbeating agent.
- **Reversal path (explicit):** `unfreeze()` (admin only) clears `AdminFrozen` **and** sets
  `LastHeartbeat = now`. The admin's signature is the liveness attestation that revives the
  account; a subsequently-heartbeating agent keeps it alive from there. Admin freeze and
  heartbeat-expiry are separate conditions; `unfreeze` clears the former, rule #2 keeps
  evaluating the latter.

---

## 6. Per-context classification and rule application

Each `Context` in `auth_contexts` is classified independently; every context must pass or the
whole authorization fails (`__check_auth` returns an error → transaction rejected).

### 6.1 Self-calls

Context whose `contract == env.current_contract_address()`. Allowed function set for v1:
`heartbeat`. (Any other self-function is blocked by default.) No spend rules apply.

### 6.2 Asset (SAC) calls — fully enforced

`contract ∈ policy.assets` **and** `fn_name ∈ { "transfer", "transfer_from" }`. These are the
calls whose semantics and arguments are known:

- `transfer` args: `(from, to, amount)` — the account is `from`; recipient = args[1], amount = args[2].
- `transfer_from` args: `(from, spender, to, amount)` — the account is `from`; recipient = args[2], amount = args[3].

Rules applied:

1. **Recipient allowlist:** if `allow_any_recipient == false`, `recipient ∈ policy.recipients`
   or block `RecipientNotAllowed`.
2. **Per-tx cap:** if `per_tx_cap != 0`, `amount <= per_tx_cap` or block `PerTxCapExceeded`.
3. **Rolling window (§3.1):** if `window_cap != 0`, prune expired entries, then
   `total + amount <= window_cap` or block `WindowCapExceeded`; on admission, update
   `total`/`entries`.
4. Amount validity: `amount > 0` or block `InvalidAmount`.

An asset contract listed in `assets` invoked with any other function (e.g. `mint`, `burn`,
`set_admin`, `clawback` — none of which the account should ever call as authorizer) is blocked
(`FunctionNotAllowed`). Asset addresses *not* listed in `assets` are blocked
(`AssetNotAllowed`) — an agent cannot silently move balances on an unregistered SAC. This keeps
the "we know what we're enforcing" promise exact.

### 6.3 Protocol calls — allowlist only (window/pause state still enforced)

`contract ∈ policy.protocols` (each with optional per-function allowlist). Allowed calls are
authorized; per-call amount/recipient limits do **not** apply because the arguments of an
arbitrary protocol are not interpretable (§2). Functions not in a rule's `fns` allowlist (when
present) are blocked `FunctionNotAllowed`.

### 6.4 Anything else — blocked

A context whose contract is not the account itself, not in `assets`, and not in `protocols`
is blocked (`UnknownContract`). The account is **default-deny**: adding a protocol is an
explicit policy act, and the roll-out of fine-grained enforcement for such calls (v2) never has
to weaken an allowlist that already exists.

**Boundary stated exactly:** pause (#4), active-window (#5), and dead-man/admin freeze (#1–#2)
are *transaction-level* gates applied before classification, so they bind every call the
account makes, SAC or protocol. Spend caps and rolling-window accounting bind SAC asset
transfers only. Recipient allowlists bind SAC asset transfers only.

---

## 7. Public surface — exact signatures and auth placement

Auth placement rule used throughout: **the authority that can change a thing is the authority
named by the change.** Admin (classic or contract address) governs policy and freeze; the
registered agent key (verified through the account's own `__check_auth`) may only heartbeat and
transact within policy. No function moves funds; funds move only through the agent's own
authorized transactions.

```rust
// ── Lifecycle ─────────────────────────────────────────────────────────────
pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>)
    // require_auth(admin). Exactly once (AlreadyInitialized otherwise). Stores
    // Admin and AgentPubkey; no policy yet -> account is default-deny until set_policy.

// ── Policy management (admin only) ────────────────────────────────────────
pub fn set_policy(env: Env, config: PolicyConfig)
    // require_auth(Admin). Validates config (§8). Replaces Policy and resets
    // Window (fresh window on every policy change — documented, admin-attested).
pub fn revoke_policy(env: Env)
    // require_auth(Admin). Removes Policy and Window -> default-deny immediately.
pub fn rotate_agent_key(env: Env, new_pubkey: BytesN<32>)
    // require_auth(Admin). Re-binds AgentPubkey. Admin never gains fund-moving
    // power; it can only replace the key the account will authenticate.

// ── Dead-man switch (see §5) ──────────────────────────────────────────────
pub fn heartbeat(env: Env)
    // require_auth(env.current_contract_address()) — i.e., routes through
    // __check_auth, which verifies the registered agent key. Records LastHeartbeat.
    // Blocked when AdminFrozen or grace already expired.
pub fn freeze(env: Env)      // require_auth(Admin); sets AdminFrozen = true
pub fn unfreeze(env: Env)    // require_auth(Admin); clears AdminFrozen, LastHeartbeat = now

// ── Read / advisory (no auth — safe reads only, nothing confidential) ─────
pub fn policy(env: Env) -> Option<PolicyConfig>       // current policy
pub fn status(env: Env) -> Status                     // frozen? admin_frozen? last_heartbeat? now?
pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult
    // Pure pre-flight replica of the §6.2 decision path (same code, no writes):
    // lets agents/SDK simulate an asset transfer before signing. Emits the same
    // events as an in-path decision so telemetry sees one vocabulary.
pub fn check_detailed(env: Env, asset: Address, to: Address, amount: i128) -> CheckDetail
  // Same zero-write pre-flight, with remaining_window and effective cap metrics.

// ── Enforcement (host-invoked; not callable by anyone) ────────────────────
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;
    fn __check_auth(env, signature_payload: Hash<32>, signatures: BytesN<64>,
                    auth_contexts: Vec<Context>) -> Result<(), Error>;
    // 1. ed25519_verify(AgentPubkey, signature_payload, signatures) or Unauthorized.
    // 2. Decision table §4 + classification §6 over every context.
    // 3. Events (§9) + storage writes only on admission.
}
```

`Status` / `CheckResult` / `CheckDetail` / reasons:

**Wire format:** Exact JSON serialization for non-Rust consumers (SDK, dashboard) is documented in [Wire Format](docs/research/wire-format.md) — includes field names, enum tagging convention (`Allowed` bare vs `{"Blocked":"reason"}`), and decoder-breakage warning.

```rust
#[contracttype]
pub struct Status { pub admin_frozen: bool, pub heartbeat_expired: bool,
                   pub last_heartbeat: u64, pub now: u64, pub has_policy: bool,
                   pub policy_revision: u64 }

#[contracttype]
pub enum CheckResult { Allowed, Blocked(BlockReason) }

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
    Unauthorized = 1, AlreadyInitialized = 2, NotInitialized = 3,
    InvalidConfig = 4, InvalidAmount = 5,
    AdminFrozen = 10, HeartbeatExpired = 11, NoPolicy = 12, Paused = 13,
    OutsideActiveWindow = 14,
    AssetNotAllowed = 20, RecipientNotAllowed = 21, PerTxCapExceeded = 22,
    WindowCapExceeded = 23, ProtocolNotAllowed = 24, FunctionNotAllowed = 25,
    UnknownContract = 26, SelfFunctionNotAllowed = 27,
}
```

`check_detailed` loads and prunes only an in-memory copy of the rolling ledger.
It writes no ledger state and emits the same `auth_checked` event, with the same
`allowed`/`blocked` result and reason, as `check`. `remaining_window` is the
capacity available before the requested transfer; it is `None` when the rolling
window cap is disabled. The configured and effective caps are `None` when
disabled; v1 has no per-asset overrides, so effective caps equal configured caps.

---

## 8. Config validation (`set_policy`)

- All amounts `>= 0`; `window_secs` and `dms_grace_secs` are `u64` (no negatives possible).
- `window_cap != 0` requires `window_secs != 0`.
- `active_until == 0 || active_until > active_from`.
- Assets, protocols, recipients, and per-protocol fn lists must be non-empty for their
  respective vectors to matter (empty `assets` = no SAC transfer is ever allowed; empty
  `recipients` with `allow_any_recipient == false` = no recipient allowed).
- Duplicate addresses within a list are rejected.
- Self-address may not appear in `assets`/`protocols`.

Invalid config → `InvalidConfig`, policy unchanged (fail-closed, never partially applied).

---

## 9. Events and telemetry

Events are the contract's audit trail and Phase-2 telemetry vocabulary. Topics chosen for cheap
filtering by the SDK listener.

| Event | Topics | Data | Emitted |
|---|---|---|---|
| `auth_checked` | `result: Symbol` (`allowed`/`blocked`), `reason: Symbol` | — | every `__check_auth` / `check` decision |
| `heartbeat` | — | `at: u64` | on agent heartbeat (skipped when `now == LastHeartbeat`; §5) |
| `frozen` / `unfrozen` | — | `by: Address` | admin freeze / unfreeze |
| `policy_set` / `policy_revoked` | — | `by: Address` | admin policy changes |
| `agent_rotated` | — | `by: Address`, `old_fingerprint: BytesN<8>`, `new_fingerprint: BytesN<8>` | admin agent-key rotation |

Reason symbols mirror `BlockReason`/`Error` naming so off-chain code maps one vocabulary.

**Key fingerprints (`agent_rotated`).** A fingerprint is `sha256(pubkey)[0..8]` — the first
8 bytes of the SHA-256 digest of the agent public key, rendered as 16 lowercase hex characters
off-chain. Rotations record both endpoints (outgoing and incoming) so an auditor can reconstruct
"when did key K stop being authoritative" from the append-only event log; the full public key is
never repeated in event data (it is already public at `initialize`). SDK/dashboard decoders must
render the `BytesN<8>` data fields as hex — a cross-repo follow-up tracked in those repositories.

---

## 10. Threat model (what this does and does not do)

Guarded against, on-chain and unbypassable (a compromised agent key cannot exceed policy —
spend caps, allowlists, freeze, default-deny all execute inside `__check_auth` before any value
moves):
- runaway/overspend loops (per-tx + rolling window caps)
- payment to unauthorized recipients (recipient allowlist on asset transfers)
- calls to unauthorized protocols/functions (protocol allowlist + default-deny)
- agent disappearance (dead-man switch) and operator-initiated halt (freeze/pause)

Not guarded by v1 (documented, not hidden):
- fine-grained amount/recipient limits on non-SAC protocol calls (§2, v2 item)
- a live attacker who keeps the agent key heartbeating (caps still bind them; the switch only
  fires on silence)
- admin compromise (admin can freeze and rewrite policy/keys — that is its function; it still
  cannot move funds)
- DoS on the *account* is not possible (anyone may call read functions); policy writes are
  admin-only. The contract is unaudited; see `SECURITY.md`/README disclaimers.

---

## 11. Testnet proof plan (five scenarios)

Executed against a real testnet deployment; evidence (contract IDs, tx hashes, event output) is
recorded in `tests/fixtures/README.md` as required by Phase 1 exit criteria:

1. **Allowed transaction** — policy-respecting asset transfer succeeds.
2. **Per-tx cap violation** — transfer above `per_tx_cap` is blocked on-chain.
3. **Rolling-window cap violation** — cumulative spend across separate transactions inside one
   `window_secs` span exceeds `window_cap`; the later one is blocked (then a window rollover
   restores spending, proving it is rolling).
4. **Allowlist violation** — transfer to a recipient outside the allowlist is blocked.
5. **Dead-man switch trigger + reversal** — heartbeat stops past `dms_grace_secs`; a subsequent
   spend is blocked with `HeartbeatExpired`; admin `unfreeze` + fresh heartbeat restores it.

Unit + invariant tests (Soroban test env, real host semantics) cover the decision table, the
window invariant, auth-context parsing, signature verification, freeze/reversal, and default
deny. Gates: `cargo test` green, `cargo clippy --all-targets --all-features` clean with
`warnings`/`clippy::all`/`clippy::pedantic` deny, `cargo fmt --check` clean, CI (`ci` job) green
on `main`.
