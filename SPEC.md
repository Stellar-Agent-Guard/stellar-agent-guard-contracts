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

*Canonical statement: the paragraph above is the single source of truth for the scope
wording. The README and `docs/enforcement-scope.md` carry short excerpts that link back
here; scope-wording edits touch this section only (CONTRIBUTING rule 2).*

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
and `docs/enforcement-scope.md` quote this section briefly and link here as canonical.

**Research note (v2):** The decomposition of "fine-grained non-SAC enforcement" into honest sub-strategies (protocol-specific parsers, declared-max, return-value commitments) is documented in [Non-SAC Enforcement](docs/research/non-sac-enforcement.md). Count-based protocol call rate limiting (v1) is now implemented; opt-in protocol parsers remain a secondary track.

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
| `Window` | `WindowState` | persistent | rolling spend ledger for asset transfers (global + per-recipient) |
| `LastHeartbeat` | `u64` | persistent | unix seconds of last agent heartbeat (0 = never) |
| `AdminFrozen` | `bool` | persistent | admin-initiated freeze flag |

```rust
#[contracttype]
pub struct PolicyConfig {
    pub per_tx_cap: i128,                    // per asset-transfer call; 0 = disabled
    pub window_secs: u64,                    // rolling window width in seconds (default 86_400)
    pub window_cap: i128,                    // rolling cap within window_secs; 0 = disabled
    pub assets: Vec<Address>,                // SAC token contracts whose transfers get parsed/enforced
    pub protocols: Vec<ProtocolRule>,        // allowlisted non-asset contracts the account may call
    pub recipients: Vec<Address>,            // allowed SAC transfer destinations
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
    pub contract: Address,
    pub fns: Option<Vec<Symbol>>,         // None = any function; Some = function allowlist
}

#[contracttype]
pub struct RecipientCap {
    pub recipient: Address,
    pub cap: i128,                        // per-recipient rolling cap within window_secs; 0 = disabled / global fallback
}

#[contracttype]
pub struct WindowState {
    pub total: i128,                      // cached rolling global total
    pub entries: Vec<SpendEntry>,         // chronological global spend entries; pruned lazily on access
    pub recipients: Vec<RecipientWindowState>, // per-recipient rolling ledgers for recipients with override caps
    pub protocol_call_entries: Vec<ProtocolCallEntry>, // rolling protocol call count entries; pruned lazily
}

#[contracttype]
pub struct RecipientWindowState {
    pub recipient: Address,
    pub total: i128,                      // cached rolling total for this recipient
    pub entries: Vec<SpendEntry>,          // chronological entries for this recipient
}

#[contracttype]
pub struct SpendEntry { pub ts: u64, pub amount: i128 }

#[contracttype]
pub struct ProtocolCallEntry { pub ts: u64, pub count: u32 }  // coalesced call count per second
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

**Invariant (window):** for every authorization decision, the global `total` after any admission equals the
sum of `entries[i].amount` over global entries with `ts > now - window_secs`, and a new asset transfer
is admitted only if the running total (plus amounts already staged in the same request) ≤ the
effective cap for that transfer. Per-recipient overrides maintain the same invariant in their own
`RecipientWindowState`; recipients without an override use the global cap. Both the global cap
and any matching per-recipient cap must be satisfied.

### 3.2 Exact ScVal encoding of `PolicyConfig` (for non-TypeScript consumers)

The SDK's `policyToScVal` is currently the only reference encoder, and it is TypeScript. This
section pins the on-wire `ScVal` layout so Go/Python/Rust integrators (or a future CLI) can
implement encoders without reverse-engineering TS source. The layout below was derived from the
soroban-sdk 27 `#[contracttype]` derives (the host is the ultimate referee) and is locked by
`tests/policyconfig_scval_encoding.rs`, which fails `cargo test` if a field, the key order, or a
primitive's `ScVal` variant changes.

**Top level:** `ScVal::Map` with exactly **13 entries**, one per field. The map keys are the
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
| 9 | `protocols` | `Vec<ProtocolRule>` | `Vec` | elements are 2-entry maps, see below |
| 10 | `recipient_window_caps` | `Vec<RecipientCap>` | `Vec` | elements are 2-entry maps, see below |
| 11 | `recipients` | `Vec<Address>` | `Vec` | account addresses |
| 12 | `window_cap` | `i128` | `I128` | 0 = disabled |
| 13 | `window_secs` | `u64` | `U64` | |

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

- `u64` → `ScVal::U64`. There are no unsigned-32 fields in `PolicyConfig`.
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
  "assets": ["CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"],
  "blocked_recipients": [],
  "dms_grace_secs": 60, "paused": false, "per_tx_cap": "1000",
  "protocols": [], "recipient_window_caps": [],
  "recipients": ["GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"],
  "window_cap": "150", "window_secs": 60
}
```

The same policy as a structural `ScVal` tree (keys in mandatory sorted order):

```text
ScVal::Map(Some(vec![
  ("active_from",         U64(0)),
  ("active_until",        U64(0)),
  ("allow_any_recipient", Bool(false)),
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

**Exact arity required; extra args deny -- we do not partially parse.** A call whose argument list does not match the SAC schema exactly (`transfer` = 3, `transfer_from` = 4) is rejected with `UnknownContract` and never reaches the cap/allowlist evaluation. We only enforce what we fully understand; a context carrying extra trailing values is treated as a call we cannot reason about (conservative default-deny).

Rules applied (in order; the denylist is checked before the allowlist/escape hatch):

1. **Recipient denylist:** if `recipient ∈ policy.blocked_recipients`, block
   `RecipientBlocked`. The denylist wins over both the allowlist and
   `allow_any_recipient`.
2. **Recipient allowlist:** if `allow_any_recipient == false`, `recipient ∈ policy.recipients`
   or block `RecipientNotAllowed`.
3. **Per-tx cap:** if `per_tx_cap != 0`, `amount <= per_tx_cap` or block `PerTxCapExceeded`.
4. **Rolling window (§3.1):**
   - Global window: if `window_cap != 0`, prune expired entries, then
     `total + amount <= window_cap` or block `WindowCapExceeded`.
   - Per-recipient window: if `recipient` has an entry in `policy.recipient_window_caps` with
     `cap > 0`, use that cap against the recipient's own rolling ledger; otherwise fall back to
     the global window cap. If the effective cap is exceeded, block `WindowCapExceeded`.
   - On admission, update the global ledger and, when a per-recipient cap applies, the
     recipient's ledger.
5. Amount validity: `amount > 0` or block `InvalidAmount`.

An asset contract listed in `assets` invoked with any other function (e.g. `mint`, `burn`,
`set_admin`, `clawback` — none of which the account should ever call as authorizer) is blocked
(`FunctionNotAllowed`). Asset addresses *not* listed in `assets` are blocked
(`AssetNotAllowed`) — an agent cannot silently move balances on an unregistered SAC. This keeps
the "we know what we're enforcing" promise exact.

### 6.3 Protocol calls — allowlist only (window/pause state still enforced)

`contract ∈ policy.protocols` (each with optional per-function allowlist). Allowed calls are
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
is blocked (`UnknownContract`). The account is **default-deny**: adding a protocol is an
explicit policy act, and the roll-out of fine-grained enforcement for such calls (v2) never has
to weaken an allowlist that already exists.

**Boundary stated exactly:** pause (#4), active-window (#5), and dead-man/admin freeze (#1–#2)
are *transaction-level* gates applied before classification, so they bind every call the
account makes, SAC or protocol. Spend caps and rolling-window accounting bind SAC asset
transfers only. Recipient allowlists bind SAC asset transfers only.

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

### 7.1 Error code ↔ CheckResult variant ↔ reason symbol mapping

To close the CheckResult/Error duality gap, every contract `Error` variant maps 1:1 to a `BlockReason` symbol emitted in `CheckResult::Blocked` and `auth_checked` events. The table below records the complete correspondence, including auth-only or admin-only variants that are unreachable via `check()` pre-flight reads and their rationale.

| Error Code | Error Variant | Reason Symbol (`CheckResult::Blocked`) | Reachable via `check()`? | Rationale for Unreachable Direction |
|---|---|---|---|---|
| 1 | `Unauthorized` | `unauthorized` | No | Auth-path only: signature validation or admin auth failure traps before policy check. |
| 2 | `AlreadyInitialized` | `already_initialized` | No | Admin lifecycle op: initialize is run once during deployment setup, not a check parameter. |
| 3 | `NotInitialized` | `not_initialized` | Yes | Pre-activation guard check. |
| 4 | `InvalidConfig` | `invalid_config` | No | Admin op: `set_policy` validation error; policies are not passed into `check()`. |
| 5 | `InvalidAmount` | `invalid_amount` | Yes | Checked directly in `check()` input arguments. |
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
| 26 | `UnknownContract` | `unknown_contract` | No | Auth-path only: unlisted contracts are encountered in auth contexts. |
| 27 | `SelfFunctionNotAllowed` | `self_function_not_allowed` | No | Auth-path only: self-calls are part of `__check_auth` context dispatch. |
| 28 | `CreateContractNotAllowed` | `create_contract_not_allowed` | No | Auth-path only: contract creation host functions occur in auth contexts. |
| 29 | `RecipientBlocked` | `recipient_blocked` | Yes | Recipient is on the explicit denylist.

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

// ── Read / advisory (no auth; non-confidential state; TTL effects in §9.5) ──
pub fn policy(env: Env) -> Option<PolicyConfig>       // current policy
pub fn status(env: Env) -> Status                     // operational snapshot (see Status block below):
                                                      // paused / window_remaining / outside_active_window
                                                      // / admin_frozen / heartbeat_expired / revision
pub fn dms_health(env: Env) -> DmsHealth                  // ok, warn (>=80%), or expired
pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult
    // Preflight / simulate a transfer (doc alias; ABI frozen as `check`):
    // pure pre-flight replica of the §6.2 decision path: it does not change
    // spend accounting, but a submitted call may refresh TTLs under §9.5.
    // Simulation before signing does not persist those rent bumps.
pub fn check_detailed(env: Env, asset: Address, to: Address, amount: i128) -> CheckDetail
  // Same preflight / simulate path, with remaining_window and effective cap metrics.
  // `remaining_window` reflects the effective cap for the queried recipient
  // (per-recipient override if configured, otherwise global cap).

// ── Enforcement (host-invoked; not callable by anyone) ────────────────────
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;
    fn __check_auth(env, signature_payload: Hash<32>, signatures: BytesN<64>,
                    auth_contexts: Vec<Context>) -> Result<(), Error>;
    // 1. ed25519_verify(AgentPubkey, signature_payload, signatures) or Unauthorized.
    // 2. Decision table §4 + classification §6 over every context.
    // 3. Events (§9) + TTL refreshes (§9.5); spend-accounting writes only on admission.
}
```

`Status` / `CheckResult` / `CheckDetail` / reasons:

**Wire format:** Exact JSON serialization for non-Rust consumers (SDK, dashboard) is documented in [Wire Format](docs/research/wire-format.md) — includes field names, enum tagging convention (`Allowed` bare vs `{"Blocked":"reason"}`), and decoder-breakage warning.

```rust
#[contracttype]
pub struct Status { pub admin_frozen: bool, pub heartbeat_expired: bool,
                   pub last_heartbeat: u64, pub now: u64, pub has_policy: bool,
                   pub policy_revision: u64,
                   pub paused: bool, pub window_remaining: Option<i128>,
                   pub outside_active_window: bool }
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
    CreateContractNotAllowed = 28,
    RecipientBlocked = 29,
}
```

`check_detailed` loads and prunes only an in-memory copy of the rolling ledger;
it does not change spend accounting. A submitted invocation may refresh persistent
entry TTLs under §9.5 and emits the same `auth_checked` event, with the same
`allowed`/`blocked` result and reason, as `check`. `remaining_window` is the
capacity available before the requested transfer; it is `None` when no effective
window cap applies to the queried recipient (no global `window_cap` and no
per-recipient override). The configured and effective caps are `None` when
disabled; v1 has no per-asset overrides, so the effective per-transaction cap
equals the configured cap.

### 7.2 Preflight / simulate a transfer (doc alias for `check`)

`check(asset, to, amount)` is the permissionless **preflight** / **simulate**
entrypoint: a pure pre-flight replica of the §6.2 SAC-transfer decision path
for agents and SDKs to call before signing. Search for "preflight",
"simulate", or `simulate_transfer` to find it.

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
`allow_any_recipient`, `assets`, `blocked_recipients`, `dms_grace_secs`, `paused`,
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

---

## 8. Config validation (`set_policy`)

> **Starter configs.** Copy-paste `PolicyConfig` presets for common operator personas
> (day-trader, payments bot, watch-only, max security) — each with rationale, explicit
> "what it does NOT protect against", and unaudited/mainnet/DMS-grace warnings — are in
> [`docs/policy-templates.md`](docs/policy-templates.md). A CI test installs every preset
> documented there, so the examples cannot rot into invalid configs.

- All amounts `>= 0`; `window_secs` and `dms_grace_secs` are `u64` (no negatives possible).
- `window_cap != 0` requires `window_secs != 0`.
- A per-recipient cap `> 0` requires `window_secs != 0`.
- `active_until == 0 || active_until > active_from`.
- Assets, protocols, recipients, and per-protocol fn lists must be non-empty for their
  respective vectors to matter (empty `assets` = no SAC transfer is ever allowed; empty
  `recipients` with `allow_any_recipient == false` = no recipient allowed).
- Duplicate addresses within a list are rejected (`assets`, `recipients`,
  `blocked_recipients`, `protocols`).
- Duplicate recipients within `recipient_window_caps` are rejected.
- `recipients`, `blocked_recipients`, and `recipient_window_caps` are each bounded to
  `MAX_RECIPIENT_ENTRIES` (256) entries to keep allowlist/denylist scans and
  per-recipient storage predictable.
- `recipients` and `blocked_recipients` must not intersect — a contradictory config is
  rejected.
- The contract's own address may not appear in **any** of the address lists:
  - `assets` — the guard is not an SAC; self-calls are governed by the fixed §6.1 rule, not
    by policy, so a self-entry would be a nonsensical allowlist.
  - `protocols` — same: allowlisting the account to call itself through the policy path is
    meaningless (and §6.1 already decides what self-calls are allowed).
  - `recipients` and `blocked_recipients` — the account paying itself is a no-op loop (a
    self-debit/re-credit of the same SAC balance) with no purpose; allowing it adds no
    capability while making a mis-pasted recipient address look like a deliberate policy.
    Rejected (recommended: catches typos) rather than allowed-with-documentation.
  - The same rule applies to `recipient_window_caps` entries.
  The self-address is known pre-`initialize` (`env.current_contract_address()` is a
  deployment-time constant), and `set_policy` can only run post-initialize, so the check
  always compares against the real deployed contract ID.

Invalid config → `InvalidConfig`, policy unchanged (fail-closed, never partially applied).

---

## 9. Events and telemetry

Events are the contract's audit trail and Phase-2 telemetry vocabulary. Topics chosen for cheap
filtering by the SDK listener.

| Event | Topics | Data | Emitted |
|---|---|---|---|
| `auth_checked` | `result: Symbol` (`allowed`/`blocked`), `reason: Symbol` | (none) | every `__check_auth` / `check` decision |
| `heartbeat` | (none) | `at: u64`, `expires_at: u64` — the attested DMS deadline as it stood at emission time, `at + dms_grace_secs` of the policy current at that moment; `0` when the dead-man switch is disabled (`dms_grace_secs == 0`, or no policy) | on agent heartbeat (skipped when `now == LastHeartbeat`; §5) |
| `initialized` | (none) | `by: Address` | contract initialization |
| `frozen` | (none) | `by: Address` | admin freeze |
| `unfrozen` | (none) | `by: Address`, `rearmed_dms: bool` — whether `LastHeartbeat` was changed (DMS clock re-armed; §5) | admin unfreeze |
| `policy_set` / `policy_revoked` | (none) | `by: Address` | admin policy changes |
| `agent_rotated` | (none) | `by: Address`, `old_fingerprint: BytesN<8>`, `new_fingerprint: BytesN<8>` | admin agent-key rotation |

Reason symbols mirror `BlockReason`/`Error` naming so off-chain code maps one vocabulary.

**Heartbeat expiry (`heartbeat.expires_at`).** `expires_at` is the deadline the heartbeat was
actually attested under, derived from the `dms_grace_secs` of the policy *current at the moment
the heartbeat is emitted* — not a value the consumer recomputes from `at` using whatever grace
the policy carries later. A `set_policy` that changes `dms_grace_secs` after a heartbeat does not
retroactively change that heartbeat's recorded deadline, so a listener replaying the log derives
the same expiry the contract enforced instead of a drifting recomputation. When the dead-man
switch is disabled the event carries `expires_at == 0` rather than `at + 0`, so `0` unambiguously
means "no deadline was attested" and never a real timestamp (ledger timestamps are far above `0`).
Reads `Policy` at emission time to obtain the grace; a missing policy reads as disabled.

**Key fingerprints (`agent_rotated`).** A fingerprint is `sha256(pubkey)[0..8]` — the first
8 bytes of the SHA-256 digest of the agent public key, rendered as 16 lowercase hex characters
off-chain. Rotations record both endpoints (outgoing and incoming) so an auditor can reconstruct
"when did key K stop being authoritative" from the append-only event log; the full public key is
never repeated in event data (it is already public at `initialize`). SDK/dashboard decoders must
render the `BytesN<8>` data fields as hex — a cross-repo follow-up tracked in those repositories.

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
expired. See [issue #43](https://github.com/aigbagbobila/stellar-agent-guard-contracts/issues/43)
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

Not guarded by v1 (documented, not hidden):
- fine-grained amount/recipient limits on non-SAC protocol calls (§2, v2 item)
- a live attacker who keeps the agent key heartbeating (caps still bind them; the switch only
  fires on silence)
- admin compromise (admin can freeze and rewrite policy/keys — that is its function; it still
  cannot move funds)
- DoS on the *account* is not possible (anyone may call read functions); policy writes are
  admin-only. The contract is unaudited; see `SECURITY.md`/README disclaimers.

### 10.1 Signature binding

**What the payload covers.** `__check_auth` step 1 is
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
- *Agent signature ≠ admin authority.* An agent signature clears step 1 only for auth
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
