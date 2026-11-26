use soroban_sdk::{contracterror, contracttype, Address, BytesN, Env, Symbol, Vec};

use soroban_sdk::{contracterror, contracttype, Address, Bytes, Env, Symbol, Vec};

/// The policy-model format version this contract implements (issue #339).
///
/// Recorded in instance storage at `initialize` and surfaced by the
/// `policy_version()` read, so an operator, indexer, or SDK can tell which
/// `PolicyConfig` wire model a deployed guard was built against. Bumping this
/// constant is a deliberate, reviewed act: it must change whenever the shape
/// or meaning of `PolicyConfig` changes (additive fields included — an older
/// consumer cannot know a new field exists), never for a pure implementation
/// change, and never by reusing a value.
///
/// Version policy: the value is a single monotonic integer. An additive-only
/// change increments it by one and remains compatible with older consumers
/// (which must still refuse a version they do not know); a breaking change
/// increments it by one **and** ships as a new contract release with a
/// documented migration. `0` is never a valid format version — the read
/// returns it only before `initialize`.
pub const POLICY_FORMAT_VERSION: u32 = 1;

/// Warning threshold percentage for dead-man switch health evaluation (80%).
pub const DMS_WARN_THRESHOLD_PERCENT: u64 = 80;

/// Dead-man switch health status returned by `dms_health`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmsHealthStatus {
    /// Grace period is below the warning threshold.
    Ok,
    /// Grace period is at least 80% elapsed but has not expired.
    Warn,
    /// Grace period has elapsed.
    Expired,
}

/// Hard bound on rolling-window entries. Above this, the engine merges the two
/// oldest entries forward (conservative over-count) — see SPEC §3.1.
///
/// The width is `u32` because that is what `soroban_sdk::Vec::len()` returns and
/// what `Ledger::len()` exposes, so the bound and the backstop comparison in
/// `window.rs` need no `as` casts (issue #338).
pub const MAX_WINDOW_ENTRIES: u32 = 8192;

/// Hard bound on auth contexts evaluated in one authorization (SPEC §4/§6).
/// Sixty-four admits large DEX batches while bounding worst-case decision work.
pub const MAX_AUTH_CONTEXTS: usize = 64;

/// Maximum number of asset contracts in a policy (SPEC §8).
pub const MAX_POLICY_ASSETS: usize = 256;

/// Maximum number of protocol contracts in a policy (SPEC §8).
pub const MAX_POLICY_PROTOCOLS: usize = 256;

/// Hard bound on the number of entries in `recipients`, `blocked_recipients`,
/// and `recipient_window_caps`. Keeps allowlist scans and per-recipient
/// storage bounded and predictable (SPEC §3 / §8).
pub const MAX_RECIPIENT_ENTRIES: usize = 256;

/// Hard bound on the number of entries in `asset_caps`. Keeps per-asset cap
/// admission and validation scans bounded and predictable (SPEC §3 / §8).
pub const MAX_ASSET_CAP_ENTRIES: usize = 256;

/// Upper bound on `window_secs` and `dms_grace_secs` (issue #34). `3_650` days
/// ≈ 10 years: far beyond any legitimate rolling spend window or dead-man
/// grace, while still catching the classic seconds/milliseconds confusion
/// (e.g. a 90-day window passed as `7_776_000_000` ms) and "effectively
/// disables pruning forever" configs such as `u64::MAX`.
pub const MAX_WINDOW_SECS: u64 = 315_360_000; // 86_400 × 3_650
/// Same upper bound as `MAX_WINDOW_SECS`, applied to the DMS grace.
pub const MAX_DMS_GRACE_SECS: u64 = MAX_WINDOW_SECS;

/// Upper bound on every cap magnitude in a policy: `per_tx_cap`, `window_cap`,
/// `asset_caps[i].per_tx_cap`, and `recipient_window_caps[i].cap` (issue #321).
///
/// `10^24` smallest units is a deliberately generous ceiling that no realistic
/// token supply can reach: at Stellar's usual 7 decimals it is `10^17` whole
/// tokens, roughly two million times the entire XLM supply (~`5 × 10^10` XLM =
/// `5 × 10^17` stroops). Above it a "cap" is indistinguishable from "unlimited"
/// while still reading as policy, and the account still pays for a window
/// ledger that nothing will ever prune.
///
/// The bound also keeps the saturating additions in `window.rs` / `engine.rs`
/// belt-and-braces rather than load-bearing: even the pathological window
/// (8192 entries, each at the ceiling) totals ~`8.2 × 10^27`, more than ten
/// orders of magnitude below `i128::MAX` (`≈1.7 × 10^38`). `0` (disabled)
/// remains legal, and the boundary value itself is accepted.
pub const MAX_CAP_MAGNITUDE: i128 = 1_000_000_000_000_000_000_000_000;

/// Which SPEC §8 validation rule rejected a policy (issue #35). `validate_policy`
/// reports the **first** failing rule. Variants added after the original set
/// preserve their established contract-type ordinals.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyRuleId {
    /// `per_tx_cap` or `window_cap` is negative.
    AmountSign,
    /// `window_cap != 0` (or a per-recipient cap `> 0`) requires
    /// `window_secs != 0`.
    WindowRequiresWidth,
    /// `active_until != 0 && active_until <= active_from`.
    ActiveWindowOrder,
    /// The contract's own address appears in `assets`, `protocols`,
    /// `recipients`, `blocked_recipients`, or a `recipient_window_caps` entry.
    SelfAddressInList,
    /// A duplicate address within `assets`, `recipients`,
    /// `blocked_recipients`, or a duplicate fn name within one protocol rule.
    DuplicateAddressInList,
    /// The same recipient appears twice in `recipient_window_caps`.
    DuplicateRecipientCap,
    /// `recipients`, `recipient_window_caps`, or `blocked_recipients`
    /// exceeds `MAX_RECIPIENT_ENTRIES`.
    RecipientListTooLong,
    /// A per-recipient cap is negative.
    RecipientCapSign,
    /// A recipient is listed in both `recipients` and `blocked_recipients`.
    RecipientAllowAndBlocked,
    /// The same contract appears in two protocol rules.
    ProtocolContractDuplicate,
    /// A protocol rule's fn list is empty or contains duplicates.
    ProtocolFnListInvalid,
    /// `window_secs` or `dms_grace_secs` exceeds `MAX_WINDOW_SECS`
    /// (`315_360_000` s ≈ 10 years; issue #34). Evaluated after the other
    /// rules so the previously documented variant ordinals stay wire-stable.
    DurationExceedsBound,
    /// `assets` exceeds `MAX_POLICY_ASSETS`.
    AssetListTooLong,
    /// `protocols` exceeds `MAX_POLICY_PROTOCOLS`.
    ProtocolListTooLong,
    /// `per_tx_cap > window_cap` when both are enabled (both > 0; issue #33).
    PerTxCapExceedsWindowCap,
    /// `asset_caps` exceeds `MAX_ASSET_CAP_ENTRIES`.
    AssetCapListTooLong,
    /// An `asset_caps` entry overrides an asset not present in `assets`.
    AssetCapUnknownAsset,
    /// The same asset appears twice in `asset_caps`.
    DuplicateAssetCap,
    /// A contract appears in both `assets` and `protocols` (issue #296).
    /// Appended last so the previously documented variant ordinals stay
    /// wire-stable.
    AssetProtocolOverlap,
    /// A cap field (`per_tx_cap`, `window_cap`, or an override cap) exceeds
    /// `MAX_CAP_MAGNITUDE` (issue #321).
    CapMagnitudeExceedsBound,
}

/// Result of the `validate_policy` read (issue #35): whether a candidate
/// policy would pass `set_policy` and, if not, which §8 rule fails first.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationOutcome {
    /// Every §8 rule passes; `set_policy` would accept this policy.
    Valid,
    /// The policy would be rejected; the payload names the first failing
    /// §8 rule (rules are evaluated in §8 order).
    Invalid(PolicyRuleId),
}

/// Per-policy rolling spend ledger for SAC asset transfers and protocol call counts.
///
/// # Wire format
///
/// **Field order and field names are part of the on-chain wire format.** As a
/// `#[contracttype]`, this struct is encoded as an `ScVal` map keyed by these names,
/// its generated decoder reads entries positionally against the sorted field list,
/// and its XDR shape follows declaration order. Renaming, reordering, inserting, or
/// removing a field therefore changes the stored `Window` value's shape for every
/// consumer. Treat such an edit as a wire-format change and regenerate
/// `tests/snapshots/abi_snapshot.txt` (`UPDATE_SNAPSHOTS=1 cargo test --test abi_snapshot`)
/// in the same PR. See SPEC §3.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowState {
    /// Cached rolling total, kept for observability and ABI stability only.
    /// The stored `total` is never used for enforcement: it is recomputed from
    /// `entries` on every load, so a corrupted cache can never admit spend
    /// (SPEC §3, issue #346).
    pub total: i128,
    /// Chronological spend entries (oldest first).
    pub entries: Vec<SpendEntry>,
    /// Per-recipient rolling spend ledgers for recipients with an override cap.
    pub recipients: Vec<RecipientWindowState>,
    /// Protocol call count entries (for rate limiting).
    pub protocol_call_entries: Vec<ProtocolCallEntry>,
}

/// Rolling spend ledger for a single recipient.
#[allow(missing_docs)] // contracttype synthesizes private conversion metadata
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientWindowState {
    /// Account receiving transfers tracked by this ledger.
    pub recipient: Address,
    /// Cached rolling total for this recipient, kept for observability and ABI
    /// stability only. Never used for enforcement: recomputed from `entries` on
    /// every load, so a corrupted cache can never admit spend (SPEC §3, #346).
    pub total: i128,
    /// Chronological spend entries (oldest first).
    pub entries: Vec<SpendEntry>,
}

/// One global or per-recipient rolling-window spend record.
///
/// **Field order and field names are part of the on-chain wire format.** This is a
/// `#[contracttype]`: renaming or reordering `ts`/`amount` changes the persisted
/// `Window` encoding and every off-chain decoder that reads it. See SPEC §3.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendEntry {
    pub ts: u64,
    pub amount: i128,
}

/// A protocol call entry in the rolling-window counter (for rate limiting).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolCallEntry {
    pub ts: u64,
    pub count: u32,
}

/// Per-recipient rolling-window cap override.
#[allow(missing_docs)]
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCap {
    /// Recipient to which this override applies.
    pub recipient: Address,
    /// Rolling cap for this recipient within `window_secs`; 0 = disabled / fall back to global.
    pub cap: i128,
}

/// Per-asset per-tx cap override.
///
/// Absent from `PolicyConfig::asset_caps` means the asset falls back to the
/// global `per_tx_cap`. An override of 0 disables the per-tx cap for that
/// asset only (the global window cap still applies).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetCap {
    pub asset: Address,
    /// Per-tx cap for this asset; 0 = disabled / fall back to global.
    pub per_tx_cap: i128,
    /// If true, the asset is blocked even when it is otherwise allowlisted.
    pub paused: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyConfig {
    pub per_tx_cap: i128,
    pub window_secs: u64,
    pub window_cap: i128,
    pub assets: Vec<Address>,
    pub protocols: Vec<ProtocolRule>,
    pub recipients: Vec<Address>,
    pub recipient_window_caps: Vec<RecipientCap>,
    pub blocked_recipients: Vec<Address>,
    pub asset_caps: Vec<AssetCap>,
    pub allow_any_recipient: bool,
    pub active_from: u64,
    pub active_until: u64,
    pub paused: bool,
    pub dms_grace_secs: u64,
    pub protocol_calls_per_window: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolRule {
    pub contract: Address,
    pub fns: Option<Vec<Symbol>>,
    pub paused: bool,
    /// Global rolling-window headroom: `window_cap - spent` within the current
    /// window, computed on the lazily pruned ledger so expired entries never
    /// count. `None` when the global `window_cap` is disabled (0) — including
    /// the no-policy case. Per-recipient override headroom is recipient-targeted
    /// and deliberately not projected here; use `check_detailed` for that.
    pub window_remaining: Option<i128>,
    /// Whether `now` falls outside the policy's active window (`active_from` /
    /// `active_until`, the §4 account gate that blocks with
    /// `outside_active_window`). `false` when no policy is installed or the
    /// window is unrestricted (either bound 0).
    pub outside_active_window: bool,
    /// Configured dead-man switch grace in seconds, or zero when disabled.
    pub dms_grace_secs: u64,
    /// Unix timestamp when the last heartbeat's grace period elapses.
    /// `None` when the dead-man switch is disabled or no heartbeat is recorded.
    pub heartbeat_expires_at: Option<u64>,
}

/// Permissionless policy decision returned by `check`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckResult {
    /// The target transfer passes the current policy snapshot.
    Allowed,
    /// The transfer is blocked with a stable reason symbol.
    Blocked(Symbol),
}

/// The documented `policy_hash()` value when no policy is installed (SPEC
/// §7.3): SHA-256 over the zero-length byte string — the "hash of the empty
/// marker" — so the no-policy case is a defined, never-trapping value that
/// off-chain implementers can reproduce trivially (`sha256("")`). It is also
/// the value restored by `revoke_policy()`.
pub const NO_POLICY_DIGEST: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Canonical encoding hashed by `policy_hash` (SPEC §7.3): the **`ScVal` XDR**
/// serialization of the policy map — the same bytes a Soroban SDK produces
/// when it passes the policy as the `set_policy` argument.
///
/// Determinism comes from two wire-stable invariants:
/// 1. `#[contracttype]` structs encode as `ScVal::Map` with entries in
///    **ascending symbol-key order** (the host map invariant — the same order
///    SPEC §3.2 pins for manual encoders), and
/// 2. `ScVal` XDR is a canonical byte format: every field has a single XDR type
///    (`i128` → `I128`, `u64` → `U64`, `Option::None` → `Void`, …), so two
///    conforming encoders never disagree on the bytes.
///
/// Any field change therefore changes the stream and the hash; a policy that
/// is unchanged across ledgers/instances hashes identically. Off-chain,
/// SDKs/dashboards reproduce the hash by SHA-256-ing the XDR bytes of the
/// map they already build for `set_policy` (or by decoding with standard XDR
/// tooling). Exposed for tests and off-chain-reproduction tooling; not part
/// of the contract ABI.
#[allow(clippy::must_use_candidate)]
pub fn policy_canonical_encoding(env: &Env, cfg: &PolicyConfig) -> Bytes {
    use soroban_sdk::xdr::ToXdr;
    cfg.to_xdr(env)
}

impl Error {
    /// Convert an `Error` variant into its corresponding block-reason `Symbol`
    /// (the payload of `CheckResult::Blocked` and the `reason` topic of
    /// `auth_checked`; there is no separate `BlockReason` type — SPEC §7.1).
    #[allow(clippy::must_use_candidate)]
    pub fn to_block_reason(self) -> Symbol {
        // Uses the existing reason() string which matches SPEC §7 / reason glossary.
        Symbol::new(&soroban_sdk::Env::default(), self.reason())
    }

    /// Attempt to convert a block-reason `Symbol` back to an `Error` variant.
    #[allow(clippy::must_use_candidate)]
    pub fn from_block_reason(symbol: &Symbol) -> Option<Self> {
        let env = soroban_sdk::Env::default();
        let all_errors = [
            Self::Unauthorized,
            Self::AlreadyInitialized,
            Self::NotInitialized,
            Self::InvalidConfig,
            Self::InvalidAmount,
            Self::NoPendingAdmin,
            Self::AdminFrozen,
            Self::HeartbeatExpired,
            Self::NoPolicy,
            Self::Paused,
            Self::OutsideActiveWindow,
            Self::AssetNotAllowed,
            Self::RecipientNotAllowed,
            Self::RecipientBlocked,
            Self::PerTxCapExceeded,
            Self::WindowCapExceeded,
            Self::ProtocolNotAllowed,
            Self::FunctionNotAllowed,
            Self::AssetFnNotAllowed,
            Self::UnknownContract,
            Self::SelfFunctionNotAllowed,
            Self::CreateContractNotAllowed,
            Self::ProtocolCallRateExceeded,
            Self::DecisionInvariantViolation,
            Self::TooManyAuthContexts,
        ];
        all_errors
            .into_iter()
            .find(|&err| symbol == &Symbol::new(&env, err.reason()))
    }
}

/// Advisory result for a targeted asset transfer. All fields are calculated
/// from the current policy and window snapshot; this type never represents a
/// storage mutation.
#[allow(missing_docs)]
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
/// Advisory outcome and cap headroom for a targeted transfer check.
pub struct CheckDetail {
    /// Policy decision for the requested transfer.
    pub result: CheckResult,
    /// Remaining global or recipient window allowance, if enabled.
    pub remaining_window: Option<i128>,
    /// Configured per-transfer cap, if enabled.
    pub per_tx_cap: Option<i128>,
    /// Effective per-transfer cap for this recipient, if enabled.
    pub effective_per_tx_cap: Option<i128>,
    /// Effective rolling cap for this recipient, if enabled.
    pub effective_window_cap: Option<i128>,
}

/// One transfer evaluated by [`PolicyEngine::check_batch`](crate::PolicyEngine::check_batch).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchTransfer {
    pub to: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientCap {
    pub recipient: Address,
    pub cap: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetCap {
    pub asset: Address,
    pub cap: i128,
}
