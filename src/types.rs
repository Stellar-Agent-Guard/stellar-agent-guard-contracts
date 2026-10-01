//! Shared types: policy model, storage keys, errors, and the pure parsed-call
//! representation that the decision engine operates on.

use soroban_sdk::{contracterror, contracttype, Address, Bytes, Env, Symbol, Vec};

/// Warning threshold percentage for dead-man switch health evaluation (80%).
pub const DMS_WARN_THRESHOLD_PERCENT: u64 = 80;

/// Dead-man switch health status returned by `dms_health`.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DmsHealthStatus {
    Ok,
    Warn,
    Expired,
}

/// Hard bound on rolling-window entries. Above this, the engine merges the two
/// oldest entries forward (conservative over-count) — see SPEC §3.1.
pub const MAX_WINDOW_ENTRIES: usize = 8192;

/// Maximum number of asset contracts in a policy (SPEC §8).
pub const MAX_POLICY_ASSETS: usize = 256;

/// Maximum number of protocol contracts in a policy (SPEC §8).
pub const MAX_POLICY_PROTOCOLS: usize = 256;

/// Hard bound on the number of entries in `recipients`, `blocked_recipients`,
/// and `recipient_window_caps`. Keeps allowlist scans and per-recipient
/// storage bounded and predictable (SPEC §3 / §8).
pub const MAX_RECIPIENT_ENTRIES: usize = 256;

/// Upper bound on `window_secs` and `dms_grace_secs` (issue #34). `3_650` days
/// ≈ 10 years: far beyond any legitimate rolling spend window or dead-man
/// grace, while still catching the classic seconds/milliseconds confusion
/// (e.g. a 90-day window passed as `7_776_000_000` ms) and "effectively
/// disables pruning forever" configs such as `u64::MAX`.
pub const MAX_WINDOW_SECS: u64 = 315_360_000; // 86_400 × 3_650
/// Same upper bound as `MAX_WINDOW_SECS`, applied to the DMS grace.
pub const MAX_DMS_GRACE_SECS: u64 = MAX_WINDOW_SECS;

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
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowState {
    /// Cached rolling total (sum of non-expired entries).
    pub total: i128,
    /// Chronological spend entries (oldest first).
    pub entries: Vec<SpendEntry>,
    /// Per-recipient rolling spend ledgers for recipients with an override cap.
    pub recipients: Vec<RecipientWindowState>,
    /// Protocol call count entries (for rate limiting).
    pub protocol_call_entries: Vec<ProtocolCallEntry>,
}

/// Rolling spend ledger for a single recipient.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientWindowState {
    pub recipient: Address,
    /// Cached rolling total (sum of non-expired entries).
    pub total: i128,
    /// Chronological spend entries (oldest first).
    pub entries: Vec<SpendEntry>,
}

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
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientCap {
    pub recipient: Address,
    /// Rolling cap for this recipient within `window_secs`; 0 = disabled / fall back to global.
    pub cap: i128,
}

/// The policy an admin installs on the account. See SPEC §3/§4.
#[contracttype]
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyConfig {
    /// Per asset-transfer call cap; 0 = disabled.
    pub per_tx_cap: i128,
    /// Rolling window width in seconds.
    pub window_secs: u64,
    /// Rolling spend cap within `window_secs`; 0 = disabled.
    pub window_cap: i128,
    /// SAC token contracts whose transfers get parsed and enforced.
    pub assets: Vec<Address>,
    /// Allowlisted non-asset contracts the account may call.
    pub protocols: Vec<ProtocolRule>,
    /// Allowed SAC transfer destinations.
    pub recipients: Vec<Address>,
    /// Per-recipient rolling-window cap overrides; recipients not listed here
    /// use the global `window_cap`. Storage bounded by `MAX_RECIPIENT_ENTRIES`.
    pub recipient_window_caps: Vec<RecipientCap>,
    /// Denied SAC transfer destinations. Checked before the allowlist and
    /// before `allow_any_recipient`; an empty list leaves behavior unchanged.
    pub blocked_recipients: Vec<Address>,
    /// Escape hatch: skip the recipient allowlist (caps still apply).
    pub allow_any_recipient: bool,
    /// Active window start (unix seconds); 0 = unrestricted.
    pub active_from: u64,
    /// Active window end (unix seconds); 0 = unrestricted.
    pub active_until: u64,
    /// Admin kill switch.
    pub paused: bool,
    /// Dead-man switch grace (seconds); 0 = disabled.
    pub dms_grace_secs: u64,
    /// Maximum protocol (non-SAC allowlisted) calls per rolling window; 0 = disabled.
    pub protocol_calls_per_window: u32,
}

/// Manual `Debug` implementation for `PolicyConfig` with stable field order.
///
/// Field order is the declaration order (as of SPEC §3 table) and must not be
/// changed without updating the snapshot test in `tests/debug_policy_config.rs`.
/// This is the *human-readable* format for logs, test fixtures, and dashboard
/// inspect scripts — it is NOT the canonical encoding for `policy_hash`.
/// The canonical encoding hashed by `policy_hash` is the `ScVal` XDR form of the
/// policy map (sorted symbol keys; see SPEC §7.3).
impl core::fmt::Debug for PolicyConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PolicyConfig")
            .field("per_tx_cap", &self.per_tx_cap)
            .field("window_secs", &self.window_secs)
            .field("window_cap", &self.window_cap)
            .field("assets", &self.assets)
            .field("protocols", &self.protocols)
            .field("recipients", &self.recipients)
            .field("recipient_window_caps", &self.recipient_window_caps)
            .field("blocked_recipients", &self.blocked_recipients)
            .field("allow_any_recipient", &self.allow_any_recipient)
            .field("active_from", &self.active_from)
            .field("active_until", &self.active_until)
            .field("paused", &self.paused)
            .field("dms_grace_secs", &self.dms_grace_secs)
            .field("protocol_calls_per_window", &self.protocol_calls_per_window)
            .finish()
    }
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolRule {
    pub contract: Address,
    /// `None` = any function; `Some` = per-function allowlist.
    pub fns: Option<Vec<Symbol>>,
}

/// A single call the account must authorize, parsed into a form the pure
/// decision engine can reason about without touching `Env`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParsedCall {
    /// A known SAC transfer on an allowlisted asset — fully enforceable.
    AssetTransfer {
        asset: Address,
        to: Address,
        amount: i128,
    },
    /// A call on an allowlisted asset that is not `transfer`/`transfer_from`
    /// (e.g. `mint`, `burn`) — never allowed for the account as authorizer.
    AssetOther { asset: Address, fname: Symbol },
    /// A call on an allowlisted protocol contract.
    Protocol { contract: Address, fname: Symbol },
    /// A call to this account's own functions (e.g. `heartbeat`).
    SelfCall { fname: Symbol },
    /// A host-function contract creation authorized by the account — denied in
    /// v1 (an account that may not call unknown contracts should not create them).
    CreateContract,
    /// Anything else — default deny.
    Unknown { contract: Address, fname: Symbol },
}

/// Operational snapshot returned by the auth-free `status()` read (SPEC §7).
/// Additive-growth contract: new fields may be appended, but existing fields
/// are never renamed or removed (see docs/research/wire-format.md).
#[allow(clippy::struct_excessive_bools)] // wire-format snapshot: the bool field set is fixed by the public ABI, not a design choice
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub has_policy: bool,
    pub policy_revision: u64,
    pub admin_frozen: bool,
    pub heartbeat_expired: bool,
    pub last_heartbeat: u64,
    pub now: u64,
    /// The installed policy's admin kill switch (`cfg.paused`). `false` when
    /// no policy is installed (default-deny has nothing to pause).
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
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckResult {
    Allowed,
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
    /// Convert an `Error` variant into its corresponding `BlockReason` symbol (as used in `CheckResult::Blocked`).
    #[allow(clippy::must_use_candidate)]
    pub fn to_block_reason(self) -> Symbol {
        // Uses the existing reason() string which matches SPEC §7 / reason glossary.
        Symbol::new(&soroban_sdk::Env::default(), self.reason())
    }

    /// Attempt to convert a `BlockReason` symbol back to an `Error` variant.
    #[allow(clippy::must_use_candidate)]
    pub fn from_block_reason(symbol: &Symbol) -> Option<Self> {
        let env = soroban_sdk::Env::default();
        let all_errors = [
            Self::Unauthorized,
            Self::AlreadyInitialized,
            Self::NotInitialized,
            Self::InvalidConfig,
            Self::InvalidAmount,
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
            Self::UnknownContract,
            Self::SelfFunctionNotAllowed,
            Self::CreateContractNotAllowed,
            Self::ProtocolCallRateExceeded,
        ];
        all_errors
            .into_iter()
            .find(|&err| symbol == &Symbol::new(&env, err.reason()))
    }
}

/// Advisory result for a targeted asset transfer. All fields are calculated
/// from the current policy and window snapshot; this type never represents a
/// storage mutation.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckDetail {
    pub result: CheckResult,
    pub remaining_window: Option<i128>,
    pub per_tx_cap: Option<i128>,
    pub effective_per_tx_cap: Option<i128>,
    pub effective_window_cap: Option<i128>,
}

// Storage layout (SPEC §3). `Initialized`/`Admin`/`AgentPubkey` live in
// instance storage (auto-TTL on every invocation); the rest live in
// persistent storage with TTL extensions on writes and thresholded refreshes
// on reads.
#[contracttype]
#[derive(Clone, Debug)]
pub enum DataKey {
    /// Instance: one-time flag for `initialize`.
    Initialized,
    /// Instance: policy admin; set once at `initialize`.
    Admin,
    /// Instance: the registered agent's Ed25519 public key (32 bytes).
    AgentPubkey,
    /// Persistent: current policy (`None` = default-deny).
    Policy,
    /// Persistent: rolling spend ledger for asset transfers.
    Window,
    /// Persistent: unix seconds of last agent heartbeat (0 = never).
    LastHeartbeat,
    /// Persistent: admin-initiated freeze flag.
    AdminFrozen,
    /// Persistent: incrementing counter for policy changes.
    PolicyRevision,
}

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // Generic / lifecycle (1..=9)
    Unauthorized = 1,
    AlreadyInitialized = 2,
    NotInitialized = 3,
    InvalidConfig = 4,
    InvalidAmount = 5,
    // Account-level gates (10..=19)
    AdminFrozen = 10,
    HeartbeatExpired = 11,
    NoPolicy = 12,
    Paused = 13,
    OutsideActiveWindow = 14,
    // Per-call decisions (20..=29)
    AssetNotAllowed = 20,
    RecipientNotAllowed = 21,
    PerTxCapExceeded = 22,
    WindowCapExceeded = 23,
    ProtocolNotAllowed = 24,
    FunctionNotAllowed = 25,
    UnknownContract = 26,
    SelfFunctionNotAllowed = 27,
    CreateContractNotAllowed = 28,
    RecipientBlocked = 29,
    ProtocolCallRateExceeded = 30,
    ListedAssetAdminOrMintAttempt = 31,
}

impl Error {
    /// Stable, human- and telemetry-readable reason name (no env needed).
    #[allow(clippy::must_use_candidate)]
    pub fn reason(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::AlreadyInitialized => "already_initialized",
            Self::NotInitialized => "not_initialized",
            Self::InvalidConfig => "invalid_config",
            Self::InvalidAmount => "invalid_amount",
            Self::AdminFrozen => "admin_frozen",
            Self::HeartbeatExpired => "heartbeat_expired",
            Self::NoPolicy => "no_policy",
            Self::Paused => "paused",
            Self::OutsideActiveWindow => "outside_active_window",
            Self::AssetNotAllowed => "asset_not_allowed",
            Self::RecipientNotAllowed => "recipient_not_allowed",
            Self::RecipientBlocked => "recipient_blocked",
            Self::PerTxCapExceeded => "per_tx_cap_exceeded",
            Self::WindowCapExceeded => "window_cap_exceeded",
            Self::ProtocolNotAllowed => "protocol_not_allowed",
            Self::FunctionNotAllowed => "function_not_allowed",
            Self::UnknownContract => "unknown_contract",
            Self::SelfFunctionNotAllowed => "self_function_not_allowed",
            Self::CreateContractNotAllowed => "create_contract_not_allowed",
            Self::ProtocolCallRateExceeded => "protocol_call_rate_exceeded",
            Self::ListedAssetAdminOrMintAttempt => "listed_asset_admin_or_mint_attempt",
        }
    }
}
