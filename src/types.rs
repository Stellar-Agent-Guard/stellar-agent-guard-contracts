//! Shared types: policy model, storage keys, errors, and the pure parsed-call
//! representation that the decision engine operates on.

use soroban_sdk::{contracterror, contracttype, Address, Symbol, Vec};

/// Hard bound on rolling-window entries. Above this, the engine merges the two
/// oldest entries forward (conservative over-count) — see SPEC §3.1.
pub const MAX_WINDOW_ENTRIES: usize = 8192;

/// Per-policy rolling spend ledger for SAC asset transfers.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowState {
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

/// The policy an admin installs on the account. See SPEC §3/§4.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub has_policy: bool,
    pub policy_revision: u64,
    pub admin_frozen: bool,
    pub heartbeat_expired: bool,
    pub last_heartbeat: u64,
    pub now: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckResult {
    Allowed,
    Blocked(Symbol),
}

// Storage layout (SPEC §3). `Initialized`/`Admin`/`AgentPubkey` live in
// instance storage (auto-TTL on every invocation); the rest live in
// persistent storage with explicit TTL extension on every write.
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
}

impl Error {
    /// Stable, human- and telemetry-readable reason name (no env needed).
    #[must_use]
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
            Self::PerTxCapExceeded => "per_tx_cap_exceeded",
            Self::WindowCapExceeded => "window_cap_exceeded",
            Self::ProtocolNotAllowed => "protocol_not_allowed",
            Self::FunctionNotAllowed => "function_not_allowed",
            Self::UnknownContract => "unknown_contract",
            Self::SelfFunctionNotAllowed => "self_function_not_allowed",
            Self::CreateContractNotAllowed => "create_contract_not_allowed",
        }
    }
}
