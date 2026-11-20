use soroban_sdk::{contracterror, contracttype, Address, BytesN, Env, Symbol, Vec};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    InvalidConfig = 4,
    Paused = 5,
    OutsideActiveWindow = 6,
    PerTxCapExceeded = 7,
    WindowCapExceeded = 8,
    AssetNotAllowed = 9,
    ProtocolNotAllowed = 10,
    RecipientNotAllowed = 11,
    BlockedRecipient = 12,
    AssetCapExceeded = 13,
    ProtocolCallLimitExceeded = 14,
    HeartbeatExpired = 15,
    AdminFrozen = 16,
    SelfFunctionNotAllowed = 17,
    AssetFnNotAllowed = 18,
    CreateContractNotAllowed = 19,
    UnknownContract = 20,
    InvalidAmount = 21,
    InvalidAdmin = 22,
    InvalidAgentKey = 23,
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
