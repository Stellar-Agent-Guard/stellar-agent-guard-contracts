use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::{
    contract, contractimpl, contracttype, log, panic_with_error, Address, BytesN, Env, IntoVal,
    Val, Vec,
};

pub mod engine;
pub mod types;
pub mod window;

#[cfg(test)]
mod event_audit_tests;
#[cfg(test)]
mod engine_property_tests;
#[cfg(test)]
mod policy_preset_tests;

use crate::engine::{decide, AccountState};
use crate::types::{Error, PolicyConfig, StatusResponse};
use crate::window::{emit_window_merge, Ledger};

#[contract]
pub struct PolicyEngine;

fn read_initialized(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&types::DataKey::Initialized)
        .unwrap_or(false)
}

fn write_initialized(env: &Env, initialized: bool) {
    env.storage().instance().set(&types::DataKey::Initialized, &initialized);
}

fn read_admin(env: &Env) -> Address {
    env.storage()
        .instance()
        .get(&types::DataKey::Admin)
        .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
}

fn write_admin(env: &Env, admin: &Address) {
    env.storage().instance().set(&types::DataKey::Admin, admin);
}

fn read_pending_admin(env: &Env) -> Option<Address> {
    env.storage().instance().get(&types::DataKey::PendingAdmin)
}

fn write_pending_admin(env: &Env, pending: Option<&Address>) {
    match pending {
        Some(addr) => env.storage().instance().set(&types::DataKey::PendingAdmin, addr),
        None => env.storage().instance().remove(&types::DataKey::PendingAdmin),
    }
}

fn read_agent_pubkey(env: &Env) -> BytesN<32> {
    env.storage()
        .instance()
        .get(&types::DataKey::AgentPubkey)
        .unwrap_or_else(|| panic_with_error!(env, Error::NotInitialized))
}

fn write_agent_pubkey(env: &Env, key: &BytesN<32>) {
    env.storage().instance().set(&types::DataKey::AgentPubkey, key);
}

fn read_policy_version(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&types::DataKey::PolicyVersion)
        .unwrap_or(0)
}

fn write_policy_version(env: &Env, version: u64) {
    env.storage().instance().set(&types::DataKey::PolicyVersion, &version);
}

fn read_policy(env: &Env) -> Option<PolicyConfig> {
    env.storage().persistent().get(&types::DataKey::Policy)
}

fn write_policy(env: &Env, policy: &PolicyConfig) {
    env.storage().persistent().set(&types::DataKey::Policy, policy);
}

fn remove_policy(env: &Env) {
    env.storage().persistent().remove(&types::DataKey::Policy);
}

fn read_ledger(env: &Env) -> Ledger {
    env.storage()
        .persistent()
        .get(&types::DataKey::Window)
        .unwrap_or_else(|| Ledger::empty(env))
}

fn write_ledger(env: &Env, ledger: &Ledger) {
    env.storage().persistent().set(&types::DataKey::Window, ledger);
}

fn read_last_heartbeat(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&types::DataKey::LastHeartbeat)
        .unwrap_or(0)
}

fn write_last_heartbeat(env: &Env, ts: u64) {
    env.storage().persistent().set(&types::DataKey::LastHeartbeat, &ts);
}

fn read_admin_frozen(env: &Env) -> bool {
    env.storage()
        .persistent()
        .get(&types::DataKey::AdminFrozen)
        .unwrap_or(false)
}

fn write_admin_frozen(env: &Env, frozen: bool) {
    env.storage().persistent().set(&types::DataKey::AdminFrozen, &frozen);
}

fn read_auto_frozen_at(env: &Env) -> Option<u64> {
    env.storage().persistent().get(&types::DataKey::AutoFrozenAt)
}

fn write_auto_frozen_at(env: &Env, ts: Option<u64>) {
    match ts {
        Some(val) => env.storage().persistent().set(&types::DataKey::AutoFrozenAt, &val),
        None => env.storage().persistent().remove(&types::DataKey::AutoFrozenAt),
    }
}

fn read_policy_revision(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&types::DataKey::PolicyRevision)
        .unwrap_or(0)
}

fn write_policy_revision(env: &Env, rev: u64) {
    env.storage().persistent().set(&types::DataKey::PolicyRevision, &rev);
}

fn require_admin(env: &Env, admin: &Address) {
    admin.require_auth();
    let current = read_admin(env);
    if *admin != current {
        panic_with_error!(env, Error::NotAdmin);
    }
}

fn validate_config(env: &Env, config: &PolicyConfig) {
    if config.window_secs == 0 {
        panic_with_error!(env, Error::InvalidConfig);
    }
}

fn validate_agent_pubkey(env: &Env, agent_pubkey: &BytesN<32>) {
    if agent_pubkey.to_array() == [0u8; 32] {
        panic_with_error!(env, Error::InvalidConfig);
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitializedEvent {
    pub by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatEvent {
    pub at: u64,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrozenEvent {
    pub by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnfrozenEvent {
    pub by: Address,
    pub rearmed_dms: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicySetEvent {
    pub by: Address,
    pub revision: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRevokedEvent {
    pub by: Address,
    pub revision: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowCapIncreasedEvent {
    pub by: Address,
    pub new_cap: i128,
    pub old_cap: i128,
    pub revision: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentKeyRotatedEvent {
    pub by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminTransferInitiatedEvent {
    pub by: Address,
    pub new_admin: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminAcceptedEvent {
    pub by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolPausedEvent {
    pub by: Address,
    pub contract: Address,
    pub fn_name: Option<soroban_sdk::Symbol>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolResumedEvent {
    pub by: Address,
    pub contract: Address,
    pub fn_name: Option<soroban_sdk::Symbol>,
}

#[contractimpl]
impl PolicyEngine {
    pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>) {
        if read_initialized(&env) {
            panic_with_error!(env, Error::AlreadyInitialized);
        }
        validate_agent_pubkey(&env, &agent_pubkey);
        admin.require_auth();

        write_initialized(&env, true);
        write_admin(&env, &admin);
        write_agent_pubkey(&env, &agent_pubkey);
        write_policy_version(&env, 1);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_initialized"),),
            InitializedEvent { by: admin.clone() },
        );
        log!(&env, "PolicyEngine initialized successfully");
    }

    pub fn heartbeat(env: Env) {
        if !read_initialized(&env) {
            panic_with_error!(env, Error::NotInitialized);
        }
        let now = env.ledger().timestamp();
        let mut ledger = read_ledger(&env);
        let mut merges = Vec::new(&env);
        ledger.prune(now, &mut merges);
        for m in merges {
            emit_window_merge(&env, m);
        }
        write_ledger(&env, &ledger);

        let policy = read_policy(&env);
        let grace = policy.as_ref().map_or(0, |p| p.dms_grace_secs);
        let last = read_last_heartbeat(&env);
        let expires_at = if last == 0 {
            0
        } else {
            last.saturating_add(grace)
        };

        write_last_heartbeat(&env, now);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_heartbeat"),),
            HeartbeatEvent {
                at: now,
                expires_at,
            },
        );
    }

    pub fn freeze(env: Env) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);
        write_admin_frozen(&env, true);
        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_frozen"),),
            FrozenEvent { by: admin },
        );
    }

    pub fn unfreeze(env: Env) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);
        let was_frozen = read_admin_frozen(&env);
        write_admin_frozen(&env, false);

        let auto_frozen = read_auto_frozen_at(&env).is_some();
        let mut rearmed_dms = false;
        if auto_frozen {
            write_auto_frozen_at(&env, None);
            write_last_heartbeat(&env, env.ledger().timestamp());
            rearmed_dms = true;
        }

        if was_frozen || auto_frozen {
            env.events().publish(
                (soroban_sdk::Symbol::new(&env, "event_unfrozen"),),
                UnfrozenEvent {
                    by: admin,
                    rearmed_dms,
                },
            );
        }
    }

    pub fn set_policy(env: Env, config: PolicyConfig) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);
        validate_config(&env, &config);

        write_policy(&env, &config);
        let rev = read_policy_revision(&env).saturating_add(1);
        write_policy_revision(&env, rev);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_policy_set"),),
            PolicySetEvent {
                by: admin,
                revision: rev,
            },
        );
    }

    pub fn revoke_policy(env: Env) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);

        remove_policy(&env);
        let rev = read_policy_revision(&env).saturating_add(1);
        write_policy_revision(&env, rev);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_policy_revoked"),),
            PolicyRevokedEvent {
                by: admin,
                revision: rev,
            },
        );
    }

    pub fn increase_window_cap(env: Env, new_cap: i128) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);

        let mut config = read_policy(&env).unwrap_or_else(|| panic_with_error!(env, Error::NoPolicy));
        let old_cap = config.window_cap;
        if new_cap <= old_cap {
            panic_with_error!(env, Error::InvalidConfig);
        }
        config.window_cap = new_cap;
        write_policy(&env, &config);

        let rev = read_policy_revision(&env).saturating_add(1);
        write_policy_revision(&env, rev);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_window_cap_increased"),),
            WindowCapIncreasedEvent {
                by: admin,
                new_cap,
                old_cap,
                revision: rev,
            },
        );
    }

    pub fn rotate_agent_key(env: Env, new_agent_pubkey: BytesN<32>) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);
        validate_agent_pubkey(&env, &new_agent_pubkey);

        write_agent_pubkey(&env, &new_agent_pubkey);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_agent_key_rotated"),),
            AgentKeyRotatedEvent { by: admin },
        );
    }

    pub fn transfer_admin(env: Env, new_admin: Address) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);

        write_pending_admin(&env, Some(&new_admin));

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_admin_transfer_initiated"),),
            AdminTransferInitiatedEvent {
                by: admin,
                new_admin,
            },
        );
    }

    pub fn accept_admin(env: Env) {
        let pending = read_pending_admin(&env).unwrap_or_else(|| panic_with_error!(env, Error::NotAdmin));
        pending.require_auth();

        write_admin(&env, &pending);
        write_pending_admin(&env, None);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_admin_accepted"),),
            AdminAcceptedEvent { by: pending },
        );
    }

    pub fn pause_protocol(env: Env, contract: Address, fn_name: Option<soroban_sdk::Symbol>) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);

        let mut config = read_policy(&env).unwrap_or_else(|| panic_with_error!(env, Error::NoPolicy));
        let mut found = false;
        for rule in config.protocols.iter_mut() {
            if rule.contract == contract && rule.fns == fn_name.map(|f| soroban_sdk::vec![&env, f]) {
                rule.paused = true;
                found = true;
            }
        }
        if !found {
            panic_with_error!(env, Error::InvalidConfig);
        }
        write_policy(&env, &config);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_protocol_paused"),),
            ProtocolPausedEvent {
                by: admin,
                contract,
                fn_name,
            },
        );
    }

    pub fn resume_protocol(env: Env, contract: Address, fn_name: Option<soroban_sdk::Symbol>) {
        let admin = read_admin(&env);
        require_admin(&env, &admin);

        let mut config = read_policy(&env).unwrap_or_else(|| panic_with_error!(env, Error::NoPolicy));
        let mut found = false;
        for rule in config.protocols.iter_mut() {
            if rule.contract == contract && rule.fns == fn_name.map(|f| soroban_sdk::vec![&env, f]) {
                rule.paused = false;
                found = true;
            }
        }
        if !found {
            panic_with_error!(env, Error::InvalidConfig);
        }
        write_policy(&env, &config);

        env.events().publish(
            (soroban_sdk::Symbol::new(&env, "event_protocol_resumed"),),
            ProtocolResumedEvent {
                by: admin,
                contract,
                fn_name,
            },
        );
    }

    pub fn status(env: Env) -> StatusResponse {
        let initialized = read_initialized(&env);
        if !initialized {
            return StatusResponse {
                initialized: false,
                admin: Address::from_string(&env, &soroban_sdk::String::from_str(&env, "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")),
                agent_pubkey: BytesN::from_array(&env, &[0u8; 32]),
                policy_version: 0,
                policy_revision: 0,
                admin_frozen: false,
                auto_frozen_at: None,
                last_heartbeat: 0,
                dms_grace_secs: 0,
            };
        }
        let admin = read_admin(&env);
        let agent_pubkey = read_agent_pubkey(&env);
        let policy_version = read_policy_version(&env);
        let policy_revision = read_policy_revision(&env);
        let admin_frozen = read_admin_frozen(&env);
        let auto_frozen_at = read_auto_frozen_at(&env);
        let last_heartbeat = read_last_heartbeat(&env);
        let policy = read_policy(&env);
        let dms_grace_secs = policy.map_or(0, |p| p.dms_grace_secs);

        StatusResponse {
            initialized: true,
            admin,
            agent_pubkey,
            policy_version,
            policy_revision,
            admin_frozen,
            auto_frozen_at,
            last_heartbeat,
            dms_grace_secs,
        }
    }
}

#[contractimpl]
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: soroban_sdk::crypto::Hash<32>,
        signatures: Self::Signature,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        if read_admin_frozen(&env) {
            return Err(Error::AdminFrozen);
        }

        let agent_pubkey = read_agent_pubkey(&env);
        let verified = env
            .crypto()
            .ed25519_verify(&agent_pubkey, &signature_payload.into(), &signatures);
        if !verified {
            return Err(Error::InvalidSignature);
        }

        let now = env.ledger().timestamp();
        let mut ledger = read_ledger(&env);
        let mut merges = Vec::new(&env);
        ledger.prune(now, &mut merges);
        for m in merges {
            emit_window_merge(&env, m);
        }

        let policy = read_policy(&env).ok_or(Error::NoPolicy)?;

        if policy.paused {
            return Err(Error::Paused);
        }

        if policy.active_from != 0 && now < policy.active_from {
            return Err(Error::OutsideActiveWindow);
        }

        if policy.active_until != 0 && now > policy.active_until {
            return Err(Error::OutsideActiveWindow);
        }

        if policy.dms_grace_secs > 0 {
            let last = read_last_heartbeat(&env);
            if last == 0 || now.saturating_sub(last) > policy.dms_grace_secs {
                write_admin_frozen(&env, true);
                write_auto_frozen_at(&env, Some(now));
                return Err(Error::HeartbeatExpired);
            }
        }

        let decisions = decide(&env, &env.current_contract_address(), Some(&policy), &AccountState { admin_frozen: false, last_heartbeat: read_last_heartbeat(&env) }, &mut ledger, now, auth_contexts);
        write_ledger(&env, &ledger);

        for d in decisions {
            if let engine::Decision::Blocked(err) = d {
                return Err(err);
            }
        }

        Ok(()}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initialize_rejects_zero_agent_key() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guard = env.register(PolicyEngine, ());
        let client = PolicyEngineClient::new(&env, &guard);

        let zero_key = BytesN::from_array(&env, &[0u8; 32]);
        let res = client.try_initialize(&admin, &zero_key);
        assert_eq!(res, Err(Ok(Error::InvalidConfig)));
    }

    #[test]
    fn test_rotate_agent_key_rejects_zero_agent_key() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guard = env.register(PolicyEngine, ());
        let client = PolicyEngineClient::new(&env, &guard);

        let valid_key = BytesN::from_array(&env, &[1u8; 32]);
        client.initialize(&admin, &valid_key);

        let zero_key = BytesN::from_array(&env, &[0u8; 32]);
        let res = client.try_rotate_agent_key(&zero_key);
        assert_eq!(res, Err(Ok(Error::InvalidConfig)));
    }

    #[test]
    fn test_initialize_and_rotate_accept_valid_non_zero_key() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let guard = env.register(PolicyEngine, ());
        let client = PolicyEngineClient::new(&env, &guard);

        let key1 = BytesN::from_array(&env, &[1u8; 32]);
        client.initialize(&admin, &key1);
        assert_eq!(client.status().agent_pubkey, key1);

        let key2 = BytesN::from_array(&env, &[2u8; 32]);
        client.rotate_agent_key(&key2);
        assert_eq!(client.status().agent_pubkey, key2);
    }
}
