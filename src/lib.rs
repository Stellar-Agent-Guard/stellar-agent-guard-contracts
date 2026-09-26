#![no_std]

//! stellar-agent-guard-contracts — a Soroban **custom account** that enforces
//! agent spend policy inside `__check_auth`. See SPEC.md.
//!
//! The registered agent is an **Ed25519 keypair** whose public key is stored
//! on the account. Every transaction that requires this account's
//! authorization is routed by the host through `__check_auth`, which first
//! verifies the Ed25519 signature presented over the transaction auth payload
//! and then evaluates the policy (SPEC §4/§6/§7). No CAP-71 delegation in v1.

#[cfg(test)]
extern crate std;

mod engine;
mod types;
mod window;

#[cfg(test)]
mod integration_tests;

use engine::{contains_addr, decide, AccountState, Decision};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::{
    contract, contractevent, contractimpl, panic_with_error, vec, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, TryFromVal, Val,
};
use types::{CheckResult, DataKey, Error, PolicyConfig, Status, WindowState};
use window::Ledger;

// ── Contract events (SPEC §9). Each event is its own type; topic layout
//    follows the SPEC table exactly so the Phase-2 listener can filter on one
//    vocabulary without decoding payloads it does not need.

/// Every decision: topic[0]=result (`allowed`/`blocked`), topic[1]=reason.
#[contractevent]
#[derive(Clone)]
struct EventAuthChecked {
    #[topic]
    result: Symbol,
    #[topic]
    reason: Symbol,
}

/// Agent heartbeat: data `at` (unix seconds).
#[contractevent]
#[derive(Clone)]
struct EventHeartbeat {
    at: u64,
}

/// Admin lifecycle events: data `by` (the admin address that acted).
#[contractevent]
#[derive(Clone)]
struct EventInitialized {
    by: Address,
}

#[contractevent]
#[derive(Clone)]
struct EventFrozen {
    by: Address,
}

#[contractevent]
#[derive(Clone)]
struct EventUnfrozen {
    by: Address,
}

#[contractevent]
#[derive(Clone)]
struct EventPolicySet {
    by: Address,
}

#[contractevent]
#[derive(Clone)]
struct EventPolicyRevoked {
    by: Address,
}

#[contractevent]
#[derive(Clone)]
struct EventAgentRotated {
    by: Address,
}

// ── Persistent-storage helpers (SPEC §3) ────────────────────────────────
// Admin / AgentPubkey / Initialized live in instance storage (auto-TTL on
// every invocation); the rest live in persistent storage with explicit TTL
// extension on every write.

fn persist_set(env: &Env, key: &DataKey, val: &impl soroban_sdk::IntoVal<Env, Val>) {
    let seq = env.ledger().sequence();
    let target = seq.saturating_add(env.storage().max_ttl());
    env.storage().persistent().set(key, val);
    env.storage().persistent().extend_ttl(key, target, target);
}

fn persist_get<T: soroban_sdk::TryFromVal<Env, Val>>(env: &Env, key: &DataKey) -> Option<T> {
    env.storage().persistent().get(key)
}

fn load_ledger(env: &Env) -> Ledger {
    match persist_get::<WindowState>(env, &DataKey::Window) {
        Some(state) => Ledger::from_entries(env, state.entries),
        None => Ledger::empty(env),
    }
}

fn save_ledger(env: &Env, ledger: &Ledger) {
    persist_set(
        env,
        &DataKey::Window,
        &WindowState {
            total: ledger.total,
            entries: ledger.entries.clone(),
        },
    );
}

fn increment_revision(env: &Env) -> u64 {
    let rev = persist_get::<u64>(env, &DataKey::PolicyRevision).unwrap_or(0);
    let next = rev.saturating_add(1);
    persist_set(env, &DataKey::PolicyRevision, &next);
    next
}

// ── Policy config validation (SPEC §8) ───────────────────────────────────

fn has_dup<T: PartialEq + TryFromVal<Env, Val> + IntoVal<Env, Val>>(
    env: &Env,
    items: &soroban_sdk::Vec<T>,
) -> bool {
    let n = items.len();
    for i in 0..n {
        for j in (i + 1)..n {
            if let (Some(a), Some(b)) = (items.get(i), items.get(j)) {
                if a == b {
                    return true;
                }
            }
        }
    }
    let _ = env;
    false
}

fn validate_config(env: &Env, cfg: &PolicyConfig) -> Result<(), Error> {
    if cfg.per_tx_cap < 0 || cfg.window_cap < 0 {
        return Err(Error::InvalidConfig);
    }
    if cfg.window_cap > 0 && cfg.window_secs == 0 {
        return Err(Error::InvalidConfig);
    }
    if cfg.active_until != 0 && cfg.active_until <= cfg.active_from {
        return Err(Error::InvalidConfig);
    }
    let self_addr = env.current_contract_address();
    if contains_addr(&cfg.assets, &self_addr) {
        return Err(Error::InvalidConfig);
    }
    for i in 0..cfg.protocols.len() {
        if let Some(rule) = cfg.protocols.get(i) {
            if rule.contract == self_addr {
                return Err(Error::InvalidConfig);
            }
        }
    }
    // The deployed address is rejected in all three lists: an asset/protocol
    // self-entry is a nonsensical allowlist (self-calls are governed by the
    // fixed §6.1 rule, not policy), and a self-recipient is a no-op loop that
    // almost certainly signals a mis-pasted address. `self_addr` is fixed at
    // deployment (known before `initialize`), and `set_policy` can only run
    // post-initialize, so this always compares against the real contract ID.
    if contains_addr(&cfg.recipients, &self_addr) {
        return Err(Error::InvalidConfig);
    }
    if has_dup(env, &cfg.assets) || has_dup(env, &cfg.recipients) {
        return Err(Error::InvalidConfig);
    }
    let mut contracts: soroban_sdk::Vec<Address> = soroban_sdk::Vec::new(env);
    for i in 0..cfg.protocols.len() {
        if let Some(rule) = cfg.protocols.get(i) {
            for j in 0..contracts.len() {
                if let Some(existing) = contracts.get(j) {
                    if existing == rule.contract {
                        return Err(Error::InvalidConfig);
                    }
                }
            }
            contracts.push_back(rule.contract.clone());
            if let Some(fns) = &rule.fns {
                if fns.is_empty() || has_dup(env, fns) {
                    return Err(Error::InvalidConfig);
                }
            }
        }
    }
    Ok(())
}

// ── Event emission ───────────────────────────────────────────────────────

fn emit_auth(env: &Env, allowed: bool, reason: Option<Error>) {
    let res = if allowed { "allowed" } else { "blocked" };
    let reason = reason.map_or("", |e| e.reason());
    EventAuthChecked {
        result: Symbol::new(env, res),
        reason: Symbol::new(env, reason),
    }
    .publish(env);
}

fn emit_heartbeat(env: &Env, at: u64) {
    EventHeartbeat { at }.publish(env);
}

fn emit_initialized(env: &Env, by: &Address) {
    EventInitialized { by: by.clone() }.publish(env);
}
fn emit_frozen(env: &Env, by: &Address) {
    EventFrozen { by: by.clone() }.publish(env);
}
fn emit_unfrozen(env: &Env, by: &Address) {
    EventUnfrozen { by: by.clone() }.publish(env);
}
fn emit_policy_set(env: &Env, by: &Address) {
    EventPolicySet { by: by.clone() }.publish(env);
}
fn emit_policy_revoked(env: &Env, by: &Address) {
    EventPolicyRevoked { by: by.clone() }.publish(env);
}
fn emit_agent_rotated(env: &Env, by: &Address) {
    EventAgentRotated { by: by.clone() }.publish(env);
}

// ── Contract ─────────────────────────────────────────────────────────────

#[contract]
pub struct PolicyEngine;

#[contractimpl]
#[allow(clippy::needless_pass_by_value)] // contract ABI requires owned args
impl PolicyEngine {
    // ── Lifecycle ────────────────────────────────────────────────────────

    /// Registers the policy `admin` and the agent's Ed25519 public key.
    /// One-time; the account is default-deny until a policy is installed.
    pub fn initialize(env: Env, admin: Address, agent_pubkey: BytesN<32>) {
        let already: Option<bool> = env.storage().instance().get(&DataKey::Initialized);
        if already.unwrap_or(false) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::AgentPubkey, &agent_pubkey);
        env.storage().instance().set(&DataKey::Initialized, &true);
        persist_set(&env, &DataKey::AdminFrozen, &false);
        persist_set(&env, &DataKey::LastHeartbeat, &0u64);
        emit_initialized(&env, &admin);
    }

    // ── Policy management (admin only) ───────────────────────────────────

    fn admin_or_panic(env: &Env) -> Address {
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        match admin {
            Some(a) => {
                a.require_auth();
                a
            }
            None => panic_with_error!(env, Error::NotInitialized),
        }
    }

    /// Installs a new policy. Resets the rolling window and starts the
    /// dead-man-switch clock at install time (a fresh policy gets full grace).
    pub fn set_policy(env: Env, config: PolicyConfig) {
        let admin = Self::admin_or_panic(&env);
        validate_config(&env, &config).unwrap_or_else(|e| panic_with_error!(&env, e));
        persist_set(&env, &DataKey::Policy, &config);
        increment_revision(&env);
        save_ledger(&env, &Ledger::empty(&env));
        let now = env.ledger().timestamp();
        persist_set(&env, &DataKey::LastHeartbeat, &now);
        emit_policy_set(&env, &admin);
    }

    /// Removes the policy and window → immediate default-deny.
    pub fn revoke_policy(env: Env) {
        let admin = Self::admin_or_panic(&env);
        env.storage().persistent().remove(&DataKey::Policy);
        env.storage().persistent().remove(&DataKey::Window);
        increment_revision(&env);
        emit_policy_revoked(&env, &admin);
    }

    /// Re-binds the agent's Ed25519 public key. Admin never gains fund-moving
    /// power; it can only replace the key the account will authenticate.
    pub fn rotate_agent_key(env: Env, new_pubkey: BytesN<32>) {
        let admin = Self::admin_or_panic(&env);
        env.storage()
            .instance()
            .set(&DataKey::AgentPubkey, &new_pubkey);
        emit_agent_rotated(&env, &admin);
    }

    // ── Dead-man switch / freeze (SPEC §5) ───────────────────────────────

    /// Records a heartbeat. Routes through `__check_auth` (self-call): the
    /// host verifies the registered agent's signature and the engine applies
    /// the account gates, so a heartbeat after the grace window expired — or
    /// while admin-frozen — is rejected.
    pub fn heartbeat(env: Env) {
        env.current_contract_address().require_auth();
        let now = env.ledger().timestamp();
        // Redundant same-second heartbeat: `LastHeartbeat` is already `now`, so
        // the write (with its TTL extension) and the event carry no new
        // information — the first heartbeat of this second already extended the
        // entry's TTL. Skip both rather than pay for a no-op write (SPEC §5).
        let last = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        if now == last {
            return;
        }
        persist_set(&env, &DataKey::LastHeartbeat, &now);
        emit_heartbeat(&env, now);
    }

    pub fn freeze(env: Env) {
        let admin = Self::admin_or_panic(&env);
        persist_set(&env, &DataKey::AdminFrozen, &true);
        emit_frozen(&env, &admin);
    }

    /// Admin liveness attestation: clears the admin freeze and restarts the
    /// heartbeat clock.
    pub fn unfreeze(env: Env) {
        let admin = Self::admin_or_panic(&env);
        persist_set(&env, &DataKey::AdminFrozen, &false);
        let now = env.ledger().timestamp();
        persist_set(&env, &DataKey::LastHeartbeat, &now);
        emit_unfrozen(&env, &admin);
    }

    // ── Read / advisory (no auth — safe reads only, nothing confidential) ─

    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn policy(env: Env) -> Option<PolicyConfig> {
        persist_get(&env, &DataKey::Policy)
    }

    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn status(env: Env) -> Status {
        let has_policy = persist_get::<PolicyConfig>(&env, &DataKey::Policy).is_some();
        let policy_revision = persist_get::<u64>(&env, &DataKey::PolicyRevision).unwrap_or(0);
        let admin_frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let grace =
            persist_get::<PolicyConfig>(&env, &DataKey::Policy).map_or(0, |c| c.dms_grace_secs);
        Status {
            has_policy,
            policy_revision,
            admin_frozen,
            heartbeat_expired: grace > 0
                && last_heartbeat != 0
                && now.saturating_sub(last_heartbeat) > grace,
            last_heartbeat,
            now,
        }
    }

    /// Pure pre-flight of the asset-transfer decision path (no writes): lets
    /// agents/SDK simulate a transfer before signing. Emits the same
    /// `auth_checked` events as an in-path decision.
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult {
        let Some(cfg) = persist_get::<PolicyConfig>(&env, &DataKey::Policy) else {
            emit_auth(&env, false, Some(Error::NoPolicy));
            return CheckResult::Blocked(Symbol::new(&env, Error::NoPolicy.reason()));
        };
        let frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let self_addr = env.current_contract_address();
        let mut ledger = load_ledger(&env);
        let call = transfer_context(&env, &asset, &to, amount);
        match decide(
            &env,
            &self_addr,
            Some(&cfg),
            &AccountState {
                admin_frozen: frozen,
                last_heartbeat,
            },
            &mut ledger,
            now,
            vec![&env, call],
        ) {
            Decision::Allowed => {
                emit_auth(&env, true, None);
                CheckResult::Allowed
            }
            Decision::Blocked(e) => {
                emit_auth(&env, false, Some(e));
                CheckResult::Blocked(Symbol::new(&env, e.reason()))
            }
        }
    }
}

/// Build the auth `Context` of a SAC `transfer` call for pre-flight checks.
fn transfer_context(env: &Env, asset: &Address, to: &Address, amount: i128) -> Context {
    let mut args: soroban_sdk::Vec<Val> = soroban_sdk::Vec::new(env);
    args.push_back(asset.clone().into_val(env)); // from
    args.push_back(to.clone().into_val(env));
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

// ── Custom account enforcement (SPEC §7) ─────────────────────────────────
//
// The host calls `__check_auth` for every authorization this account must
// approve. The account verifies the agent's Ed25519 signature over the
// transaction auth payload, then evaluates the policy decision table over
// every auth context. `Ok(())` approves; `Err` rejects the whole transaction.

#[contractimpl]
#[allow(clippy::needless_pass_by_value)] // trait + contract ABI require owned args
impl CustomAccountInterface for PolicyEngine {
    type Signature = BytesN<64>;
    type Error = Error;

    fn __check_auth(
        env: Env,
        signature_payload: soroban_sdk::crypto::Hash<32>,
        signatures: Self::Signature,
        auth_contexts: soroban_sdk::Vec<Context>,
    ) -> Result<(), Error> {
        // 1. Agent key registered (initialize done).
        let agent: Option<BytesN<32>> = env.storage().instance().get(&DataKey::AgentPubkey);
        let Some(agent) = agent else {
            emit_auth(&env, false, Some(Error::NotInitialized));
            return Err(Error::NotInitialized);
        };

        // 2. Verify the agent's Ed25519 signature over the auth payload. The
        //    host crypto function traps the frame on a bad signature, so a
        //    wrong key can never reach policy evaluation.
        let message: Bytes = signature_payload.into();
        env.crypto().ed25519_verify(&agent, &message, &signatures);

        // 3. Policy snapshot + gate evaluation over every context.
        let Some(cfg) = persist_get::<PolicyConfig>(&env, &DataKey::Policy) else {
            emit_auth(&env, false, Some(Error::NoPolicy));
            return Err(Error::NoPolicy);
        };
        let frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let self_addr = env.current_contract_address();

        let mut ledger = load_ledger(&env);
        match decide(
            &env,
            &self_addr,
            Some(&cfg),
            &AccountState {
                admin_frozen: frozen,
                last_heartbeat,
            },
            &mut ledger,
            now,
            auth_contexts,
        ) {
            Decision::Allowed => {
                // 4. Persist window changes made by the decision.
                let had_window = persist_get::<WindowState>(&env, &DataKey::Window).is_some();
                let has_entries = ledger.len() > 0;
                if had_window || has_entries {
                    save_ledger(&env, &ledger);
                }
                emit_auth(&env, true, None);
                Ok(())
            }
            Decision::Blocked(e) => {
                emit_auth(&env, false, Some(e));
                Err(e)
            }
        }
    }
}

// ── Test utilities (exposed via `testutils` feature) ──────────────────────
#[cfg(feature = "testutils")]
#[allow(clippy::must_use_candidate, clippy::len_without_is_empty)]
pub mod testutils {
    pub use crate::engine::{contains_addr, decide, parse_call, AccountState, Decision};
    pub use crate::types::{
        CheckResult, DataKey, Error, PolicyConfig, ProtocolRule, Status, WindowState,
    };
    pub use crate::window::Ledger;
    pub use soroban_sdk::auth::{Context, ContractContext};
    pub use soroban_sdk::{vec, Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec};
}
