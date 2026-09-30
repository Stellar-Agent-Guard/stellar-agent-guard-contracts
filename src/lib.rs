#![no_std]

//! stellar-agent-guard-contracts — a Soroban **custom account** that enforces
//! agent spend policy inside `__check_auth`. See SPEC.md.
//!
//! The registered agent is an **Ed25519 keypair** whose public key is stored
//! on the account. Every transaction that requires this account's
//! authorization is routed by the host through `__check_auth`, which first
//! verifies the Ed25519 signature presented over the transaction auth payload
//! and then evaluates the policy (SPEC §4/§6/§7). No CAP-71 delegation in v1.

extern crate alloc;

#[cfg(test)]
extern crate std;

mod engine;
mod types;
mod window;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod policy_preset_tests;

use engine::{cap_metrics, contains_addr, decide, AccountState, Decision};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::{
    contract, contractevent, contractimpl, panic_with_error, vec, Address, Bytes, BytesN, Env,
    IntoVal, Symbol, TryFromVal, Val,
};
pub use types::NO_POLICY_DIGEST;
pub use types::{
    CheckDetail, Error, PolicyConfig, ProtocolRule, RecipientCap, RecipientWindowState,
};
use types::{CheckResult, DataKey, Status, WindowState, MAX_RECIPIENT_ENTRIES};
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
    context_index: u32,
}

/// Agent heartbeat: data `at` (unix seconds) and `expires_at` — the
/// attested dead-man-switch deadline as it stood at emission time, derived
/// from the *current* policy's `dms_grace_secs` (`at + dms_grace_secs`).
/// `0` when the dead-man switch is disabled (`dms_grace_secs == 0`, which is
/// also how a missing policy reads). Recording the deadline on the event means
/// a consumer no longer recomputes it from whatever the policy happens to be
/// after a later `set_policy`; the event states the deadline it was attested
/// under (SPEC §9).
#[contractevent]
#[derive(Clone)]
struct EventHeartbeat {
    at: u64,
    expires_at: u64,
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

/// Admin unfreeze: data `by` (the admin address that acted) plus
/// `rearmed_dms: bool` — whether the call also re-armed the dead-man-switch
/// clock by changing `LastHeartbeat` (SPEC §5: the admin's signature is the
/// liveness attestation, so an unfreeze of a DMS-expired account silently
/// restarts the grace window; the flag makes that side effect auditable).
#[contractevent]
#[derive(Clone)]
struct EventUnfrozen {
    by: Address,
    rearmed_dms: bool,
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

/// Agent key rotation: data `by` (the admin that acted) plus truncated
/// fingerprints of the outgoing and incoming agent keys, so an auditor can
/// reconstruct the old→new linkage without carrying full pubkeys (SPEC §9).
#[contractevent]
#[derive(Clone)]
struct EventAgentRotated {
    by: Address,
    old_fingerprint: BytesN<8>,
    new_fingerprint: BytesN<8>,
}

// ── Persistent-storage helpers (SPEC §3) ────────────────────────────────
// Admin / AgentPubkey / Initialized live in instance storage (auto-TTL on
// every invocation); persistent values are extended on writes and refreshed
// on reads when their remaining TTL falls below the safety threshold.

fn extend_persistent_ttl(env: &Env, key: &DataKey, threshold: u32) {
    // `extend_ttl` takes a TTL duration relative to the current ledger, not an
    // absolute ledger sequence. Passing max_ttl directly also keeps the target
    // valid at nonzero ledger sequences.
    let max_ttl = env.storage().max_ttl();
    env.storage()
        .persistent()
        .extend_ttl(key, threshold, max_ttl);
}

fn persist_set(env: &Env, key: &DataKey, val: &impl soroban_sdk::IntoVal<Env, Val>) {
    env.storage().persistent().set(key, val);
    let max_ttl = env.storage().max_ttl();
    extend_persistent_ttl(env, key, max_ttl);
}

fn persist_get<T: soroban_sdk::TryFromVal<Env, Val>>(env: &Env, key: &DataKey) -> Option<T> {
    let value = env.storage().persistent().get(key)?;
    // Refresh active and automatically restored entries before returning
    // them. The half-life threshold avoids paying for a rent extension on
    // every read while retaining at least half of max_ttl between accesses.
    extend_persistent_ttl(env, key, env.storage().max_ttl() / 2);
    Some(value)
}

fn load_ledger(env: &Env) -> Ledger {
    match persist_get::<WindowState>(env, &DataKey::Window) {
        Some(state) => Ledger::from_state(env, state),
        None => Ledger::empty(env),
    }
}

fn save_ledger(env: &Env, ledger: &Ledger) {
    persist_set(env, &DataKey::Window, &ledger.to_state(env));
}

fn increment_revision(env: &Env) -> u64 {
    let rev = persist_get::<u64>(env, &DataKey::PolicyRevision).unwrap_or(0);
    let next = rev.saturating_add(1);
    persist_set(env, &DataKey::PolicyRevision, &next);
    next
}

#[allow(clippy::must_use_candidate)]
fn ledger_has_recipient_entries(ledger: &Ledger) -> bool {
    for i in 0..ledger.recipients.len() {
        if let Some(r) = ledger.recipients.get(i) {
            if !r.entries.is_empty() {
                return true;
            }
        }
    }
    false
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
    if contains_addr(&cfg.recipients, &self_addr)
        || contains_addr(&cfg.blocked_recipients, &self_addr)
    {
        return Err(Error::InvalidConfig);
    }
    if has_dup(env, &cfg.assets)
        || has_dup(env, &cfg.recipients)
        || has_dup(env, &cfg.blocked_recipients)
    {
        return Err(Error::InvalidConfig);
    }
    for i in 0..cfg.recipient_window_caps.len() {
        for j in (i + 1)..cfg.recipient_window_caps.len() {
            if let (Some(a), Some(b)) = (
                cfg.recipient_window_caps.get(i),
                cfg.recipient_window_caps.get(j),
            ) {
                if a.recipient == b.recipient {
                    return Err(Error::InvalidConfig);
                }
            }
        }
    }
    if (cfg.recipients.len() as usize) > MAX_RECIPIENT_ENTRIES
        || (cfg.recipient_window_caps.len() as usize) > MAX_RECIPIENT_ENTRIES
        || (cfg.blocked_recipients.len() as usize) > MAX_RECIPIENT_ENTRIES
    {
        return Err(Error::InvalidConfig);
    }
    for i in 0..cfg.recipient_window_caps.len() {
        if let Some(rc) = cfg.recipient_window_caps.get(i) {
            if rc.cap < 0 {
                return Err(Error::InvalidConfig);
            }
            if rc.cap > 0 && cfg.window_secs == 0 {
                return Err(Error::InvalidConfig);
            }
            // Same rule as `recipients`: a self-addressed cap entry is a
            // meaningless no-op loop.
            if rc.recipient == self_addr {
                return Err(Error::InvalidConfig);
            }
        }
    }
    // A recipient cannot be both explicitly allowed and explicitly denied.
    for i in 0..cfg.recipients.len() {
        if let Some(recipient) = cfg.recipients.get(i) {
            if contains_addr(&cfg.blocked_recipients, &recipient) {
                return Err(Error::InvalidConfig);
            }
        }
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

fn emit_auth(env: &Env, allowed: bool, reason: Option<Error>, context_index: u32) {
    let res = if allowed { "allowed" } else { "blocked" };
    let reason = reason.map_or("", |e| e.reason());
    EventAuthChecked {
        result: Symbol::new(env, res),
        reason: Symbol::new(env, reason),
        context_index,
    }
    .publish(env);
}

fn emit_heartbeat(env: &Env, at: u64, expires_at: u64) {
    EventHeartbeat { at, expires_at }.publish(env);
}

fn emit_initialized(env: &Env, by: &Address) {
    EventInitialized { by: by.clone() }.publish(env);
}
fn emit_frozen(env: &Env, by: &Address) {
    EventFrozen { by: by.clone() }.publish(env);
}
fn emit_unfrozen(env: &Env, by: &Address, rearmed_dms: bool) {
    EventUnfrozen {
        by: by.clone(),
        rearmed_dms,
    }
    .publish(env);
}
fn emit_policy_set(env: &Env, by: &Address) {
    EventPolicySet { by: by.clone() }.publish(env);
}
fn emit_policy_revoked(env: &Env, by: &Address) {
    EventPolicyRevoked { by: by.clone() }.publish(env);
}
/// Compact key fingerprint: the first 8 bytes of `SHA-256(pubkey)`. Rendered
/// as 16 lowercase hex characters off-chain (greppable, small event payload);
/// deliberately truncating so events never carry a full pubkey.
fn key_fingerprint(env: &Env, pubkey: &BytesN<32>) -> BytesN<8> {
    let digest: [u8; 32] = env
        .crypto()
        .sha256(&Bytes::from_array(env, &pubkey.to_array()))
        .into();
    let mut fingerprint = [0u8; 8];
    fingerprint.copy_from_slice(&digest[..8]);
    BytesN::from_array(env, &fingerprint)
}

fn emit_agent_rotated(env: &Env, by: &Address, old: &BytesN<32>, new: &BytesN<32>) {
    EventAgentRotated {
        by: by.clone(),
        old_fingerprint: key_fingerprint(env, old),
        new_fingerprint: key_fingerprint(env, new),
    }
    .publish(env);
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
        // Post-initialize the key always exists; the fingerprint needs the old
        // key before the storage slot is overwritten.
        let old_pubkey: Option<BytesN<32>> = env.storage().instance().get(&DataKey::AgentPubkey);
        let Some(old_pubkey) = old_pubkey else {
            panic_with_error!(&env, Error::NotInitialized);
        };
        env.storage()
            .instance()
            .set(&DataKey::AgentPubkey, &new_pubkey);
        emit_agent_rotated(&env, &admin, &old_pubkey, &new_pubkey);
    }

    // ── Dead-man switch / freeze (SPEC §5) ───────────────────────────────

    /// Records a heartbeat. Routes through `__check_auth` (self-call): the
    /// host verifies the registered agent's signature and the engine applies
    /// the account gates, so a heartbeat after the grace window expired — or
    /// while admin-frozen — is rejected.
    ///
    /// Reads and writes: `Policy` (read, for the DMS grace at emission time)
    /// and `LastHeartbeat` (read + write).
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
        // Read the policy fresh here, at emission time, so the recorded
        // deadline reflects the grace actually in force for this heartbeat and
        // not a value cached from an earlier call. A missing policy or a zero
        // `dms_grace_secs` means the dead-man switch is disabled, which the
        // event records as `expires_at == 0` (SPEC §9).
        let grace =
            persist_get::<PolicyConfig>(&env, &DataKey::Policy).map_or(0, |cfg| cfg.dms_grace_secs);
        let expires_at = if grace == 0 {
            0
        } else {
            now.saturating_add(grace)
        };
        emit_heartbeat(&env, now, expires_at);
    }

    pub fn freeze(env: Env) {
        let admin = Self::admin_or_panic(&env);
        persist_set(&env, &DataKey::AdminFrozen, &true);
        emit_frozen(&env, &admin);
    }

    /// Admin liveness attestation: clears the admin freeze and restarts the
    /// heartbeat clock. One call, two jobs (SPEC §5 recorded decision): the
    /// brake release and the liveness attestation are combined on purpose —
    /// when the DMS grace was already elapsed, this re-arms the liveness clock
    /// on the admin's authority, and the emitted event carries
    /// `rearmed_dms: bool` so telemetry can surface exactly that side effect
    /// (`true` = `LastHeartbeat` changed, `false` = it was already `now`).
    pub fn unfreeze(env: Env) {
        let admin = Self::admin_or_panic(&env);
        persist_set(&env, &DataKey::AdminFrozen, &false);
        let now = env.ledger().timestamp();
        let last = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let rearmed_dms = last != now;
        persist_set(&env, &DataKey::LastHeartbeat, &now);
        emit_unfrozen(&env, &admin, rearmed_dms);
    }

    // ── Read / advisory (no auth; non-confidential state; TTL effects in §9.5) ─

    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn policy(env: Env) -> Option<PolicyConfig> {
        persist_get(&env, &DataKey::Policy)
    }

    /// Canonical encoding fingerprint for cheap policy drift detection
    /// (`policy_hash`): SHA-256 over the deterministic canonical encoding of
    /// the installed policy (SPEC §7.3), or `NO_POLICY_DIGEST` (the SHA-256 of
    /// the empty marker, documented and never trapping) when no policy is
    /// installed. No auth, event-free, and write-free. A returned hash only
    /// changes when the *policy* changes — not on any other storage or ledger
    /// activity — so SDKs/dashboards can detect drift by comparing one 32-byte
    /// value instead of shipping and diffing the full `PolicyConfig`, and can
    /// record the value alongside `auth_checked` events as a tamper-evident
    /// log anchor.
    ///
    /// Off-chain reproduction is pinned by SPEC §7.3 (field order, per-field
    /// encoding, sentinel value) and locked by `tests/policy_hash_encoding.rs`.
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn policy_hash(env: Env) -> BytesN<32> {
        match persist_get::<PolicyConfig>(&env, &DataKey::Policy) {
            None => BytesN::from_array(&env, &crate::types::NO_POLICY_DIGEST),
            Some(cfg) => {
                let encoding = crate::types::policy_canonical_encoding(&env, &cfg);
                env.crypto().sha256(&encoding).into()
            }
        }
    }

    /// Evaluates dead-man switch health (`Ok`, `Warn` at ≥80% elapsed, or `Expired`).
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn dms_health(env: Env) -> crate::types::DmsHealthStatus {
        let Some(cfg) = persist_get::<PolicyConfig>(&env, &DataKey::Policy) else {
            return crate::types::DmsHealthStatus::Ok;
        };
        let last = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        engine::dms_health(now, last, &cfg)
    }

    /// Operational snapshot: policy presence/revision, admin freeze, DMS state,
    /// plus the operational fields (`paused`, `window_remaining`,
    /// `outside_active_window`) a dashboard or SDK needs to explain *why* the
    /// next transaction would be admitted or rejected. Event-free read with no
    /// auth and no spend-accounting writes; like every persistent read it may
    /// refresh entry TTLs (SPEC §9.5).
    ///
    /// Semantics of the operational fields mirror the §4 account gates and
    /// `check_detailed` headroom exactly:
    /// - `paused` is the policy's kill switch (`false` with no policy —
    ///   default-deny has nothing to pause).
    /// - `window_remaining` is global `window_cap - spent` on the *pruned*
    ///   ledger (expired entries never count), or `None` when the global cap
    ///   is disabled — including the no-policy case. Per-recipient override
    ///   headroom is recipient-targeted; use `check_detailed` for that.
    /// - `outside_active_window` evaluates the same bounds the §4 gate uses
    ///   (`false` with no policy or an unrestricted window).
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn status(env: Env) -> Status {
        let policy = persist_get::<PolicyConfig>(&env, &DataKey::Policy);
        let policy_revision = persist_get::<u64>(&env, &DataKey::PolicyRevision).unwrap_or(0);
        let admin_frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let (paused, window_remaining, outside_active_window, grace) = match &policy {
            None => (false, None, false, 0),
            Some(cfg) => {
                // Prune a local copy of the ledger so remaining headroom never
                // counts expired entries. No storage write: this is a read.
                let mut ledger = load_ledger(&env);
                if cfg.window_cap > 0 || !cfg.recipient_window_caps.is_empty() {
                    ledger.prune(now, cfg.window_secs);
                }
                (
                    cfg.paused,
                    engine::global_window_remaining(cfg, &ledger),
                    (cfg.active_from != 0 && now < cfg.active_from)
                        || (cfg.active_until != 0 && now > cfg.active_until),
                    cfg.dms_grace_secs,
                )
            }
        };
        Status {
            has_policy: policy.is_some(),
            policy_revision,
            admin_frozen,
            heartbeat_expired: grace > 0
                && last_heartbeat != 0
                && now.saturating_sub(last_heartbeat) > grace,
            last_heartbeat,
            now,
            paused,
            window_remaining,
            outside_active_window,
        }
    }

    /// Preflight / simulate a transfer (`check`): permissionless pre-flight
    /// of the asset-transfer decision path.
    ///
    /// Search aliases for SDK discoverability: "preflight", "simulate",
    /// `simulate_transfer`, `simulate-transfer`. These are documentation
    /// aliases only — the on-chain ABI is frozen as `check` (and
    /// `check_detailed`); there is no `simulate_transfer` entrypoint.
    ///
    /// Lets agents/SDKs simulate a transfer before signing. A submitted call
    /// may refresh persistent TTLs; simulation does not persist those rent
    /// bumps. Emits the same `auth_checked` event as an in-path decision.
    ///
    /// # Example
    ///
    /// Mirrors the live Phase-1 testnet invocation (permissionless read,
    /// simulation only; this account is DMS-frozen, so the honest answer
    /// today is blocked):
    ///
    /// ```text
    /// stellar contract invoke --id CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7 \
    ///   --network testnet --source-account guard_admin --send=no -- \
    ///   check --asset CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7 \
    ///   --to GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX --amount 50
    /// # → {"Blocked":"heartbeat_expired"}
    /// ```
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn check(env: Env, asset: Address, to: Address, amount: i128) -> CheckResult {
        Self::check_detailed(env, asset, to, amount).result
    }

    /// Preflight / simulate a transfer with headroom (`check_detailed`):
    /// pre-flight decision plus current cap headroom for the targeted asset.
    /// Part of the `check` preflight / simulate alias family (documentation
    /// aliases only; the ABI is frozen — there is no `simulate_transfer`
    /// entrypoint).
    ///
    /// This path does not change spend accounting: it mutates a local ledger
    /// copy and emits exactly the same `auth_checked` event as `check`. A
    /// submitted call may refresh persistent TTLs; simulation does not persist
    /// those rent bumps.
    ///
    /// # Panics
    ///
    /// This function panics if the policy engine's `decide` evaluation returns an empty list of verdicts.
    #[allow(clippy::must_use_candidate)] // public read surface
    pub fn check_detailed(env: Env, asset: Address, to: Address, amount: i128) -> CheckDetail {
        let Some(cfg) = persist_get::<PolicyConfig>(&env, &DataKey::Policy) else {
            emit_auth(&env, false, Some(Error::NoPolicy), 0);
            return CheckDetail {
                result: CheckResult::Blocked(Symbol::new(&env, Error::NoPolicy.reason())),
                remaining_window: None,
                per_tx_cap: None,
                effective_per_tx_cap: None,
                effective_window_cap: None,
            };
        };
        let frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let self_addr = env.current_contract_address();
        let mut ledger = load_ledger(&env);
        if cfg.window_cap > 0 || !cfg.recipient_window_caps.is_empty() {
            ledger.prune(now, cfg.window_secs);
        }
        let (remaining_window, per_tx_cap, effective_window_cap) = cap_metrics(&cfg, &ledger, &to);
        let effective_per_tx_cap = per_tx_cap;
        let call = transfer_context(&env, &asset, &to, amount);
        let verdicts = decide(
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
        );
        let result = match verdicts.first().unwrap() {
            Decision::Allowed => {
                emit_auth(&env, true, None, 0);
                CheckResult::Allowed
            }
            Decision::Blocked(e) => {
                emit_auth(&env, false, Some(*e), 0);
                CheckResult::Blocked(Symbol::new(&env, e.reason()))
            }
        };
        CheckDetail {
            result,
            remaining_window,
            per_tx_cap,
            effective_per_tx_cap,
            effective_window_cap,
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
            for i in 0..auth_contexts.len() {
                emit_auth(&env, false, Some(Error::NotInitialized), i);
            }
            return Err(Error::NotInitialized);
        };

        // 2. Verify the agent's Ed25519 signature over the auth payload. The
        //    host crypto function traps the frame on a bad signature, so a
        //    wrong key can never reach policy evaluation.
        let message: Bytes = signature_payload.into();
        env.crypto().ed25519_verify(&agent, &message, &signatures);

        // 3. Policy snapshot + gate evaluation over every context.
        let Some(cfg) = persist_get::<PolicyConfig>(&env, &DataKey::Policy) else {
            for i in 0..auth_contexts.len() {
                emit_auth(&env, false, Some(Error::NoPolicy), i);
            }
            return Err(Error::NoPolicy);
        };
        let frozen = persist_get::<bool>(&env, &DataKey::AdminFrozen).unwrap_or(false);
        let last_heartbeat = persist_get::<u64>(&env, &DataKey::LastHeartbeat).unwrap_or(0);
        let now = env.ledger().timestamp();
        let self_addr = env.current_contract_address();

        let mut ledger = load_ledger(&env);
        let verdicts = decide(
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
        );

        let mut all_passed = true;
        let mut first_error = None;
        for (i, v) in verdicts.iter().enumerate() {
            match v {
                Decision::Allowed => emit_auth(&env, true, None, u32::try_from(i).unwrap()),
                Decision::Blocked(e) => {
                    all_passed = false;
                    if first_error.is_none() {
                        first_error = Some(*e);
                    }
                    emit_auth(&env, false, Some(*e), u32::try_from(i).unwrap());
                }
            }
        }

        if all_passed {
            // 4. Persist window changes made by the decision.
            let had_window = persist_get::<WindowState>(&env, &DataKey::Window).is_some();
            let has_entries = ledger.len() > 0 || ledger_has_recipient_entries(&ledger);
            if had_window || has_entries {
                save_ledger(&env, &ledger);
            }
            Ok(())
        } else {
            Err(first_error.unwrap())
        }
    }
}

// ── Test utilities (exposed via `testutils` feature) ──────────────────────
#[cfg(feature = "testutils")]
#[allow(clippy::must_use_candidate, clippy::len_without_is_empty)]
pub mod testutils {
    pub use crate::engine::{contains_addr, decide, parse_call, AccountState, Decision};
    pub use crate::types::policy_canonical_encoding;
    pub use crate::types::{
        CheckResult, DataKey, Error, PolicyConfig, ProtocolRule, RecipientCap,
        RecipientWindowState, Status, WindowState,
    };
    pub use crate::window::Ledger;
    pub use soroban_sdk::auth::{Context, ContractContext};
    pub use soroban_sdk::{vec, Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec};
}
