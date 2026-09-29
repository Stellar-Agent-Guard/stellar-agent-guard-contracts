//! Contract-level integration tests (SPEC §11).
//!
//! These drive the *real host routing*: `require_auth` on the guard contract
//! makes the host invoke `PolicyEngine::__check_auth` with a signature payload
//! computed by the host over the authorized invocation. Each test signs that
//! exact payload with the registered agent's Ed25519 key (replicating the
//! protocol's `HashIdPreimage::SorobanAuthorization` hashing), attaches it as
//! `SorobanCredentials::Address`, and runs the call in **enforcing** auth
//! mode (`Env::set_auths`). A blocked policy decision therefore surfaces as a
//! failed `require_auth`, exactly as it would on-chain.
//!
//! Two helper contracts:
//! - `MockAsset` plays a Stellar Asset Contract: `transfer(from, to, amount)`
//!   does `from.require_auth()`, so authorizing a transfer from the guard
//!   routes through the guard's `__check_auth` with the real context shape.
//! - `MockAdmin` is a trivial custom account (`Signature = ()`, always
//!   approves) so admin calls can be enforced in the same env without key
//!   material.

use crate::types::{CheckResult, DataKey, Error as GuardError, PolicyConfig, ProtocolRule};
use crate::{PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limited, Limits,
    ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, vec, Address, BytesN, Env, FromVal, IntoVal, Symbol, Val,
};
use std::format;

/// A `ScVal::Symbol` built from a plain string (event names / map keys).
fn symbol_val(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(s)).unwrap())
}

/// Off-chain reproduction of the contract's key fingerprint (SPEC §9):
/// `sha256(pubkey)[0..8]`, as the `ScVal::Bytes` an event data map carries.
fn fingerprint(pubkey: &[u8; 32]) -> ScVal {
    let digest = Sha256::digest(pubkey);
    ScVal::Bytes(ScBytes::try_from(digest[..8].to_vec()).unwrap())
}

/// Number of `heartbeat` events published by the last contract invocation.
fn heartbeat_event_count(env: &Env) -> usize {
    let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("event_heartbeat")).unwrap());
    env.events()
        .all()
        .events()
        .iter()
        .filter(|e| {
            matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want))
        })
        .count()
}

// ── Test contracts ───────────────────────────────────────────────────────

#[contract]
pub struct MockAsset;

#[contractimpl]
#[allow(clippy::needless_pass_by_value)] // contract ABI requires owned args
impl MockAsset {
    /// SAC-shaped `transfer`: requires auth from the sender. The guard
    /// contract is the `from`, so this routes through `__check_auth`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        #[allow(deprecated)] // test-only helper; not part of the shipped surface
        env.events()
            .publish((Symbol::new(&env, "transfer_ok"),), (to, amount));
    }
}

/// Admin account contract: approves every authorization it is asked to
/// verify (`Signature = ()`, no key material needed in tests).
#[contract]
pub struct MockAdmin;

#[contractimpl]
#[allow(
    clippy::needless_pass_by_value, // trait ABI requires owned args
    clippy::used_underscore_binding // trait-required params, deliberately unused
)]
impl CustomAccountInterface for MockAdmin {
    type Signature = ();
    type Error = GuardError;

    #[allow(clippy::used_underscore_binding)] // trait-required params, deliberately unused
    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signatures: Self::Signature,
        _auth_contexts: soroban_sdk::Vec<Context>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ── Harness ──────────────────────────────────────────────────────────────

struct Harness {
    env: Env,
    guard: Address,
    admin: Address,
    asset: Address,
    agent: SigningKey,
    recv: Address,
    other: Address,
    guard_nonce: i64,
    admin_nonce: i64,
}

impl Harness {
    fn new() -> Self {
        Self::with_env(Env::default())
    }

    fn with_short_persistent_ttl() -> Self {
        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(2);
        env.ledger().set_max_entry_ttl(10);
        // Exercise the host's max-TTL semantics away from ledger sequence 0.
        env.ledger().set_sequence_number(1_000);
        Self::with_env(env)
    }

    fn with_env(env: Env) -> Self {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let admin = env.register(MockAdmin, ());
        let asset = env.register(MockAsset, ());
        let guard = env.register(PolicyEngine, ());
        // Recipients/others are arbitrary addresses used only as data.
        let recv = Address::generate(&env);
        let other = Address::generate(&env);

        // soroban-sdk 27 test env defaults to *enforcing* auth: `require_auth`
        // only passes with explicit entries. Admin setup ops (initialize,
        // set_policy, ...) run under blanket mocking; `enforce()` flips the env
        // back into enforcing mode with a hand-signed entry for the guarded
        // flow. `mock_all_auths` is the documented default intent of the
        // harness (see header comment).
        env.mock_all_auths();
        let client = PolicyEngineClient::new(&env, &guard);
        let pk = agent.verifying_key().to_bytes();
        client.initialize(&admin, &BytesN::from_array(&env, &pk));

        Harness {
            env,
            guard,
            admin,
            asset,
            agent,
            recv,
            other,
            guard_nonce: 1,
            admin_nonce: 1,
        }
    }

    /// Base policy: asset = `MockAsset`, one allowed recipient, no caps.
    fn base_policy(&self) -> PolicyConfig {
        PolicyConfig {
            per_tx_cap: 0,
            window_secs: 86_400,
            window_cap: 0,
            assets: soroban_sdk::vec![&self.env, self.asset.clone()],
            protocols: soroban_sdk::Vec::new(&self.env),
            recipients: soroban_sdk::vec![&self.env, self.recv.clone()],
            recipient_window_caps: soroban_sdk::Vec::new(&self.env),
            blocked_recipients: soroban_sdk::Vec::new(&self.env),
            allow_any_recipient: false,
            active_from: 0,
            active_until: 0,
            paused: false,
            dms_grace_secs: 0,
        }
    }

    fn set_time(&self, ts: u64) {
        self.env.ledger().set_timestamp(ts);
    }

    // ── Admin ops (mock mode: before any `set_auths`) ────────────────────
    fn install_policy(&self, cfg: &PolicyConfig) {
        PolicyEngineClient::new(&self.env, &self.guard).set_policy(&cfg.clone());
    }

    fn revoke_policy(&self) {
        PolicyEngineClient::new(&self.env, &self.guard).revoke_policy();
    }

    // ── Auth-entry construction ──────────────────────────────────────────

    fn invocation(
        &self,
        contract: &Address,
        fn_name: &str,
        args: std::vec::Vec<Val>,
    ) -> SorobanAuthorizedInvocation {
        let sc_args: std::vec::Vec<ScVal> = args
            .into_iter()
            .map(|v| xdr::ScVal::from_val(&self.env, &v))
            .collect();
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: xdr::ScAddress::from(contract),
                function_name: ScSymbol::try_from(fn_name.as_bytes().to_vec()).unwrap(),
                args: xdr::VecM::try_from(sc_args).unwrap(),
            }),
            sub_invocations: xdr::VecM::default(),
        }
    }

    fn transfer_invocation(
        &self,
        from: &Address,
        to: &Address,
        amount: i128,
    ) -> SorobanAuthorizedInvocation {
        let args = std::vec![
            from.clone().into_val(&self.env),
            to.clone().into_val(&self.env),
            amount.into_val(&self.env),
        ];
        self.invocation(&self.asset, "transfer", args)
    }

    fn heartbeat_invocation(&self) -> SorobanAuthorizedInvocation {
        self.invocation(&self.guard, "heartbeat", std::vec![])
    }

    fn unfreeze_invocation(&self) -> SorobanAuthorizedInvocation {
        self.invocation(&self.guard, "unfreeze", std::vec![])
    }

    fn signature_expiration_ledger(&self) -> u32 {
        self.env
            .ledger()
            .sequence()
            .saturating_add(self.env.storage().max_ttl())
    }

    fn payload(&self, nonce: i64, invocation: &SorobanAuthorizedInvocation) -> [u8; 32] {
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: self.signature_expiration_ledger(),
            invocation: invocation.clone(),
        });
        let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
        preimage
            .write_xdr(&mut Limited::new(&mut buf, Limits::none()))
            .unwrap();
        Sha256::digest(&buf).into()
    }

    /// Build an auth entry for the guard signed by the agent's key over the
    /// host-computed signature payload.
    fn guard_entry(&mut self, root: &SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
        let key = self.agent.clone(); // entry builder takes &mut self
        self.guard_entry_with(&key, root)
    }

    /// Build a guard auth entry signed by an arbitrary key — for tests that
    /// must present a rotated-out or never-registered key to the account.
    fn guard_entry_with(
        &mut self,
        key: &SigningKey,
        root: &SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.guard_nonce;
        self.guard_nonce += 1;
        let payload = self.payload(nonce, root);
        let sig = key.sign(&payload).to_bytes();
        let signature_expiration_ledger = self.signature_expiration_ledger();
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.guard),
                nonce,
                signature_expiration_ledger,
                signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
            }),
            root_invocation: root.clone(),
        }
    }

    /// Build an auth entry for the (signature-less) admin account.
    fn admin_entry(&mut self, root: &SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
        let nonce = self.admin_nonce;
        self.admin_nonce += 1;
        let signature_expiration_ledger = self.signature_expiration_ledger();
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.admin),
                nonce,
                signature_expiration_ledger,
                signature: ScVal::Void,
            }),
            root_invocation: root.clone(),
        }
    }

    /// Switch the env into enforcing auth mode with exactly one entry.
    fn enforce(&mut self, entry: SorobanAuthorizationEntry) {
        self.env.set_auths(&[entry]);
    }

    // ── Guarded operations (enforcing) ───────────────────────────────────

    fn transfer(&mut self, to: &Address, amount: i128) {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        MockAssetClient::new(&self.env, &self.asset).transfer(&self.guard, to, &amount);
    }

    fn transfer_expect_blocked(&mut self, to: &Address, amount: i128) {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MockAssetClient::new(&self.env, &self.asset).transfer(&self.guard, to, &amount);
        }));
        assert!(res.is_err(), "expected the transfer to be blocked");
    }

    fn heartbeat(&mut self) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
    }

    fn heartbeat_expect_blocked(&mut self) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
        }));
        assert!(res.is_err(), "expected the heartbeat to be blocked");
    }

    fn heartbeat_with(&mut self, key: &SigningKey) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry_with(key, &root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
    }

    /// Send a heartbeat signed by a specific key and assert the guard blocks
    /// it. Returns the panic payload (the host's `HostError` event log), so
    /// callers can assert which reason blocked it — e.g. a signature failure
    /// vs the DMS `HeartbeatExpired`.
    fn heartbeat_with_expect_blocked(&mut self, key: &SigningKey) -> std::string::String {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry_with(key, &root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
        }));
        if let Err(payload) = res {
            payload
                .downcast_ref::<std::string::String>()
                .cloned()
                .unwrap_or_default()
        } else {
            panic!("expected the heartbeat to be blocked")
        }
    }

    fn unfreeze(&mut self) {
        let root = self.unfreeze_invocation();
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).unfreeze();
    }

    fn status(&self) -> crate::types::Status {
        PolicyEngineClient::new(&self.env, &self.guard).status()
    }

    /// Did the guard emit an `auth_checked` event with `result = allowed`?
    /// `#[contractevent]` prepends the event name to the topic list, so the
    /// `result` topic (SPEC §9) is at index 1.
    fn emitted_allowed_auth(&self) -> bool {
        let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("allowed")).unwrap());
        self.env
            .events()
            .all()
            .events()
            .iter()
            .any(|e| match &e.body {
                xdr::ContractEventBody::V0(v0) => v0.topics.get(1) == Some(&want),
            })
    }

    /// The `(old, new)` key fingerprints carried by the most recent
    /// `agent_rotated` event (SPEC §9), as raw `ScVal`s. Panics if the event
    /// is absent or malformed.
    fn agent_rotated_fingerprints(&self) -> (ScVal, ScVal) {
        let event_name = symbol_val("event_agent_rotated");
        for event in self.env.events().all().events().iter().rev() {
            let xdr::ContractEventBody::V0(v0) = &event.body;
            if v0.topics.first() != Some(&event_name) {
                continue;
            }
            let ScVal::Map(Some(map)) = &v0.data else {
                panic!("agent_rotated data is not a map");
            };
            let mut old = None;
            let mut new = None;
            for entry in &map.0 {
                if entry.key == symbol_val("old_fingerprint") {
                    old = Some(entry.val.clone());
                } else if entry.key == symbol_val("new_fingerprint") {
                    new = Some(entry.val.clone());
                }
            }
            return (
                old.expect("agent_rotated is missing old_fingerprint"),
                new.expect("agent_rotated is missing new_fingerprint"),
            );
        }
        panic!("no agent_rotated event was emitted");
    }
}

// ── Scenarios ────────────────────────────────────────────────────────────

#[test]
fn lifecycle_initialize_once_then_status() {
    let h = Harness::new();
    // Second initialize must fail even under mock auth.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&h.admin, &BytesN::from_array(&h.env, &[9u8; 32]));
    }));
    assert!(res.is_err(), "initialize must be exactly-once");

    let st = client.status();
    assert!(!st.has_policy);
    assert_eq!(st.policy_revision, 0);
    assert!(!st.admin_frozen);
    assert!(!st.heartbeat_expired);
    assert_eq!(st.now, 0);
}

#[test]
fn persistent_read_refreshes_ttl_below_half_life() {
    let h = Harness::with_short_persistent_ttl();
    h.set_time(1_000);
    h.install_policy(&h.base_policy());

    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let initial_sequence = h.env.ledger().sequence();
    h.env.ledger().set_sequence_number(initial_sequence + 6);

    assert!(client.policy().is_some());
    let policy_ttl = h.env.as_contract(&h.guard, || {
        h.env.storage().persistent().get_ttl(&DataKey::Policy)
    });
    assert_eq!(
        policy_ttl, 10,
        "a successful read should restore the TTL to max"
    );
}

#[test]
fn archived_policy_window_and_heartbeat_restore_without_resetting_limits() {
    let mut h = Harness::with_short_persistent_ttl();
    let recv = h.recv.clone();
    let mut policy = h.base_policy();
    policy.window_cap = 100;
    policy.dms_grace_secs = 60;
    h.set_time(1_000);
    h.install_policy(&policy);
    h.set_time(1_010);
    h.transfer(&recv, 80);

    // Let Policy, Window, LastHeartbeat, and AdminFrozen all pass their
    // deliberately short test TTL. Protocol 23+ restores archived persistent
    // entries from the invocation's restore footprint before contract code.
    let expired_sequence = h.env.ledger().sequence() + 11;
    h.env.ledger().set_sequence_number(expired_sequence);

    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(client.policy(), Some(policy));

    // The check does not change spend accounting but succeeds as an invocation,
    // so it commits TTL refreshes. The 80 units in Window must still block 30.
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 30)
    });
    assert_eq!(
        detail.result,
        CheckResult::Blocked(Symbol::new(&h.env, "window_cap_exceeded"))
    );

    let status = client.status();
    assert!(!status.admin_frozen);
    assert_eq!(status.last_heartbeat, 1_000);
    h.set_time(1_100);
    assert!(client.status().heartbeat_expired);

    let ttls = h.env.as_contract(&h.guard, || {
        let persistent = h.env.storage().persistent();
        (
            persistent.get_ttl(&DataKey::Policy),
            persistent.get_ttl(&DataKey::Window),
            persistent.get_ttl(&DataKey::LastHeartbeat),
            persistent.get_ttl(&DataKey::AdminFrozen),
        )
    });
    assert_eq!(ttls, (10, 10, 10, 10));
}

#[test]
fn allowed_transaction_succeeds() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 50);
    assert!(h.emitted_allowed_auth());
    let st = h.status();
    assert!(!st.heartbeat_expired);
}

#[test]
fn detailed_check_reports_exact_headroom_and_effective_caps() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.per_tx_cap = 75;
    policy.window_cap = 100;
    h.install_policy(&policy);
    h.set_time(1_000);
    let recv = h.recv.clone();
    h.transfer(&recv, 40);

    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 10)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
    assert_eq!(detail.remaining_window, Some(60));
    assert_eq!(detail.per_tx_cap, Some(75));
    assert_eq!(detail.effective_per_tx_cap, Some(75));
    assert_eq!(detail.effective_window_cap, Some(100));
}

#[test]
fn detailed_check_reports_none_for_disabled_caps() {
    let h = Harness::new();
    h.install_policy(&h.base_policy());
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), h.recv.clone(), 10)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
    assert_eq!(detail.remaining_window, None);
    assert_eq!(detail.per_tx_cap, None);
    assert_eq!(detail.effective_per_tx_cap, None);
    assert_eq!(detail.effective_window_cap, None);
}

#[test]
fn blocked_detailed_check_reports_headroom_without_writing_window() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.window_cap = 100;
    h.install_policy(&policy);
    h.set_time(1_000);
    let recv = h.recv.clone();
    h.transfer(&recv, 40);

    let first = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 70)
    });
    assert_eq!(
        first.result,
        CheckResult::Blocked(Symbol::new(&h.env, "window_cap_exceeded"))
    );
    assert_eq!(first.remaining_window, Some(60));
    let second = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(second.remaining_window, Some(60));
}

#[test]
fn policy_revision_increments_across_set_and_revoke() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // 0 pre-first-set
    let mut st = client.status();
    assert_eq!(st.policy_revision, 0);

    // 1 after set
    h.env.mock_all_auths();
    client.set_policy(&h.base_policy());
    st = client.status();
    assert_eq!(st.policy_revision, 1);

    // 2 after revoke
    h.env.mock_all_auths();
    client.revoke_policy();
    st = client.status();
    assert_eq!(st.policy_revision, 2);

    // 3 after second set
    h.env.mock_all_auths();
    client.set_policy(&h.base_policy());
    st = client.status();
    assert_eq!(st.policy_revision, 3);
}

#[test]
fn no_policy_is_default_deny_on_chain() {
    let mut h = Harness::new();
    // initialize only — no policy ever installed.
    let recv = h.recv.clone();
    h.set_time(1_000);
    h.transfer_expect_blocked(&recv, 10);
}

#[test]
fn per_tx_cap_violation_blocked_without_window_effect() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 50;
    p.window_cap = 100; // also watch the window: blocked txs must not spend it
    h.install_policy(&p);
    h.set_time(1_000);

    h.transfer(&recv, 20); // ok: window total 20
    h.transfer_expect_blocked(&recv, 60); // per-tx cap (60 > 50); window must stay 20
    h.transfer(&recv, 30); // ok: total 50 — would fail if the blocked 60 had hit the window (110 > 100)
    h.transfer(&recv, 50); // ok: total exactly 100
    h.transfer_expect_blocked(&recv, 1); // window ledger is genuinely full: proves the 60 never counted
}

#[test]
fn rolling_window_cap_blocks_and_recovers_after_expiry() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 100;
    p.window_cap = 50;
    h.install_policy(&p);

    h.set_time(0);
    h.transfer(&recv, 30); // ok
    h.set_time(50);
    h.transfer_expect_blocked(&recv, 30); // 60 > 50 within a 100s span
    h.set_time(150); // first spend (ts 0) has expired: 150-100 = 50 >= 0
    h.transfer(&recv, 30); // ok again -> window is genuinely rolling
}

#[test]
fn recipient_allowlist_blocked() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    h.install_policy(&h.base_policy()); // only h.recv allowed
    h.set_time(1_000);
    h.transfer_expect_blocked(&other, 5);
    h.transfer(&recv, 5); // allowlisted recipient still fine
}

#[test]
fn blocked_recipient_wins_over_escape_hatch() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    // With the escape hatch on, any recipient would be allowed — except the
    // explicit denylist. `other` is neither allowed nor in the blocklist by
    // default, so it would pass under `allow_any_recipient`.
    p.allow_any_recipient = true;
    p.blocked_recipients = soroban_sdk::vec![&h.env, other.clone()];
    h.install_policy(&p);
    h.set_time(1_000);

    // Denylist beats the escape hatch.
    h.transfer_expect_blocked(&other, 5);
    // Non-blocked recipients still pass through the escape hatch.
    h.transfer(&recv, 5);
}

#[test]
fn blocked_recipients_contradiction_rejected_at_set_policy() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.recv.clone(), h.other.clone()];
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.other.clone()];

    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(&p);
    }));
    assert!(
        res.is_err(),
        "contradictory recipient config must be rejected"
    );
}

#[test]
fn allow_any_recipient_escape_hatch_still_capped() {
    let mut h = Harness::new();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.allow_any_recipient = true;
    p.per_tx_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&other, 5); // non-allowlisted recipient passes
    h.transfer_expect_blocked(&other, 101); // but the cap still binds
}

#[test]
fn dead_man_switch_freeze_and_admin_reversal() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    // Install at a realistic (non-zero) ledger time: `set_policy` starts the
    // DMS clock at install time, and the `LastHeartbeat != 0` sentinel (SPEC
    // §4 rule 2) is only meaningful off the epoch — ledger ts 0 would collide
    // with "never heartbeated".
    h.set_time(1_000_000);
    h.install_policy(&p); // LastHeartbeat = 1_000_000

    // Within grace: fine.
    h.set_time(1_000_010);
    h.transfer(&recv, 5);

    // Grace (60s) elapsed: transfers and even heartbeats are blocked.
    h.set_time(1_000_100);
    h.transfer_expect_blocked(&recv, 5);
    h.heartbeat_expect_blocked(); // silence cannot self-revive (SPEC §5)

    // Admin unfreeze is the reversal path (SPEC §5). The DMS grace had
    // elapsed, so the admin's signature re-arms the liveness clock — the
    // event must carry `rearmed_dms: true` to make that side effect
    // auditable (SPEC §5 recorded decision).
    h.unfreeze(); // sets LastHeartbeat = now (1_000_100)
    assert_unfrozen_event_rearmed(&h.env, true);
    h.heartbeat(); // a subsequently-heartbeating agent keeps it alive
    h.transfer(&recv, 5); // revived
}

/// Reads the most recent `event_unfrozen` data map and asserts the value of
/// its `rearmed_dms` field (SPEC §5 / §9).
fn assert_unfrozen_event_rearmed(env: &Env, expected: bool) {
    let want = symbol_val("event_unfrozen");
    let all = env.events().all();
    let events = all.events();
    let event = events
        .iter()
        .rfind(|e| {
            matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want))
        })
        .expect("event_unfrozen not found");
    let xdr::ContractEventBody::V0(v0) = &event.body;
    let ScVal::Map(Some(map)) = &v0.data else {
        panic!("event_unfrozen data must be a Map");
    };
    let entry = map
        .0
        .iter()
        .find(|entry| entry.key == symbol_val("rearmed_dms"))
        .expect("event_unfrozen must carry rearmed_dms");
    let rearmed = match &entry.val {
        ScVal::Bool(b) => *b,
        _ => panic!("event_unfrozen rearmed_dms must be a Bool"),
    };
    assert_eq!(
        rearmed, expected,
        "event_unfrozen rearmed_dms mismatch (LastHeartbeat side effect)"
    );
}

/// The admin brake cycle while the agent is live: a fresh heartbeat, then
/// `freeze` + `unfreeze` in the same ledger second. `LastHeartbeat` already
/// equals `now` at unfreeze time, so the event must carry `rearmed_dms:
/// false` — the flag distinguishes the two jobs `unfreeze` performs (SPEC §5).
#[test]
fn unfreeze_while_dms_fresh_emits_rearmed_dms_false() {
    let mut h = Harness::new();
    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    h.set_time(1_000_000);
    h.install_policy(&p); // LastHeartbeat = 1_000_000
    h.set_time(1_000_010);
    h.heartbeat(); // agent live: LastHeartbeat = 1_000_010, DMS fresh

    // Admin brake cycle in the same second as the heartbeat: unfreeze writes
    // `LastHeartbeat = now` but the value is already `now` — no re-arm.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    h.env.mock_all_auths();
    client.freeze();
    h.unfreeze();
    assert_unfrozen_event_rearmed(&h.env, false);
    assert_eq!(h.status().last_heartbeat, 1_000_010);
}

#[test]
fn admin_freeze_blocks_immediately_and_unfreeze_restores() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 5);

    // freeze() is an admin call; re-enable blanket mocking for it, then
    // re-enforce for the guard flow that follows.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    h.env.mock_all_auths();
    client.freeze();
    let st = h.status();
    assert!(st.admin_frozen);

    // Frozen: even a valid agent-signed transfer is blocked.
    h.transfer_expect_blocked(&recv, 5);
    assert!(h.status().admin_frozen);

    h.env.mock_all_auths();
    client.unfreeze();
    let st = h.status();
    assert!(!st.admin_frozen);
    h.transfer(&recv, 5); // restored
}

#[test]
fn wrong_signature_is_rejected_by_host_crypto() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Build an entry signed by a *different* key than the registered agent.
    let wrong = SigningKey::from_bytes(&[42u8; 32]);
    let root = h.transfer_invocation(&h.guard, &recv, 5);
    let nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let payload = h.payload(nonce, &root);
    let sig = wrong.sign(&payload).to_bytes();
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
        }),
        root_invocation: root,
    };
    h.env.set_auths(&[entry]);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);
    }));
    assert!(
        res.is_err(),
        "a signature by an unregistered key must not authorize"
    );

    // The registered agent still works afterwards.
    h.transfer(&recv, 5);
}

#[test]
fn rotate_agent_key_event_carries_old_and_new_fingerprints() {
    let h = Harness::new();
    let old_pk = h.agent.verifying_key().to_bytes();
    let new_pk = SigningKey::from_bytes(&[11u8; 32])
        .verifying_key()
        .to_bytes();

    // First rotation: the `old` fingerprint is the key set at `initialize`.
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    let (old_fp, new_fp) = h.agent_rotated_fingerprints();
    assert_eq!(old_fp, fingerprint(&old_pk));
    assert_eq!(new_fp, fingerprint(&new_pk));
    assert_ne!(old_fp, new_fp, "old and new keys must be distinguishable");
}

#[test]
fn rotated_agent_key_binds() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Admin rotates the key before enforcement begins.
    let new_key = SigningKey::from_bytes(&[11u8; 32]);
    let new_pk = new_key.verifying_key().to_bytes();
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    // Old agent key no longer authorizes.
    let old_root = h.transfer_invocation(&h.guard, &recv, 5);
    let old_nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let old_payload = h.payload(old_nonce, &old_root);
    let old_sig = h.agent.sign(&old_payload).to_bytes();
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let old_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: old_nonce,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(old_sig.to_vec()).unwrap()),
        }),
        root_invocation: old_root,
    };
    h.env.set_auths(&[old_entry]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);
    }));
    assert!(res.is_err(), "rotated-out key must not authorize");

    // Swap the harness agent to the new key and confirm it works.
    h.agent = new_key;
    h.transfer(&recv, 5);
}

#[test]
fn rotate_agent_key_next_heartbeat_validity_spec_5_7() {
    // Edge: the DMS clock keeps counting from heartbeats *signed by the old
    // key* while a rotation lands inside a nearly-expired grace (SPEC §5).
    // Post-rotate, the new key is the only accepted signer (SPEC §7), and the
    // DMS rule #2 still gates the new key's heartbeats: fine within grace,
    // `HeartbeatExpired` once the grace elapses. Unit-level counterpart of the
    // on-chain agent-key-rotation proof (issue #5, SPEC §11 scenario 6).
    let mut h = Harness::new();
    let old = h.agent.clone();
    let new = SigningKey::from_bytes(&[11u8; 32]);

    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    h.set_time(1_000_000);
    h.install_policy(&p); // `set_policy` starts the DMS clock: LastHeartbeat = 1_000_000

    // Baseline: the current (old) key heartbeats fine while in grace.
    h.set_time(1_000_010);
    h.heartbeat_with(&old);
    assert_eq!(h.status().last_heartbeat, 1_000_010);

    // Admin rotates mid-grace (50s of 60s used, 10s remain). The rotation
    // itself neither resets nor consumes the heartbeat clock (SPEC §7).
    let new_pk = new.verifying_key().to_bytes();
    h.env.mock_all_auths(); // admin call, not the guarded agent flow
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    // 1. Old key is rejected immediately post-rotate. `rotate_agent_key`
    //    stores the new key *first*, so even a validly signed old-key
    //    heartbeat now fails signature verification in `__check_auth` —
    //    and the DMS clock is untouched (still the pre-rotate heartbeat).
    h.set_time(1_000_050);
    let blocked = h.heartbeat_with_expect_blocked(&old);
    assert!(blocked.contains("failed ED25519 verification"));
    assert_eq!(h.status().last_heartbeat, 1_000_010);

    // 2. New key is accepted while grace remains (signature verifies against
    //    the new stored key; 45 of 60s elapsed — rule #2 still passes).
    h.set_time(1_000_055);
    h.heartbeat_with(&new);
    assert_eq!(h.status().last_heartbeat, 1_000_055);

    // 3. Once the grace elapses, the (correctly signed) new-key heartbeat is
    //    blocked — DMS rule #2 fires with `HeartbeatExpired`. This pins that
    //    the DMS is not reset by a valid signature alone; only a heartbeat
    //    admitted by the engine restarts the clock. The host event log records
    //    the emitted `auth_checked` reason (`heartbeat_expired`) even though
    //    the failing frame rolls the event back from the ledger events API.
    h.set_time(1_000_120);
    let blocked = h.heartbeat_with_expect_blocked(&new);
    assert!(blocked.contains("heartbeat_expired"));
    assert_eq!(h.status().last_heartbeat, 1_000_055);
}

#[test]
fn redundant_same_second_heartbeat_is_a_measured_no_op() {
    // No policy/initialize needed: `heartbeat` itself only touches
    // `LastHeartbeat`; the policy gates live in `__check_auth`, which mock auth
    // bypasses. This isolates the storage-write path the optimization targets.
    let env = Env::default();
    env.mock_all_auths();
    let guard = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &guard);
    env.ledger().set_timestamp(1_000);

    // First heartbeat of the second: a real write + one event.
    client.heartbeat();
    let fresh_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    assert_eq!(
        heartbeat_event_count(&env),
        1,
        "fresh heartbeat writes + emits"
    );

    // Second heartbeat in the same ledger second: skipped entirely.
    client.heartbeat();
    let redundant_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    assert_eq!(
        heartbeat_event_count(&env),
        0,
        "the no-op heartbeat must not emit"
    );

    std::println!(
        "heartbeat cpu instructions: fresh={fresh_cpu} redundant_same_second={redundant_cpu}\
         saved={}",
        fresh_cpu.saturating_sub(redundant_cpu)
    );
    assert!(
        redundant_cpu < fresh_cpu,
        "skipping the redundant write must cost less (fresh={fresh_cpu}, \
         redundant={redundant_cpu})"
    );

    // Behaviour matches a write: `LastHeartbeat` is still `now`.
    let st = client.status();
    assert_eq!(st.last_heartbeat, 1_000);
    assert_eq!(st.now, 1_000);
}

#[test]
fn revoke_policy_is_instant_default_deny() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 5);
    // The transfer above left the env in enforcing mode; revoke is an admin op
    // under blanket mocking, so re-enable it before the admin call.
    h.env.mock_all_auths();
    h.revoke_policy();
    h.transfer_expect_blocked(&recv, 5);
}

/// SPEC §8: the contract's own address is rejected in **all three** policy
/// lists. An `assets`/`protocols` self-entry is a nonsensical allowlist (the
/// account's self-calls are governed by the fixed §6.1 rule, not policy), and
/// a `recipients` self-entry is a pay-itself no-op loop that almost certainly
/// signals a mis-pasted address — rejected as `InvalidConfig` (fail-closed)
/// rather than admitted as a meaningless allowlist entry.
#[test]
fn self_address_rejected_in_every_list() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Every case must fail `set_policy` with `InvalidConfig` (fail-closed:
    // the previously installed policy, if any, stays unchanged).
    //
    // `set_policy` returns `()` and signals rejection by panicking through
    // `panic_with_error!`, so the SDK generates no `try_set_policy` client
    // method to assert on; `catch_unwind` + `AssertUnwindSafe` is this crate's
    // established way to assert a rejected call (same as
    // `transfer_expect_blocked` / `heartbeat_expect_blocked`). Asserting only
    // "it panicked" would also pass for an unrelated panic, so each case
    // additionally asserts the fail-closed invariant: the rejected policy was
    // never written to storage.
    let expect_invalid = |cfg: &PolicyConfig, list: &str| {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_policy(cfg);
        }));
        assert!(
            res.is_err(),
            "self-address in `{list}` must fail set_policy with InvalidConfig"
        );
        assert!(
            client.policy().is_none(),
            "self-address in `{list}` must leave the policy uninstalled (fail-closed)"
        );
    };

    // assets: the guard itself listed as an SAC token.
    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.guard.clone()];
    expect_invalid(&p, "assets");

    // protocols: the guard itself listed as an allowlisted protocol contract.
    let mut p = h.base_policy();
    let rule = ProtocolRule {
        contract: h.guard.clone(),
        fns: None,
    };
    p.protocols = soroban_sdk::vec![&h.env, rule];
    expect_invalid(&p, "protocols");

    // recipients: the guard transferring to itself — a no-op loop.
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    expect_invalid(&p, "recipients");

    // Sanity: the same env still installs a self-free policy cleanly, proving
    // the rejections above came from the self-address rule and not from an
    // unrelated validation defect in the harness.
    client.set_policy(&h.base_policy());
    assert!(client.policy().is_some());
}

#[test]
fn error_and_block_reason_round_trip() {
    let all_errors = [
        GuardError::Unauthorized,
        GuardError::AlreadyInitialized,
        GuardError::NotInitialized,
        GuardError::InvalidConfig,
        GuardError::InvalidAmount,
        GuardError::AdminFrozen,
        GuardError::HeartbeatExpired,
        GuardError::NoPolicy,
        GuardError::Paused,
        GuardError::OutsideActiveWindow,
        GuardError::AssetNotAllowed,
        GuardError::RecipientNotAllowed,
        GuardError::RecipientBlocked,
        GuardError::PerTxCapExceeded,
        GuardError::WindowCapExceeded,
        GuardError::ProtocolNotAllowed,
        GuardError::FunctionNotAllowed,
        GuardError::UnknownContract,
        GuardError::SelfFunctionNotAllowed,
        GuardError::CreateContractNotAllowed,
    ];

    for err in all_errors {
        let reason = err.to_block_reason();
        let round_tripped = GuardError::from_block_reason(&reason);
        assert_eq!(
            Some(err),
            round_tripped,
            "failed round trip for error {err:?} with symbol {reason:?}"
        );
    }
}

#[test]
fn agent_runtime_lifecycle_simulation_continuous_heartbeat_loop_and_spends() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut policy = h.base_policy();
    policy.window_secs = 100;
    policy.window_cap = 100;
    policy.dms_grace_secs = 50;

    let mut now = 1_000_000u64;
    h.set_time(now);
    h.install_policy(&policy);

    // Span ≥3 window periods and ≥5 heartbeats
    // Window is 100s, so 3 windows = 300s. Let's run for 350s with heartbeats every 40s (total 9 heartbeats).
    for _i in 0..9 {
        h.set_time(now);
        h.heartbeat();

        // Spend some budget within caps (e.g. 20 per heartbeat)
        h.set_time(now + 5);
        h.transfer(&recv, 20);

        now += 40;
    }

    // Verify budget recovery across rolled-out windows: windows have rolled, so we can spend again despite prior cumulative totals.
    h.set_time(now);
    h.heartbeat();
    h.set_time(now + 5);
    h.transfer(&recv, 30);

    // Stop heartbeats and assert freeze at grace expiry
    // Last heartbeat was at roughly now - 40. Grace is 50s. Advancing time by 60s should expire grace.
    now += 60;
    h.set_time(now);
    let st = h.status();
    assert!(
        st.heartbeat_expired,
        "heartbeat should have expired after grace"
    );

    // Assert transfers and heartbeats are frozen
    h.transfer_expect_blocked(&recv, 10);
    h.heartbeat_expect_blocked();

    // Unfreeze
    h.unfreeze();
    let st_after = h.status();
    assert!(!st_after.heartbeat_expired, "guard should be unfreezed");

    // Resume normal ops
    h.set_time(now + 10);
    h.heartbeat();
    h.transfer(&recv, 10);
}

#[test]
fn policy_config_debug_snapshot() {
    let env = Env::default();
    env.mock_all_auths();

    let asset_a = Address::generate(&env);
    let asset_b = Address::generate(&env);
    let proto_a = Address::generate(&env);
    let proto_b = Address::generate(&env);
    let recip_a = Address::generate(&env);
    let recip_b = Address::generate(&env);

    let config = PolicyConfig {
        per_tx_cap: 1000,
        window_secs: 86_400,
        window_cap: 50_000,
        assets: vec![&env, asset_a.clone(), asset_b],
        protocols: vec![
            &env,
            ProtocolRule {
                contract: proto_a,
                fns: Some(vec![&env, Symbol::new(&env, "swap")]),
            },
            ProtocolRule {
                contract: proto_b,
                fns: None,
            },
        ],
        recipients: vec![&env, recip_a.clone(), recip_b],
        recipient_window_caps: vec![
            &env,
            crate::types::RecipientCap {
                recipient: recip_a,
                cap: 10_000,
            },
        ],
        blocked_recipients: vec![&env],
        allow_any_recipient: false,
        active_from: 1_700_000_000,
        active_until: 1_800_000_000,
        paused: true,
        dms_grace_secs: 3600,
    };

    let debug_output = format!("{config:?}");

    let fields = [
        "per_tx_cap",
        "window_secs",
        "window_cap",
        "assets",
        "protocols",
        "recipients",
        "recipient_window_caps",
        "blocked_recipients",
        "allow_any_recipient",
        "active_from",
        "active_until",
        "paused",
        "dms_grace_secs",
    ];

    let mut last_pos = 0;
    for field in fields {
        let pos = debug_output
            .find(field)
            .unwrap_or_else(|| panic!("field {field} not found in debug output"));
        assert!(
            pos >= last_pos,
            "field {field} appears before previous field (order: {fields:?})"
        );
        last_pos = pos;
    }
}

#[test]
fn batch_events_emit_in_order_with_context_index() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.per_tx_cap = 100;
    p.window_cap = 0;
    p.allow_any_recipient = true;
    h.install_policy(&p);

    let to = Address::generate(&h.env);

    let ctx1 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            50i128.into_val(&h.env),
        ],
    });

    let ctx2 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            200i128.into_val(&h.env),
        ],
    });

    let ctx3 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            10i128.into_val(&h.env),
        ],
    });

    let contexts = soroban_sdk::vec![&h.env, ctx1, ctx2, ctx3];

    let payload_bytes = [0u8; 32];
    let payload = soroban_sdk::BytesN::from_array(&h.env, &payload_bytes);
    let sig = h.agent.sign(&payload_bytes).to_bytes();
    let signatures = soroban_sdk::BytesN::from_array(&h.env, &sig);

    let res = h.env.as_contract(&h.guard, || {
        <PolicyEngine as soroban_sdk::auth::CustomAccountInterface>::__check_auth(
            h.env.clone(),
            unsafe {
                std::mem::transmute::<soroban_sdk::BytesN<32>, soroban_sdk::crypto::Hash<32>>(
                    payload.clone(),
                )
            },
            signatures.clone(),
            contexts.clone(),
        )
    });
    assert!(res.is_err());

    // Verify events
    let want_allowed = soroban_sdk::xdr::ScVal::Symbol(
        soroban_sdk::xdr::ScSymbol::try_from(std::vec::Vec::from("allowed")).unwrap(),
    );
    let want_blocked = soroban_sdk::xdr::ScVal::Symbol(
        soroban_sdk::xdr::ScSymbol::try_from(std::vec::Vec::from("blocked")).unwrap(),
    );

    let mut auth_events = std::vec::Vec::new();
    for e in h.env.events().all().events() {
        let soroban_sdk::xdr::ContractEventBody::V0(v0) = &e.body;
        if v0.topics.len() == 3 {
            let res = v0.topics.get(1).unwrap();
            if res == &want_allowed || res == &want_blocked {
                auth_events.push((v0.topics.clone(), v0.data.clone()));
            }
        }
    }

    assert_eq!(auth_events.len(), 3);

    let build_map = |idx: u32| {
        let key = soroban_sdk::xdr::ScVal::Symbol(
            soroban_sdk::xdr::ScSymbol::try_from(std::vec::Vec::from("context_index")).unwrap(),
        );
        let val = soroban_sdk::xdr::ScVal::U32(idx);
        soroban_sdk::xdr::ScVal::Map(Some(soroban_sdk::xdr::ScMap(
            soroban_sdk::xdr::VecM::try_from(std::vec::Vec::from([soroban_sdk::xdr::ScMapEntry {
                key,
                val,
            }]))
            .unwrap(),
        )))
    };

    // ctx1: allowed
    assert_eq!(auth_events[0].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[0].1, build_map(0)); // context_index

    // ctx2: blocked, PerTxCapExceeded
    assert_eq!(auth_events[1].0.get(1).unwrap(), &want_blocked);
    assert_eq!(auth_events[1].1, build_map(1));

    // ctx3: allowed (even though the batch fails, decide evaluates all contexts and emits for all)
    assert_eq!(auth_events[2].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[2].1, build_map(2));
}

#[test]
fn per_recipient_window_cap_enforced_on_chain() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, recv.clone(), other.clone()];
    p.window_cap = 1_000; // loose global cap
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 100,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // Within the per-recipient cap.
    h.transfer(&recv, 60);
    // Second transfer to the same recipient exceeds its per-recipient cap.
    h.transfer_expect_blocked(&recv, 50);
    // A different recipient uses the global cap and is still allowed.
    h.transfer(&other, 500);
}

#[test]
fn per_recipient_window_cap_falls_back_to_global() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, recv.clone(), other.clone()];
    p.window_cap = 100;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 1_000,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // `recv` has a generous override but is still bound by the global cap.
    h.transfer(&recv, 60);
    h.transfer_expect_blocked(&recv, 50); // would exceed global 100
                                          // `other` has no override and uses the global cap.
    h.transfer_expect_blocked(&other, 101);
    h.transfer(&other, 30);
}

#[test]
fn per_recipient_window_cap_with_allow_any_recipient() {
    let mut h = Harness::new();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.allow_any_recipient = true;
    p.window_cap = 1_000;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: other.clone(),
            cap: 50,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // Unlisted recipient with an override cap.
    h.transfer(&other, 30);
    h.transfer_expect_blocked(&other, 25); // exceeds per-recipient 50

    // Another unlisted recipient has no override, so it falls back to global.
    let third = Address::generate(&h.env);
    h.transfer(&third, 500);
}

#[test]
fn invalid_recipient_window_cap_rejected() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: -1,
        },
    ];
    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    }));
    assert!(res.is_err(), "negative per-recipient cap must be rejected");
}

#[test]
fn invalid_duplicate_recipient_window_cap_rejected() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: 100,
        },
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: 200,
        },
    ];
    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    }));
    assert!(res.is_err(), "duplicate per-recipient cap must be rejected");
}

#[test]
fn detailed_check_reports_per_recipient_headroom() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 1_000;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 100,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 40);

    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 10)
    });
    assert_eq!(detail.result, crate::types::CheckResult::Allowed);
    assert_eq!(detail.remaining_window, Some(60)); // 100 cap - 40 already admitted
    assert_eq!(detail.effective_window_cap, Some(100));
}
