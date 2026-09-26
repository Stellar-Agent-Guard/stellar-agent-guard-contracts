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

use crate::types::{CheckResult, Error as GuardError, PolicyConfig};
use crate::{PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, ContractCostType, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs,
    Limited, Limits, ScBytes, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, vec, Address, BytesN, Env, FromVal, IntoVal, Symbol, Val,
};

const SIG_EXPIRATION_LEDGER: u32 = 6_000_000;

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

// ── Storage-read accounting (issue #135) ─────────────────────────────────
//
// How the read set of one authorization is measured here.
//
// The host exposes **no per-`get_contract_data` counter**. Its storage map is
// read-through cached and is deliberately *not* reset between invocations
// ("the storage itself shouldn't be reset, as it's treated as the ledger state
// before invocation"), so the second read of a key is a pure cache hit that
// emits no separately countable event, and `ContractCostType` has no
// storage-read variant at all. A counting `SnapshotSource` cannot recover it
// either: the source is only consulted on a cache *miss*, i.e. once per key.
//
// Two exact quantities are observable, and they are what this module uses:
//
// * `MemCmp` budget charges. A storage read adds a constant, strictly positive
//   number of them, so "charges consumed" is a linear read counter. Because
//   the comparison work is bounded and independent of the stored value, a
//   measured total is only attributable to a read *count* when the measured
//   code does nothing else — which is precisely the case for the isolated
//   `AuthSnapshot::load` measurement in
//   `authorization_reads_each_storage_key_exactly_once`.
// * `resources().memory_read_entries`, the host's own footprint accounting:
//   the number of distinct ledger entries an invocation put in its footprint,
//   i.e. how many storage *keys* it read. This is host-reported and exact, and
//   it pins the read *set* of a real `__check_auth` frame.

/// `MemCmp` charges consumed by the frame currently executing.
fn memcmp_charges(env: &Env) -> i64 {
    env.cost_estimate()
        .budget()
        .tracker(ContractCostType::MemCmp)
        .iterations
        .try_into()
        .expect("MemCmp charges fit in i64")
}

/// `MemCmp` charges consumed by the four persistent keys an authorization
/// reads, read inline — the exact reference for `AuthSnapshot::load`.
///
/// Deliberately *not* `load_ledger`-style shared code: this is an independent
/// restatement of the audited read set, so the test comparing the two detects
/// drift in either direction.
fn reference_snapshot_reads(env: &Env, guard: &Address) -> i64 {
    env.as_contract(guard, || {
        let before = memcmp_charges(env);
        let _: Option<PolicyConfig> = env.storage().persistent().get(&DataKey::Policy);
        let _: Option<bool> = env.storage().persistent().get(&DataKey::AdminFrozen);
        let _: Option<u64> = env.storage().persistent().get(&DataKey::LastHeartbeat);
        let _: Option<WindowState> = env.storage().persistent().get(&DataKey::Window);
        memcmp_charges(env) - before
    })
}

/// What the host charged one `__check_auth` frame.
#[derive(Debug, Clone, Copy)]
struct AuthMeters {
    /// Distinct ledger entries the frame put in its footprint.
    memory_read_entries: i32,
    /// `MemCmp` charges for the whole frame.
    memcmp: i64,
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

    /// Touches no storage at all. Calibration point for the fixed entry that
    /// `memory_read_entries` reports for every invocation of a registered
    /// contract, on top of whatever storage entries the frame actually read.
    pub fn ping() {}
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
        let env = Env::default();
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

    fn payload(&self, nonce: i64, invocation: &SorobanAuthorizedInvocation) -> [u8; 32] {
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: SIG_EXPIRATION_LEDGER,
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
        let nonce = self.guard_nonce;
        self.guard_nonce += 1;
        let payload = self.payload(nonce, root);
        let sig = self.agent.sign(&payload).to_bytes();
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.guard),
                nonce,
                signature_expiration_ledger: SIG_EXPIRATION_LEDGER,
                signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
            }),
            root_invocation: root.clone(),
        }
    }

    /// Build an auth entry for the (signature-less) admin account.
    fn admin_entry(&mut self, root: &SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
        let nonce = self.admin_nonce;
        self.admin_nonce += 1;
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.admin),
                nonce,
                signature_expiration_ledger: SIG_EXPIRATION_LEDGER,
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

    /// Run one real, agent-signed transfer authorization and return the host's
    /// accounting for it.
    ///
    /// `try_invoke_contract_check_auth` calls `__check_auth` as the *root*
    /// invocation, so the budget trackers and the invocation resources describe
    /// exactly that frame and nothing else. Going through
    /// `MockAsset::transfer` + `require_auth` instead would nest it under the
    /// asset call and mix the two frames' costs together.
    fn measure_authorization(&mut self, to: &Address, amount: i128) -> AuthMeters {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let nonce = self.guard_nonce;
        self.guard_nonce += 1;
        let payload = self.payload(nonce, &root);
        let sig = self.agent.sign(&payload).to_bytes();

        let mut args: soroban_sdk::Vec<Val> = soroban_sdk::Vec::new(&self.env);
        args.push_back(self.guard.clone().into_val(&self.env)); // from
        args.push_back(to.clone().into_val(&self.env));
        args.push_back(amount.into_val(&self.env));
        let contexts = vec![
            &self.env,
            Context::Contract(ContractContext {
                contract: self.asset.clone(),
                fn_name: Symbol::new(&self.env, "transfer"),
                args,
            }),
        ];

        let payload = BytesN::<32>::from_array(&self.env, &payload);
        let signature: Val = BytesN::<64>::from_array(&self.env, &sig).into_val(&self.env);
        self.env
            .try_invoke_contract_check_auth::<GuardError>(
                &self.guard,
                &payload,
                signature,
                &contexts,
            )
            .expect("the harness policy allows this transfer");

        let detailed = self
            .env
            .host()
            .get_detailed_last_invocation_resources()
            .expect("the check_auth frame is metered");
        AuthMeters {
            memory_read_entries: detailed.resources.memory_read_entries,
            memcmp: memcmp_charges(&self.env),
        }
    }

    /// Same as `measure_authorization`, but tolerates the default-deny answer:
    /// with no policy installed the frame is expected to be rejected, and the
    /// point of the measurement is what it read *before* rejecting.
    fn measure_blocking_authorization(&mut self, to: &Address, amount: i128) -> AuthMeters {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let nonce = self.guard_nonce;
        self.guard_nonce += 1;
        let payload = self.payload(nonce, &root);
        let sig = self.agent.sign(&payload).to_bytes();

        let mut args: soroban_sdk::Vec<Val> = soroban_sdk::Vec::new(&self.env);
        args.push_back(self.guard.clone().into_val(&self.env));
        args.push_back(to.clone().into_val(&self.env));
        args.push_back(amount.into_val(&self.env));
        let contexts = vec![
            &self.env,
            Context::Contract(ContractContext {
                contract: self.asset.clone(),
                fn_name: Symbol::new(&self.env, "transfer"),
                args,
            }),
        ];

        let payload = BytesN::<32>::from_array(&self.env, &payload);
        let signature: Val = BytesN::<64>::from_array(&self.env, &sig).into_val(&self.env);
        let outcome = self.env.try_invoke_contract_check_auth::<GuardError>(
            &self.guard,
            &payload,
            signature,
            &contexts,
        );
        assert!(
            matches!(outcome, Err(Ok(GuardError::NoPolicy))),
            "an account with no policy is default-deny, got {outcome:?}"
        );

        let detailed = self
            .env
            .host()
            .get_detailed_last_invocation_resources()
            .expect("the check_auth frame is metered");
        AuthMeters {
            memory_read_entries: detailed.resources.memory_read_entries,
            memcmp: memcmp_charges(&self.env),
        }
    }

    /// The fixed entry `memory_read_entries` reports for *every* invocation of
    /// a registered contract, independent of how much storage the frame reads.
    /// Calibrated against an entry point that reads nothing, so the per-key
    /// read counts asserted on a real authorization are read off the host's
    /// footprint accounting rather than hard-coded.
    fn footprint_constant(&self) -> i32 {
        MockAssetClient::new(&self.env, &self.asset).ping();
        self.footprint_entries()
    }

    fn footprint_entries(&self) -> i32 {
        self.env
            .host()
            .get_detailed_last_invocation_resources()
            .map_or(0, |d| d.resources.memory_read_entries)
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

    // Admin unfreeze is the reversal path (SPEC §5).
    h.unfreeze(); // sets LastHeartbeat = now (1_000_100)
    h.heartbeat(); // a subsequently-heartbeating agent keeps it alive
    h.transfer(&recv, 5); // revived
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
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce,
            signature_expiration_ledger: SIG_EXPIRATION_LEDGER,
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
    let old_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: old_nonce,
            signature_expiration_ledger: SIG_EXPIRATION_LEDGER,
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

#[test]
fn authorization_reads_each_storage_key_exactly_once() {
    // ── The audited read set (issue #135) ─────────────────────────────────
    //
    // Before this change `__check_auth` read `DataKey::Window` twice on the
    // allowed path: once to build the ledger, then again for `had_window`.
    // The snapshot now carries that flag, so the read set of one authorization
    // is:
    //
    //   instance    DataKey::AgentPubkey          once, to verify the signature
    //   persistent  DataKey::Policy               ┐
    //               DataKey::AdminFrozen          │ each once, all four inside
    //               DataKey::LastHeartbeat        │ `AuthSnapshot::load`
    //               DataKey::Window                ┘
    //
    // Totals measured here: 468 MemCmp charges for an allowed authorization
    // (down from 524 before the snapshot), 81 for the default-deny short
    // circuit (unchanged — the removed read was on the allowed path only).

    // ── Calibration: the read quantum is constant and positive ───────────
    // A storage read charges a fixed number of `MemCmp` comparisons, so the
    // count is recoverable from a total. This is the assumption that makes
    // every measurement below meaningful, so it is asserted rather than
    // assumed.
    let env = Env::default();
    let guard = env.register(PolicyEngine, ());
    let marginal = env.as_contract(&guard, || {
        // First read of the key pays the footprint insert; every later read of
        // an already-resident key is the pure "one more read" cost.
        let _: Option<u64> = env.storage().persistent().get(&DataKey::PolicyRevision);
        let before = memcmp_charges(&env);
        let _: Option<u64> = env.storage().persistent().get(&DataKey::PolicyRevision);
        memcmp_charges(&env) - before
    });
    assert!(
        marginal > 0,
        "a storage read must cost something measurable"
    );

    // ── Multiplicity: the snapshot does exactly four reads, no more ──────
    // `AuthSnapshot::load` is pure storage access, so its total is attributable
    // to reads alone and the count is exact: equal to the reference means four
    // reads, anything higher means a key is read more than once. Measured in
    // the same env, so an SDK cost-model change moves both sides together.
    let mut h = Harness::new();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    let recv = h.recv.clone();

    let reference = reference_snapshot_reads(&h.env, &h.guard);
    let snapshot = h.env.as_contract(&h.guard, || {
        let before = memcmp_charges(&h.env);
        let snap = AuthSnapshot::load(&h.env).expect("a policy is installed");
        let charges = memcmp_charges(&h.env) - before;
        // The snapshot carries the write-back decision without a second read:
        // `set_policy` seeds an *empty* `Window` entry, so "an entry exists"
        // and "the ledger has entries" are genuinely different facts — which
        // is exactly the distinction the pre-#135 second `Window` read
        // recomputed.
        assert!(snap.window_persisted, "set_policy seeds a Window entry");
        assert_eq!(snap.ledger.len(), 0, "nothing has been spent yet");
        assert!(!snap.admin_frozen);
        charges
    });
    std::println!(
        "AuthSnapshot::load: memcmp={snapshot} (four reads = {reference}, \
         one read = {marginal})"
    );
    assert_eq!(
        snapshot, reference,
        "AuthSnapshot::load must perform exactly one read per key \
         (a redundant read costs {marginal} MemCmp charges)"
    );

    // ── The read set of a real authorization ────────────────────────────
    // `memory_read_entries` is the host's own footprint accounting, so this
    // pins which storage keys a real `__check_auth` frame loads. The first
    // authorization on a fresh account is measured with an empty window.
    let allowed = h.measure_authorization(&recv, 5);

    // Every invocation of a registered contract contributes one fixed entry
    // (its contract code) on top of the storage entries it reads. Pin that
    // constant against an entry point that reads nothing.
    let constant = h.footprint_constant();
    assert_eq!(
        constant, 1,
        "expected exactly one fixed (contract code) entry per invocation"
    );
    assert_eq!(
        allowed.memory_read_entries,
        constant + 4,
        "__check_auth must read exactly the four snapshot keys \
         (Policy, AdminFrozen, LastHeartbeat, Window) and nothing else; \
         measured {}",
        allowed.memory_read_entries - constant
    );

    // A second authorization is allowed to re-read the same four keys (a new
    // transaction is a new frame), and must not reach a fifth.
    let again = h.measure_authorization(&recv, 6);
    assert_eq!(
        again.memory_read_entries,
        constant + 4,
        "the read set must not depend on how many authorizations came before"
    );
    std::println!(
        "__check_auth: memory_read_entries={} memcmp={} (repeat: \
         memory_read_entries={} memcmp={})",
        allowed.memory_read_entries,
        allowed.memcmp,
        again.memory_read_entries,
        again.memcmp,
    );

    // ── The default-deny short circuit reads less ───────────────────────
    // With no policy installed the snapshot stops at the `?` after
    // `DataKey::Policy`, so the frame must not touch the other three keys.
    let mut bare = Harness::new();
    bare.set_time(1_000);
    let bare_recv = bare.recv.clone();
    let no_policy = bare.measure_blocking_authorization(&bare_recv, 5);
    assert_eq!(
        no_policy.memory_read_entries,
        constant + 1,
        "the no-policy short circuit must read DataKey::Policy and stop"
    );
    std::println!(
        "__check_auth (no policy): memory_read_entries={} memcmp={}",
        no_policy.memory_read_entries,
        no_policy.memcmp
    );
}

/// Body of `fn <name>` in `src/lib.rs`, brace-matched, as written (the file on
/// disk is pre-`#[contractimpl]` expansion, so this is the code a contributor
/// edits).
fn lib_fn_body(name: &str) -> std::string::String {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("src/lib.rs is readable");
    let start = src
        .find(&std::format!("fn {name}("))
        .unwrap_or_else(|| std::panic!("fn {name} not found in src/lib.rs"));
    let open = src[start..]
        .find('{')
        .map(|i| start + i)
        .expect("function body opens");
    let mut depth = 0_usize;
    for (i, ch) in src[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            // Closing brace of the body: the first time the nesting returns to
            // zero, excluding the opening brace itself.
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return std::string::ToString::to_string(&src[open..=(open + i)]);
                }
            }
            _ => {}
        }
    }
    std::panic!("fn {name} body is not brace-balanced");
}

#[test]
fn authorization_touches_storage_only_through_the_snapshot() {
    // The numeric side of #135 (`authorization_reads_each_storage_key_exactly_once`)
    // measures the read *set* exactly, but the host exposes no counter for how
    // many times an already-loaded key is read again, so a redundant read does
    // not move any observable number. Re-introducing the pre-#135 second
    // `DataKey::Window` read was verified to leave every assertion passing.
    //
    // So the invariant is also enforced at the source level: the authorization
    // path may reach storage only through `AuthSnapshot::load`. This is the
    // mechanical form of the comment on `AuthSnapshot`, and it is what keeps a
    // future edit from adding an inline read back.
    for fn_name in ["__check_auth", "check"] {
        let body = lib_fn_body(fn_name);

        let snapshots = body.matches("AuthSnapshot::load").count();
        assert_eq!(
            snapshots, 1,
            "fn {fn_name} must take exactly one storage snapshot, found {snapshots}\n{body}"
        );

        for forbidden in ["persist_get", "persist_set", "load_window", "load_ledger"] {
            assert!(
                !body.contains(forbidden),
                "fn {fn_name} reads storage directly (`{forbidden}`); load new keys \
                 in `AuthSnapshot::load` so every key is read exactly once per \
                 authorization\n{body}"
            );
        }

        // The one key legitimately read outside the snapshot is the registered
        // agent pubkey: it is needed to verify the signature, which has to
        // happen before any policy state is touched. It must still be read
        // exactly once, and before the verification that consumes it.
        let inline = body.matches(".storage()").count();
        let agent_reads = body.matches("DataKey::AgentPubkey").count();
        let (agent_at, verify_at) = (
            body.find("DataKey::AgentPubkey"),
            body.find("ed25519_verify"),
        );
        match (verify_at, agent_at) {
            // `__check_auth`: exactly the one pre-verification agent-key read.
            (Some(v), Some(a)) => {
                assert_eq!(agent_reads, 1, "fn {fn_name} reads AgentPubkey once");
                assert_eq!(inline, 1, "fn {fn_name} has one inline storage read");
                assert!(
                    a < v,
                    "fn {fn_name} must read the agent key before verifying with it"
                );
            }
            // `check`: a pre-flight, so it has no signature to verify and no
            // reason to touch the agent key at all.
            (None, None) => assert_eq!(
                inline, 0,
                "fn {fn_name} must reach storage only through the snapshot\n{body}"
            ),
            _ => std::panic!("fn {fn_name} has a storage read unrelated to the snapshot"),
        }
    }

    // The snapshot is the single read site: it reads one key per gate —
    // policy, the admin freeze flag, the heartbeat stamp — and delegates the
    // rolling window to `load_window`, which reads that key once and reports
    // whether it was present so no caller has to ask again.
    let load = lib_fn_body("load");
    let load_window = lib_fn_body("load_window");
    assert_eq!(
        load.matches("persist_get").count() + load_window.matches("persist_get").count(),
        4,
        "the snapshot must read exactly the four audited keys\n{load}\n{load_window}"
    );
    for key in [
        "DataKey::Policy",
        "DataKey::AdminFrozen",
        "DataKey::LastHeartbeat",
    ] {
        assert!(
            load.contains(key),
            "AuthSnapshot::load must read {key}\n{load}"
        );
    }
    assert!(
        load.contains("load_window(env)"),
        "AuthSnapshot::load must take the window through load_window\n{load}"
    );
    assert_eq!(
        load_window.matches("DataKey::Window").count(),
        1,
        "load_window must reference DataKey::Window exactly once\n{load_window}"
    );
}
