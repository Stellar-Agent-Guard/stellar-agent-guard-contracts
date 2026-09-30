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

use crate::types::{
    CheckResult, DataKey, Error as GuardError, PolicyConfig, PolicyRuleId, ProtocolRule,
    RecipientCap, ValidationOutcome, WindowState,
};
use crate::{AuthSnapshot, PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, ContractCostType, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs,
    Limited, Limits, ScBytes, ScSymbol, ScVal, SorobanAddressCredentials,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, WriteXdr,
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

/// `(at, expires_at)` recorded by the most recent `heartbeat` event (SPEC §9).
/// Returns `None` when no heartbeat event has been published yet.
fn last_heartbeat_payload(env: &Env) -> Option<(u64, u64)> {
    let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("event_heartbeat")).unwrap());
    let recorded = env.events().all();
    let found = recorded.events().iter().rfind(
        |e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want)),
    )?;
    let xdr::ContractEventBody::V0(v0) = &found.body;
    let xdr::ScVal::Map(Some(map)) = &v0.data else {
        panic!("event_heartbeat data must be a Map");
    };
    let read = |name: &str| -> u64 {
        let key = symbol_val(name);
        let entry = map
            .0
            .iter()
            .find(|e| e.key == key)
            .unwrap_or_else(|| panic!("event_heartbeat data is missing `{name}`"));
        let xdr::ScVal::U64(value) = entry.val else {
            panic!(
                "event_heartbeat `{name}` must be a U64, got {:?}",
                entry.val
            )
        };
        value
    };
    Some((read("at"), read("expires_at")))
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

/// One persistent read plus the same TTL refresh performed by `persist_get`.
/// Kept inline in the test reference so the cost comparison includes all host
/// work associated with reading a present key.
fn reference_persist_get<T: soroban_sdk::TryFromVal<Env, Val>>(
    env: &Env,
    key: &DataKey,
) -> Option<T> {
    let value = env.storage().persistent().get(key)?;
    let max_ttl = env.storage().max_ttl();
    env.storage()
        .persistent()
        .extend_ttl(key, max_ttl / 2, max_ttl);
    Some(value)
}

/// `MemCmp` charges consumed by the four persistent keys an authorization
/// reads, with the same TTL refresh semantics — the exact reference for
/// `AuthSnapshot::load`.
///
/// Deliberately *not* `load_ledger`-style shared code: this is an independent
/// restatement of the audited read set, so the test comparing the two detects
/// drift in either direction.
fn reference_snapshot_reads(env: &Env, guard: &Address) -> i64 {
    env.as_contract(guard, || {
        let before = memcmp_charges(env);
        let _: Option<PolicyConfig> = reference_persist_get(env, &DataKey::Policy);
        let _: Option<bool> = reference_persist_get(env, &DataKey::AdminFrozen);
        let _: Option<u64> = reference_persist_get(env, &DataKey::LastHeartbeat);
        let _: Option<WindowState> = reference_persist_get(env, &DataKey::Window);
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

/// Number of events named `name` emitted by the **most recent** top-level
/// invocation (SPEC §9).
///
/// `env.events().all()` exposes one invocation's event log, not a cumulative
/// history: a new top-level call replaces it. Assert event content directly
/// after the call that should have produced it.
fn event_count(env: &Env, name: &str) -> usize {
    let want = symbol_val(name);
    env.events()
        .all()
        .events()
        .iter()
        .filter(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want)))
        .count()
}

/// Was an event named `name` emitted by the most recent invocation with exactly
/// this topic list?
///
/// `#[contractevent]` prepends the event name to the topic list, so `expected`
/// starts with the event name itself — this asserts the full SPEC §9 topic
/// layout, not just that "something" was emitted.
fn has_event_with_topics(env: &Env, name: &str, expected: &[&str]) -> bool {
    let want = symbol_val(name);
    env.events()
        .all()
        .events()
        .iter()
        .filter(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want)))
        .any(|e| {
            let xdr::ContractEventBody::V0(v0) = &e.body;
            v0.topics.len() == expected.len()
                && expected
                    .iter()
                    .enumerate()
                    .all(|(i, topic)| v0.topics.get(i) == Some(&symbol_val(topic)))
        })
}

/// The `revision` field of the only event named `name` in the most recent
/// invocation's log (SPEC §9). Panics when the event is absent, carries no
/// map, or has no `revision`.
fn last_event_revision(env: &Env, name: &str) -> u64 {
    let want = symbol_val(name);
    let all = env.events().all();
    let found = all
        .events()
        .iter()
        .rev()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want)))
        .unwrap_or_else(|| panic!("no `{name}` event was emitted"));
    let xdr::ContractEventBody::V0(v0) = &found.body;
    let ScVal::Map(Some(map)) = &v0.data else {
        panic!("`{name}` data must be a Map");
    };
    let entry = map
        .0
        .iter()
        .find(|e| e.key == symbol_val("revision"))
        .unwrap_or_else(|| panic!("`{name}` data must carry revision"));
    match entry.val {
        ScVal::U64(revision) => revision,
        ref other => panic!("`{name}` revision must be a U64, got {other:?}"),
    }
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
            protocol_calls_per_window: 0,
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

    /// `set_policy` once the harness has entered enforcing auth mode: the
    /// plain `install_policy` relies on mock auth and would be rejected.
    fn set_policy_enforcing(&mut self, cfg: &PolicyConfig) {
        let root = self.invocation(
            &self.guard,
            "set_policy",
            std::vec![cfg.clone().into_val(&self.env)],
        );
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).set_policy(cfg);
    }

    fn status(&self) -> crate::types::Status {
        PolicyEngineClient::new(&self.env, &self.guard).status()
    }

    /// The persisted rolling-window ledger (SPEC §3), or `None` when the
    /// `Window` entry does not exist at all. Read as the contract so it sees
    /// exactly the bytes `__check_auth` would load.
    fn stored_window(&self) -> Option<crate::types::WindowState> {
        self.env.as_contract(&self.guard, || {
            self.env
                .storage()
                .persistent()
                .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
        })
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
fn disabled_window_cap_writes_no_window_entries() {
    // Issue #20: `window_cap = 0` disables the rolling window, so a caps-only
    // policy (per_tx_cap set, window off) must not accrue spend rows —
    // otherwise every allowed transfer would grow persistent storage forever.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 100; // caps-only policy
    p.window_cap = 0; // window disabled
    h.install_policy(&p);
    h.set_time(1_000);

    for _ in 0..5 {
        h.transfer(&recv, 10); // N allowed transfers
    }

    let window = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    // The ledger is either absent or entirely empty: no global rows, no cached
    // total, and no per-recipient ledgers left behind.
    if let Some(w) = window {
        assert_eq!(w.total, 0);
        assert!(w.entries.is_empty(), "window disabled: no spend rows");
        assert!(w.recipients.is_empty());
    }
}

#[test]
fn enabled_window_cap_accrues_with_per_tx_cap_disabled() {
    // Issue #20, converse: with `per_tx_cap = 0` the rolling window still
    // accrues and enforces.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 0; // per-tx cap disabled
    p.window_secs = 60;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);

    h.transfer(&recv, 40);
    h.transfer(&recv, 30); // same second -> coalesces into a single entry

    let window = h
        .env
        .as_contract(&h.guard, || {
            h.env
                .storage()
                .persistent()
                .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
        })
        .expect("an enabled window must persist its ledger");
    assert_eq!(window.total, 70);
    assert_eq!(window.entries.len(), 1);

    h.transfer_expect_blocked(&recv, 31); // 70 + 31 = 101 > 100
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

/// SPEC §10.1: a signature captured for tx A binds to A's host-computed
/// payload digest (invocation + nonce + expiry ledger + network) and cannot
/// authorize tx B — even though tx B is policy-admissible on its own, so
/// the only possible cause of rejection is the binding.
#[test]
fn captured_signature_cannot_authorize_different_tx() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Tx A: the transfer the agent actually signed (policy-admissible).
    let root_a = h.transfer_invocation(&h.guard, &recv, 5);
    let nonce_a = h.guard_nonce;
    h.guard_nonce += 1;
    let payload_a = h.payload(nonce_a, &root_a);
    let sig_a = h.agent.sign(&payload_a).to_bytes();

    // Tx B: a different transfer — also admissible, once correctly signed.
    let root_b = h.transfer_invocation(&h.guard, &recv, 10);
    let nonce_b = h.guard_nonce;
    h.guard_nonce += 1;
    let payload_b = h.payload(nonce_b, &root_b);
    assert_ne!(
        payload_a, payload_b,
        "distinct transactions must produce distinct payload digests"
    );

    // Cross-context confusion: tx A's signature presented inside tx B's entry.
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let replay = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: nonce_b,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig_a.to_vec()).unwrap()),
        }),
        root_invocation: root_b,
    };
    h.env.set_auths(&[replay]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &10);
    }));
    let err = res.expect_err("a signature captured for tx A must not authorize tx B");
    let msg = err
        .downcast_ref::<std::string::String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        msg.contains("failed ED25519 verification"),
        "tx B must be rejected at signature verification, not by policy: {msg}"
    );

    // Control 1: the very same sig_a still authorizes tx A — it is valid,
    // just bound to A's payload.
    let honest_a = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: nonce_a,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig_a.to_vec()).unwrap()),
        }),
        root_invocation: root_a,
    };
    h.env.set_auths(&[honest_a]);
    MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);

    // Control 2: tx B's shape passes policy when signed over its own payload —
    // so the rejection above was the signature binding, not the policy.
    h.transfer(&recv, 10);
}

/// SPEC §10.1: `__check_auth` step 1 verifies the signature against the
/// exact payload it is presented — the matching pair approves, the
/// cross-context mismatch traps before any policy evaluation.
#[test]
fn check_auth_binds_signature_to_the_exact_payload() {
    let h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    let root_a = h.transfer_invocation(&h.guard, &recv, 5);
    let root_b = h.transfer_invocation(&h.guard, &recv, 10);
    let payload_a = h.payload(1, &root_a);
    let payload_b = h.payload(2, &root_b);
    assert_ne!(payload_a, payload_b);

    // The agent's signature over tx A's payload only.
    let sig_a = h.agent.sign(&payload_a).to_bytes();
    let signatures = BytesN::from_array(&h.env, &sig_a);
    let contexts = soroban_sdk::vec![
        &h.env,
        Context::Contract(soroban_sdk::auth::ContractContext {
            contract: h.asset.clone(),
            fn_name: Symbol::new(&h.env, "transfer"),
            args: soroban_sdk::vec![
                &h.env,
                h.guard.into_val(&h.env),
                recv.into_val(&h.env),
                5i128.into_val(&h.env),
            ],
        }),
    ];

    let check = |payload: [u8; 32]| {
        let payload = BytesN::from_array(&h.env, &payload);
        h.env.as_contract(&h.guard, || {
            <PolicyEngine as CustomAccountInterface>::__check_auth(
                h.env.clone(),
                unsafe {
                    std::mem::transmute::<BytesN<32>, soroban_sdk::crypto::Hash<32>>(payload)
                },
                signatures.clone(),
                contexts.clone(),
            )
        })
    };

    // Matching pair: sig over payload A presented with payload A → approved.
    assert!(
        check(payload_a).is_ok(),
        "the signature over payload A must verify against payload A"
    );

    // Mismatch: the same signature presented with tx B's payload → trap.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(payload_b)));
    assert!(
        res.is_err(),
        "a signature over payload A must not verify against payload B"
    );
}

/// SPEC §10.1: the agent's signature never satisfies the admin path —
/// `require_auth(Admin)` checks a different address's auth entry, so an
/// agent-signed payload whose root invocation is an admin-only call
/// confers no admin authority.
#[test]
fn agent_signature_does_not_confer_admin_authority() {
    let mut h = Harness::new();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // The agent signs a payload whose root invocation is an admin-only write.
    let root = h.unfreeze_invocation();
    let nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let payload = h.payload(nonce, &root);
    let sig = h.agent.sign(&payload).to_bytes();
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
        PolicyEngineClient::new(&h.env, &h.guard).unfreeze();
    }));
    let err = res.expect_err("an agent-signed entry must not satisfy require_auth(Admin)");
    let msg = err
        .downcast_ref::<std::string::String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        msg.contains("Unauthorized function call for address"),
        "the admin path must fail on the admin's missing authentication: {msg}"
    );

    // Control: the admin's own auth entry authorizes the identical call.
    h.unfreeze();
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

// ── revoke_policy mid-flight (issue #95) ────────────────────────────────
//
// SPEC §7 documents `revoke_policy` as "Removes Policy and Window ->\n// default-deny immediately", and SPEC §3's storage table makes `Window` the\n// account's only rolling spend ledger. The behaviour those two statements\n// jointly promise is *not* pinned by any test, and the interesting part is\n// precisely the interaction an admin could exploit: because the window is\n// **cleared** (not merely paused), an admin cycling revoke -> set_policy starts\n// the account on a fresh window, so spend history does not survive the cycle.\n// That is admin-attested by design (SPEC §7: "fresh window on every policy\n// change"), so the tests below pin it as intentional rather than let it read\n// as an accident.
//
// SPEC §4 rule 3 is the gate the cleared policy falls through to: with no\n// `Policy` stored, every context blocks with `Reason::NoPolicy`.

/// Issue #95 (a): after a mid-flight revoke, the next authorization is blocked
/// with `NoPolicy` — not merely blocked, and not blocked for some unrelated
/// reason such as a full window. Asserted on both the enforced auth path (the
/// agent's signature is valid, so only policy can reject it) and the
/// permissionless pre-flight, which returns the reason as a typed value and
/// therefore pins *which* gate fired rather than merely "it was denied".
#[test]
fn revoke_policy_blocks_subsequent_auth_with_no_policy() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    // An *enabled* window with real spend, so a `WindowCapExceeded` block
    // would be the competing explanation and the assertion below is meaningful.
    p.window_secs = 60;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 80);
    assert_eq!(h.stored_window().map(|w| w.total), Some(80));

    h.env.mock_all_auths();
    h.revoke_policy();
    assert!(
        PolicyEngineClient::new(&h.env, &h.guard).policy().is_none(),
        "revoke must remove the stored policy (SPEC §7)"
    );

    // Enforced path: a correctly-signed transfer cannot authorize.
    h.transfer_expect_blocked(&recv, 5);

    // Pre-flight: the structured reason is `no_policy` (SPEC §4 rule 3), not
    // `window_cap_exceeded` — the window was cleared along with the policy.
    let detail = PolicyEngineClient::new(&h.env, &h.guard).check_detailed(&h.asset, &recv, &5);
    assert_eq!(
        detail.result,
        CheckResult::Blocked(Symbol::new(&h.env, "no_policy"))
    );

    // SPEC §9: the pre-flight commits its `auth_checked` event with the full
    // topic layout — `blocked` at index 1, the reason at index 2.
    assert!(
        has_event_with_topics(
            &h.env,
            "event_auth_checked",
            &["event_auth_checked", "blocked", "no_policy"],
        ),
        "post-revoke pre-flight must emit auth_checked(blocked, no_policy)"
    );
}

/// Issue #95 (b): the rolling window does not survive a revoke, and a
/// subsequent `set_policy` therefore starts genuinely empty.
///
/// This is the assertion that would catch the uncleared-window defect the
/// issue asks about: if `revoke_policy` left `Window` behind (or `set_policy`
/// failed to reset it), the re-installed policy would inherit the 80 already
/// spent, and the full 80-unit transfer below would be blocked by a 100-unit
/// cap (80 + 80 > 100). It is admitted only when the ledger really is empty.
#[test]
fn revoke_policy_clears_the_window_even_after_spend() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 60;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 80);

    // Precondition: real spend is on the ledger, so "the window was cleared"
    // is a claim about something that existed.
    let spent = h
        .stored_window()
        .expect("an enabled window persists its ledger");
    assert_eq!(spent.total, 80);
    assert!(!spent.entries.is_empty());

    h.env.mock_all_auths();
    h.revoke_policy();
    assert!(
        h.stored_window().is_none(),
        "revoke must remove the Window entry, not merely stop reading it (SPEC §7)"
    );

    // Re-install the identical policy. `set_policy` writes a fresh empty
    // ledger (SPEC §7: "Resets Policy and Window"), so the account is live
    // again on a window that does not remember the 80.
    h.set_time(1_010);
    h.install_policy(&p);

    let fresh = h
        .stored_window()
        .expect("set_policy persists a fresh ledger");
    assert_eq!(
        fresh.total, 0,
        "the re-installed window must not inherit prior spend"
    );
    assert!(
        fresh.entries.is_empty(),
        "no spend entries may survive revoke"
    );
    assert!(
        fresh.recipients.is_empty(),
        "no per-recipient ledger may survive revoke"
    );

    // Behavioural proof, not just a storage assertion: the full 80 is
    // admissible again (a surviving 80 would make this 160 > 100 and block).
    h.transfer(&recv, 80);
    // …and the window is genuinely live again, not merely disabled: the next
    // 80 no longer fits.
    h.transfer_expect_blocked(&recv, 80);
}

/// Issue #95 (c): both lifecycle steps emit their event, carrying the
/// `PolicyRevision` each step produced (SPEC §9, issue #38), so the whole
/// cycle is auditable from the event log alone.
///
/// Each assertion runs immediately after the call that should have produced
/// it, because `env.events().all()` exposes one invocation's log rather than a
/// cumulative history.
#[test]
fn revoke_then_set_policy_emits_both_lifecycle_events() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 60;
    p.window_cap = 100;

    // Step 1: the first set_policy emits `policy_set` at revision 1.
    h.install_policy(&p);
    assert_eq!(
        event_count(&h.env, "event_policy_set"),
        1,
        "set_policy emits exactly one policy_set event"
    );
    assert_eq!(
        last_event_revision(&h.env, "event_policy_set"),
        1,
        "the first set_policy is revision 1 (SPEC §3)"
    );

    h.set_time(1_000);
    h.transfer(&recv, 80);

    // Step 2: the revoke emits `policy_revoked` at revision 2, and nothing else
    // — a `policy_set` here would mean the two lifecycle events are conflated.
    h.env.mock_all_auths();
    h.revoke_policy();
    assert_eq!(
        event_count(&h.env, "event_policy_revoked"),
        1,
        "revoke_policy emits exactly one policy_revoked event"
    );
    assert_eq!(
        event_count(&h.env, "event_policy_set"),
        0,
        "revoke_policy must not also emit a policy_set event"
    );
    assert_eq!(
        last_event_revision(&h.env, "event_policy_revoked"),
        2,
        "revoke_policy increments the revision counter (SPEC §3, issue #38)"
    );
    // SPEC §9: neither lifecycle event carries topic fields — the name alone
    // is the topic, so `by`/`revision` are data. An extra topic here would mean
    // the layout drifted from the documented table.
    assert!(
        has_event_with_topics(&h.env, "event_policy_revoked", &["event_policy_revoked"]),
        "event_policy_revoked must carry exactly one topic (SPEC §9)"
    );

    // Step 3: the post-revoke set_policy emits `policy_set` at revision 3 — the
    // counter keeps marching across the revoke and is never reset.
    h.set_time(1_010);
    h.install_policy(&p);
    assert_eq!(
        event_count(&h.env, "event_policy_set"),
        1,
        "the post-revoke set_policy emits exactly one policy_set event"
    );
    assert_eq!(
        last_event_revision(&h.env, "event_policy_set"),
        3,
        "the post-revoke set_policy advances the counter again (issue #38)"
    );
    assert!(
        has_event_with_topics(&h.env, "event_policy_set", &["event_policy_set"]),
        "event_policy_set must carry exactly one topic (SPEC §9)"
    );

    // The cycle is over and the account is enforcing again.
    h.transfer(&recv, 10);
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
    //               DataKey::PolicyRevision       once per auth_checked event
    //
    // The real-frame footprint also includes PolicyRevision, read by event
    // emission after each decision. The isolated snapshot measurement below
    // counts only the four decision keys and compares them with an independent
    // four-read reference.

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
        constant + 5,
        "__check_auth must read the four snapshot keys once and PolicyRevision \
         for auth_checked event metadata; measured {} storage keys",
        allowed.memory_read_entries - constant
    );

    // A second authorization is allowed to re-read the same four keys (a new
    // transaction is a new frame), and must not reach a fifth.
    let again = h.measure_authorization(&recv, 6);
    assert_eq!(
        again.memory_read_entries,
        constant + 5,
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
    // `DataKey::Policy`, so it does not touch the other three decision keys.
    // The diagnostic auth_checked event still reads PolicyRevision.
    let mut bare = Harness::new();
    bare.set_time(1_000);
    let bare_recv = bare.recv.clone();
    let no_policy = bare.measure_blocking_authorization(&bare_recv, 5);
    assert_eq!(
        no_policy.memory_read_entries,
        constant + 2,
        "the no-policy short circuit reads Policy and PolicyRevision for its diagnostic event"
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
    let check = lib_fn_body("check");
    assert!(
        check.contains("Self::check_detailed"),
        "fn check must delegate to check_detailed\n{check}"
    );

    for fn_name in ["__check_auth", "check_detailed"] {
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
        protocol_calls_per_window: 0,
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

    let build_map = |idx: u32, revision: u64| {
        use soroban_sdk::xdr::{ScMap, ScMapEntry, ScSymbol, ScVal as XdrScVal, VecM};
        let entry = |key: &str, val: XdrScVal| ScMapEntry {
            key: XdrScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(key)).unwrap()),
            val,
        };
        // `auth_checked` data: {context_index, revision} (issue #38: the
        // policy revision in force at decision time joins the event to the
        // policy generation that produced it).
        XdrScVal::Map(Some(ScMap(
            VecM::try_from(std::vec::Vec::from([
                entry("context_index", XdrScVal::U32(idx)),
                entry("revision", XdrScVal::U64(revision)),
            ]))
            .unwrap(),
        )))
    };

    // The policy was installed once, so every decision in this batch runs
    // under revision 1 (issue #38).
    let revision = 1;

    // ctx1: allowed
    assert_eq!(auth_events[0].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[0].1, build_map(0, revision));

    // ctx2: blocked, PerTxCapExceeded
    assert_eq!(auth_events[1].0.get(1).unwrap(), &want_blocked);
    assert_eq!(auth_events[1].1, build_map(1, revision));

    // ctx3: allowed (even though the batch fails, decide evaluates all contexts and emits for all)
    assert_eq!(auth_events[2].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[2].1, build_map(2, revision));
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

// ── status() operational fields (issue #29) ──────────────────────────────

#[test]
fn status_without_policy_reports_null_operational_fields() {
    let h = Harness::new();
    let st = h.status();
    assert!(!st.has_policy);
    // Default-deny has nothing to pause, no cap to project headroom from, and
    // no active window to sit outside of — all three must be inert.
    assert!(!st.paused);
    assert_eq!(st.window_remaining, None);
    assert!(!st.outside_active_window);
}

#[test]
fn status_reports_paused_flag_from_policy() {
    let h = Harness::new();
    let mut p = h.base_policy();
    h.install_policy(&p);
    assert!(!h.status().paused);

    p.paused = true;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    assert!(h.status().paused);
}

#[test]
fn status_window_remaining_full_partial_and_disabled() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);

    // Full headroom before any spend.
    let st = h.status();
    assert_eq!(st.window_remaining, Some(100));

    // Partially spent window: 40 admitted, headroom drops to 60. This must
    // agree with the `remaining_window` `check_detailed` reports for a
    // recipient without a per-recipient override.
    h.transfer(&recv, 40);
    let st = h.status();
    assert_eq!(st.window_remaining, Some(60));
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(detail.remaining_window, st.window_remaining);

    // Spent to exactly the cap: headroom floors at 0 (never negative).
    h.transfer(&recv, 60);
    let st = h.status();
    assert_eq!(st.window_remaining, Some(0));
    assert_eq!(st.now, h.env.ledger().timestamp());

    // Disabled global cap (window_cap = 0): None, even with a live policy.
    p.window_cap = 0;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    assert_eq!(h.status().window_remaining, None);
}

#[test]
fn status_window_remaining_ignores_expired_entries() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 100;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 80);
    assert_eq!(h.status().window_remaining, Some(20));

    // 200s later the whole window has rolled over: headroom must be back to
    // full even though the ledger still *stores* the expired entry, because
    // `status` prunes on read exactly like the decision path.
    h.set_time(1_200);
    assert_eq!(h.status().window_remaining, Some(100));
}

#[test]
fn status_window_remaining_agrees_with_check_detailed_for_recipient_override_too() {
    // A recipient *with* a per-recipient override gets its own tighter ledger;
    // the global `window_remaining` must still track the global cap/total so
    // the two reads can never disagree about the global picture.
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

    assert_eq!(h.status().window_remaining, Some(960));
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    // The recipient-targeted read is tighter — that difference is the point.
    assert_eq!(detail.remaining_window, Some(60));
}

#[test]
fn status_outside_active_window_tracks_bounds() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.active_from = 1_500;
    p.active_until = 1_600;
    h.install_policy(&p);

    // Before the window opens.
    h.set_time(1_499);
    // Inclusive open boundary (now == active_from is inside).
    h.set_time(1_500);
    assert!(!h.status().outside_active_window);
    h.set_time(1_600);
    assert!(!h.status().outside_active_window);
    // Inclusive close boundary (now == active_until is inside), then after.
    h.set_time(1_601);
    assert!(h.status().outside_active_window);

    // Unrestricted windows never read as outside.
    p.active_from = 0;
    p.active_until = 0;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    h.set_time(1_700);
    assert!(!h.status().outside_active_window);
}

#[test]
fn status_outside_active_window_matches_check_block_reason() {
    // The flag must agree with the §4 gate: when `check` blocks with
    // `outside_active_window`, `status` must say so — and vice versa.
    let h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.active_from = 1_400;
    p.active_until = 1_500;
    h.install_policy(&p);
    h.set_time(1_000);
    assert!(h.status().outside_active_window);
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(
        detail.result,
        CheckResult::Blocked(Symbol::new(&h.env, "outside_active_window"))
    );

    // Inside the window: flag clears and the same transfer is allowed.
    h.set_time(1_450);
    assert!(!h.status().outside_active_window);
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
}

#[test]
fn status_reads_never_write_window_or_emit_events() {
    // `status` is an event-free, write-free read. `env.events().all()` holds
    // only the most recent top-level invocation's events, so a status() call
    // followed by an empty event list proves that invocation emitted nothing.
    // Write-freedom is asserted directly on the persisted window ledger.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 40);

    let ledger_before = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    for _ in 0..3 {
        assert_eq!(h.status().window_remaining, Some(60));
        assert!(
            h.env.events().all().events().is_empty(),
            "status must not emit (an auth_checked event here is a bug)"
        );
    }
    let ledger_after = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    assert_eq!(
        ledger_after, ledger_before,
        "status must not rewrite the window ledger"
    );

    // And spend accounting was untouched: a further 60 transfer must still fit.
    h.transfer(&recv, 60);
    assert_eq!(h.status().window_remaining, Some(0));
}

// ── heartbeat `expires_at` (SPEC §9) ───────────────────────────────────
// The event records the deadline the heartbeat was attested under, derived
// from the policy current at emission time, so a consumer never has to
// recompute it from `at` with a later policy's grace.

#[test]
fn heartbeat_event_reports_expiry_from_current_grace() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.dms_grace_secs = 60;
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();

    let (at, expires_at) = last_heartbeat_payload(&h.env).expect("heartbeat event");
    assert_eq!(at, 1_000, "at is the ledger timestamp at emission");
    assert_eq!(
        expires_at, 1_060,
        "with grace=60 the attested deadline is at + 60"
    );
}

#[test]
fn heartbeat_event_reports_zero_expiry_when_dms_disabled() {
    let mut h = Harness::new();
    // base_policy leaves dms_grace_secs == 0, which is how "DMS disabled" is
    // encoded (engine::dms_health returns Ok without consulting the clock).
    let policy = h.base_policy();
    assert_eq!(policy.dms_grace_secs, 0);
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();

    let (at, expires_at) = last_heartbeat_payload(&h.env).expect("heartbeat event");
    assert_eq!(at, 1_000);
    assert_eq!(
        expires_at, 0,
        "a disabled dead-man switch attests no deadline, so expires_at is 0 (not at + 0)"
    );
}

#[test]
fn heartbeat_event_uses_grace_current_at_emission_not_a_stale_one() {
    // This is the behaviour the issue exists for: a consumer that recomputed
    // expiry as `at + <current policy grace>` gets the wrong answer for every
    // heartbeat emitted before a `set_policy` that changes the grace.
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.dms_grace_secs = 60;
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();
    let (first_at, first_expiry) = last_heartbeat_payload(&h.env).expect("first heartbeat event");
    assert_eq!((first_at, first_expiry), (1_000, 1_060));

    // The admin shortens the grace. The already-emitted event must keep the
    // deadline it was attested under.
    let mut tightened = h.base_policy();
    tightened.dms_grace_secs = 30;
    h.set_policy_enforcing(&tightened);

    // A later heartbeat is stamped with the grace in force at *its* emission.
    // Stay inside the tightened 30s window, since a heartbeat past the grace
    // is (correctly) rejected by the DMS gate before any event is published.
    h.set_time(1_010);
    h.heartbeat();
    let (second_at, second_expiry) =
        last_heartbeat_payload(&h.env).expect("second heartbeat event");
    assert_eq!(
        (second_at, second_expiry),
        (1_010, 1_040),
        "a heartbeat must use the grace current at its own emission time"
    );

    // And the earlier event is untouched: a naive `at + current_grace`
    // recomputation would read 1_000 + 30 = 1_030, not the attested 1_060.
    assert_eq!(
        first_expiry, 1_060,
        "the earlier heartbeat keeps the deadline it was attested under"
    );

    // Disabling the switch entirely is the third state: 0 again, distinct from
    // any real timestamp.
    let mut disabled = h.base_policy();
    disabled.dms_grace_secs = 0;
    h.set_policy_enforcing(&disabled);
    h.set_time(1_020);
    h.heartbeat();
    let (third_at, third_expiry) = last_heartbeat_payload(&h.env).expect("third heartbeat event");
    assert_eq!((third_at, third_expiry), (1_020, 0));
}

// ── Issue #35: `validate_policy` per-rule identifiability ─────────────────
//
// SPEC §8 validation rules reject a candidate policy at `set_policy`, but the
// on-chain surface collapses every rejection into the single stable
// `InvalidConfig` code. The `validate_policy` read is the identifiable
// counterpart: it dry-runs the same rules over a *candidate* config and names
// the first failing rule in §8 order, so SDKs and dashboards can preflight a
// policy without paying a rejected on-chain call. Each test pins one rule via
// the dry-run read and re-asserts the on-chain path stays fail-closed for the
// same config (panic + policy never installed).

/// Dry-run names the exact rule, and `set_policy` still rejects fail-closed.
fn assert_rejects_with(h: &Harness, cfg: &PolicyConfig, want: &PolicyRuleId) {
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(
        client.validate_policy(cfg),
        ValidationOutcome::Invalid(want.clone()),
        "validate_policy must identify the failing rule"
    );
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(cfg);
    }));
    assert!(res.is_err(), "set_policy must still reject this config");
    assert!(
        client.policy().is_none(),
        "a rejected config must never be installed (fail-closed)"
    );
}

#[test]
fn validate_policy_reports_amount_sign() {
    let h = Harness::new();

    let mut p = h.base_policy();
    p.per_tx_cap = -1;
    assert_rejects_with(&h, &p, &PolicyRuleId::AmountSign);

    let mut p = h.base_policy();
    p.window_cap = -1;
    assert_rejects_with(&h, &p, &PolicyRuleId::AmountSign);
}

#[test]
fn validate_policy_reports_window_requires_width() {
    let h = Harness::new();

    // Global form: a spend cap with no window to spend within.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.window_cap = 100;
    assert_rejects_with(&h, &p, &PolicyRuleId::WindowRequiresWidth);

    // Per-recipient form: an override cap with no window is the same rule.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 50,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::WindowRequiresWidth);
}

#[test]
fn validate_policy_reports_active_window_order() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.active_from = 100;
    p.active_until = 100; // end equal to start is not "after"
    assert_rejects_with(&h, &p, &PolicyRuleId::ActiveWindowOrder);
}

#[test]
fn validate_policy_reports_self_address_in_list() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // assets
    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // protocols
    let mut p = h.base_policy();
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.guard.clone(),
            fns: None,
        },
    ];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // recipients
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // recipient_window_caps
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.guard.clone(),
            cap: 10,
        },
    ];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // blocked_recipients
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );
}

#[test]
fn validate_policy_reports_duplicate_address_in_list() {
    let h = Harness::new();

    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.asset.clone(), h.asset.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateAddressInList);

    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.recv.clone(), h.recv.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateAddressInList);
}

#[test]
fn validate_policy_reports_duplicate_recipient_cap() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 10,
        },
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 20,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateRecipientCap);
}

#[test]
fn validate_policy_reports_recipient_list_too_long() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Bound is inclusive: exactly the limit is still valid.
    let mut at_limit = soroban_sdk::Vec::new(&h.env);
    for _ in 0..256u32 {
        at_limit.push_back(Address::generate(&h.env));
    }
    let mut p = h.base_policy();
    p.blocked_recipients = at_limit;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);

    // One more exceeds it; the dry run names the list-length rule.
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env];
    for _ in 0..257u32 {
        p.blocked_recipients.push_back(Address::generate(&h.env));
    }
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientListTooLong);
}

#[test]
fn policy_asset_protocol_and_recipient_limits_are_inclusive_and_fail_closed() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let baseline = h.base_policy();
    client.set_policy(&baseline);

    let mut assets = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_POLICY_ASSETS {
        assets.push_back(Address::generate(&h.env));
    }
    let mut at_limit = baseline.clone();
    at_limit.assets = assets.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    assets.push_back(Address::generate(&h.env));
    let mut over_limit = at_limit.clone();
    over_limit.assets = assets;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::AssetListTooLong,
    );

    let mut protocols = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_POLICY_PROTOCOLS {
        protocols.push_back(ProtocolRule {
            contract: Address::generate(&h.env),
            fns: None,
        });
    }
    let mut at_limit = baseline.clone();
    at_limit.protocols = protocols.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    protocols.push_back(ProtocolRule {
        contract: Address::generate(&h.env),
        fns: None,
    });
    let mut over_limit = at_limit.clone();
    over_limit.protocols = protocols;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::ProtocolListTooLong,
    );

    let mut recipients = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_RECIPIENT_ENTRIES {
        recipients.push_back(Address::generate(&h.env));
    }
    let mut at_limit = baseline;
    at_limit.recipients = recipients.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    recipients.push_back(Address::generate(&h.env));
    let mut over_limit = at_limit.clone();
    over_limit.recipients = recipients;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::RecipientListTooLong,
    );
}

fn assert_rejects_preserving_policy(
    env: &Env,
    guard: &Address,
    candidate: &PolicyConfig,
    installed: &PolicyConfig,
    rule: &PolicyRuleId,
) {
    let client = PolicyEngineClient::new(env, guard);
    assert_eq!(
        client.validate_policy(candidate),
        ValidationOutcome::Invalid(rule.clone())
    );
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(candidate);
    }));
    assert!(
        res.is_err(),
        "over-limit policy must fail with InvalidConfig"
    );
    assert_eq!(client.policy(), Some(installed.clone()));
}

#[test]
fn validate_policy_reports_recipient_cap_sign() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: -5,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientCapSign);
}

#[test]
fn validate_policy_reports_recipient_allow_and_blocked() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.recv.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientAllowAndBlocked);
}

#[test]
fn validate_policy_reports_protocol_contract_duplicate() {
    let h = Harness::new();
    let mut p = h.base_policy();
    let rule = ProtocolRule {
        contract: h.asset.clone(),
        fns: None,
    };
    p.protocols = soroban_sdk::vec![&h.env, rule.clone(), rule];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolContractDuplicate);
}

#[test]
fn validate_policy_reports_protocol_fn_list_invalid() {
    let h = Harness::new();

    // An explicit `Some` fn list may not be empty.
    let mut p = h.base_policy();
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.asset.clone(),
            fns: Some(soroban_sdk::Vec::new(&h.env)),
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolFnListInvalid);

    // ...nor contain duplicate fn names.
    let mut p = h.base_policy();
    let fns = soroban_sdk::vec![
        &h.env,
        Symbol::new(&h.env, "transfer"),
        Symbol::new(&h.env, "transfer"),
    ];
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.asset.clone(),
            fns: Some(fns),
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolFnListInvalid);
}

#[test]
fn validate_policy_accepts_valid_config_and_ignores_installed_policy() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // No policy installed: the candidate is judged on its own merits.
    assert_eq!(
        client.validate_policy(&h.base_policy()),
        ValidationOutcome::Valid
    );

    // Install one, then dry-run the same candidate plus a broken one: the
    // verdict is about the *argument*, never the installed policy...
    h.install_policy(&h.base_policy());
    assert_eq!(
        client.validate_policy(&h.base_policy()),
        ValidationOutcome::Valid
    );
    let mut broken = h.base_policy();
    broken.window_cap = -1;
    assert_eq!(
        client.validate_policy(&broken),
        ValidationOutcome::Invalid(PolicyRuleId::AmountSign)
    );

    // ...and a rejected dry-run never disturbs the installed policy.
    assert_eq!(client.policy().unwrap().window_cap, 0);
}

// ── Issue #34: sane upper bounds on `window_secs` / `dms_grace_secs` ─────

/// SPEC §8 (issue #34): both duration fields are `u64`, so a seconds/millis
/// mix-up or `u64::MAX` would read as a valid config while silently disabling
/// pruning (or the dead-man switch) forever. Anything above
/// `MAX_WINDOW_SECS` / `MAX_DMS_GRACE_SECS` (`315_360_000` s ≈ 10 years) is
/// rejected as `InvalidConfig`, fail-closed: the previously installed policy
/// (if any) stays unchanged.
#[test]
fn window_and_dms_upper_bounds_rejected() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // `set_policy` returns `()` and signals rejection by panicking through
    // `panic_with_error!` (same pattern as `self_address_rejected_in_every_list`):
    // assert the panic *and* the fail-closed invariant.
    let expect_invalid = |cfg: &PolicyConfig, what: &str| {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_policy(cfg);
        }));
        assert!(
            res.is_err(),
            "`{what}` must fail set_policy with InvalidConfig"
        );
        assert!(
            client.policy().is_none(),
            "`{what}` must leave the policy uninstalled (fail-closed)"
        );
    };

    // The motivating case: `u64::MAX` — "effectively forever".
    let mut p = h.base_policy();
    p.window_secs = u64::MAX;
    expect_invalid(&p, "window_secs = u64::MAX");

    // One second past the bound is already rejected (inclusive bound).
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS + 1;
    expect_invalid(&p, "window_secs = MAX + 1");

    // Same rule for the dead-man switch grace: `u64::MAX` silently turns §5 off.
    let mut p = h.base_policy();
    p.dms_grace_secs = u64::MAX;
    expect_invalid(&p, "dms_grace_secs = u64::MAX");

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS + 1;
    expect_invalid(&p, "dms_grace_secs = MAX + 1");

    // Sanity: the same env still installs an in-bounds policy cleanly, proving
    // the rejections above came from the bound and not from a broken harness.
    client.set_policy(&h.base_policy());
    assert!(client.policy().is_some());
}

/// SPEC §8 (issue #34): the bound is inclusive — exactly `MAX_WINDOW_SECS` /
/// `MAX_DMS_GRACE_SECS` installs cleanly — and `0` stays legal for both
/// fields (feature disabled), so no legitimate policy regresses.
#[test]
fn window_and_dms_upper_bounds_accept_boundary() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Exactly at the bound: accepted, stored verbatim.
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS;
    client.set_policy(&p);
    assert_eq!(
        client.policy().expect("policy installed").window_secs,
        crate::types::MAX_WINDOW_SECS
    );

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS;
    client.set_policy(&p);
    assert_eq!(
        client.policy().expect("policy installed").dms_grace_secs,
        crate::types::MAX_DMS_GRACE_SECS
    );

    // 0 remains legal for both fields.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.dms_grace_secs = 0;
    client.set_policy(&p);
    let stored = client.policy().expect("policy installed");
    assert_eq!((stored.window_secs, stored.dms_grace_secs), (0, 0));
}

/// The dry-run read reports the same duration rule: the #34 bound is
/// implemented as a `PolicyRuleId`, so `validate_policy` identifies it too —
/// `set_policy` and the dry run can never disagree about this rule.
#[test]
fn validate_policy_reports_duration_exceeds_bound() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS + 1;
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::DurationExceedsBound)
    );

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS + 1;
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::DurationExceedsBound)
    );

    // Exactly at the bound (both fields at once): the dry run is `Valid` and
    // the real `set_policy` accepts — inclusive bound, on both surfaces.
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS;
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    assert!(client.policy().is_some());
}
