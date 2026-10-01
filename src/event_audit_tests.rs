//! Comprehensive event payload audit tests for every event emitted by the contract.
//! Asserts exact topic counts, topic symbols, and data payload shapes per SPEC §9.

use crate::emit_window_merge;
use crate::types::PolicyConfig;
use crate::window::{Ledger, WindowMergeKind};
use crate::{PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limited, Limits,
    ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};
use soroban_sdk::{contract, contractimpl, vec, Address, BytesN, Env, FromVal, IntoVal, Val};

const SIG_EXPIRATION_LEDGER: u32 = 6_000_000;

/// Read the `u64` value of a named data-map entry from an event already
/// validated to be a `ScVal::Map` payload (SPEC §9 event data shape).
fn map_u64_field(event: &xdr::ContractEvent, field: &str) -> u64 {
    let xdr::ContractEventBody::V0(v0) = &event.body;
    let ScVal::Map(Some(map)) = &v0.data else {
        panic!("event data must be a Map");
    };
    let entry = map
        .0
        .iter()
        .find(|entry| {
            entry.key == ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(field)).unwrap())
        })
        .unwrap_or_else(|| panic!("event data must carry `{field}`"));
    match &entry.val {
        ScVal::U64(v) => *v,
        other => panic!("event field `{field}` must be U64, got {other:?}"),
    }
}

fn map_i128_field(event: &xdr::ContractEvent, field: &str) -> i128 {
    let xdr::ContractEventBody::V0(v0) = &event.body;
    let ScVal::Map(Some(map)) = &v0.data else {
        panic!("event data must be a Map");
    };
    let entry = map
        .0
        .iter()
        .find(|entry| {
            entry.key == ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(field)).unwrap())
        })
        .unwrap_or_else(|| panic!("event data must carry `{field}`"));
    match &entry.val {
        ScVal::I128(v) => (i128::from(v.hi) << 64) | i128::from(v.lo),
        other => panic!("event field `{field}` must be I128, got {other:?}"),
    }
}

/// A `ScVal::Symbol` for an event's first topic (the `event_*` name that
/// `#[contractevent]` prepends, SPEC §9).
fn event_name(name: &str) -> ScVal {
    ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(name)).unwrap())
}

#[contract]
pub struct MockAdmin;

// The module is a lint-clean event-shape audit: the mock admin's trait params
// are deliberately unused, and the monolithic audit test exceeds
// `too_many_lines` by design (one narrative walk over every event).

#[contractimpl]
impl CustomAccountInterface for MockAdmin {
    type Signature = ();
    type Error = crate::types::Error;

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

struct EventAuditHarness {
    env: Env,
    guard: Address,
    admin: Address,
    agent: SigningKey,
    guard_nonce: i64,
    admin_nonce: i64,
}

impl EventAuditHarness {
    fn new() -> Self {
        let env = Env::default();
        let agent = SigningKey::from_bytes(&[5u8; 32]);
        let admin = env.register(MockAdmin, ());
        let guard = env.register(PolicyEngine, ());

        env.mock_all_auths();
        let client = PolicyEngineClient::new(&env, &guard);
        let pk = agent.verifying_key().to_bytes();
        client.initialize(&admin, &BytesN::from_array(&env, &pk));

        EventAuditHarness {
            env,
            guard,
            admin,
            agent,
            guard_nonce: 1,
            admin_nonce: 1,
        }
    }

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

    fn heartbeat_invocation(&self) -> SorobanAuthorizedInvocation {
        self.invocation(&self.guard, "heartbeat", std::vec![])
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

    fn enforce(&mut self, entry: SorobanAuthorizationEntry) {
        self.env.set_auths(&[entry]);
    }

    fn heartbeat(&mut self) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
    }

    fn freeze(&mut self) {
        let root = self.invocation(&self.guard, "freeze", std::vec![]);
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).freeze();
    }

    fn unfreeze(&mut self) {
        let root = self.invocation(&self.guard, "unfreeze", std::vec![]);
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).unfreeze();
    }

    fn set_policy(&mut self, cfg: &PolicyConfig) {
        let root = self.invocation(
            &self.guard,
            "set_policy",
            std::vec![cfg.clone().into_val(&self.env)],
        );
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).set_policy(cfg);
    }

    fn revoke_policy(&mut self) {
        let root = self.invocation(&self.guard, "revoke_policy", std::vec![]);
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).revoke_policy();
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one narrative walk over every event shape
fn audit_event_payloads_and_topics() {
    let mut h = EventAuditHarness::new();

    // 1. Initialized event (emitted during new() via initialize)
    let all = h.env.events().all();
    let events = all.events();
    let init_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_initialized")).unwrap(),
                    ))
            }
        })
        .expect("event_initialized not found");

    let xdr::ContractEventBody::V0(init_v0) = &init_event.body;
    assert_eq!(
        init_v0.topics.len(),
        1,
        "event_initialized must have 1 topic"
    );
    // Data must contain 'by' address
    match &init_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(map.0.len(), 1);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
        }
        _ => panic!("event_initialized data must be a Map"),
    }

    // 2. Heartbeat event. A guarded heartbeat routes through __check_auth,
    // so a policy must be installed first — otherwise the decision path
    // blocks with `no_policy` and no heartbeat event is emitted.
    let heartbeat_policy = PolicyConfig {
        per_tx_cap: 0,
        window_secs: 60,
        window_cap: 0,
        assets: vec![&h.env],
        protocols: vec![&h.env],
        recipients: vec![&h.env],
        recipient_window_caps: vec![&h.env],
        blocked_recipients: vec![&h.env],
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };
    h.set_policy(&heartbeat_policy);
    h.env.ledger().set_timestamp(2_000);
    h.heartbeat();

    let all = h.env.events().all();
    let events = all.events();
    let hb_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_heartbeat")).unwrap(),
                    ))
            }
        })
        .expect("event_heartbeat not found");

    let xdr::ContractEventBody::V0(hb_v0) = &hb_event.body;
    assert_eq!(hb_v0.topics.len(), 1, "event_heartbeat must have 1 topic");
    match &hb_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(map.0.len(), 2, "event_heartbeat carries at + expires_at");
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("at")).unwrap())
            );
            assert_eq!(
                map.0[1].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("expires_at")).unwrap())
            );
        }
        _ => panic!("event_heartbeat data must be a Map"),
    }

    // 3. Frozen event
    h.freeze();
    let all = h.env.events().all();
    let events = all.events();
    let frozen_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_frozen")).unwrap(),
                    ))
            }
        })
        .expect("event_frozen not found");

    let xdr::ContractEventBody::V0(frozen_v0) = &frozen_event.body;
    assert_eq!(frozen_v0.topics.len(), 1, "event_frozen must have 1 topic");
    match &frozen_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(map.0.len(), 1);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
        }
        _ => panic!("event_frozen data must be a Map"),
    }

    // 4. Unfrozen event
    h.unfreeze();
    let all = h.env.events().all();
    let events = all.events();
    let unfrozen_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_unfrozen")).unwrap(),
                    ))
            }
        })
        .expect("event_unfrozen not found");

    let xdr::ContractEventBody::V0(unfrozen_v0) = &unfrozen_event.body;
    assert_eq!(
        unfrozen_v0.topics.len(),
        1,
        "event_unfrozen must have 1 topic"
    );
    match &unfrozen_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(map.0.len(), 2);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
            assert_eq!(
                map.0[1].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("rearmed_dms")).unwrap())
            );
            assert!(
                matches!(map.0[1].val, ScVal::Bool(_)),
                "event_unfrozen rearmed_dms must be a Bool"
            );
        }
        _ => panic!("event_unfrozen data must be a Map"),
    }

    // 5. PolicySet event
    let dummy_policy = PolicyConfig {
        per_tx_cap: 100,
        window_secs: 60,
        window_cap: 500,
        assets: vec![&h.env],
        protocols: vec![&h.env],
        recipients: vec![&h.env],
        recipient_window_caps: vec![&h.env],
        blocked_recipients: vec![&h.env],
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };
    h.set_policy(&dummy_policy);
    let all = h.env.events().all();
    let events = all.events();
    let ps_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_policy_set")).unwrap(),
                    ))
            }
        })
        .expect("event_policy_set not found");

    let xdr::ContractEventBody::V0(ps_v0) = &ps_event.body;
    assert_eq!(ps_v0.topics.len(), 1, "event_policy_set must have 1 topic");
    match &ps_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(
                map.0.len(),
                2,
                "event_policy_set must carry by + revision (issue #38)"
            );
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
            assert_eq!(
                map.0[1].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("revision")).unwrap())
            );
        }
        _ => panic!("event_policy_set data must be a Map"),
    }
    assert_eq!(
        map_u64_field(ps_event, "revision"),
        2,
        "set_policy stamps the incremented revision (heartbeat policy was 1) (issue #38)"
    );

    // 6. PolicyRevoked event
    h.revoke_policy();
    let all = h.env.events().all();
    let events = all.events();
    let revoked_event = events
        .iter()
        .find(|e| match &e.body {
            xdr::ContractEventBody::V0(v0) => {
                v0.topics.first()
                    == Some(&ScVal::Symbol(
                        ScSymbol::try_from(std::vec::Vec::from("event_policy_revoked")).unwrap(),
                    ))
            }
        })
        .expect("event_policy_revoked not found");

    let xdr::ContractEventBody::V0(revoked_v0) = &revoked_event.body;
    assert_eq!(
        revoked_v0.topics.len(),
        1,
        "event_policy_revoked must have 1 topic"
    );
    match &revoked_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(
                map.0.len(),
                2,
                "event_policy_revoked must carry by + revision (issue #38)"
            );
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
            assert_eq!(
                map.0[1].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("revision")).unwrap())
            );
        }
        _ => panic!("event_policy_revoked data must be a Map"),
    }
    assert_eq!(
        map_u64_field(revoked_event, "revision"),
        3,
        "revoke_policy increments the counter (issue #38)"
    );
}

/// Issue #38 acceptance: the revision counter advances set → revoke → set,
/// and every `auth_checked` event stamps the revision in force at decision
/// time — including the default-deny path after a revoke, where no policy
/// exists but the rejection must still be attributable to a generation.
#[test]
#[allow(clippy::similar_names)] // ps_event/ps2_event, auth_event/auth2_event are the point
fn policy_revision_sequence_is_incremental_and_stamped_on_auth_events() {
    let mut h = EventAuditHarness::new();
    let cfg = PolicyConfig {
        per_tx_cap: 100,
        window_secs: 60,
        window_cap: 500,
        assets: vec![&h.env],
        protocols: vec![&h.env],
        recipients: vec![&h.env],
        recipient_window_caps: vec![&h.env],
        blocked_recipients: vec![&h.env],
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };

    // set → heartbeat → revoke → set → heartbeat: the counter must march
    // 1, 2, 3 with no gaps or resets, so each generation is a unique,
    // monotone join key, and a guarded decision under each generation stamps
    // that generation's revision on its `auth_checked` event.
    // `env.events().all()` holds only the most recent top-level invocation's
    // events, so each step is asserted against the snapshot taken right
    // after it.
    h.set_policy(&cfg);
    let all = h.env.events().all();
    let events = all.events();
    let ps_event = events
        .iter()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&event_name("event_policy_set"))))
        .expect("event_policy_set not found");
    assert_eq!(
        map_u64_field(ps_event, "revision"),
        1,
        "first set_policy stamps revision 1"
    );

    h.heartbeat(); // authorized under generation 1
    let all = h.env.events().all();
    let events = all.events();
    let auth_event = events
        .iter()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&event_name("event_auth_checked"))))
        .expect("event_auth_checked not found");
    assert_eq!(
        map_u64_field(auth_event, "revision"),
        1,
        "auth_checked under the first policy stamps revision 1"
    );

    h.revoke_policy();
    let all = h.env.events().all();
    let events = all.events();
    let pr_event = events
        .iter()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&event_name("event_policy_revoked"))))
        .expect("event_policy_revoked not found");
    assert_eq!(
        map_u64_field(pr_event, "revision"),
        2,
        "revoke_policy increments to 2"
    );

    h.set_policy(&cfg);
    let all = h.env.events().all();
    let events = all.events();
    let ps2_event = events
        .iter()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&event_name("event_policy_set"))))
        .expect("event_policy_set not found");
    assert_eq!(
        map_u64_field(ps2_event, "revision"),
        3,
        "second set_policy increments to 3 (no reset after revoke)"
    );

    h.heartbeat(); // authorized under generation 3
    let all = h.env.events().all();
    let events = all.events();
    let auth2_event = events
        .iter()
        .find(|e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&event_name("event_auth_checked"))))
        .expect("event_auth_checked not found");
    assert_eq!(
        map_u64_field(auth2_event, "revision"),
        3,
        "auth_checked after re-install stamps revision 3 — the join key distinguishes generations"
    );

    // status() must agree with the event stamp for the current generation.
    assert_eq!(
        PolicyEngineClient::new(&h.env, &h.guard)
            .status()
            .policy_revision,
        3
    );
}

#[test]
fn window_merge_event_emits_once_at_the_entry_bound() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let mut ledger = Ledger::empty(&env);
    for ts in 0..crate::types::MAX_WINDOW_ENTRIES as u64 {
        ledger.admit(ts, 1);
    }
    assert!(
        ledger.merges.is_empty(),
        "no merge or event below the bound"
    );
    assert!(env.events().all().events().is_empty());

    ledger.admit(crate::types::MAX_WINDOW_ENTRIES as u64, 1);
    assert_eq!(ledger.merges.len(), 1);
    let merge = ledger.merges.pop().expect("one merge metadata record");
    assert_eq!(merge.kind, WindowMergeKind::GlobalSpend);
    assert_eq!(merge.merged_ts, 1);
    assert_eq!(merge.merged_value, 2);
    let contract = env.register(MockAdmin, ());
    env.as_contract(&contract, || emit_window_merge(&env, merge));

    let all_events = env.events().all();
    let events = all_events.events();
    assert_eq!(events.len(), 1);
    let event = events.first().unwrap();
    assert!(matches!(
        &event.body,
        xdr::ContractEventBody::V0(v0)
            if v0.topics.first() == Some(&event_name("event_window_merged"))
    ));
    assert_eq!(map_u64_field(event, "merged_ts"), 1);
    assert_eq!(map_i128_field(event, "merged_value"), 2);
}
