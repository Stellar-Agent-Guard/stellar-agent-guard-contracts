//! Comprehensive event payload audit tests for every event emitted by the contract.
//! Asserts exact topic counts, topic symbols, and data payload shapes per SPEC §9.

use crate::types::{PolicyConfig, ProtocolRule};
use crate::{PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limited, Limits,
    ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, vec, Address, BytesN, Env, FromVal, IntoVal, Symbol, Val,
};
use std::format;

const SIG_EXPIRATION_LEDGER: u32 = 6_000_000;

#[contract]
pub struct MockAdmin;

#[contractimpl]
#[allow(clippy::needless_pass_by_value, clippy::used_underscore_binding)]
impl CustomAccountInterface for MockAdmin {
    type Signature = ();
    type Error = crate::types::Error;

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
fn audit_event_payloads_and_topics() {
    let mut h = EventAuditHarness::new();

    // 1. Initialized event (emitted during new() via initialize)
    let events = h.env.events().all().events();
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

    // 2. Heartbeat event
    h.env.ledger().set_timestamp(2_000);
    h.heartbeat();

    let events = h.env.events().all().events();
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
            assert_eq!(map.0.len(), 1);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("at")).unwrap())
            );
        }
        _ => panic!("event_heartbeat data must be a Map"),
    }

    // 3. Frozen event
    h.freeze();
    let events = h.env.events().all().events();
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
    let events = h.env.events().all().events();
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
    };
    h.set_policy(&dummy_policy);
    let events = h.env.events().all().events();
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
            assert_eq!(map.0.len(), 1);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
        }
        _ => panic!("event_policy_set data must be a Map"),
    }

    // 6. PolicyRevoked event
    h.revoke_policy();
    let events = h.env.events().all().events();
    let pr_event = events
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

    let xdr::ContractEventBody::V0(pr_v0) = &pr_event.body;
    assert_eq!(
        pr_v0.topics.len(),
        1,
        "event_policy_revoked must have 1 topic"
    );
    match &pr_v0.data {
        ScVal::Map(Some(map)) => {
            assert_eq!(map.0.len(), 1);
            assert_eq!(
                map.0[0].key,
                ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("by")).unwrap())
            );
        }
        _ => panic!("event_policy_revoked data must be a Map"),
    }
}
