//! Shared XDR vectors for `PolicyConfig` encoding parity with the TypeScript SDK.
//!
//! The fixture is canonical in the contracts repository; the SDK follow-up
//! issue points its `policyToScVal` test at this same file.

use serde_json::Value;
use soroban_sdk::{
    xdr::{FromXdr, ToXdr},
    Address, Bytes, Env, Symbol, Vec as SdkVec,
};
use stellar_agent_guard_contracts::{PolicyConfig, ProtocolRule, RecipientCap};

const VECTORS: &str = include_str!("fixtures/policy-vectors.json");

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .get(name)
        .unwrap_or_else(|| panic!("missing policy vector field `{name}`"))
}

fn text<'a>(value: &'a Value, name: &str) -> &'a str {
    field(value, name)
        .as_str()
        .unwrap_or_else(|| panic!("policy vector field `{name}` must be a string"))
}

fn number<T: core::str::FromStr>(value: &Value, name: &str) -> T
where
    T::Err: core::fmt::Debug,
{
    text(value, name)
        .parse()
        .unwrap_or_else(|error| panic!("invalid integer in `{name}`: {error:?}"))
}

fn addresses(env: &Env, value: &Value) -> SdkVec<Address> {
    let entries = value
        .as_array()
        .expect("address list in policy vector must be an array");
    let mut result = SdkVec::new(env);
    for entry in entries {
        let strkey = entry
            .as_str()
            .expect("address in policy vector must be a string");
        result.push_back(Address::from_str(env, strkey));
    }
    result
}

fn policy_from_json(env: &Env, value: &Value) -> PolicyConfig {
    let protocol_values = field(value, "protocols")
        .as_array()
        .expect("protocols in policy vector must be an array");
    let mut protocols = SdkVec::new(env);
    for protocol in protocol_values {
        let functions = field(protocol, "fns");
        let fns = if functions.is_null() {
            None
        } else {
            let values = functions
                .as_array()
                .expect("protocol fns must be an array or null");
            let mut symbols = SdkVec::new(env);
            for value in values {
                symbols.push_back(Symbol::new(
                    env,
                    value.as_str().expect("protocol fn must be a string"),
                ));
            }
            Some(symbols)
        };
        protocols.push_back(ProtocolRule {
            contract: Address::from_str(env, text(protocol, "contract")),
            fns,
        });
    }

    let cap_values = field(value, "recipient_window_caps")
        .as_array()
        .expect("recipient_window_caps in policy vector must be an array");
    let mut recipient_window_caps = SdkVec::new(env);
    for cap in cap_values {
        recipient_window_caps.push_back(RecipientCap {
            recipient: Address::from_str(env, text(cap, "recipient")),
            cap: number(cap, "cap"),
        });
    }

    PolicyConfig {
        per_tx_cap: number(value, "per_tx_cap"),
        window_secs: number(value, "window_secs"),
        window_cap: number(value, "window_cap"),
        assets: addresses(env, field(value, "assets")),
        protocols,
        recipients: addresses(env, field(value, "recipients")),
        recipient_window_caps,
        blocked_recipients: addresses(env, field(value, "blocked_recipients")),
        asset_caps: soroban_sdk::Vec::new(env),
        allow_any_recipient: field(value, "allow_any_recipient")
            .as_bool()
            .expect("allow_any_recipient must be a boolean"),
        active_from: number(value, "active_from"),
        active_until: number(value, "active_until"),
        paused: field(value, "paused")
            .as_bool()
            .expect("paused must be a boolean"),
        dms_grace_secs: number(value, "dms_grace_secs"),
        protocol_calls_per_window: number(value, "protocol_calls_per_window"),
    }
}

fn decode_hex(value: &str) -> std::vec::Vec<u8> {
    assert_eq!(value.len() % 2, 0, "XDR hex must have an even length");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = core::str::from_utf8(pair).expect("hex is ASCII");
            u8::from_str_radix(digits, 16).expect("XDR hex contains only hex digits")
        })
        .collect()
}

#[test]
fn shared_policy_vectors_decode_and_round_trip_exact_scval_xdr() {
    let fixture: Value = serde_json::from_str(VECTORS).expect("valid policy vector JSON");
    assert_eq!(
        field(&fixture, "format").as_str(),
        Some("soroban-policy-scval-xdr-v1")
    );
    let vectors = field(&fixture, "vectors")
        .as_array()
        .expect("vectors must be an array");
    assert!(
        vectors.len() >= 5,
        "fixture must cover at least five policies"
    );
    for required in [
        "defaults",
        "all-lists-populated",
        "zero-caps",
        "boundary-timestamps",
        "allow-any-recipient",
    ] {
        assert!(
            vectors
                .iter()
                .any(|vector| field(vector, "name").as_str() == Some(required)),
            "fixture is missing the `{required}` policy case"
        );
    }

    let env = Env::default();
    for vector in vectors {
        let name = text(vector, "name");
        let config = policy_from_json(&env, field(vector, "policy"));
        let expected_bytes = decode_hex(text(vector, "expected_scval_xdr_hex"));
        let expected_xdr = Bytes::from_slice(&env, &expected_bytes);

        let decoded = PolicyConfig::from_xdr(&env, &expected_xdr)
            .unwrap_or_else(|_| panic!("{name}: fixture XDR must decode as PolicyConfig"));
        assert_eq!(decoded, config, "{name}: decoded fixture policy mismatch");
        assert_eq!(
            decoded.to_xdr(&env).to_alloc_vec(),
            expected_bytes,
            "{name}: PolicyConfig XDR round-trip changed bytes"
        );
        assert_eq!(
            config.to_xdr(&env).to_alloc_vec(),
            expected_bytes,
            "{name}: Rust PolicyConfig encoding differs from shared vector"
        );
    }
}
