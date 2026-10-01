//! Keeps the policy presets in `docs/policy-templates.md` installable.
//!
//! The doc is the single source of truth: every fenced `json` block is
//! extracted, deserialized into a `PolicyConfig`, installed via `set_policy`
//! against the real contract in the Soroban test environment (which runs the
//! production `validate_config` path, SPEC §8), and read back to assert a
//! faithful round-trip. A preset that stops deserializing, stops validating,
//! or stops round-tripping fails `cargo test` — doc rot cannot ship silently.

use crate::types::{PolicyConfig, ProtocolRule, RecipientCap};
use crate::{PolicyEngine, PolicyEngineClient};

use serde_json::Value as JsonValue;
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Symbol, Vec};
use std::fs;
use std::string::String;

const DOC: &str = "docs/policy-templates.md";
const MIN_PRESETS: usize = 4;
const PRESET_NAMES: [&str; 4] = [
    "Day-trader agent",
    "Payments bot",
    "Watch-only + heartbeat",
    "Max security",
];

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
    type Error = crate::types::Error;

    #[allow(clippy::used_underscore_binding)] // trait-required params, deliberately unused
    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signatures: Self::Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn doc_text() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(DOC);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// Every fenced `json` block in the doc, in order of appearance.
fn json_blocks(doc: &str) -> std::vec::Vec<String> {
    let mut blocks = std::vec::Vec::new();
    let mut current: Option<String> = None;
    for line in doc.lines() {
        let trimmed = line.trim();
        match current.as_mut() {
            None => {
                if trimmed == "```json" {
                    current = Some(String::new());
                }
            }
            Some(block) => {
                if trimmed == "```" {
                    blocks.push(std::mem::take(block));
                    current = None;
                } else {
                    block.push_str(line);
                    block.push('\n');
                }
            }
        }
    }
    assert!(current.is_none(), "unclosed ```json block in {DOC}");
    blocks
}

fn required_field<'a>(block: &'a JsonValue, field: &str, index: usize) -> &'a JsonValue {
    block
        .get(field)
        .unwrap_or_else(|| panic!("preset #{index} ({DOC}) is missing required field `{field}`"))
}

fn addr_list(env: &Env, block: &JsonValue, field: &str, index: usize) -> Vec<Address> {
    let items = required_field(block, field, index)
        .as_array()
        .unwrap_or_else(|| panic!("preset #{index}: `{field}` must be an array of addresses"));
    let mut out = Vec::new(env);
    for item in items {
        let raw = item
            .as_str()
            .unwrap_or_else(|| panic!("preset #{index}: `{field}` entries must be strings"));
        out.push_back(Address::from_str(env, raw));
    }
    out
}

fn u64_field(block: &JsonValue, field: &str, index: usize) -> u64 {
    required_field(block, field, index)
        .as_u64()
        .unwrap_or_else(|| panic!("preset #{index}: `{field}` must be a u64 number"))
}

fn i128_field(block: &JsonValue, field: &str, index: usize) -> i128 {
    let raw = required_field(block, field, index)
        .as_str()
        .unwrap_or_else(|| panic!("preset #{index}: `{field}` must be a string-encoded i128"));
    raw.parse::<i128>()
        .unwrap_or_else(|err| panic!("preset #{index}: `{field}` is not a valid i128: {err}"))
}

fn bool_field(block: &JsonValue, field: &str, index: usize) -> bool {
    required_field(block, field, index)
        .as_bool()
        .unwrap_or_else(|| panic!("preset #{index}: `{field}` must be a bool"))
}

fn protocols(env: &Env, block: &JsonValue, index: usize) -> Vec<ProtocolRule> {
    let items = required_field(block, "protocols", index)
        .as_array()
        .unwrap_or_else(|| panic!("preset #{index}: `protocols` must be an array"));
    let mut out = Vec::new(env);
    for rule in items {
        let contract = rule
            .get("contract")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("preset #{index}: protocol rule needs a `contract` string"));
        let fns = match rule.get("fns") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::Array(names)) => {
                let mut symbols = Vec::new(env);
                for name in names {
                    let raw = name.as_str().unwrap_or_else(|| {
                        panic!("preset #{index}: `fns` entries must be strings")
                    });
                    symbols.push_back(Symbol::new(env, raw));
                }
                Some(symbols)
            }
            Some(other) => {
                panic!("preset #{index}: `fns` must be null or an array of strings, got {other}")
            }
        };
        out.push_back(ProtocolRule {
            contract: Address::from_str(env, contract),
            fns,
        });
    }
    out
}

fn recipient_window_caps(env: &Env, block: &JsonValue, index: usize) -> Vec<RecipientCap> {
    let mut out = Vec::new(env);
    let Some(items) = block.get("recipient_window_caps") else {
        return out;
    };
    let items = items
        .as_array()
        .unwrap_or_else(|| panic!("preset #{index}: `recipient_window_caps` must be an array"));
    for item in items {
        let recipient = item
            .get("recipient")
            .and_then(JsonValue::as_str)
            .unwrap_or_else(|| panic!("preset #{index}: recipient cap needs a `recipient` string"));
        let cap = item
            .get("cap")
            .and_then(JsonValue::as_str)
            .and_then(|raw| raw.parse::<i128>().ok())
            .unwrap_or_else(|| {
                panic!("preset #{index}: recipient cap needs a string-encoded i128 `cap`")
            });
        out.push_back(RecipientCap {
            recipient: Address::from_str(env, recipient),
            cap,
        });
    }
    out
}

fn policy_config_from_json(env: &Env, block: &JsonValue, index: usize) -> PolicyConfig {
    PolicyConfig {
        per_tx_cap: i128_field(block, "per_tx_cap", index),
        window_secs: u64_field(block, "window_secs", index),
        window_cap: i128_field(block, "window_cap", index),
        assets: addr_list(env, block, "assets", index),
        protocols: protocols(env, block, index),
        recipients: addr_list(env, block, "recipients", index),
        recipient_window_caps: recipient_window_caps(env, block, index),
        blocked_recipients: soroban_sdk::Vec::new(env),
        allow_any_recipient: bool_field(block, "allow_any_recipient", index),
        active_from: u64_field(block, "active_from", index),
        active_until: u64_field(block, "active_until", index),
        paused: bool_field(block, "paused", index),
        dms_grace_secs: u64_field(block, "dms_grace_secs", index),
        protocol_calls_per_window: 0,
    }
}

/// A real contract instance in the Soroban test environment, initialized and
/// ready for `set_policy` (blanket-mocked auths, like the integration tests).
struct PresetEnv {
    env: Env,
    guard: Address,
}

fn preset_env() -> PresetEnv {
    let env = Env::default();
    env.mock_all_auths();
    let admin = env.register(MockAdmin, ());
    let guard = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &guard);
    client.initialize(&admin, &BytesN::from_array(&env, &[7u8; 32]));
    PresetEnv { env, guard }
}

#[test]
fn doc_documents_at_least_four_named_presets() {
    let doc = doc_text();
    for name in PRESET_NAMES {
        assert!(
            doc.contains(name),
            "{DOC} no longer documents the `{name}` preset — update the doc or this test"
        );
    }
}

#[test]
fn every_documented_preset_installs_and_round_trips() {
    let doc = doc_text();
    let blocks = json_blocks(&doc);
    assert!(
        blocks.len() >= MIN_PRESETS,
        "{DOC} documents {} ```json preset(s); at least {MIN_PRESETS} required",
        blocks.len()
    );

    let PresetEnv { env, guard } = preset_env();
    for (index, block) in blocks.iter().enumerate() {
        let number = index + 1;
        let value: JsonValue = serde_json::from_str(block)
            .unwrap_or_else(|err| panic!("preset #{number} is not valid JSON: {err}"));
        let expected = policy_config_from_json(&env, &value, number);

        // Installing runs the production validate_config path (SPEC §8): an
        // invalid preset panics the contract with InvalidConfig here.
        let client = PolicyEngineClient::new(&env, &guard);
        client.set_policy(&expected);

        let installed = client
            .policy()
            .unwrap_or_else(|| panic!("preset #{number} did not install"));
        assert_eq!(
            installed, expected,
            "preset #{number} round-trip mismatch: the doc's JSON does not deserialize \
             to the config the contract stores",
        );
    }
}
