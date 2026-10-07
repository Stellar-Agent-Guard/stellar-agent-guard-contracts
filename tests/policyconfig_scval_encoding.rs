//! Locks the exact `ScVal` wire encoding of `PolicyConfig` documented in SPEC §3.2.
//!
//! The section is the reference for non-TypeScript consumers (Go/Python/Rust
//! integrators, a future CLI) who must produce byte-compatible `ScVal` maps
//! without reading the TS SDK. The doc and the derives are independent views of
//! the same wire format, so this test is the drift ratchet: if a field is added,
//! a key is renamed, the sorted-entry order changes, or a primitive switches
//! `ScVal` variant (e.g. `i128` stops being `ScVal::I128`, `None` stops being
//! `ScVal::Void`), this test fails and SPEC §3.2 must be updated in the same PR.

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    xdr::{Int128Parts, ScVal},
    Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec as SdkVec,
};
use stellar_agent_guard_contracts::{AssetCap, PolicyConfig, ProtocolRule, RecipientCap};

/// Converts a host value to its exact `ScVal` via the host (`Val`) representation,
/// the same path a real `set_policy` invocation takes through the SDK. Takes the
/// value by design: call sites pass either owned or referenced policy values, and
/// `IntoVal` consumes the host representation.
#[allow(clippy::needless_pass_by_value)]
fn to_scval(env: &Env, v: impl IntoVal<Env, Val>) -> ScVal {
    ScVal::try_from_val(env, &v.into_val(env)).expect("scval conversion")
}

/// The sorted symbol keys of `PolicyConfig` — SPEC §3.2 table column 2.
const EXPECTED_KEYS: [&str; 15] = [
    "active_from",
    "active_until",
    "allow_any_recipient",
    "asset_caps",
    "assets",
    "blocked_recipients",
    "dms_grace_secs",
    "paused",
    "per_tx_cap",
    "protocol_calls_per_window",
    "protocols",
    "recipient_window_caps",
    "recipients",
    "window_cap",
    "window_secs",
];

fn map_entries(scval: &ScVal) -> Vec<(String, ScVal)> {
    match scval {
        ScVal::Map(Some(entries)) => entries
            .iter()
            .map(|e| {
                let key = match &e.key {
                    ScVal::Symbol(s) => s.to_utf8_string().expect("symbol utf8"),
                    other => panic!("map key is not a Symbol: {other:?}"),
                };
                (key, e.val.clone())
            })
            .collect(),
        other => panic!("expected ScVal::Map, got {other:?}"),
    }
}

fn first_vec_item(scval: &ScVal, field: &str) -> ScVal {
    match scval {
        ScVal::Vec(Some(items)) => {
            assert_eq!(items.len(), 1, "{field} must hold exactly one element");
            items.iter().next().expect("non-empty").clone()
        }
        other => panic!("{field} must be ScVal::Vec, got {other:?}"),
    }
}

fn field<'a>(entries: &'a [(String, ScVal)], name: &str) -> &'a ScVal {
    let found = entries
        .iter()
        .find(|(k, _)| k == name)
        .unwrap_or_else(|| panic!("missing field {name}"));
    &found.1
}

/// A sample policy with a value in every field, including negative and
/// positive i128 values and a Some/None `fns` split across tests.
fn sample_policy(env: &Env) -> PolicyConfig {
    let mut fns = SdkVec::new(env);
    fns.push_back(Symbol::new(env, "swap"));
    let mut protocols = SdkVec::new(env);
    protocols.push_back(ProtocolRule {
        contract: Address::generate(env),
        fns: Some(fns),
    });
    let mut assets = SdkVec::new(env);
    assets.push_back(Address::generate(env));
    let mut caps = SdkVec::new(env);
    caps.push_back(RecipientCap {
        recipient: Address::generate(env),
        cap: -5i128,
    });
    let mut blocked = SdkVec::new(env);
    blocked.push_back(Address::generate(env));
    let mut asset_caps = SdkVec::new(env);
    asset_caps.push_back(AssetCap {
        asset: Address::generate(env),
        per_tx_cap: 250i128,
    });
    let mut recipients = SdkVec::new(env);
    // A real account (G…) strkey from the Phase-1 fixture policy so the
    // recipients vec exercises the ScAddress::Account shape (SPEC §3.2).
    recipients.push_back(Address::from_str(
        env,
        "GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX",
    ));

    PolicyConfig {
        per_tx_cap: -1_234_567i128,
        window_secs: 86_400u64,
        window_cap: 987_654_321i128,
        assets,
        protocols,
        recipients,
        recipient_window_caps: caps,
        asset_caps,
        blocked_recipients: blocked,
        allow_any_recipient: true,
        active_from: 0u64,
        active_until: 1_700_000_000u64,
        paused: false,
        dms_grace_secs: 604_800u64,
        protocol_calls_per_window: 42u32,
    }
}

#[test]
fn top_level_map_has_exactly_the_fifteen_fields_in_sorted_symbol_order() {
    let env = Env::default();
    let entries = map_entries(&to_scval(&env, sample_policy(&env)));

    let keys: Vec<String> = entries.iter().map(|(k, _)| k.clone()).collect();
    let expected: Vec<String> = EXPECTED_KEYS.map(std::string::ToString::to_string).to_vec();
    assert_eq!(
        keys, expected,
        "SPEC §3.2 table order must match wire key order"
    );
}

#[test]
fn primitive_fields_encode_as_the_scval_variants_documented_in_spec_3_2() {
    let env = Env::default();
    let entries = map_entries(&to_scval(&env, sample_policy(&env)));

    // u64 -> ScVal::U64
    assert!(matches!(field(&entries, "window_secs"), ScVal::U64(86_400)));
    assert!(matches!(
        field(&entries, "dms_grace_secs"),
        ScVal::U64(604_800)
    ));
    assert!(matches!(
        field(&entries, "active_until"),
        ScVal::U64(1_700_000_000)
    ));
    // bool -> ScVal::Bool
    assert!(matches!(
        field(&entries, "allow_any_recipient"),
        ScVal::Bool(true)
    ));
    assert!(matches!(field(&entries, "paused"), ScVal::Bool(false)));
    // i128 -> ScVal::I128 with two's-complement Int128Parts:
    // -1234567 = hi: -1, lo: 2^64 - 1234567 = 18446744073708317049
    assert!(matches!(
        field(&entries, "per_tx_cap"),
        ScVal::I128(Int128Parts {
            hi: -1,
            lo: 18_446_744_073_708_317_049
        })
    ));
    // 987654321 = hi: 0, lo: 987_654_321
    assert!(matches!(
        field(&entries, "window_cap"),
        ScVal::I128(Int128Parts {
            hi: 0,
            lo: 987_654_321
        })
    ));
}

#[test]
fn vec_fields_are_scvec_and_addresses_use_the_documented_scaddress_shapes() {
    let env = Env::default();
    let entries = map_entries(&to_scval(&env, sample_policy(&env)));

    // assets hold SAC token contracts -> ScAddress::Contract
    let asset_addr = first_vec_item(field(&entries, "assets"), "assets");
    assert!(
        matches!(&asset_addr, ScVal::Address(a) if matches!(a, soroban_sdk::xdr::ScAddress::Contract(_))),
        "asset addresses must encode as contract addresses, got {asset_addr:?}"
    );

    // recipients hold accounts -> ScAddress::Account
    let recipient_addr = first_vec_item(field(&entries, "recipients"), "recipients");
    assert!(
        matches!(&recipient_addr, ScVal::Address(a) if matches!(a, soroban_sdk::xdr::ScAddress::Account(_))),
        "recipient addresses must encode as account addresses, got {recipient_addr:?}"
    );
}

#[test]
fn protocol_rule_is_a_two_entry_sorted_map_and_some_fns_is_a_vec_of_symbols() {
    let env = Env::default();
    let entries = map_entries(&to_scval(&env, sample_policy(&env)));
    let rule = first_vec_item(field(&entries, "protocols"), "protocols");

    let rule_entries = map_entries(&rule);
    let rule_keys: Vec<String> = rule_entries.iter().map(|(k, _)| k.clone()).collect();
    assert_eq!(rule_keys, vec!["contract", "fns"]);

    // Some(vec!["swap"]) -> ScVal::Vec of ScVal::Symbol
    match field(&rule_entries, "fns") {
        ScVal::Vec(Some(items)) => {
            assert_eq!(items.len(), 1);
            let sym = items.iter().next().expect("non-empty").clone();
            assert!(
                matches!(&sym, ScVal::Symbol(s) if s.to_utf8_string().expect("utf8") == "swap"),
                "Some(fns) must be a vec of symbols, got {sym:?}"
            );
        }
        other => panic!("Some(fns) must be ScVal::Vec of symbols, got {other:?}"),
    }
}

#[test]
fn none_fns_encodes_as_void() {
    let env = Env::default();
    let mut policy = sample_policy(&env);
    let mut protocols_none = SdkVec::new(&env);
    protocols_none.push_back(ProtocolRule {
        contract: Address::generate(&env),
        fns: None,
    });
    policy.protocols = protocols_none;

    let entries = map_entries(&to_scval(&env, policy));
    let rule = first_vec_item(field(&entries, "protocols"), "protocols");
    let rule_entries = map_entries(&rule);
    let none_fns = field(&rule_entries, "fns");
    assert!(
        matches!(none_fns, ScVal::Void),
        "None fns must encode as ScVal::Void, got {none_fns:?}"
    );
}

#[test]
fn empty_vecs_stay_empty_vecs_not_void() {
    let env = Env::default();
    let mut policy = sample_policy(&env);
    policy.protocols = SdkVec::new(&env);

    let entries = map_entries(&to_scval(&env, policy));
    match field(&entries, "protocols") {
        ScVal::Vec(Some(items)) => {
            assert_eq!(items.len(), 0, "empty Vec must stay Vec([]), not Void");
        }
        ScVal::Void => panic!("empty Vec must NOT encode as Void (SPEC §3.2)"),
        other => panic!("protocols must be ScVal::Vec, got {other:?}"),
    }
}
