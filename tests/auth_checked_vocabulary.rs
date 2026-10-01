//! Keeps the consumer-facing `auth_checked` vocabulary fixture in sync with Error.

use std::collections::BTreeMap;
use std::fs;

use serde_json::{json, Value};
use soroban_sdk::{Env, Symbol};
use stellar_agent_guard_contracts::Error;

const FIXTURE: &str = "tests/fixtures/auth-checked-vocabulary.json";

#[test]
fn auth_checked_fixture_covers_every_error_variant_and_allowed() {
    let raw = fs::read_to_string(FIXTURE).expect("auth_checked vocabulary fixture exists");
    let fixture: Value = serde_json::from_str(&raw).expect("fixture is valid JSON");
    assert_eq!(fixture["schema_version"], 1);
    assert_eq!(fixture["event"], "event_auth_checked");

    let source_errors = error_variants_from_source(include_str!("../src/types.rs"));
    let outcomes = fixture["outcomes"]
        .as_array()
        .expect("outcomes must be an array");
    let allowed: Vec<_> = outcomes
        .iter()
        .filter(|outcome| outcome["error_variant"] == "Allowed")
        .collect();
    assert_eq!(allowed.len(), 1, "fixture has exactly one allowed outcome");
    assert_eq!(outcomes.len(), source_errors.len() + 1);

    let expected_data = json!({
        "type": "Map",
        "fields": [
            {"name": "context_index", "type": "u32"},
            {"name": "revision", "type": "u64"}
        ]
    });
    assert_eq!(allowed[0]["code"], Value::Null);
    assert_eq!(allowed[0]["symbol"], "allowed");
    assert_eq!(
        allowed[0]["topics"],
        json!(["event_auth_checked", "allowed", ""])
    );
    assert_eq!(allowed[0]["data"], expected_data);
    assert_eq!(allowed[0]["spec_ref"], "§9");

    let env = Env::default();
    let mut fixture_errors = BTreeMap::new();
    for outcome in outcomes
        .iter()
        .filter(|outcome| outcome["error_variant"] != "Allowed")
    {
        let variant = outcome["error_variant"]
            .as_str()
            .expect("error_variant is a string");
        let code = u32::try_from(outcome["code"].as_u64().expect("error code is numeric"))
            .expect("error code fits u32");
        let symbol = outcome["symbol"].as_str().expect("symbol is a string");
        assert!(
            fixture_errors.insert(variant.to_owned(), code).is_none(),
            "duplicate fixture variant {variant}"
        );
        assert_eq!(
            outcome["topics"],
            json!(["event_auth_checked", "blocked", symbol])
        );
        assert_eq!(outcome["data"], expected_data);
        assert!(outcome["spec_ref"]
            .as_str()
            .is_some_and(|reference| reference.starts_with('§')));

        let error = Error::from_block_reason(&Symbol::new(&env, symbol))
            .unwrap_or_else(|| panic!("{variant} symbol {symbol} is not recognized by Error"));
        assert_eq!(error as u32, code, "{variant} code drifted");
        assert_eq!(error.reason(), symbol, "{variant} reason symbol drifted");
    }
    assert_eq!(
        fixture_errors, source_errors,
        "fixture and Error enum drifted"
    );
}

fn error_variants_from_source(source: &str) -> BTreeMap<String, u32> {
    let body = source
        .split_once("pub enum Error {")
        .expect("Error enum declaration exists")
        .1
        .split_once("\n}")
        .expect("Error enum body closes")
        .0;
    body.lines()
        .filter_map(|line| {
            let declaration = line.trim();
            let (variant, code) = declaration.split_once('=')?;
            let variant = variant.trim();
            if variant.is_empty()
                || !variant
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric())
            {
                return None;
            }
            let code = code.trim().trim_end_matches(',').parse().ok()?;
            Some((variant.to_owned(), code))
        })
        .collect()
}
