//! Keeps the loadable policy preset files and the SPEC parity vector aligned
//! with the machine-readable schema used by tooling.

use jsonschema::Validator;
use serde_json::Value;
use std::{fs, path::PathBuf};

const PRESET_DIR: &str = "examples/policies";
const MIN_PRESETS: usize = 4;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn assert_valid(schema: &Validator, value: &Value, label: &str) {
    if !schema.is_valid(value) {
        let details = schema
            .iter_errors(value)
            .map(|error| error.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        panic!("{label} does not match policy.schema.json:\n{details}");
    }
}

#[test]
fn presets_and_scval_parity_vector_match_policy_schema() {
    let root = root();
    let schema_json: Value = serde_json::from_slice(
        &fs::read(root.join("policy.schema.json")).expect("read policy schema"),
    )
    .expect("parse policy schema");
    let schema = jsonschema::validator_for(&schema_json).expect("compile policy schema");

    // Discover presets dynamically: adding a file without schema validation
    // cannot silently pass.
    let preset_dir = root.join(PRESET_DIR);
    let mut preset_paths: Vec<PathBuf> = fs::read_dir(&preset_dir)
        .unwrap_or_else(|error| panic!("read {PRESET_DIR}: {error}"))
        .map(|entry| entry.expect("read preset directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    preset_paths.sort();
    assert!(
        preset_paths.len() >= MIN_PRESETS,
        "{PRESET_DIR} contains {} preset file(s); at least {MIN_PRESETS} required",
        preset_paths.len()
    );

    for path in &preset_paths {
        let label = format!("policy preset {}", path.display());
        let value: Value = serde_json::from_slice(
            &fs::read(path).unwrap_or_else(|error| panic!("read {label}: {error}")),
        )
        .unwrap_or_else(|error| panic!("{label} is invalid JSON: {error}"));
        assert_valid(&schema, &value, &label);
    }

    let parity: Value = serde_json::from_slice(
        &fs::read(root.join("tests/fixtures/policy-config-parity.json"))
            .expect("read PolicyConfig parity vector"),
    )
    .expect("parse PolicyConfig parity vector");
    assert_valid(&schema, &parity, "SPEC §3.2 ScVal parity vector");

    let invalid_window: Value = serde_json::from_str(
        r#"{"per_tx_cap":"0","window_secs":0,"window_cap":"1","assets":[],"protocols":[],"recipients":[],"allow_any_recipient":false,"active_from":0,"active_until":0,"paused":false,"dms_grace_secs":0}"#,
    )
    .unwrap();
    assert!(
        !schema.is_valid(&invalid_window),
        "positive window cap requires a window"
    );
}

#[test]
fn schema_rejects_duplicate_values_in_policy_lists() {
    let root = root();
    let schema_json: Value = serde_json::from_slice(
        &fs::read(root.join("policy.schema.json")).expect("read policy schema"),
    )
    .expect("parse policy schema");
    let schema = jsonschema::validator_for(&schema_json).expect("compile policy schema");
    let policy: Value = serde_json::from_slice(
        &fs::read(root.join("tests/fixtures/policy-config-parity.json"))
            .expect("read PolicyConfig parity vector"),
    )
    .expect("parse PolicyConfig parity vector");
    let asset = policy["assets"][0].clone();
    let recipient = policy["recipients"][0].clone();

    for field in ["assets", "recipients", "blocked_recipients"] {
        let value = if field == "assets" {
            asset.clone()
        } else {
            recipient.clone()
        };
        let mut candidate = policy.clone();
        candidate[field] = serde_json::json!([value.clone(), value]);
        assert!(
            !schema.is_valid(&candidate),
            "duplicate entries in `{field}` must fail schema validation"
        );
    }

    let protocol = serde_json::json!({"contract": asset, "fns": ["swap"]});
    let mut candidate = policy.clone();
    candidate["protocols"] = serde_json::json!([protocol.clone(), protocol]);
    assert!(
        !schema.is_valid(&candidate),
        "duplicate protocol rules must fail"
    );

    let recipient_cap = serde_json::json!({"recipient": recipient, "cap": "10"});
    let mut candidate = policy.clone();
    candidate["recipient_window_caps"] = serde_json::json!([recipient_cap.clone(), recipient_cap]);
    assert!(
        !schema.is_valid(&candidate),
        "identical recipient cap entries must fail schema validation"
    );

    let asset = policy["assets"][0].clone();
    let asset_cap = serde_json::json!({"asset": asset, "per_tx_cap": "10"});
    let mut candidate = policy.clone();
    candidate["asset_caps"] = serde_json::json!([asset_cap.clone(), asset_cap]);
    assert!(
        !schema.is_valid(&candidate),
        "identical asset cap entries must fail schema validation"
    );

    let protocol = serde_json::json!({"contract": asset, "fns": ["swap", "swap"]});
    let mut candidate = policy.clone();
    candidate["protocols"] = serde_json::json!([protocol]);
    assert!(
        !schema.is_valid(&candidate),
        "duplicate protocol function names must fail schema validation"
    );
}
