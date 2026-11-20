//! Keeps copy-paste policy examples and the SPEC parity vector aligned with
//! the machine-readable schema used by tooling.

use jsonschema::Validator;
use serde_json::Value;
use std::{fs, path::PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn json_blocks(markdown: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        match (current.as_mut(), line.trim()) {
            (None, "```json") => current = Some(String::new()),
            (Some(block), "```") => {
                blocks.push(std::mem::take(block));
                current = None;
            }
            (Some(block), _) => {
                block.push_str(line);
                block.push('\n');
            }
            (None, _) => {}
        }
    }
    assert!(current.is_none(), "unclosed JSON code fence");
    blocks
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

    let presets = fs::read_to_string(root.join("docs/policy-templates.md"))
        .expect("read documented policy presets");
    let blocks = json_blocks(&presets);
    assert!(blocks.len() >= 4, "expected all documented policy presets");
    for (index, block) in blocks.iter().enumerate() {
        let value: Value = serde_json::from_str(block)
            .unwrap_or_else(|error| panic!("preset #{} is invalid JSON: {error}", index + 1));
        assert_valid(&schema, &value, &format!("policy preset #{}", index + 1));
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
