//! Keeps `tests/fixtures/index.json` and `tests/fixtures/README.md` in agreement.
//!
//! The README is the human narrative of the Phase 1 testnet evidence; the JSON
//! index is the stable shape tooling parses instead of scraping prose. Neither
//! file is derived from the other, so this test is the drift ratchet: every
//! full transaction hash in the README must appear in the index, every hash in
//! the index must appear in the README, and each truncated `deadbeef…`-style
//! reference must resolve to an indexed hash. Any mismatch fails `cargo test`,
//! which is the `ci` status check.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;

const README_FILE: &str = "README.md";
const INDEX_FILE: &str = "index.json";
const SCENARIO_COUNT: usize = 5;
const ELLIPSIS: char = '\u{2026}';
const HASH_LEN: usize = 64;
const PREFIX_MIN_LEN: usize = 4;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn read_fixture(name: &str) -> String {
    let path = fixtures_dir().join(name);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// Every maximal run of ASCII hex digits in `text`, in order of appearance.
fn hex_runs(text: &str) -> Vec<String> {
    let mut runs: Vec<String> = Vec::new();
    let mut current = String::new();
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            current.push(character);
        } else if !current.is_empty() {
            runs.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    runs
}

/// Full 64-digit hashes found in `text`.
fn full_hashes(text: &str) -> BTreeSet<String> {
    hex_runs(text)
        .into_iter()
        .filter(|run| run.len() == HASH_LEN)
        .collect()
}

/// Truncated references such as `6f17c570…`: the hex run immediately before
/// an ellipsis. Short trailing runs (`GDUYLF…`, `C…`) are prose elisions, not
/// hash references, so only runs of at least [`PREFIX_MIN_LEN`] are returned.
fn truncated_prefixes(text: &str) -> BTreeSet<String> {
    let mut prefixes = BTreeSet::new();
    for (index, _) in text.match_indices(ELLIPSIS) {
        let reversed: String = text[..index]
            .chars()
            .rev()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        let prefix: String = reversed.chars().rev().collect();
        if prefix.len() >= PREFIX_MIN_LEN {
            prefixes.insert(prefix);
        }
    }
    prefixes
}

/// Every string value anywhere in the JSON document, depth first.
fn json_strings(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::String(text) => found.push(text.clone()),
        Value::Array(items) => items.iter().for_each(|item| json_strings(item, found)),
        Value::Object(fields) => fields.values().for_each(|field| json_strings(field, found)),
        _ => {}
    }
}

/// Every full transaction hash recorded anywhere in `index.json`.
fn index_hashes(index: &Value) -> BTreeSet<String> {
    let mut values = Vec::new();
    json_strings(index, &mut values);
    values.iter().flat_map(|value| full_hashes(value)).collect()
}

fn load_index() -> Value {
    let raw = read_fixture(INDEX_FILE);
    serde_json::from_str(&raw).unwrap_or_else(|err| panic!("{INDEX_FILE} is not valid JSON: {err}"))
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> &'a Value {
    value
        .get(key)
        .unwrap_or_else(|| panic!("{context}: missing required field `{key}`"))
}

fn array<'a>(value: &'a Value, key: &str, context: &'a str) -> &'a [Value] {
    field(value, key, context)
        .as_array()
        .unwrap_or_else(|| panic!("{context}: `{key}` must be a JSON array"))
}

fn text<'a>(value: &'a Value, key: &str, context: &str) -> Option<&'a str> {
    field(value, key, context).as_str()
}

fn assert_hash(candidate: Option<&str>, context: &str) {
    let hash = candidate.unwrap_or_else(|| panic!("{context}: expected a transaction hash"));
    assert!(
        hash.len() == HASH_LEN && hash.chars().all(|character| character.is_ascii_hexdigit()),
        "{context}: `{hash}` is not a {HASH_LEN}-digit hex transaction hash"
    );
}

#[test]
fn readme_and_index_list_the_same_transaction_hashes() {
    let readme = read_fixture(README_FILE);
    let indexed = index_hashes(&load_index());
    let documented = full_hashes(&readme);

    let only_in_readme: Vec<&String> = documented.difference(&indexed).collect();
    let only_in_index: Vec<&String> = indexed.difference(&documented).collect();

    assert!(
        !documented.is_empty(),
        "no transaction hashes extracted from {README_FILE}; the extractor is broken"
    );
    assert!(
        only_in_readme.is_empty() && only_in_index.is_empty(),
        "README.md and index.json disagree about transaction hashes.\n\
         In README.md but not index.json: {only_in_readme:?}\n\
         In index.json but not README.md: {only_in_index:?}\n\
         Add the missing side (and its scenario/setup entry) so both files describe the same run."
    );
}

#[test]
fn readme_hash_prefixes_resolve_to_indexed_hashes() {
    let readme = read_fixture(README_FILE);
    let indexed = index_hashes(&load_index());
    let prefixes = truncated_prefixes(&readme);

    assert!(
        !prefixes.is_empty(),
        "no `deadbeef…` style hash references found in {README_FILE}; either the README now spells \
         every hash in full (update this test) or the extractor broke"
    );

    for prefix in &prefixes {
        assert!(
            indexed.iter().any(|hash| hash.starts_with(prefix.as_str())),
            "README.md truncates a hash to `{prefix}…` but index.json has no hash starting with it"
        );
    }
}

/// The contracts and the admin seat must be the same objects the README's
/// tables name: `(guard, token, admin)`.
fn indexed_identifiers(index: &Value) -> (Option<&str>, Option<&str>, Option<&str>) {
    let contracts = field(index, "contracts", INDEX_FILE);
    let accounts = array(index, "accounts", INDEX_FILE);
    let admin = accounts
        .iter()
        .find(|account| account.get("role").and_then(Value::as_str) == Some("admin"))
        .and_then(|account| account.get("address"))
        .and_then(Value::as_str);
    assert!(admin.is_some(), "index.json accounts: no `admin` role");
    (
        text(contracts, "guard", "index.json contracts"),
        text(contracts, "token", "index.json contracts"),
        admin,
    )
}

fn assert_scenario(
    scenario: &Value,
    position: usize,
    guard: Option<&str>,
    token: Option<&str>,
    seen_ids: &mut BTreeSet<u64>,
) {
    let context = format!("index.json scenarios[{position}]");
    let id = field(scenario, "id", &context)
        .as_u64()
        .unwrap_or_else(|| panic!("{context}: `id` must be an unsigned integer"));
    assert!(
        seen_ids.insert(id),
        "{context}: duplicate scenario id {id}; ids must be 1..={SCENARIO_COUNT}"
    );

    let title = text(scenario, "title", &context).unwrap_or_default();
    assert!(
        !title.is_empty(),
        "{context}: `title` must be a non-empty string"
    );
    assert!(
        text(scenario, "policy_tx", &context).is_some(),
        "{context}: `policy_tx` missing"
    );
    assert_eq!(
        text(scenario, "guard", &context),
        guard,
        "{context}: `guard` must match contracts.guard"
    );
    assert_eq!(
        text(scenario, "token", &context),
        token,
        "{context}: `token` must match contracts.token"
    );

    let outcome = text(scenario, "outcome", &context).unwrap_or_default();
    let reason = text(scenario, "expected_reason", &context).unwrap_or_default();
    assert!(!reason.is_empty(), "{context}: `expected_reason` is empty");

    let tx = scenario.get("tx");
    let ledger = scenario.get("ledger");
    match outcome {
        "allowed" => {
            assert_eq!(
                reason, "allowed",
                "{context}: an allowed outcome must expect `allowed`"
            );
            assert_hash(tx.and_then(Value::as_str), &context);
            assert!(
                ledger.and_then(Value::as_u64).is_some(),
                "{context}: a confirmed transaction must record its ledger"
            );
        }
        "blocked" => {
            assert_ne!(
                reason, "allowed",
                "{context}: a blocked outcome must expect a block reason"
            );
            assert!(
                tx.is_some_and(Value::is_null),
                "{context}: blocked scenarios are pre-broadcast, so `tx` must be null"
            );
            assert!(
                ledger.is_some_and(Value::is_null),
                "{context}: blocked scenarios never reached a ledger, so `ledger` must be null"
            );
        }
        other => panic!("{context}: `outcome` must be `allowed` or `blocked`, got `{other}`"),
    }

    assert_eq!(
        topics(scenario),
        expected_topics(outcome, reason),
        "{context}: `event_topics` must match the recorded `event_auth_checked` topics"
    );
}

fn topics(scenario: &Value) -> Vec<String> {
    array(scenario, "event_topics", "index.json scenarios[]")
        .iter()
        .map(|topic| topic.as_str().unwrap_or_default().to_string())
        .collect()
}

fn expected_topics(outcome: &str, reason: &str) -> Vec<String> {
    if outcome == "allowed" {
        vec!["event_auth_checked".to_string(), "allowed".to_string()]
    } else {
        vec![
            "event_auth_checked".to_string(),
            "blocked".to_string(),
            reason.to_string(),
        ]
    }
}

/// Scenario 5 is the only one with an admin reversal and a post-reversal run;
/// both must be recorded with the admin seat that the README names.
fn assert_dms_reversal(scenario: &Value, admin: Option<&str>) {
    let context = "index.json scenarios[4]";
    let reversal = field(scenario, "reversal", context);
    let reversal_context = "index.json scenarios[4].reversal";
    assert_eq!(
        text(reversal, "by", reversal_context),
        admin,
        "{reversal_context}: the DMS reversal must be attested by the admin in `accounts`"
    );
    assert_hash(text(reversal, "tx", reversal_context), reversal_context);
    assert!(
        reversal.get("event_topics").is_some(),
        "{reversal_context}: `event_topics` missing"
    );

    let post_context = "index.json scenarios[4].post_reversal";
    let post_reversal = field(scenario, "post_reversal", context);
    assert_eq!(
        text(post_reversal, "outcome", post_context),
        Some("allowed"),
        "{post_context}: the transfer after `unfreeze()` must be `allowed`"
    );
    assert_hash(text(post_reversal, "tx", post_context), post_context);
    assert!(
        post_reversal
            .get("ledger")
            .and_then(Value::as_u64)
            .is_some(),
        "{post_context}: a confirmed transaction must record its ledger"
    );
}

#[test]
fn index_covers_the_five_scenarios() {
    let index = load_index();
    let scenarios = array(&index, "scenarios", INDEX_FILE);
    assert_eq!(
        scenarios.len(),
        SCENARIO_COUNT,
        "index.json must index the five recorded scenarios"
    );

    let (guard, token, admin) = indexed_identifiers(&index);

    let mut seen_ids: BTreeSet<u64> = BTreeSet::new();
    for (position, scenario) in scenarios.iter().enumerate() {
        assert_scenario(scenario, position, guard, token, &mut seen_ids);
    }
    assert_eq!(
        seen_ids,
        (1..=SCENARIO_COUNT as u64).collect::<BTreeSet<u64>>(),
        "index.json scenario ids must be exactly 1..={SCENARIO_COUNT}"
    );

    assert_dms_reversal(&scenarios[SCENARIO_COUNT - 1], admin);
}

#[test]
fn index_records_the_phase_one_setup_transactions() {
    let index = load_index();
    let setup = array(&index, "setup_transactions", INDEX_FILE);
    let readme = read_fixture(README_FILE);

    assert!(
        !setup.is_empty(),
        "index.json: `setup_transactions` must list the Phase 1 setup transactions"
    );

    let mut steps: BTreeSet<&str> = BTreeSet::new();
    for (position, entry) in setup.iter().enumerate() {
        let context = format!("index.json setup_transactions[{position}]");
        let step = text(entry, "step", &context).unwrap_or_default();
        assert!(
            !step.is_empty(),
            "{context}: `step` must be a non-empty key"
        );
        assert!(
            steps.insert(step),
            "{context}: duplicate setup step `{step}`"
        );
        assert_hash(text(entry, "tx", &context), &context);
        assert!(
            entry.get("ledger").is_some(),
            "{context}: `ledger` must be present (null when not recorded)"
        );
    }

    // The setup table in the README is the prose twin of this array: it must
    // still carry one row per indexed setup transaction.
    let setup_rows = readme
        .lines()
        .filter(|line| line.starts_with('|') && full_hashes(line).len() == 1)
        .count();
    assert_eq!(
        setup_rows,
        setup.len(),
        "README.md setup table has {setup_rows} transaction rows but index.json lists {}",
        setup.len()
    );
}

#[test]
fn index_identifiers_appear_in_the_readme() {
    let index = load_index();
    let readme = read_fixture(README_FILE);
    let contracts = field(&index, "contracts", INDEX_FILE);

    for key in ["guard", "token"] {
        let value = text(contracts, key, "index.json contracts").unwrap_or_default();
        assert!(
            readme.contains(value),
            "index.json contracts.{key} = {value} does not appear in {README_FILE}"
        );
    }

    for (position, account) in array(&index, "accounts", INDEX_FILE).iter().enumerate() {
        let context = format!("index.json accounts[{position}]");
        let address = text(account, "address", &context).unwrap_or_default();
        assert!(
            readme.contains(address),
            "index.json accounts[{position}] address {address} does not appear in {README_FILE}"
        );
    }

    assert!(
        readme.contains(INDEX_FILE),
        "{README_FILE} must link to {INDEX_FILE} so readers can find the machine-readable index"
    );
}
