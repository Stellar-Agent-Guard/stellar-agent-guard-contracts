//! Drift gate for the policy decision table (issue #76).
//!
//! `decision-table.json` is the machine-readable twin of the `SPEC` §4 table.
//! Before this test, keeping that table, the `README` walkthrough, and the
//! engine's `Error` branches in agreement was a *review* requirement
//! (`CONTRIBUTING` rule 2). It is a mechanical check now: every row renders
//! into `SPEC` verbatim, every reason is a real variant whose telemetry symbol
//! is documented, every reason the engine can actually return is listed, and
//! each one is either pinned by a named test or carries a note saying why it
//! cannot be. Drift in any of those directions fails `cargo test`, which CI
//! runs — so a change to one artifact without the others is a red build rather
//! than a review miss.
//!
//! The test only reads files; it never touches the network or a ledger.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

const TABLE: &str = "decision-table.json";
const SPEC: &str = "SPEC.md";
const README: &str = "README.md";
const GLOSSARY: &str = "docs/reason-glossary.md";
const ENGINE: &str = "src/engine.rs";
const TYPES: &str = "src/types.rs";

/// The §4 table is a seven-row table, so a row quietly appearing or
/// disappearing on either side has to fail rather than shrink the check.
const EXPECTED_ROWS: usize = 7;

fn repo_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(name)
}

fn read_repo_file(name: &str) -> String {
    let path = repo_path(name);
    let raw = fs::read_to_string(&path);
    raw.unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

fn load_table() -> Value {
    let raw = read_repo_file(TABLE);
    let parsed = serde_json::from_str(&raw);
    parsed.unwrap_or_else(|err| panic!("{TABLE} is not valid JSON: {err}"))
}

fn field<'a>(value: &'a Value, key: &str, context: &str) -> &'a Value {
    let found = value.get(key);
    found.unwrap_or_else(|| panic!("{context}: missing required field `{key}`"))
}

fn array<'a>(value: &'a Value, key: &str, context: &str) -> &'a [Value] {
    let found = field(value, key, context).as_array();
    found.unwrap_or_else(|| panic!("{context}: `{key}` must be a JSON array"))
}

/// A list that only some rows carry (e.g. `kinds`, which the account-level
/// rows do not classify anything into).
fn optional_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    match value.get(key).and_then(Value::as_array) {
        Some(items) => items,
        None => &[],
    }
}

fn text<'a>(value: &'a Value, key: &str, context: &str) -> &'a str {
    let found = field(value, key, context).as_str();
    found.unwrap_or_else(|| panic!("{context}: `{key}` must be a string"))
}

fn optional_text<'a>(value: &'a Value, key: &str, _context: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The row's own id, with a message that names the row.
fn row_id(row: &Value, context: &str) -> u64 {
    let found = field(row, "id", context).as_u64();
    found.unwrap_or_else(|| panic!("{context}: `id` must be an unsigned integer"))
}

/// The body of `SPEC` §4 — the decision table, and nothing after it.
fn spec_decision_table() -> String {
    let spec = read_repo_file(SPEC);
    let found = spec.find("\n## 4.");
    let start = found.map(|at| at + 1);
    let start = start.unwrap_or_else(|| panic!("{SPEC} has no `## 4.` heading"));
    let rest = &spec[start..];
    let end = rest.find("\n### 4.1");
    let end = end.unwrap_or_else(|| panic!("{SPEC} §4 has no `### 4.1` to stop at"));
    rest[..end].to_owned()
}

/// Every numbered row of the §4 markdown table, exactly as written.
fn spec_rows() -> Vec<String> {
    spec_decision_table()
        .lines()
        .filter_map(|line| {
            let first_cell = line.strip_prefix('|')?.split('|').next()?;
            first_cell.trim().parse::<usize>().ok()?;
            Some(line.to_owned())
        })
        .collect()
}

/// The README's `parse_call` box — the flow diagram's classification cell, up
/// to the end of its fenced block. Anchoring here means a `ParsedCall` kind
/// that disappears from the *diagram* fails, not one that merely survives
/// somewhere else in the prose.
fn readme_flow_diagram() -> String {
    let readme = read_repo_file(README);
    let found = readme.find("parse_call: classify");
    let start = found.unwrap_or_else(|| {
        panic!("{README} no longer contains the `parse_call` box of the flow diagram")
    });
    let tail = &readme[start..];
    let end = tail.find("\n```").unwrap_or(tail.len());
    tail[..end].to_owned()
}

/// Names of the `Error` enum's variants.
fn error_variants() -> BTreeSet<String> {
    let types = read_repo_file(TYPES);
    let (_, after) = types
        .split_once("pub enum Error {")
        .unwrap_or_else(|| panic!("{TYPES} declares no `Error` enum"));
    let (body, _) = after
        .split_once("\n}")
        .unwrap_or_else(|| panic!("{TYPES} `Error` body never closes"));
    body.lines()
        .filter_map(|line| {
            let (variant, code) = line.trim().split_once('=')?;
            let variant = variant.trim();
            if variant.is_empty() || !variant.chars().all(|c| c.is_ascii_alphanumeric()) {
                return None;
            }
            let numeric = code.trim().trim_end_matches(',').parse::<u32>();
            numeric.ok()?;
            Some(variant.to_owned())
        })
        .collect()
}

/// The telemetry symbol `Error::reason()` gives each variant.
fn reason_symbols() -> BTreeSet<(String, String)> {
    let types = read_repo_file(TYPES);
    let (_, body) = types
        .split_once("pub fn reason(self)")
        .unwrap_or_else(|| panic!("{TYPES} declares no `Error::reason()`"));
    body.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("Self::")?;
            let (variant, symbol) = rest.split_once("=>")?;
            let quoted = symbol.trim().trim_end_matches(',').trim();
            Some((
                variant.trim().to_owned(),
                quoted.trim_matches('"').to_owned(),
            ))
        })
        .collect()
}

/// The call kinds the classifier can produce.
fn parsed_call_kinds() -> BTreeSet<String> {
    let types = read_repo_file(TYPES);
    let (_, after) = types
        .split_once("pub enum ParsedCall {")
        .unwrap_or_else(|| panic!("{TYPES} declares no `ParsedCall` enum"));
    let (body, _) = after
        .split_once("\n}")
        .unwrap_or_else(|| panic!("{TYPES} `ParsedCall` body never closes"));
    body.lines()
        .filter_map(|line| {
            let name = line.trim().split([' ', ',']).next()?;
            let first = name.chars().next()?;
            first.is_ascii_uppercase().then(|| name.to_owned())
        })
        .collect()
}

/// The engine with its test module removed — the branches that ship.
fn engine_source() -> String {
    let engine = read_repo_file(ENGINE);
    match engine.split_once("#[cfg(test)]") {
        Some((shipped, _tests)) => shipped.to_owned(),
        None => engine,
    }
}

/// Names of every `#[test] fn` in the engine (the tests live *after* the
/// `#[cfg(test)]` marker, so this reads the whole file). A doc comment may sit
/// between the attribute and the signature, so the attribute is a sticky flag
/// rather than an adjacency assumption.
fn engine_test_names() -> BTreeSet<String> {
    read_repo_file(ENGINE)
        .lines()
        .fold(
            (BTreeSet::new(), false),
            |(mut names, mut pending), line| {
                let trimmed = line.trim();
                if trimmed.starts_with("#[test]") {
                    pending = true;
                } else if pending && trimmed.starts_with("fn ") {
                    let signature = trimmed.trim_start_matches("fn ");
                    let name = signature.split('(').next().unwrap_or_default();
                    names.insert(name.to_owned());
                    pending = false;
                }
                (names, pending)
            },
        )
        .0
}

/// Every `Error` variant the shipped engine can return.
fn engine_block_reasons() -> BTreeSet<String> {
    let engine = engine_source();
    let mut reasons = BTreeSet::new();
    let mut rest = engine.as_str();
    while let Some(position) = rest.find("Error::") {
        rest = &rest[position + "Error::".len()..];
        let name: String = rest
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        if !name.is_empty() {
            reasons.insert(name);
        }
    }
    reasons
}

/// `(row id, error variant)` for every reason the table claims.
fn table_reasons(table: &Value) -> BTreeSet<(u64, String)> {
    let mut claimed = BTreeSet::new();
    for row in array(table, "rows", TABLE) {
        let id = row_id(row, TABLE);
        let context = format!("{TABLE} row {id}");
        for reason in array(row, "reasons", &context) {
            let error = text(reason, "error", &context);
            claimed.insert((id, error.to_owned()));
        }
    }
    claimed
}

/// The test names a reason entry cites.
fn cited_tests(reason: &Value, context: &str) -> Vec<String> {
    array(reason, "tests", context)
        .iter()
        .map(|test| {
            let name = test.as_str();
            name.unwrap_or_else(|| panic!("{context}: `tests` must hold test names"))
                .to_owned()
        })
        .collect()
}

#[test]
fn spec_section_four_renders_every_row_from_the_table() {
    let table = load_table();
    let rows = array(&table, "rows", TABLE);
    assert_eq!(
        rows.len(),
        EXPECTED_ROWS,
        "{TABLE} must describe the {EXPECTED_ROWS} rows of the SPEC §4 table"
    );

    let documented = spec_rows();
    assert_eq!(
        documented.len(),
        EXPECTED_ROWS,
        "SPEC §4 has {} numbered rows, the table has {EXPECTED_ROWS}",
        documented.len()
    );

    let mut ids = BTreeSet::new();
    for row in rows {
        let context = format!("{TABLE} row {}", row_id(row, TABLE));
        let id = row_id(row, TABLE);
        assert!(ids.insert(id), "{context}: duplicate row id {id}");
        let rendered = format!(
            "| {id} | {} | {} |",
            text(row, "condition", &context),
            text(row, "result", &context)
        );
        assert!(
            documented.iter().any(|line| line == &rendered),
            "{context} does not render to a SPEC §4 row.\n  table renders: {rendered}\n  \
             edit the row in {TABLE} first, then paste the rendered line into {SPEC} §4."
        );
    }
}

#[test]
fn row_reasons_are_real_variants_with_a_verdict() {
    let table = load_table();
    let variants = error_variants();

    for row in array(&table, "rows", TABLE) {
        let context = format!("{TABLE} row {}", row_id(row, TABLE));
        let condition = text(row, "condition", &context);
        assert!(!condition.is_empty(), "{context}: `condition` is empty");

        let verdict = text(row, "verdict", &context);
        assert!(
            verdict == "block" || verdict == "mixed",
            "{context}: `verdict` must be `block` or `mixed`, got `{verdict}`"
        );

        let reasons = array(row, "reasons", &context);
        assert!(
            !reasons.is_empty(),
            "{context}: every row of a deny-by-default table names a reason"
        );

        for reason in reasons {
            let error = text(reason, "error", &context);
            assert!(
                variants.contains(error),
                "{context}: `{error}` is not an `Error` variant in {TYPES}"
            );
            if cited_tests(reason, &context).is_empty() {
                let note = optional_text(reason, "note", &context).unwrap_or_default();
                assert!(
                    !note.is_empty(),
                    "{context}: `{error}` lists no test and has no `note` saying why"
                );
            }
        }
    }
}

#[test]
fn table_reasons_are_exactly_what_the_engine_can_block_with() {
    let table = load_table();
    let engine = engine_block_reasons();
    let claimed: BTreeSet<String> = table_reasons(&table)
        .into_iter()
        .map(|(_id, error)| error)
        .collect();

    let undocumented: Vec<&String> = engine.difference(&claimed).collect();
    let invented: Vec<&String> = claimed.difference(&engine).collect();
    assert!(
        undocumented.is_empty() && invented.is_empty(),
        "the decision table and the engine disagree about what a call can be blocked with.\n  \
         blocked by the engine but absent from {TABLE}: {undocumented:?}\n  listed in {TABLE} \
         but never returned by the engine: {invented:?}\n  update the row in {TABLE} in the \
         same commit that changes {ENGINE}."
    );
}

#[test]
fn every_reason_symbol_is_documented_in_the_reason_glossary() {
    let table = load_table();
    let glossary = read_repo_file(GLOSSARY);
    let symbols = reason_symbols();

    for (_id, error) in table_reasons(&table) {
        let symbol = symbols
            .iter()
            .find(|(variant, _)| variant == &error)
            .map_or_else(
                || panic!("{TYPES}: no `reason()` arm for `{error}`"),
                |(_variant, symbol)| symbol.as_str(),
            );
        assert!(
            glossary.contains(symbol),
            "{GLOSSARY} does not document `{symbol}` ({error}), so SDK and UI consumers have \
             no canonical message for it"
        );
    }
}

#[test]
fn every_row_is_pinned_by_a_named_engine_test() {
    let table = load_table();
    let known = engine_test_names();

    for row in array(&table, "rows", TABLE) {
        let context = format!("{TABLE} row {}", row_id(row, TABLE));
        for reason in array(row, "reasons", &context) {
            let error = text(reason, "error", &context);
            for name in cited_tests(reason, &context) {
                assert!(
                    known.contains(&name),
                    "{context}: `{error}` cites `{name}`, but {ENGINE} has no `#[test] fn \
                     {name}`. Point at a test that exists, or drop the entry and say why in \
                     `note`."
                );
            }
        }
    }
}

#[test]
fn readme_walkthrough_matches_the_table() {
    let table = load_table();
    let readme = read_repo_file(README);
    let diagram = readme_flow_diagram();

    for row in array(&table, "rows", TABLE) {
        let id = row_id(row, TABLE);
        let context = format!("{TABLE} row {id}");
        for term in array(row, "readme_terms", &context) {
            let term = term.as_str().unwrap_or_default();
            assert!(
                readme.contains(term),
                "{context}: the {README} walkthrough no longer mentions `{term}`, so the prose \
                 and the table disagree about row {id}"
            );
        }
        for kind in optional_array(row, "kinds") {
            let kind = kind.as_str().unwrap_or_default();
            assert!(
                diagram.contains(kind),
                "{context}: the {README} flow diagram no longer names the `{kind}` call kind, \
                 so a reader cannot see which branch row {id} covers"
            );
        }
    }
}

#[test]
fn readme_lists_the_account_gates_in_decision_order() {
    let table = load_table();
    let readme = read_repo_file(README);

    let anchor = text(&table, "readme_gate_order_anchor", TABLE);
    let position = readme.find(anchor);
    let anchor_position = position.unwrap_or_else(|| {
        panic!("{README} no longer contains `{anchor}`; the gate order cannot be checked")
    });

    let mut cursor = anchor_position;
    for gate in array(&table, "readme_gate_order", TABLE) {
        let gate = gate.as_str().unwrap_or_default();
        let found = readme[cursor..].find(gate);
        let offset = found.unwrap_or_else(|| {
            panic!("{README} does not list the `{gate}` gate in SPEC §4's order below `{anchor}`")
        });
        cursor += offset + gate.len();
    }
}

#[test]
fn classification_kinds_are_real_parsed_call_variants() {
    let table = load_table();
    let kinds = parsed_call_kinds();

    for row in array(&table, "rows", TABLE) {
        let context = format!("{TABLE} row {}", row_id(row, TABLE));
        for kind in optional_array(row, "kinds") {
            let kind = kind.as_str().unwrap_or_default();
            assert!(
                kinds.contains(kind),
                "{context}: `{kind}` is not a `ParsedCall` variant in {TYPES}"
            );
        }
    }
}
