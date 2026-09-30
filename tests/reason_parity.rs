//! Reason-symbol parity between the contract and the committed SDK vocabulary
//! (issue #41).
//!
//! The contract's `auth_checked` events (and `check`/`check_detailed`
//! results) carry `reason` symbols from `Error::reason()` (src/types.rs). The
//! SDK ships a human-readable `explainReason` map keyed by the same symbols —
//! but nothing failed CI when a new contract reason landed without an SDK
//! entry (the CreateContract-reason gap). This test is the contract-side
//! parity gate:
//!
//! 1. **Source of truth** — the `Self::Variant => "symbol"` arms parsed from
//!    `src/types.rs`. Parsing the source (not a second fixture) means a new
//!    `Error` variant cannot land without this test seeing it.
//! 2. **SDK vocabulary** — the keys of the committed
//!    `tests/fixtures/sdk-reasons.json` copy of the SDK's `explainReason` map.
//!    The SDK repository asserts *its own* copy against this same file
//!    (companion SDK issue), so a diff here is a diff on both sides.
//! 3. **Fixture evidence** — the blocked `expected_reason` values recorded in
//!    `tests/fixtures/index.json` must use the same vocabulary (the fixtures
//!    also record the documented verdict `"allowed"`, which is not an `Error`
//!    reason and is skipped here).
//!
//! 4. **Runtime cross-check** — every parsed symbol must round-trip through
//!    `Error::from_block_reason`, proving the source parse matches the
//!    compiled enum (guards against a stale or duplicated arm).
//!
//! `scripts/check-reason-parity.sh` re-checks the same parity standalone in
//! CI (after tests) with a human-readable diff; this test keeps the gate
//! green under plain `cargo test` too.
//!
//! Fails with an itemized diff on: missing / extra / renamed reasons.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use serde_json::Value;
use stellar_agent_guard_contracts::Error;

const TYPES_FILE: &str = "src/types.rs";
const VOCAB_FILE: &str = "tests/fixtures/sdk-reasons.json";
const INDEX_FILE: &str = "tests/fixtures/index.json";

/// Documented fixture verdict for admitted scenarios (tests/fixtures/README.md
/// schema table). Not an `Error` reason; excluded from the blocked-reason set.
const ALLOWED_VERDICT: &str = "allowed";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(rel: &str) -> String {
    let path = manifest_dir().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

/// The `Self::Variant => "symbol"` match arms of `Error::reason()`, as
/// `(variant, symbol)` pairs in declaration order. Duplicates fail loudly.
fn parse_reason_arms() -> std::vec::Vec<(String, String)> {
    let source = read_repo_file(TYPES_FILE);
    let mut arms = std::vec::Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for line in source.lines() {
        let trimmed = line.trim();
        // Match: Self::Variant => "symbol",
        if let Some(rest) = trimmed.strip_prefix("Self::") {
            if let Some((variant, tail)) = rest.split_once(" => ") {
                let symbol = tail.trim().trim_end_matches(',');
                if let Some(symbol) = symbol.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    assert!(
                        seen.insert(variant.to_string()),
                        "duplicate reason arm in {TYPES_FILE}: Self::{variant}"
                    );
                    arms.push((variant.to_string(), symbol.to_string()));
                }
            }
        }
    }

    assert!(
        !arms.is_empty(),
        "no `Self::Variant => \"symbol\"` arms parsed from {TYPES_FILE} — \
         the parser must track Error::reason() match arms"
    );
    arms
}

/// The reason keys of the committed SDK vocabulary file (`reasons` object).
fn parse_sdk_vocabulary() -> BTreeSet<String> {
    let vocab: Value = serde_json::from_str(&read_repo_file(VOCAB_FILE))
        .unwrap_or_else(|err| panic!("{VOCAB_FILE} is not valid JSON: {err}"));
    let reasons = vocab
        .get("reasons")
        .unwrap_or_else(|| panic!("{VOCAB_FILE} must carry a \"reasons\" object"));
    let map = reasons
        .as_object()
        .unwrap_or_else(|| panic!("{VOCAB_FILE} \"reasons\" must be a JSON object"));
    assert!(
        !map.is_empty(),
        "{VOCAB_FILE} \"reasons\" must not be empty"
    );
    map.keys().cloned().collect()
}

/// The blocked `expected_reason` values recorded in the fixture index.
fn parse_fixture_blocked_reasons() -> BTreeSet<String> {
    let index: Value = serde_json::from_str(&read_repo_file(INDEX_FILE))
        .unwrap_or_else(|err| panic!("{INDEX_FILE} is not valid JSON: {err}"));
    let mut out = BTreeSet::new();
    let mut walk = |value: &Value| {
        if let Some(reason) = value.get("expected_reason").and_then(Value::as_str) {
            if reason != ALLOWED_VERDICT {
                out.insert(reason.to_string());
            }
        }
    };
    let Some(scenarios) = index.get("scenarios").and_then(Value::as_array) else {
        panic!("{INDEX_FILE} must carry a \"scenarios\" array");
    };
    for scenario in scenarios {
        walk(scenario);
        // Scenario 5 records a post-reversal transfer with its own verdict.
        if let Some(post) = scenario.get("post_reversal") {
            walk(post);
        }
    }
    out
}

/// Render a `BTreeSet` diff as one bullet per offending symbol.
fn diff_bullets(label: &str, items: &BTreeSet<String>) -> String {
    if items.is_empty() {
        return format!("  no {label}\n");
    }
    let bullets: std::vec::Vec<String> = items.iter().map(|item| format!("    - {item}")).collect();
    format!("  {label}:\n{}\n", bullets.join("\n"))
}

#[test]
fn contract_reasons_match_the_committed_sdk_vocabulary() {
    let arms = parse_reason_arms();
    let contract: BTreeSet<String> = arms.iter().map(|(_, s)| s.clone()).collect();
    let sdk = parse_sdk_vocabulary();

    let missing_in_sdk: BTreeSet<String> = contract.difference(&sdk).cloned().collect();
    let stale_in_sdk: BTreeSet<String> = sdk.difference(&contract).cloned().collect();

    assert!(
        missing_in_sdk.is_empty() && stale_in_sdk.is_empty(),
        "reason-symbol parity FAILURE between the contract and the committed SDK \
         vocabulary ({VOCAB_FILE}) — add/remove/rename on BOTH sides in the same PR:\n\
         contract side: src/types.rs :: Error::reason() (and the Error variant)\n\
         sdk side:      {VOCAB_FILE} (the SDK repo asserts its own copy against this file)\n\
         docs:          docs/reason-glossary.md + docs/research/wire-format.md\n{}{}",
        diff_bullets(
            "contract reasons missing from the SDK vocabulary (SDK must add an entry)",
            &missing_in_sdk
        ),
        diff_bullets(
            "SDK vocabulary entries no contract reason produces (stale or renamed?)",
            &stale_in_sdk
        ),
    );
}

#[test]
fn fixture_blocked_reasons_use_the_contract_vocabulary() {
    let arms = parse_reason_arms();
    let contract: BTreeSet<String> = arms.iter().map(|(_, s)| s.clone()).collect();
    let fixtures = parse_fixture_blocked_reasons();

    let unknown: BTreeSet<String> = fixtures.difference(&contract).cloned().collect();
    assert!(
        unknown.is_empty(),
        "fixture evidence ({INDEX_FILE}) records expected_reason values the contract \
         never emits — update the fixtures to the real reason symbols:\n{}",
        diff_bullets("unknown blocked reasons", &unknown),
    );
}

#[test]
fn every_parsed_reason_round_trips_through_the_compiled_error_enum() {
    let arms = parse_reason_arms();

    // No two variants may share a reason symbol — a rename that collides
    // would make off-chain reason mapping ambiguous.
    let mut seen = BTreeSet::new();
    for (variant, symbol) in &arms {
        assert!(
            seen.insert(symbol.clone()),
            "reason symbol {symbol:?} is produced by more than one Error variant \
             (seen at Self::{variant}) — off-chain reason mapping must stay unambiguous"
        );
    }

    // And every symbol must map back to exactly the variant that declares it:
    // proves the source parse and the compiled enum agree (a stale arm, a
    // typo, or a reason moved to another variant fails here).
    for (variant, symbol) in &arms {
        let env = soroban_sdk::Env::default();
        let parsed = Error::from_block_reason(&soroban_sdk::Symbol::new(&env, symbol))
            .unwrap_or_else(|| {
                panic!("reason symbol {symbol:?} does not round-trip to any Error variant")
            });
        // `Error` derives Debug; `{:?}` of a unit variant is exactly its name.
        let variant_name = format!("{parsed:?}");
        assert_eq!(
            &variant_name, variant,
            "reason symbol {symbol:?} round-trips to {variant_name:?}, but its \
             {TYPES_FILE} arm says Self::{variant} — the parse and the compiled \
             enum disagree"
        );
    }
}
