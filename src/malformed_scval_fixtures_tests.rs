//! Drift ratchet for the minimized malformed-`ScVal` fixtures (issue #603).
//!
//! `tests/fixtures/malformed-scval/manifest.json` names three malformed policy
//! shapes, each with a byte-identical copy in the committed fuzz corpus. This
//! test proves the production decoder rejects each one with the stable
//! `InvalidConfig` error (never a panic), that the result is stable across
//! repeated runs, and that the fixture sizes recorded in the manifest still
//! describe the minimized inputs. If a guard change makes one of these panics
//! or a different error, or the fixture grows, this fails and the manifest,
//! corpus entry, and reproduction notes must be updated together.

use super::testutils::validate_policy_config_scval;
use super::{Error, PolicyEngine};
use soroban_sdk::xdr::{Limits, ReadXdr, ScVal};
use soroban_sdk::Env;
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST_FILE: &str = "manifest.json";
const MIN_FIXTURES: usize = 3;
const MAX_XDR_DEPTH: u32 = 64;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("malformed-scval")
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz")
        .join("corpus")
        .join("policy_config_deserialization")
}

fn required_str<'a>(value: &'a serde_json::Value, key: &str, context: &str) -> &'a str {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{context}: missing string field `{key}`"))
}

fn decode(bytes: &[u8], path: &Path) -> ScVal {
    let limits = Limits {
        depth: MAX_XDR_DEPTH,
        len: bytes.len(),
    };
    ScVal::from_xdr(bytes, limits).unwrap_or_else(|error| {
        panic!(
            "{} must stay valid XDR: the shape guard, not the reader, is what rejects it ({error:?})",
            path.display()
        )
    })
}

#[test]
fn minimized_malformed_scval_fixtures_fail_stably_with_invalid_config() {
    let dir = fixtures_dir();
    let manifest_path = dir.join(MANIFEST_FILE);
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display())),
    )
    .unwrap_or_else(|error| panic!("parse {}: {error}", manifest_path.display()));

    let fixtures = manifest
        .get("fixtures")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("{MANIFEST_FILE}: `fixtures` must be an array"));
    assert!(
        fixtures.len() >= MIN_FIXTURES,
        "issue #603 requires at least {MIN_FIXTURES} minimized malformed shapes"
    );

    let env = Env::default();
    let contract_id = env.register(PolicyEngine, ());

    for (index, fixture) in fixtures.iter().enumerate() {
        let context = std::format!("fixture {index}");
        let name = required_str(fixture, "file", &context);
        let corpus_entry = required_str(fixture, "corpus_entry", &context);
        let expected_error = required_str(fixture, "expected_error", &context);
        let expected_bytes = usize::try_from(
            fixture
                .get("bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_else(|| panic!("{context}: missing integer field `bytes`")),
        )
        .expect("fixture byte length fits in usize");

        let path = dir.join(name);
        let bytes =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            bytes.len(),
            expected_bytes,
            "{} changed size; if this is a new minimized artifact, update the manifest and the reproduction notes",
            path.display()
        );

        let corpus_path = corpus_dir().join(corpus_entry);
        let corpus_bytes = fs::read(&corpus_path)
            .unwrap_or_else(|error| panic!("read {}: {error}", corpus_path.display()));
        assert_eq!(
            bytes,
            corpus_bytes,
            "{} must stay byte-identical to its fuzz corpus entry {}",
            path.display(),
            corpus_path.display()
        );

        assert_eq!(
            expected_error, "InvalidConfig",
            "{context}: this test only locks the stable InvalidConfig rejection"
        );

        let scval = decode(&bytes, &path);
        assert!(
            matches!(scval, ScVal::Map(Some(_))),
            "{context}: malformed policy fixtures are map-shaped ScVals"
        );

        let first = env.as_contract(&contract_id, || validate_policy_config_scval(&env, &scval));
        let second = env.as_contract(&contract_id, || validate_policy_config_scval(&env, &scval));
        assert_eq!(
            first,
            Err(Error::InvalidConfig),
            "{context}: {name} must reject with the stable InvalidConfig error"
        );
        assert_eq!(
            first, second,
            "{context}: {name} must reject identically on repeated evaluation"
        );
    }
}
