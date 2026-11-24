//! Exercises `scripts/check-fixture-vocab.sh` against synthetic fixture trees:
//! valid current symbols, unknown current symbols, historical symbols, missing
//! or invalid version metadata, and exact fixture-line reporting.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SCRIPT: &str = "scripts/check-fixture-vocab.sh";

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct FixtureTree {
    root: PathBuf,
}

impl FixtureTree {
    fn new(name: &str) -> Self {
        let counter = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "guard-fixture-vocab-{name}-{}-{counter}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).expect("create synthetic src dir");
        fs::create_dir_all(root.join("tests/fixtures")).expect("create synthetic fixtures dir");
        let tree = Self { root };
        tree.write(
            "Cargo.toml",
            "[package]\nname = \"synthetic\"\nversion = \"0.2.0\"\n",
        );
        tree.write(
            "src/types.rs",
            "pub enum Error { Variant = 1 }\n\
             impl Error {\n\
             \x20   pub fn reason(self) -> &'static str {\n\
             \x20       match self {\n\
             \x20           Self::Variant => \"variant_reason\",\n\
             \x20       }\n\
             \x20   }\n\
             }\n",
        );
        tree.write(
            "tests/fixtures/reason-vocabulary.json",
            r#"{
  "schema_version": 1,
  "historical": {
    "legacy-net": {
      "symbols": ["allowed", "legacy_reason"]
    }
  }
}"#,
        );
        tree.write(
            "tests/fixtures/README.md",
            "# Synthetic evidence\n\nNo reason references here.\n",
        );
        tree.write(
            "tests/fixtures/index.json",
            r#"{
  "schema_version": 1,
  "contract_version": "0.2.0",
  "scenarios": [
    {
      "expected_reason": "variant_reason",
      "event_topics": ["event_auth_checked", "blocked", "variant_reason"]
    }
  ]
}"#,
        );
        tree
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        fs::write(path, contents).expect("write synthetic fixture");
    }

    fn run(&self) -> std::process::Output {
        Command::new("bash")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(SCRIPT)
                    .as_os_str(),
            )
            .arg("--root")
            .arg(&self.root)
            .output()
            .expect("run fixture vocabulary script")
    }
}

impl Drop for FixtureTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn valid_current_symbols_pass() {
    let tree = FixtureTree::new("valid-current");
    let output = tree.run();
    assert!(
        output.status.success(),
        "expected pass, stderr: {}",
        stderr(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("contract_version:   0.2.0"));
    assert!(stdout.contains("current package version"));
}

#[test]
fn unknown_current_symbol_fails_with_exact_line() {
    let tree = FixtureTree::new("unknown-current");
    let index = "{\n  \"schema_version\": 1,\n  \"contract_version\": \"0.2.0\",\n  \"scenarios\": [\n    {\"expected_reason\": \"retired_reason\"}\n  ]\n}\n";
    tree.write("tests/fixtures/index.json", index);
    let output = tree.run();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("tests/fixtures/index.json:5"),
        "missing exact line location: {stderr}"
    );
    assert!(
        stderr.contains("retired_reason"),
        "missing symbol: {stderr}"
    );
}

#[test]
fn historical_symbols_validate_against_recorded_version_and_are_not_current() {
    let tree = FixtureTree::new("historical");
    tree.write(
        "tests/fixtures/index.json",
        r#"{
  "schema_version": 1,
  "contract_version": "legacy-net",
  "scenarios": [
    {
      "expected_reason": "legacy_reason",
      "event_topics": ["event_auth_checked", "blocked", "legacy_reason"]
    }
  ]
}"#,
    );
    let output = tree.run();
    assert!(
        output.status.success(),
        "historical vocabulary should pass, stderr: {}",
        stderr(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("historical 'legacy-net'"));
    assert!(stdout.contains("not in the current vocabulary"));
}

#[test]
fn missing_contract_version_fails() {
    let tree = FixtureTree::new("missing-version");
    tree.write(
        "tests/fixtures/index.json",
        "{\n  \"schema_version\": 1,\n  \"scenarios\": []\n}\n",
    );
    let output = tree.run();
    assert!(!output.status.success());
    assert!(stderr(&output).contains("contract_version"));
}

#[test]
fn unknown_contract_version_fails() {
    let tree = FixtureTree::new("unknown-version");
    tree.write(
        "tests/fixtures/index.json",
        "{\n  \"schema_version\": 1,\n  \"contract_version\": \"not-recorded\",\n  \"scenarios\": []\n}\n",
    );
    let output = tree.run();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("unknown fixture contract_version 'not-recorded'"));
    assert!(stderr.contains("reason-vocabulary.json"));
}

#[test]
fn readme_unknown_symbol_reports_exact_line() {
    let tree = FixtureTree::new("readme-line");
    tree.write(
        "tests/fixtures/README.md",
        "line one\nline two\nline three\nline four\n\nGuard event: [event_auth_checked, blocked, invented_reason]\n",
    );
    let output = tree.run();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(
        stderr.contains("tests/fixtures/README.md:6"),
        "missing exact README line: {stderr}"
    );
    assert!(stderr.contains("invented_reason"));
}
