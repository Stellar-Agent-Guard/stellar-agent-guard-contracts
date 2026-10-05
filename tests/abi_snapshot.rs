//! Committed ABI snapshot: the public contract surface as a diffable file.
//!
//! The SDK, dashboard, and deployed integrations consume the Soroban ABI —
//! entrypoint signatures, `contracttype` shapes, and error codes — so a
//! renamed field, a renumbered error, or a removed function breaks consumers
//! in production unless CI catches it first. This test is that gate: it
//! re-derives the surface from `src/` on every run and compares it byte for
//! byte against `tests/snapshots/abi_snapshot.txt`.
//!
//! A cargo-level semver tool was deliberately not used: the consumed ABI is
//! the Soroban XDR surface, not the Rust crate API, so `cargo semver-checks`
//! cannot see it. The committed file plus
//! `git diff <last-release-tag> HEAD -- tests/snapshots/abi_snapshot.txt` is
//! the breaking-change review surface.
//!
//! To update after an intentional surface change:
//!   `UPDATE_SNAPSHOTS=1` cargo test --test `abi_snapshot`
//! and explain the breaking change (or why it is NOT breaking) in the PR
//! body. An unexplained snapshot diff blocks the PR.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use stellar_agent_guard_contracts::Error;

const SNAPSHOT_FILE: &str = "tests/snapshots/abi_snapshot.txt";
const LIB_SOURCE: &str = "src/lib.rs";
const TYPES_SOURCE: &str = "src/types.rs";
const WINDOW_SOURCE: &str = "src/window.rs";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_repo_file(rel: &str) -> String {
    let path = manifest_dir().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()))
}

fn snapshot_path() -> PathBuf {
    manifest_dir().join(SNAPSHOT_FILE)
}

/// Collapse every run of whitespace to a single space.
fn collapse_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `collapse_ws` plus cleanup of the stray spaces a joined multi-line
/// signature leaves around the outer parentheses and commas.
fn normalize_sig(text: &str) -> String {
    collapse_ws(text)
        .replace("( ", "(")
        .replace(" ,", ",")
        .replace(" )", ")")
        .replace(",)", ")")
}

/// Contract entrypoints from `src/lib.rs`: indented `pub fn` declarations
/// inside the contract implementation (top-level `fn` helpers sit at column 0)
/// plus the host-invoked `__check_auth`.
fn extract_functions(src: &str) -> Vec<String> {
    let lines: Vec<&str> = src.lines().collect();
    let mut fns = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let body = lines[i].trim_start();
        let is_indented = body.len() < lines[i].len();
        let is_entrypoint =
            is_indented && (body.starts_with("pub fn ") || body.starts_with("fn __check_auth("));
        if is_entrypoint {
            let mut sig = body.to_string();
            while !sig.contains('{') && i + 1 < lines.len() {
                i += 1;
                sig.push(' ');
                sig.push_str(lines[i].trim());
            }
            let sig = sig.trim_end_matches(['{', ' ']).trim_end().to_string();
            fns.push(normalize_sig(&sig));
        }
        i += 1;
    }
    fns
}

struct ContractType {
    kind: String,
    name: String,
    members: Vec<String>,
}

/// Every `#[contracttype]` item in `source`: structs render as their
/// `name: type` fields, enums as their variants (with payloads), both in
/// declaration order. Doc comments and attributes between members are
/// skipped; a member may span lines up to its terminating comma.
fn extract_contract_types(source: &str) -> Vec<ContractType> {
    let lines: Vec<&str> = source.lines().collect();
    let mut types = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() != "#[contracttype]" {
            i += 1;
            continue;
        }
        i += 1;
        while i < lines.len() {
            let head = lines[i].trim();
            if head.starts_with("#[")
                || head.starts_with("///")
                || head.starts_with("//")
                || head.is_empty()
            {
                i += 1;
                continue;
            }
            break;
        }
        if i >= lines.len() {
            break;
        }
        let head = lines[i].trim();
        let (kind, rest) = if let Some(rest) = head.strip_prefix("pub struct ") {
            ("struct", rest)
        } else if let Some(rest) = head.strip_prefix("pub enum ") {
            ("enum", rest)
        } else {
            i += 1;
            continue;
        };
        let name = collapse_ws(rest.trim_end_matches('{').trim());
        let mut members = Vec::new();
        let mut pending = String::new();
        i += 1;
        while i < lines.len() {
            let member = lines[i].trim();
            if member == "}" {
                break;
            }
            if !member.is_empty()
                && !member.starts_with("///")
                && !member.starts_with("//")
                && !member.starts_with("#[")
            {
                if !pending.is_empty() {
                    pending.push(' ');
                }
                pending.push_str(member);
                if member.ends_with(',') {
                    let mut finished = pending.trim_end_matches(',').trim_end().to_string();
                    if let Some(field) = finished.strip_prefix("pub ") {
                        finished = field.to_string();
                    }
                    members.push(collapse_ws(&finished));
                    pending.clear();
                }
            }
            i += 1;
        }
        types.push(ContractType {
            kind: kind.to_string(),
            name,
            members,
        });
        i += 1;
    }
    types
}

/// `(variant, discriminant)` pairs from the `Error` enum in `src/types.rs`.
fn extract_errors(src: &str) -> Vec<(String, u32)> {
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.trim() == "pub enum Error {")
        .unwrap_or_else(|| panic!("{TYPES_SOURCE}: `pub enum Error` not found"));
    let mut errors = Vec::new();
    for line in lines.iter().skip(start + 1) {
        let entry = line.trim();
        if entry == "}" {
            break;
        }
        if entry.is_empty() || entry.starts_with("//") {
            continue;
        }
        let (name, rest) = entry
            .split_once('=')
            .unwrap_or_else(|| panic!("{TYPES_SOURCE}: cannot parse error entry `{entry}`"));
        let code: u32 = rest
            .trim()
            .trim_end_matches(',')
            .parse()
            .unwrap_or_else(|_| panic!("{TYPES_SOURCE}: bad discriminant in `{entry}`"));
        errors.push((name.trim().to_string(), code));
    }
    errors
}

/// Map a snapshot error name to the real enum variant. A variant added to
/// `src/types.rs` without extending this match fails the snapshot test with
/// an explicit pointer here, so the new code+reason is reviewed, not
/// silently absorbed.
fn error_by_name(name: &str) -> Option<Error> {
    let err = match name {
        "Unauthorized" => Error::Unauthorized,
        "AlreadyInitialized" => Error::AlreadyInitialized,
        "NotInitialized" => Error::NotInitialized,
        "InvalidConfig" => Error::InvalidConfig,
        "InvalidAmount" => Error::InvalidAmount,
        "NoPendingAdmin" => Error::NoPendingAdmin,
        "AdminFrozen" => Error::AdminFrozen,
        "HeartbeatExpired" => Error::HeartbeatExpired,
        "NoPolicy" => Error::NoPolicy,
        "Paused" => Error::Paused,
        "OutsideActiveWindow" => Error::OutsideActiveWindow,
        "AssetNotAllowed" => Error::AssetNotAllowed,
        "RecipientNotAllowed" => Error::RecipientNotAllowed,
        "PerTxCapExceeded" => Error::PerTxCapExceeded,
        "WindowCapExceeded" => Error::WindowCapExceeded,
        "ProtocolNotAllowed" => Error::ProtocolNotAllowed,
        "FunctionNotAllowed" => Error::FunctionNotAllowed,
        "UnknownContract" => Error::UnknownContract,
        "SelfFunctionNotAllowed" => Error::SelfFunctionNotAllowed,
        "CreateContractNotAllowed" => Error::CreateContractNotAllowed,
        "RecipientBlocked" => Error::RecipientBlocked,
        "ProtocolCallRateExceeded" => Error::ProtocolCallRateExceeded,
        "DecisionInvariantViolation" => Error::DecisionInvariantViolation,
        _ => return None,
    };
    Some(err)
}

fn render_snapshot() -> String {
    let lib = read_repo_file(LIB_SOURCE);
    let types = read_repo_file(TYPES_SOURCE);
    let window = read_repo_file(WINDOW_SOURCE);

    let mut out = String::new();
    out.push_str(
        "# Stellar Agent Guard — public contract ABI snapshot.\n\
         #\n\
         # Committed baseline of the surface SDK, dashboard, and deployed\n\
         # integrations consume: every contract entrypoint with its signature,\n\
         # every #[contracttype] shape with its fields/variants, and every\n\
         # contract error with its numeric code and reason symbol. Any diff to\n\
         # this file is a potential breaking change for consumers.\n\
         #\n\
         # Scope:\n\
         # - Functions: all `pub fn` entrypoints of `PolicyEngine` plus the\n\
         #   host-invoked `__check_auth` (CustomAccountInterface), from src/lib.rs.\n\
         # - Types: every `#[contracttype]` item in src/types.rs (policy, ledger,\n\
         #   status, and advisory shapes) plus `RecipientLedger` in src/window.rs\n\
         #   (a #[contracttype] in a private module, listed for completeness\n\
         #   because it still shapes the XDR surface).\n\
         # - Errors: every `Error` variant in src/types.rs with its discriminant\n\
         #   (the on-chain `Error(Contract, #N)`) and its `reason()` symbol (the\n\
         #   `auth_checked` topic and `check`/`check_detailed` block reason).\n\
         #   Events are pinned separately by src/event_audit_tests.rs.\n\
         #\n\
         # Breaking-change gate: CI runs `cargo test` on every push/PR, and this\n\
         # test fails on any drift. Review it with\n\
         #   git diff <last-release-tag> HEAD -- tests/snapshots/abi_snapshot.txt\n\
         #\n\
         # To update after an intentional surface change:\n\
         #   UPDATE_SNAPSHOTS=1 cargo test --test abi_snapshot\n\
         # and explain the breaking change (or why it is NOT breaking) in the PR\n\
         # body. An unexplained snapshot diff blocks the PR.\n\
         #\n\
         # GENERATED — do not edit by hand; regenerate with the command above.\n",
    );

    out.push_str("\n## Functions\n");
    for sig in extract_functions(&lib) {
        out.push_str(&sig);
        out.push('\n');
    }

    out.push_str("\n## Contract types\n");
    let mut contract_types = extract_contract_types(&types);
    contract_types.extend(extract_contract_types(&window));
    for item in &contract_types {
        out.push_str(&item.kind);
        out.push(' ');
        out.push_str(&item.name);
        out.push('\n');
        for member in &item.members {
            let _ = writeln!(out, "  {member}");
        }
    }

    out.push_str("\n## Errors\n");
    for (name, code) in extract_errors(&types) {
        let err = error_by_name(&name).unwrap_or_else(|| {
            panic!("{TYPES_SOURCE} lists error `{name}` missing from `error_by_name`; extend the match")
        });
        assert_eq!(
            err as u32, code,
            "{TYPES_SOURCE}: `{name}` discriminant drifted (source says {code})"
        );
        let reason = err.reason();
        let _ = writeln!(out, "{code} {name} {reason}");
    }
    out
}

#[test]
fn abi_snapshot_matches_committed_baseline() {
    let actual = render_snapshot();
    let path = snapshot_path();
    if std::env::var("UPDATE_SNAPSHOTS").is_ok() {
        fs::write(&path, &actual)
            .unwrap_or_else(|err| panic!("cannot write {}: {err}", path.display()));
        return;
    }
    let committed = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("cannot read {}: {err}", path.display()));
    assert_eq!(
        actual, committed,
        "public contract ABI drifted from {SNAPSHOT_FILE}.\n\
         If the surface change is intentional, regenerate with\n\
         `UPDATE_SNAPSHOTS=1 cargo test --test abi_snapshot`\n\
         and explain the breaking change (or why it is NOT breaking) in the PR body."
    );
}
