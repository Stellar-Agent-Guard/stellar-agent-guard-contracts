#!/usr/bin/env bash
# scripts/check-fixture-vocab.sh
#
# Verifies that every reason symbol referenced by the enforcement-evidence
# fixtures exists in the contract vocabulary that applies to that fixture
# (issue #128).
#
# Current vocabulary: extracted from the `Error::reason()` match in
# src/types.rs, plus the non-error `allowed` outcome symbol.
#
# Historical fixtures: tests/fixtures/index.json declares `contract_version`.
# When it names a historical deployment instead of the current Cargo.toml
# package version, symbols are validated against that version's recorded
# vocabulary in tests/fixtures/reason-vocabulary.json. Historical symbols are
# never treated as current symbols, and historical evidence is never rewritten
# to match today's enum.
#
# Usage:
#   ./scripts/check-fixture-vocab.sh [--root DIR]
#
# Exit codes: 0 = every reference is valid, 1 = invalid reference or metadata,
# 2 = usage/setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --root)
            [[ $# -ge 2 ]] || { echo "ERROR: --root requires a directory" >&2; exit 2; }
            ROOT="$(cd "$2" && pwd)" || { echo "ERROR: cannot access root directory: $2" >&2; exit 2; }
            shift 2
            ;;
        -h|--help)
            sed -n '2,22p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "Usage: $0 [--root DIR]" >&2
            exit 2
            ;;
    esac
done

python3 - "$ROOT" <<'PY'
import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
types_path = root / "src/types.rs"
cargo_path = root / "Cargo.toml"
index_path = root / "tests/fixtures/index.json"
vocab_path = root / "tests/fixtures/reason-vocabulary.json"
readme_path = root / "tests/fixtures/README.md"

for required in (types_path, cargo_path, index_path):
    if not required.is_file():
        print(f"ERROR: required fixture-vocabulary input missing: {required}", file=sys.stderr)
        sys.exit(2)

types_source = types_path.read_text(encoding="utf-8")
reason_parts = types_source.split("fn reason", 1)
if len(reason_parts) != 2:
    print(f"ERROR: cannot find `fn reason` in {types_path}", file=sys.stderr)
    sys.exit(2)

current_symbols = set(
    re.findall(r'Self::[A-Za-z0-9_]+\s*=>\s*"([a-z0-9_]+)"', reason_parts[1])
)
if not current_symbols:
    print(f"ERROR: no reason symbols extracted from Error::reason() in {types_path}", file=sys.stderr)
    sys.exit(2)
# `allowed` is the event vocabulary's success symbol; it is not an Error variant.
current_symbols.add("allowed")

cargo_source = cargo_path.read_text(encoding="utf-8")
version_match = re.search(r'^version\s*=\s*"([^"]+)"', cargo_source, re.MULTILINE)
current_version = version_match.group(1) if version_match else None

try:
    index_text = index_path.read_text(encoding="utf-8")
    index = json.loads(index_text)
except (OSError, json.JSONDecodeError) as error:
    print(f"ERROR: cannot read {index_path}: {error}", file=sys.stderr)
    sys.exit(1)

raw_version = index.get("contract_version")
if not isinstance(raw_version, str) or not raw_version.strip():
    print(
        f"ERROR: {index_path}: `contract_version` is missing or empty; "
        "the fixture vocabulary cannot be scoped safely",
        file=sys.stderr,
    )
    sys.exit(1)
contract_version = raw_version.strip()

historical = contract_version != current_version
if historical:
    try:
        vocabulary = json.loads(vocab_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(
            f"ERROR: fixture contract_version '{contract_version}' is historical, but "
            f"{vocab_path} cannot be read: {error}",
            file=sys.stderr,
        )
        sys.exit(1)
    historical_versions = vocabulary.get("historical")
    if not isinstance(historical_versions, dict):
        print(f"ERROR: {vocab_path}: `historical` must be an object", file=sys.stderr)
        sys.exit(1)
    entry = historical_versions.get(contract_version)
    if not isinstance(entry, dict):
        print(
            f"ERROR: unknown fixture contract_version '{contract_version}'. "
            f"Add its recorded vocabulary to {vocab_path} or correct the metadata.",
            file=sys.stderr,
        )
        sys.exit(1)
    symbols = entry.get("symbols")
    if not isinstance(symbols, list) or not all(
        isinstance(symbol, str) and re.fullmatch(r"[a-z0-9_]+", symbol) for symbol in symbols
    ):
        print(
            f"ERROR: {vocab_path}: historical version '{contract_version}' needs a "
            "`symbols` array of lowercase reason symbols",
            file=sys.stderr,
        )
        sys.exit(1)
    vocabulary_symbols = set(symbols)
    mode = f"historical '{contract_version}' ({vocab_path})"
else:
    vocabulary_symbols = set(current_symbols)
    mode = f"current package version ({current_version})"

errors = []


def check_symbol(symbol, location, allow_current=False):
    # Structured index entries are evidence for one deployed contract_version,
    # so they use that version's vocabulary exactly. The human README also
    # documents planned scenarios against the current contract, so it may
    # reference either the historical vocabulary or today's symbols.
    accepted = vocabulary_symbols | (current_symbols if allow_current else set())
    if symbol in accepted:
        if historical and symbol not in current_symbols:
            print(
                f"note: {location}: '{symbol}' is valid for historical contract_version "
                f"'{contract_version}' but is not in the current vocabulary — preserved "
                "as historical evidence, not treated as current",
            )
        return
    errors.append(
        f"{location}: unknown reason symbol '{symbol}' for contract_version "
        f"'{contract_version}'"
    )


def symbols_from_topics(topics):
    if "event_auth_checked" not in topics:
        return []
    if "blocked" in topics:
        return [topic for topic in topics if topic not in ("event_auth_checked", "blocked")]
    if "allowed" in topics:
        return ["allowed"]
    return []


for line_number, line in enumerate(index_text.splitlines(), start=1):
    location = f"tests/fixtures/index.json:{line_number}"
    for symbol in re.findall(r'"expected_reason"\s*:\s*"([^"]*)"', line):
        check_symbol(symbol, location)
    for raw_topics in re.findall(r'"event_topics"\s*:\s*(\[[^\]]*\])', line):
        try:
            topics = json.loads(raw_topics)
        except json.JSONDecodeError:
            errors.append(f"{location}: malformed event_topics array: {raw_topics}")
            continue
        if not isinstance(topics, list) or not all(isinstance(topic, str) for topic in topics):
            errors.append(f"{location}: event_topics must be an array of strings")
            continue
        for symbol in symbols_from_topics(topics):
            check_symbol(symbol, location)

if readme_path.is_file():
    for line_number, line in enumerate(
        readme_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        location = f"tests/fixtures/README.md:{line_number}"
        for raw_topics in re.findall(r"\[([^\]]*event_auth_checked[^\]]*)\]", line):
            topics = [token.strip().strip("`") for token in raw_topics.split(",")]
            for symbol in symbols_from_topics(topics):
                if re.fullmatch(r"[a-z][a-z0-9_]*", symbol):
                    check_symbol(symbol, location, allow_current=True)
        # Reason lists in prose look like "block reason symbol (`a`, `b`)".
        # Restricted to parenthesised lists so table columns and file names
        # containing the words "reason symbol" are not mistaken for symbols.
        for match in re.finditer(r"reason symbols?\b", line, re.IGNORECASE):
            for group in re.findall(r"\(([^)]*)\)", line[match.end() :]):
                for symbol in re.findall(r"`([a-z][a-z0-9_]*)`", group):
                    check_symbol(symbol, location, allow_current=True)

print("Fixture reason vocabulary check")
print(f"  current vocabulary: {len(current_symbols)} symbols from src/types.rs (incl. allowed)")
print(f"  contract_version:   {contract_version}")
print(f"  validation mode:    {mode}")

if errors:
    print("", file=sys.stderr)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    print(
        f"\n{len(errors)} invalid reason reference(s). Current symbols: "
        + ", ".join(sorted(current_symbols)),
        file=sys.stderr,
    )
    print(
        "\nRemediation: keep the fixture reason vocabulary in sync with the contract. Add the "
        "missing symbol to src/types.rs (and its SPEC §4/§6 row, §7.1 mapping table, and "
        "docs/reason-glossary.md entry), record historical vocabulary in "
        "tests/fixtures/reason-vocabulary.json, or correct the references in "
        "tests/fixtures/index.json and tests/fixtures/README.md. See CONTRIBUTING.md rule 6 "
        "(testnet proof plan) and SPEC §11 before re-running.",
        file=sys.stderr,
    )
    sys.exit(1)

print("OK: every fixture reason symbol is valid for its contract_version.")
PY
