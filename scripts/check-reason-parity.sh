#!/usr/bin/env bash
# scripts/check-reason-parity.sh
#
# Reason-symbol parity gate (issue #41): the contract's auth_checked events
# carry `reason` symbols from Error::reason() (src/types.rs); the SDK ships a
# human-readable explainReason map keyed by the same symbols. Nothing else in
# CI fails when one side adds/renames a reason without the other — this script
# is that gate.
#
# Compares:
#   1. Error::reason() strings parsed from src/types.rs      (the source of truth)
#   2. The committed SDK vocabulary file, tests/fixtures/sdk-reasons.json
#      (the SDK repo asserts ITS copy against this same file — companion SDK issue)
#   3. `expected_reason` values recorded in tests/fixtures/index.json
#      (fixture evidence must use the same vocabulary, issue #41 acceptance)
#
# Fails on: missing / extra / renamed reasons, with a human-readable diff.
# A Rust-side wrapper (tests/reason_parity.rs) enforces the contract↔vocabulary
# half inside `cargo test` too, so drift fails even where only cargo runs.
#
# Usage: ./scripts/check-reason-parity.sh
# Exit codes: 0 = parity, 1 = violations found (diff printed), 2 = usage/internal error.

set -euo pipefail

TYPES_FILE="${1:-src/types.rs}"
VOCAB_FILE="${2:-tests/fixtures/sdk-reasons.json}"
INDEX_FILE="${3:-tests/fixtures/index.json}"

if [[ ! -f "$TYPES_FILE" ]]; then
    echo "ERROR: types file not found: $TYPES_FILE" >&2
    exit 2
fi
if [[ ! -f "$VOCAB_FILE" ]]; then
    echo "ERROR: SDK vocabulary file not found: $VOCAB_FILE" >&2
    exit 2
fi

# ── 1. Contract side: Error::reason() match arms in src/types.rs ────────
# Each arm looks like `Self::Xxx => "snake_case_symbol",` inside the
# `impl Error` `reason()` match. Parsing the source (not a second fixture)
# means a new enum variant + reason arm cannot land without this check seeing it.
contract_reasons=$(grep -oE 'Self::[A-Za-z0-9]+ => "[a-z0-9_]+"' "$TYPES_FILE" \
    | sed -E 's/Self::[A-Za-z0-9]+ => "([a-z0-9_]+)"/\1/' | sort -u)

if [[ -z "$contract_reasons" ]]; then
    echo "ERROR: no Error::reason() strings parsed from $TYPES_FILE" >&2
    echo "       (expected match arms shaped like: Self::Variant => \"reason_symbol\")" >&2
    exit 2
fi

# ── 2. SDK side: keys of the committed vocabulary file ──────────────────
# Extract only the "reasons" object (awk range from its opening brace to the
# 2-space-indented closing brace), then pull its keys — other objects in the
# file (e.g. "source") use the same indentation and must not count.
sdk_reasons=$(awk '/"reasons": \{/,/^  \}/' "$VOCAB_FILE" \
    | grep -oE '^\s{4}"[a-z0-9_]+":' \
    | sed -E 's/^\s*"([a-z0-9_]+)":/\1/' | sort -u)

if [[ -z "$sdk_reasons" ]]; then
    echo "ERROR: no reason keys parsed from $VOCAB_FILE" >&2
    echo "       (expected the \"reasons\" object: one \"<symbol>\": \"<explanation>\" line per reason)" >&2
    exit 2
fi

# ── 3. Fixture evidence side: expected_reason values in index.json ──────
# The fixtures record `expected_reason: "allowed"` for admitted scenarios
# (documented verdict vocabulary, tests/fixtures/README.md schema table) —
# that is not an Error reason and is whitelisted here; every BLOCKED value
# must still be a real contract reason.
fixture_reasons=""
if [[ -f "$INDEX_FILE" ]]; then
    fixture_reasons=$(grep -oE '"expected_reason":\s*"[a-z0-9_]+"' "$INDEX_FILE" \
        | sed -E 's/"expected_reason":\s*"([a-z0-9_]+)"/\1/' \
        | grep -vx allowed | sort -u)
fi

# ── Diff with human-readable output ─────────────────────────────────────
# comm needs sorted input; both lists are sorted -u already.
missing_in_sdk=$(comm -23 <(echo "$contract_reasons") <(echo "$sdk_reasons"))
extra_in_sdk=$(comm -13 <(echo "$contract_reasons") <(echo "$sdk_reasons"))
unknown_in_fixtures=""
if [[ -f "$INDEX_FILE" && -n "$fixture_reasons" ]]; then
    unknown_in_fixtures=$(comm -23 <(echo "$fixture_reasons") <(echo "$contract_reasons"))
fi

errors=0

echo "Contract reasons (src/types.rs :: Error::reason): $(echo "$contract_reasons" | wc -l)"
echo "SDK vocabulary entries ($VOCAB_FILE):            $(echo "$sdk_reasons" | wc -l)"
if [[ -f "$INDEX_FILE" && -n "$fixture_reasons" ]]; then
    echo "Fixture expected_reason values ($INDEX_FILE):  $(echo "$fixture_reasons" | wc -l)"
fi
echo ""

if [[ -n "$missing_in_sdk" || -n "$extra_in_sdk" ]]; then
    errors=$((errors + 1))
    echo "✗ Parity FAILURE: contract reasons vs SDK vocabulary ($VOCAB_FILE)"
    echo ""
    echo "  --- Contract reasons missing from the SDK vocabulary (SDK must add an entry) ---"
    if [[ -n "$missing_in_sdk" ]]; then
        echo "$missing_in_sdk" | sed 's/^/    - /'
    else
        echo "    (none)"
    fi
    echo ""
    echo "  --- SDK vocabulary entries that no contract reason produces (stale/renamed?) ---"
    if [[ -n "$extra_in_sdk" ]]; then
        echo "$extra_in_sdk" | sed 's/^/    - /'
    else
        echo "    (none)"
    fi
    echo ""
    echo "  Fix: add/remove/rename on BOTH sides in the same PR:"
    echo "    - contract: src/types.rs :: Error::reason()  (and the Error variant itself)"
    echo "    - SDK copy: $VOCAB_FILE (the SDK repo asserts its own copy against this file)"
    echo "    - docs: docs/reason-glossary.md + docs/research/wire-format.md reason tables"
    echo ""
fi

if [[ -n "${unknown_in_fixtures}" ]]; then
    errors=$((errors + 1))
    echo "✗ Fixture vocabulary FAILURE: $INDEX_FILE records expected_reason values the contract never emits:"
    echo "$unknown_in_fixtures" | sed 's/^/    - /'
    echo ""
fi

if [[ "$errors" -eq 0 ]]; then
    echo "✓ Reason parity OK: contract, SDK vocabulary, and fixture evidence agree"
    echo "  ($(( $(echo "$contract_reasons" | wc -l) )) reasons: $(echo "$contract_reasons" | tr '\n' ' '))"
    exit 0
fi

exit 1
