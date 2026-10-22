#!/usr/bin/env bash
# scripts/check-spec-coverage.sh
#
# Deny-list CI check: every Error variant must appear in SPEC §4/§6 tables at least once
# and exactly once in §7 enum (glossary).
# Fails on: variant absent from §4/§6; variant absent from §7 enum; duplicate in §7 enum.
# Runtime: <1s (grep-level, no codegen).
#
# Usage: ./scripts/check-spec-coverage.sh
# Exit codes: 0 = all good, 1 = violations found, 2 = usage/internal error.

set -euo pipefail

SPEC_FILE="${1:-SPEC.md}"
TYPES_FILE="${2:-src/types.rs}"

if [[ ! -f "$SPEC_FILE" ]]; then
    echo "ERROR: SPEC file not found: $SPEC_FILE" >&2
    exit 2
fi

if [[ ! -f "$TYPES_FILE" ]]; then
    echo "ERROR: Types file not found: $TYPES_FILE" >&2
    exit 2
fi

# Extract Error variant names from src/types.rs (the enum definition)
variants=$(grep -E '^\s+[A-Z][a-zA-Z0-9]+\s*=' "$TYPES_FILE" | sed -E 's/^\s+([A-Z][a-zA-Z0-9]+)\s*=.*/\1/' | sort -u)

if [[ -z "$variants" ]]; then
    echo "ERROR: No Error variants found in $TYPES_FILE" >&2
    exit 2
fi

echo "Found Error variants:"
echo "$variants" | sed 's/^/  /'

# Extract the relevant SPEC sections using awk
# §4 includes both the decision table and gate cost table
spec_section_4=$(awk '/^## 4\./ {p=1} /^## [56]\./ {p=0} p' "$SPEC_FILE")
spec_section_6=$(awk '/^## 6\./ {p=1} /^## 7\./ {p=0} p' "$SPEC_FILE")
spec_section_7_enum=$(awk '/pub enum Error/ {p=1} /^}/ {if(p) {print; p=0; exit}} p' "$SPEC_FILE")

# Pre-compute all variant mentions in §4 (both Reason:: and bare in tables)
# We just need to know IF a variant appears in §4, not count duplicates across tables
section_4_variants=$(echo "$spec_section_4" | grep -oE 'Reason::[A-Z][a-zA-Z0-9]+\b|`[A-Z][a-zA-Z0-9]+`' | sed -E 's/Reason:://; s/`//g' | sort -u)

# §6: bare variant names in per-context rules
section_6_variants=$(echo "$spec_section_6" | grep -oE '`[A-Z][a-zA-Z0-9]+`|\b[A-Z][a-zA-Z0-9]+\b' | sed 's/`//g' | sort -u)

# §7 enum: VariantName = number (the glossary)
section_7_variants=$(echo "$spec_section_7_enum" | grep -oE '\b[A-Z][a-zA-Z0-9]+\s*=' | sed 's/\s*=//' | sort | uniq -c)

echo ""
echo "Checking SPEC.md sections for each variant..."

errors=0

for variant in $variants; do
    # Check if variant appears in §4 or §6 (at least once across both)
    in_section_4=0
    if echo "$section_4_variants" | grep -qx "$variant"; then
        in_section_4=1
    fi

    in_section_6=0
    if echo "$section_6_variants" | grep -qx "$variant"; then
        in_section_6=1
    fi

    if [[ $in_section_4 -eq 0 && $in_section_6 -eq 0 ]]; then
        echo "  FAIL: $variant — NOT FOUND in §4 or §6 (orphan variant, no semantic documentation)"
        errors=$((errors + 1))
    else
        echo "  OK:   $variant — found in semantic docs (§4: $in_section_4, §6: $in_section_6)"
    fi

    # Check §7 enum: must appear exactly once
    count_7=$(echo "$section_7_variants" | grep -E "^\s*[0-9]+\s+${variant}$" | awk '{print $1}' || true)
    count_7=${count_7:-0}

    if [[ "$count_7" -eq 0 ]]; then
        echo "  FAIL: $variant — NOT FOUND in §7 enum listing (missing from public surface glossary)"
        errors=$((errors + 1))
    elif [[ "$count_7" -gt 1 ]]; then
        echo "  FAIL: $variant — FOUND $count_7 TIMES in §7 enum (duplicate in glossary)"
        errors=$((errors + 1))
    else
        echo "  OK:   $variant — found exactly once in §7 enum glossary"
    fi
done

echo ""
if [[ $errors -eq 0 ]]; then
    echo "All Error variants covered in SPEC.md §4/§6 and exactly once in §7 enum ✓"
    exit 0
else
    echo "FAIL: $errors variant(s) have coverage issues"
    exit 1
fi