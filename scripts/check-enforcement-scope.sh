#!/usr/bin/env bash
# Issue #331: the enforcement-scope statement is the single most safety-critical
# paragraph in this repository — it is what stops a reader from believing the
# caps cover protocol calls. It is deliberately duplicated for its three
# audiences, so this gate makes the duplication mechanical instead of trusting
# review memory.
#
# Single source of truth: the bold paragraph in SPEC §2 under
# "## 2. Enforcement scope". This script extracts that paragraph, normalises
# whitespace (line wrapping is not content), strips Markdown emphasis, and
# requires README.md and docs/enforcement-scope.md to contain the same text
# word for word. Each copy must also keep its link back to SPEC §2.
#
# How to update the statement without fighting the check:
#   1. Edit the paragraph in SPEC §2 only.
#   2. Paste the same paragraph into README.md's "Enforcement scope" section and
#      docs/enforcement-scope.md's "The confirmed scope" section.
#   3. Run this script; it names the file that drifted if you missed one.
#   4. Keep each copy's "full statement: SPEC §2" link.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SPEC_FILE="${ROOT_DIR}/SPEC.md"
readonly README_FILE="${ROOT_DIR}/README.md"
readonly SCOPE_FILE="${ROOT_DIR}/docs/enforcement-scope.md"

pass=0
fail=0

check_pass() {
  printf '[PASS] %s\n' "$1"
  pass=$((pass + 1))
}

check_fail() {
  printf '[FAIL] %s\n' "$1" >&2
  fail=$((fail + 1))
}

# Whitespace is layout, not wording: collapse every run (including newlines) to
# one space, trim the ends, and drop Markdown bold markers so SPEC's bold copy
# and a plain copy compare equal.
normalize() {
  tr '\n' ' ' | sed -E 's/\*\*//g; s/[[:space:]]+/ /g; s/^ //; s/ $//'
}

printf 'Enforcement-scope statement drift check\n'
printf '%s\n' '======================================='

if [[ ! -f "$SPEC_FILE" ]]; then
  check_fail "SPEC.md not found at ${SPEC_FILE}"
fi

# The canonical paragraph starts with the bold lead-in and ends with the bold
# close. If either marker is edited, this extraction fails loudly rather than
# silently checking an empty string.
canonical="$(sed -n '/^\*\*Full recipient\/amount enforcement/,/already covered\.\*\*$/p' "$SPEC_FILE" | normalize)"

if [[ -z "$canonical" ]]; then
  check_fail "could not extract the canonical statement from SPEC §2 (expected a bold paragraph starting 'Full recipient/amount enforcement' and ending 'already covered.**')"
  printf '\nSummary: %d passed, %d failed\n' "$pass" "$fail" >&2
  exit 1
fi

check_pass "extracted canonical statement from SPEC §2 ($(printf '%s' "$canonical" | wc -w) words)"

check_copy() {
  local label="$1"
  local file="$2"
  local spec_link="$3"

  if [[ ! -f "$file" ]]; then
    check_fail "${label} not found at ${file}"
    return
  fi

  local normalized
  normalized="$(normalize < "$file")"

  if [[ "$normalized" == *"$canonical"* ]]; then
    check_pass "${label} quotes the canonical statement word for word"
  else
    check_fail "${label} does not match SPEC §2. Re-sync the paragraph from SPEC §2 (see the header of this script)."
  fi

  if [[ "$normalized" == *"$spec_link"* ]]; then
    check_pass "${label} links back to SPEC §2"
  else
    check_fail "${label} is missing its canonical link (expected a link containing '${spec_link}')"
  fi
}

check_copy "README.md" "$README_FILE" "SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing"
check_copy "docs/enforcement-scope.md" "$SCOPE_FILE" "../SPEC.md#2-enforcement-scope--sac-token-calls-vs-every-other-soroban-call-required-framing"

printf '\nSummary: %d passed, %d failed\n' "$pass" "$fail"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
