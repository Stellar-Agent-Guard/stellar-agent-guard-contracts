#!/usr/bin/env bash
# Verifies that every page under docs/ is reachable from docs/SUMMARY.md
# (unless explicitly allowlisted), and verifies that all links in docs/SUMMARY.md
# resolve to existing files.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly DOCS_DIR="${ROOT_DIR}/docs"
readonly SUMMARY_FILE="${DOCS_DIR}/SUMMARY.md"
readonly ALLOWLIST_FILE="${DOCS_DIR}/.summary-allowlist"

if [[ ! -f "$SUMMARY_FILE" ]]; then
  echo "Error: ${SUMMARY_FILE} not found." >&2
  exit 1
fi

pass=0
fail=0

check_pass() {
  printf '[PASS] %s\n' "$1"
  pass=$((pass + 1))
}

check_fail() {
  printf '[FAIL] %s\n' "$1"
  fail=$((fail + 1))
}

printf 'Documentation Reachability Verification\n'
printf '%s\n' '======================================'

# Load allowlist into an associative array
declare -A allowlist
if [[ -f "$ALLOWLIST_FILE" ]]; then
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip leading/trailing whitespace
    trimmed="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ -z "$trimmed" || "$trimmed" =~ ^# ]] && continue
    # Normalize path relative to docs/
    norm="${trimmed#docs/}"
    allowlist["$norm"]=1
    if [[ ! -e "${DOCS_DIR}/${norm}" ]]; then
      check_fail "Allowlist entry does not exist on disk: docs/${norm}"
    fi
  done < "$ALLOWLIST_FILE"
fi

# Always allow SUMMARY.md itself
allowlist["SUMMARY.md"]=1

# 1. Reverse check: verify that all links in SUMMARY.md point to real files/directories
printf '\n1. Verifying SUMMARY.md links point to existing files...\n'

while IFS= read -r link; do
  [[ -z "$link" ]] && continue
  # Ignore external links
  [[ "$link" =~ ^https?:// || "$link" =~ ^mailto: ]] && continue
  # Strip anchor if present
  file_target="${link%%#*}"
  [[ -z "$file_target" ]] && continue

  resolved="${DOCS_DIR}/${file_target}"
  if [[ -e "$resolved" ]]; then
    check_pass "SUMMARY link points to existing target: ${file_target}"
  else
    check_fail "SUMMARY link '${file_target}' does not exist (resolved: ${resolved})"
  fi
done < <(grep -oE '\[[^]]*\]\([^)]+\)' "$SUMMARY_FILE" | sed -E 's/.*\]\(([^)]+)\)/\1/')

# 2. Forward check: verify that all markdown files under docs/ are reachable from SUMMARY.md
printf '\n2. Verifying all markdown files under docs/ are reachable from SUMMARY.md...\n'

summary_content="$(cat "$SUMMARY_FILE")"

while IFS= read -r file; do
  rel_path="${file#"${DOCS_DIR}/"}"

  if [[ -n "${allowlist["$rel_path"]:-}" ]]; then
    check_pass "docs/${rel_path} is intentionally allowlisted"
    continue
  fi

  # Check if rel_path is referenced as a link target in SUMMARY.md
  # Matches (rel_path) or (rel_path#anchor)
  if echo "$summary_content" | grep -Fq "(${rel_path}" || echo "$summary_content" | grep -Fq "(${rel_path%.md}"; then
    check_pass "docs/${rel_path} is reachable from SUMMARY.md"
  else
    check_fail "docs/${rel_path} is not reachable from SUMMARY.md and not listed in docs/.summary-allowlist"
  fi
done < <(find "$DOCS_DIR" -type f -name "*.md" | sort)

printf '\nSummary: %d passed, %d failed\n' "$pass" "$fail"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
