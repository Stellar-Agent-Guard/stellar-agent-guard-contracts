#!/usr/bin/env bash
# Verifies documentation integrity in two directions:
#   1. every page under docs/ is reachable from docs/SUMMARY.md unless
#      explicitly allowlisted, and every link in docs/SUMMARY.md resolves;
#   2. every repository-local Markdown link resolves to a file on disk.
#
# The link check walks every tracked Markdown file (not only docs/) so a link
# from a tool README or the root README cannot rot unnoticed. Fenced code
# blocks are ignored because links in examples are not navigation.
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
  printf '[FAIL] %s\n' "$1" >&2
  fail=$((fail + 1))
}

printf 'Documentation Integrity Verification\n'
printf '%s\n' '===================================='

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
    check_fail "docs/SUMMARY.md: link '${file_target}' does not exist (resolved: ${resolved})"
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

# 3. Link integrity: every repository-local Markdown link resolves.
printf '\n3. Verifying local links in Markdown files resolve...\n'

while IFS= read -r source; do
  rel_source="${source#"${ROOT_DIR}/"}"

  # Drop fenced code blocks so example snippets are not parsed as navigation.
  links="$(
    awk '
      /^[[:space:]]*(```|~~~)/ { fence = !fence; next }
      !fence { print }
    ' "$source" |
      grep -oE '!?\[[^]]*\]\([^)]+\)' |
      sed -E 's/^!?\[[^]]*\]\(([^)]*)\)$/\1/' || true
  )"

  file_links=0
  file_failures=0

  while IFS= read -r link; do
    [[ -z "$link" ]] && continue

    # Trim surrounding whitespace, then drop an optional Markdown title
    # ("path" or 'path' after the target) so only the target remains.
    link="${link#"${link%%[![:space:]]*}"}"
    link="${link%"${link##*[![:space:]]}"}"
    link="${link%%[[:space:]]*}"

    # External, protocol-relative, anchor-only, and placeholder links are not
    # repository-local targets.
    case "$link" in
      '' | '#'* | '<'* | '//'* | http://* | https://* | mailto:* | tel:* | *'://'*)
        continue
        ;;
    esac

    target="${link%%#*}"
    target="${target%%\?*}"
    [[ -z "$target" ]] && continue

    file_links=$((file_links + 1))

    if [[ "$target" == /* ]]; then
      resolved="${ROOT_DIR}${target}"
    else
      resolved="$(dirname "$source")/${target}"
    fi

    if [[ -e "$resolved" ]]; then
      continue
    fi

    check_fail "${rel_source}: link target '${link}' does not resolve (resolved: ${resolved})"
    file_failures=$((file_failures + 1))
  done <<< "$links"

  if [[ "$file_links" -gt 0 && "$file_failures" -eq 0 ]]; then
    check_pass "${rel_source}: ${file_links} local link(s) resolve"
  fi
done < <(
  find "$ROOT_DIR" -type f -name '*.md' \
    -not -path '*/.git/*' \
    -not -path '*/target/*' |
    sort
)

printf '\nSummary: %d passed, %d failed\n' "$pass" "$fail"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
