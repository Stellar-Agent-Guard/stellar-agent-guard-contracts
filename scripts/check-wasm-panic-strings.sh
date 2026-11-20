#!/usr/bin/env bash
set -euo pipefail

artifact="${1:-target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm}"
allowlist="${2:-scripts/wasm-panic-strings.allowlist}"

if [[ ! -f "$artifact" ]]; then
  echo "WASM artifact not found: $artifact" >&2
  exit 2
fi
if [[ ! -f "$allowlist" ]]; then
  echo "Panic-string allowlist not found: $allowlist" >&2
  exit 2
fi
if ! command -v strings >/dev/null 2>&1; then
  echo "strings is required to scan the WASM artifact" >&2
  exit 2
fi

pattern='panicked at|panic in a function that cannot unwind|assertion failed|assertion `.*` failed|called `Result::unwrap\(\)` on an `Err` value|called `Option::unwrap\(\)` on a `None` value|index out of bounds:|slice index starts at|attempt to (add|subtract|multiply|divide) with overflow|unsafe precondition(s) violated'
matches="$(strings -a -- "$artifact" | grep -oE "$pattern" | sort -u || true)"
if [[ -z "$matches" ]]; then
  echo "No panic/unwrap diagnostic strings found in $artifact"
  exit 0
fi

exceptions="$(sed -e '/^[[:space:]]*#/d' -e '/^[[:space:]]*$/d' "$allowlist")"
if [[ -n "$exceptions" ]]; then
  findings="$(printf '%s\n' "$matches" | grep -Fvx -f <(printf '%s\n' "$exceptions") || true)"
else
  findings="$matches"
fi

if [[ -n "$findings" ]]; then
  printf 'Unallowlisted panic/unwrap diagnostic strings found in %s:\n%s\n' \
    "$artifact" "$findings" >&2
  echo "Review the artifact and add only justified exact strings to $allowlist." >&2
  exit 1
fi

echo "Panic/unwrap diagnostic strings found, but all are explicitly allowlisted in $allowlist"