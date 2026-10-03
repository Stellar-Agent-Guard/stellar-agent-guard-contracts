#!/usr/bin/env bash
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly README="${ROOT_DIR}/README.md"
readonly FIXTURES_README="${ROOT_DIR}/tests/fixtures/README.md"
readonly FIXTURE_INDEX="${ROOT_DIR}/tests/fixtures/index"
readonly WASM="${ROOT_DIR}/target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm"

pass=0
fail=0
info=0

check_pass() {
  printf '[PASS] %s\n' "$1"
  pass=$((pass + 1))
}

check_fail() {
  printf '[FAIL] %s\n' "$1"
  fail=$((fail + 1))
}

check_info() {
  printf '[INFO] %s\n' "$1"
  info=$((info + 1))
}

printf 'README claim verification\n'
printf '%s\n' '=========================='

test_output="$(mktemp)"
trap 'rm -f "$test_output"' EXIT

if cargo test 2>&1 | tee "$test_output" >/dev/null; then
  expected_count="$(grep -Eo '[0-9]+ tests' "$README" | awk '{print $1}' | sort -nu | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
  actual_count="$(sed -nE 's/.*test result: ok\. ([0-9]+) passed.*/\1/p' "$test_output" | awk '{total += $1} END {print total + 0}')"
  if [[ "$expected_count" == "32" && "$actual_count" == "$expected_count" ]]; then
    check_pass "README test count is ${actual_count}"
  else
    check_fail "README test count claims [${expected_count}], cargo test reports ${actual_count}"
  fi
else
  check_fail "cargo test could not run, so the README test-count claim was not verified"
fi

if [[ -f "$WASM" ]]; then
  wasm_hash="$(sha256sum "$WASM" | awk '{print $1}')"
  expected_wasm_hash="$(awk '$1 == "wasm_sha256" {print $2}' "$FIXTURE_INDEX" 2>/dev/null || true)"
  if [[ -n "$expected_wasm_hash" && "$wasm_hash" == "$expected_wasm_hash" ]]; then
    check_pass "Wasm SHA-256 matches tests/fixtures/index (${wasm_hash})"
  elif [[ -n "$expected_wasm_hash" ]]; then
    check_fail "Wasm SHA-256 drift: expected ${expected_wasm_hash}, got ${wasm_hash}"
  else
    check_info "Wasm SHA-256 is ${wasm_hash}; no release-manifest hash is recorded yet"
  fi
else
  check_fail "Wasm artifact is missing; run cargo build --release --target wasm32v1-none"
fi

if [[ -f "$FIXTURE_INDEX" ]]; then
  missing_hashes=0
  while read -r kind value; do
    [[ "$kind" == "tx" ]] || continue
    if grep -Fq "$value" "$FIXTURES_README"; then
      continue
    fi
    printf '[FAIL] Fixture transaction hash is missing from README: %s\n' "$value"
    missing_hashes=$((missing_hashes + 1))
  done < "$FIXTURE_INDEX"
  if [[ "$missing_hashes" -eq 0 ]]; then
    check_pass "Fixture transaction hashes match tests/fixtures/index"
  else
    fail=$((fail + missing_hashes))
  fi

  missing_ids=0
  while read -r kind value; do
    [[ "$kind" == "contract" ]] || continue
    if grep -Fq "$value" "$README"; then
      continue
    fi
    printf '[FAIL] Fixture contract ID is missing from README: %s\n' "$value"
    missing_ids=$((missing_ids + 1))
  done < "$FIXTURE_INDEX"
  if [[ "$missing_ids" -eq 0 ]]; then
    check_pass "Fixture contract IDs match tests/fixtures/index"
  else
    fail=$((fail + missing_ids))
  fi
else
  check_fail "Fixture index is missing: ${FIXTURE_INDEX}"
fi

if command -v stellar >/dev/null 2>&1 && [[ -n "${STELLAR_README_NETWORK:-}" ]]; then
  check_info "Network verification requested for ${STELLAR_README_NETWORK}; use the configured read-only fixture command"
else
  check_info "Network claims were not queried: stellar CLI/network access is intentionally optional in CI"
fi

printf '\nSummary: %d passed, %d failed, %d informational\n' "$pass" "$fail" "$info"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi