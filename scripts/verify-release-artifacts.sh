#!/usr/bin/env bash
# Verifies the staged release artifacts before they are published:
#
#   dist/stellar_agent_guard_contracts.wasm
#   dist/stellar_agent_guard_contracts.wasm.sha256
#   dist/provenance.txt
#   dist/sbom.cdx.json
#   dist/agent-tx
#   dist/agent-tx.sha256
#   dist/agent-tx.provenance.txt
#
# The check fails on missing or mismatched metadata: package version, release
# tag, commit SHA, target, pinned toolchain, build command, and SHA-256 must all
# agree with the repository and the actual artifact bytes. Run it on a staged
# directory with:
#
#   GITHUB_REF_NAME=v0.1.0 GITHUB_SHA="$(git rev-parse HEAD)" \
#     scripts/verify-release-artifacts.sh dist
#
# The release workflow runs it automatically after staging and before
# `softprops/action-gh-release`, so a metadata mistake cannot be published.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CARGO_TOML="${ROOT_DIR}/Cargo.toml"
readonly TOOL_CARGO_TOML="${ROOT_DIR}/tools/agent-tx/Cargo.toml"
readonly TOOLCHAIN_FILE="${ROOT_DIR}/rust-toolchain.toml"
readonly DIST_DIR="${1:-${ROOT_DIR}/dist}"

readonly WASM_ASSET="stellar_agent_guard_contracts.wasm"
readonly WASM_SHA_ASSET="${WASM_ASSET}.sha256"
readonly WASM_PROVENANCE="provenance.txt"
readonly SBOM_ASSET="sbom.cdx.json"
readonly TOOL_ASSET="agent-tx"
readonly TOOL_SHA_ASSET="${TOOL_ASSET}.sha256"
readonly TOOL_PROVENANCE="agent-tx.provenance.txt"

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

usage() {
  printf 'Usage: %s [dist-dir]\n' "${BASH_SOURCE[0]}"
  printf '  Verifies staged release artifacts (default: ./dist).\n'
  printf '  Set GITHUB_REF_NAME and GITHUB_SHA when running outside a tagged checkout.\n'
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

printf 'Release artifact metadata verification\n'
printf '%s\n' '======================================'

if [[ ! -d "$DIST_DIR" ]]; then
  printf 'Error: artifact directory %s does not exist.\n' "$DIST_DIR" >&2
  exit 1
fi

crate_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$CARGO_TOML" | head -n 1)"
tool_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$TOOL_CARGO_TOML" | head -n 1)"
pinned_channel="$(sed -nE 's/^channel = "(.*)"$/\1/p' "$TOOLCHAIN_FILE")"

if [[ -z "$crate_version" ]]; then
  printf 'Error: could not read the package version from %s\n' "$CARGO_TOML" >&2
  exit 1
fi
if [[ -z "$tool_version" ]]; then
  printf 'Error: could not read the package version from %s\n' "$TOOL_CARGO_TOML" >&2
  exit 1
fi
if [[ -z "$pinned_channel" ]]; then
  printf 'Error: could not read the pinned channel from %s\n' "$TOOLCHAIN_FILE" >&2
  exit 1
fi

expected_tag="v${crate_version}"

tag="${GITHUB_REF_NAME:-}"
if [[ -z "$tag" ]] && [[ "${GITHUB_REF:-}" =~ ^refs/tags/(.*)$ ]]; then
  tag="${BASH_REMATCH[1]}"
fi
if [[ -z "$tag" ]]; then
  tag="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)"
fi

if [[ -z "$tag" ]]; then
  check_fail "no release tag could be resolved (set GITHUB_REF_NAME or run on a tagged commit)"
else
  check_pass "resolved release tag: ${tag}"
  if "${ROOT_DIR}/scripts/verify-release-version.sh" "$tag" >/dev/null; then
    check_pass "release tag matches Cargo.toml version ${crate_version}"
  else
    check_fail "release tag '${tag}' does not match Cargo.toml version '${crate_version}' (expected '${expected_tag}')"
  fi
fi

commit="${GITHUB_SHA:-}"
if [[ -z "$commit" ]]; then
  commit="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || true)"
fi
if [[ -z "$commit" ]]; then
  check_fail "no commit SHA could be resolved (set GITHUB_SHA or run in a git checkout)"
else
  check_pass "resolved commit SHA: ${commit}"
fi

host_target=""
if command -v rustc >/dev/null 2>&1; then
  host_target="$(rustc -vV | sed -n 's/^host: //p')"
fi
if [[ -z "$host_target" ]]; then
  check_fail "could not determine the host target from rustc -vV"
fi

check_field() {
  local label="$1"
  local file="$2"
  local key="$3"
  local expected="$4"
  local actual

  actual="$(awk -v k="${key}: " 'index($0, k) == 1 { print substr($0, length(k) + 1); exit }' "$file")"

  if [[ -z "$actual" ]]; then
    check_fail "${label}: missing non-empty '${key}' metadata (expected '${expected}')"
    return
  fi

  if [[ "$actual" != "$expected" ]]; then
    check_fail "${label}: '${key}' is '${actual}', expected '${expected}'"
    return
  fi

  check_pass "${label}: ${key} = ${actual}"
}

check_provenance() {
  local label="$1"
  local file="$2"
  local package="$3"
  local version="$4"
  local target="$5"
  local build_command="$6"
  local actual_sha="$7"

  if [[ ! -s "$file" ]]; then
    check_fail "${label}: provenance file is missing or empty: ${file}"
    return
  fi

  check_field "$label provenance" "$file" "package" "$package"
  check_field "$label provenance" "$file" "version" "$version"
  check_field "$label provenance" "$file" "tag" "$tag"
  check_field "$label provenance" "$file" "commit" "$commit"
  check_field "$label provenance" "$file" "target" "$target"
  check_field "$label provenance" "$file" "build command" "$build_command"
  check_field "$label provenance" "$file" "sha256" "$actual_sha"

  local rustc_value cargo_value
  rustc_value="$(awk 'index($0, "rustc: ") == 1 { print substr($0, 8); exit }' "$file")"
  cargo_value="$(awk 'index($0, "cargo: ") == 1 { print substr($0, 8); exit }' "$file")"

  if [[ "$rustc_value" == "rustc ${pinned_channel}"* ]]; then
    check_pass "${label} provenance: rustc matches pinned channel ${pinned_channel}"
  else
    check_fail "${label} provenance: rustc is '${rustc_value}', expected a rustc ${pinned_channel} build"
  fi

  if [[ "$cargo_value" == "cargo ${pinned_channel}"* ]]; then
    check_pass "${label} provenance: cargo matches pinned channel ${pinned_channel}"
  else
    check_fail "${label} provenance: cargo is '${cargo_value}', expected a cargo ${pinned_channel} build"
  fi

  if grep -Eq '^runner: .+' "$file"; then
    check_pass "${label} provenance: runner is recorded"
  else
    check_fail "${label} provenance: missing non-empty 'runner' metadata"
  fi
}

check_artifact() {
  local label="$1"
  local asset="$2"
  local sha_file="$3"
  local expected_magic="$4"

  if [[ ! -s "$asset" ]]; then
    check_fail "${label}: artifact is missing or empty: ${asset}"
    CHECKED_SHA=""
    return
  fi

  local magic
  magic="$(od -An -tx1 -N4 "$asset" | tr -d ' \n')"
  if [[ "$magic" == "$expected_magic" ]]; then
    check_pass "${label}: artifact magic is ${expected_magic}"
  else
    check_fail "${label}: artifact magic is ${magic}, expected ${expected_magic}"
  fi

  local actual_sha
  actual_sha="$(sha256sum "$asset" | awk '{print $1}')"

  if [[ ! -s "$sha_file" ]]; then
    check_fail "${label}: checksum file is missing or empty: ${sha_file}"
    CHECKED_SHA="$actual_sha"
    return
  fi

  local listed_sha listed_name
  listed_sha="$(awk 'NR == 1 { print $1 }' "$sha_file")"
  listed_name="$(awk 'NR == 1 { $1 = ""; sub(/^[[:space:]]+/, ""); print }' "$sha_file")"
  listed_name="${listed_name#\*}"

  if [[ "$listed_sha" == "$actual_sha" ]]; then
    check_pass "${label}: checksum file matches the artifact bytes"
  else
    check_fail "${label}: checksum file records '${listed_sha}', actual is '${actual_sha}'"
  fi

  if [[ "$(basename "$listed_name")" == "$(basename "$asset")" ]]; then
    check_pass "${label}: checksum file names the artifact"
  else
    check_fail "${label}: checksum file names '${listed_name}', expected '$(basename "$asset")'"
  fi

  CHECKED_SHA="$actual_sha"
}

check_sbom() {
  local file="$1"
  local package="$2"
  local version="$3"

  if [[ ! -s "$file" ]]; then
    check_fail "SBOM: file is missing or empty: ${file}"
    return
  fi

  local json_query=""
  if command -v jq >/dev/null 2>&1; then
    json_query="jq"
  elif command -v python3 >/dev/null 2>&1; then
    json_query="python3"
  else
    check_fail "SBOM: neither jq nor python3 is available to validate ${file}"
    return
  fi

  local bom_format spec_version component_name component_version component_count
  if [[ "$json_query" == "jq" ]]; then
    bom_format="$(jq -r '.bomFormat // empty' "$file")"
    spec_version="$(jq -r '.specVersion // empty' "$file")"
    component_name="$(jq -r '.metadata.component.name // empty' "$file")"
    component_version="$(jq -r '.metadata.component.version // empty' "$file")"
    component_count="$(jq -r '.components | if type == "array" then length else 0 end' "$file")"
  else
    read -r bom_format spec_version component_name component_version component_count < <(
      python3 - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    bom = json.load(handle)
component = bom.get("metadata", {}).get("component", {})
print(
    bom.get("bomFormat", ""),
    bom.get("specVersion", ""),
    component.get("name", ""),
    component.get("version", ""),
    len(bom.get("components", [])),
)
PY
    )
  fi

  if [[ "$bom_format" == "CycloneDX" ]]; then
    check_pass "SBOM: bomFormat is CycloneDX"
  else
    check_fail "SBOM: bomFormat is '${bom_format}', expected 'CycloneDX'"
  fi

  if [[ -n "$spec_version" ]]; then
    check_pass "SBOM: specVersion is ${spec_version}"
  else
    check_fail "SBOM: missing specVersion"
  fi

  if [[ "$component_name" == "$package"* ]]; then
    check_pass "SBOM: metadata component name is ${component_name}"
  else
    check_fail "SBOM: metadata component name is '${component_name}', expected '${package}'"
  fi

  if [[ "$component_version" == "$version" ]]; then
    check_pass "SBOM: metadata component version is ${version}"
  else
    check_fail "SBOM: metadata component version is '${component_version}', expected '${version}'"
  fi

  if [[ "$component_count" =~ ^[0-9]+$ ]] && ((component_count > 0)); then
    check_pass "SBOM: lists ${component_count} component(s)"
  else
    check_fail "SBOM: component list is missing or empty"
  fi
}

wasm_path="${DIST_DIR}/${WASM_ASSET}"
wasm_sha_path="${DIST_DIR}/${WASM_SHA_ASSET}"
wasm_provenance_path="${DIST_DIR}/${WASM_PROVENANCE}"
sbom_path="${DIST_DIR}/${SBOM_ASSET}"
tool_path="${DIST_DIR}/${TOOL_ASSET}"
tool_sha_path="${DIST_DIR}/${TOOL_SHA_ASSET}"
tool_provenance_path="${DIST_DIR}/${TOOL_PROVENANCE}"

printf '\n1. Verifying contract WASM and metadata...\n'
CHECKED_SHA=""
check_artifact "WASM" "$wasm_path" "$wasm_sha_path" "0061736d"
wasm_sha="$CHECKED_SHA"
check_provenance "WASM" "$wasm_provenance_path" \
  "stellar-agent-guard-contracts" "$crate_version" "wasm32v1-none" \
  "cargo build --release --target wasm32v1-none" "$wasm_sha"

printf '\n2. Verifying agent-tx tool artifact and metadata...\n'
CHECKED_SHA=""
check_artifact "agent-tx" "$tool_path" "$tool_sha_path" "7f454c46"
tool_sha="$CHECKED_SHA"
check_provenance "agent-tx" "$tool_provenance_path" \
  "agent-tx" "$tool_version" "$host_target" \
  "cargo build --release --manifest-path tools/agent-tx/Cargo.toml" "$tool_sha"

printf '\n3. Verifying SBOM metadata...\n'
check_sbom "$sbom_path" "stellar-agent-guard-contracts" "$crate_version"

printf '\nSummary: %d passed, %d failed\n' "$pass" "$fail"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
