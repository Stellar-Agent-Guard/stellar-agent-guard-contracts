#!/usr/bin/env bash
# Verifies that the git release tag matches the crate version in Cargo.toml.
# Usage: ./scripts/verify-release-version.sh [tag]
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly CARGO_TOML="${ROOT_DIR}/Cargo.toml"

if [[ ! -f "$CARGO_TOML" ]]; then
  echo "Error: Cargo.toml not found at ${CARGO_TOML}" >&2
  exit 1
fi

crate_version="$(sed -nE 's/^version = "([^"]+)"$/\1/p' "$CARGO_TOML" | head -n 1)"
if [[ -z "$crate_version" ]]; then
  echo "Error: Could not extract package version from ${CARGO_TOML}" >&2
  exit 1
fi

expected_tag="v${crate_version}"

# Resolve target tag from arguments or environment
tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$tag" ]] && [[ "${GITHUB_REF:-}" =~ ^refs/tags/(.*) ]]; then
  tag="${BASH_REMATCH[1]}"
fi
if [[ -z "$tag" ]]; then
  tag="$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)"
fi

echo "Crate version in Cargo.toml : ${crate_version}"
echo "Expected release tag       : ${expected_tag}"

if [[ -n "$tag" ]]; then
  echo "Resolved release tag       : ${tag}"
  if [[ "$tag" != "$expected_tag" ]]; then
    echo "ERROR: Release tag '${tag}' does not match Cargo.toml version '${crate_version}' (expected '${expected_tag}')" >&2
    exit 1
  fi
  echo "SUCCESS: Release tag '${tag}' matches Cargo.toml version '${crate_version}'."
else
  # If triggered in CI on tag push, a tag is mandatory
  if [[ "${GITHUB_EVENT_NAME:-}" == "push" ]] && [[ "${GITHUB_REF:-}" =~ ^refs/tags/ ]]; then
    echo "ERROR: Release tag event triggered but no tag could be determined from GITHUB_REF (${GITHUB_REF:-none})" >&2
    exit 1
  fi
  echo "Notice: No git tag detected on current ref; pass a tag as an argument to test (e.g. ./scripts/verify-release-version.sh ${expected_tag})."
fi
