#!/usr/bin/env bash
# scripts/check-wasm-reproducible.sh
#
# Issue #67: prove that two clean builds of the same working tree produce
# byte-identical contract WASM. Each build runs in its own CARGO_TARGET_DIR,
# so the second build shares no artifact with the first — a cached rlib, a
# stale fingerprint, or a leftover object file cannot make the check pass.
#
# Runs on CI (job `wasm-reproducible`) and is the same command a contributor
# runs locally, so "CI says it is reproducible" and "I can reproduce it" are
# the same statement. The toolchain comes from `rust-toolchain.toml`, which
# rustup applies automatically; nothing here pins a version of its own.
#
# Usage: ./scripts/check-wasm-reproducible.sh
# Exit codes: 0 = both builds agree, 1 = hashes differ or a build failed,
#             2 = usage/internal error.

set -euo pipefail

TARGET="wasm32v1-none"
ARTIFACT="stellar_agent_guard_contracts.wasm"
WORK_DIR="${REPRO_WORK_DIR:-target/repro-check}"

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo not found on PATH (rustup with the pinned toolchain required)" >&2
    exit 2
fi

if [[ ! -f rust-toolchain.toml ]]; then
    echo "ERROR: rust-toolchain.toml not found; run this from the repository root" >&2
    exit 2
fi

# Build once into $1 and print the artifact's SHA-256 on stdout.
build_once() {
    local target_dir="$1"
    CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --target "$TARGET"
    sha256sum "$target_dir/$TARGET/release/$ARTIFACT" | cut -d' ' -f1
}

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

echo "toolchain: $(rustc --version)"
echo "cargo:     $(cargo --version)"
echo "target:    $TARGET"
echo "tree:      $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"

first="$(build_once "$WORK_DIR/a")"
second="$(build_once "$WORK_DIR/b")"

echo "build A: $first"
echo "build B: $second"

if [[ "$first" != "$second" ]]; then
    echo "FAIL: two clean builds of the same tree produced different bytes." >&2
    echo "      A: $first" >&2
    echo "      B: $second" >&2
    echo "      The toolchain is pinned in rust-toolchain.toml; a difference here" >&2
    echo "      means something in the build environment is not deterministic." >&2
    exit 1
fi

# This compares two builds of the same working tree, so it proves the build is
# deterministic — it does NOT prove the tree matches a release tag. Compare
# against a published hash by checking out that tag and reading the
# `provenance.txt` the release workflow publishes alongside the checksum.
echo "OK: both builds produced $first"