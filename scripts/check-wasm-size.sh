#!/usr/bin/env bash
# scripts/check-wasm-size.sh
#
# Enforces the committed WASM size budget (issue #68). The budget lives in
# scripts/wasm-size-budget.txt and is measured against the artifact produced
# by the repository's real release build:
#   cargo build --release --target wasm32v1-none
#
# Usage:
#   ./scripts/check-wasm-size.sh [--wasm PATH] [--budget PATH]
#
# Exit codes: 0 = within budget, 1 = over budget, 2 = usage/setup error.
#
# When GITHUB_STEP_SUMMARY is set (GitHub Actions), the same numbers are also
# written to the job summary on every build, pass or fail.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WASM_PATH="${SCRIPT_DIR}/../target/wasm32v1-none/release/stellar_agent_guard_contracts.wasm"
BUDGET_PATH="${SCRIPT_DIR}/wasm-size-budget.txt"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wasm)
            [[ $# -ge 2 ]] || { echo "ERROR: --wasm requires a path" >&2; exit 2; }
            WASM_PATH="$2"
            shift 2
            ;;
        --budget)
            [[ $# -ge 2 ]] || { echo "ERROR: --budget requires a path" >&2; exit 2; }
            BUDGET_PATH="$2"
            shift 2
            ;;
        -h|--help)
            sed -n '2,16p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "Usage: $0 [--wasm PATH] [--budget PATH]" >&2
            exit 2
            ;;
    esac
done

if [[ ! -f "$WASM_PATH" ]]; then
    echo "ERROR: WASM artifact not found: $WASM_PATH" >&2
    echo "Build it first with: cargo build --release --target wasm32v1-none" >&2
    exit 2
fi

if [[ ! -f "$BUDGET_PATH" ]]; then
    echo "ERROR: WASM size budget file not found: $BUDGET_PATH" >&2
    exit 2
fi

# The budget file may contain comments and blank lines, but exactly one
# `bytes=<positive integer>` entry.
budget_lines="$(grep -E '^[[:space:]]*bytes[[:space:]]*=' "$BUDGET_PATH" || true)"
budget_count="$(printf '%s\n' "$budget_lines" | grep -c . || true)"
if [[ "$budget_count" -ne 1 ]]; then
    echo "ERROR: $BUDGET_PATH must contain exactly one 'bytes=<integer>' line (found $budget_count)" >&2
    exit 2
fi

budget="${budget_lines#*=}"
budget="${budget//[[:space:]]/}"
if [[ ! "$budget" =~ ^[0-9]+$ ]] || [[ "$budget" -le 0 ]]; then
    echo "ERROR: malformed WASM size budget in $BUDGET_PATH: '$budget' is not a positive integer" >&2
    exit 2
fi

actual="$(wc -c < "$WASM_PATH" | tr -d '[:space:]')"
if [[ ! "$actual" =~ ^[0-9]+$ ]] || [[ "$actual" -le 0 ]]; then
    echo "ERROR: could not measure WASM artifact size: $WASM_PATH" >&2
    exit 2
fi

headroom=$((budget - actual))
percent="$(awk -v h="$headroom" -v b="$budget" 'BEGIN { h = h < 0 ? -h : h; printf "%.2f", (h * 100) / b }')"
if [[ "$headroom" -ge 0 ]]; then
    status="PASS"
else
    status="FAIL"
fi

echo "WASM size budget"
echo "  artifact: $WASM_PATH"
echo "  actual:   $actual bytes"
echo "  budget:   $budget bytes ($BUDGET_PATH)"
if [[ "$headroom" -ge 0 ]]; then
    echo "  headroom: $headroom bytes remaining ($percent% of budget)"
else
    echo "  headroom: ${headroom#-} bytes over budget ($percent% of budget)"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "## WASM size budget"
        echo
        echo "| Metric | Value |"
        echo "|---|---|"
        echo "| Artifact | \`$(basename "$WASM_PATH")\` |"
        echo "| Actual | $actual bytes |"
        echo "| Budget | $budget bytes |"
        if [[ "$headroom" -ge 0 ]]; then
            echo "| Headroom | $headroom bytes ($percent%) |"
        else
            echo "| Over budget | ${headroom#-} bytes ($percent%) |"
        fi
        echo "| Result | $status |"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$headroom" -lt 0 ]]; then
    echo "" >&2
    echo "FAIL: WASM artifact is ${headroom#-} bytes over the committed budget." >&2
    echo "If the growth is intentional: rebuild, measure, update 'bytes' in $BUDGET_PATH," >&2
    echo "and explain the increase and its rationale in the PR." >&2
    exit 1
fi

echo "OK: WASM artifact is within the committed size budget."
