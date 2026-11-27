#!/usr/bin/env bash
# scripts/check-wasm-size.sh
#
# Enforces the committed WASM size budget (issue #68) and prints a
# deterministic per-section byte breakdown (issue #610) so maintainers can see
# which WASM sections consume the budget. The budget lives in
# scripts/wasm-size-budget.txt and is measured against the artifact produced by
# the repository's real release build:
#   cargo build --release --target wasm32v1-none
#
# Usage:
#   ./scripts/check-wasm-size.sh [--wasm PATH] [--budget PATH]
#
# Exit codes: 0 = within budget, 1 = over budget, 2 = usage/setup error.
#
# When GITHUB_STEP_SUMMARY is set (GitHub Actions), the same numbers and section
# table are also written to the job summary on every build, pass or fail.

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
            sed -n '2,18p' "$0"
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

if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 is required to parse WASM sections" >&2
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

section_report="$(python3 - "$WASM_PATH" "$actual" "$budget" <<'PY'
import sys
from collections import defaultdict
from pathlib import Path

wasm_path = Path(sys.argv[1])
expected_total = int(sys.argv[2])
budget = int(sys.argv[3])
data = wasm_path.read_bytes()

if len(data) != expected_total:
    print(
        f"ERROR: byte count mismatch for {wasm_path}: read {len(data)}, wc -c saw {expected_total}",
        file=sys.stderr,
    )
    sys.exit(2)

if len(data) < 8 or data[:4] != b"\x00asm":
    print(f"ERROR: {wasm_path} is not a valid WebAssembly binary (missing magic header)", file=sys.stderr)
    sys.exit(2)

STANDARD_SECTIONS = {
    1: "type",
    2: "import",
    3: "function",
    4: "table",
    5: "memory",
    6: "global",
    7: "export",
    8: "start",
    9: "element",
    10: "code",
    11: "data",
    12: "data_count",
}


def read_uleb128(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated LEB128 integer")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return result, pos
        shift += 7
        if shift > 35:
            raise ValueError("oversized LEB128 integer")


totals: dict[str, int] = defaultdict(int)
totals["header"] = 8
pos = 8

try:
    while pos < len(data):
        sec_start = pos
        sec_id = data[pos]
        pos += 1
        payload_len, pos = read_uleb128(data, pos)
        payload_end = pos + payload_len
        if payload_end > len(data):
            raise ValueError(f"section {sec_id} extends past end of file")

        if sec_id == 0:
            name_len, name_start = read_uleb128(data, pos)
            name_end = name_start + name_len
            if name_end > payload_end:
                raise ValueError("custom section name extends past section payload")
            raw_name = data[name_start:name_end].decode("utf-8", errors="replace")
            label = f"custom ({raw_name})"
        else:
            label = STANDARD_SECTIONS.get(sec_id, f"unknown ({sec_id})")

        totals[label] += payload_end - sec_start
        pos = payload_end
except ValueError as err:
    print(f"ERROR: failed to parse WASM sections in {wasm_path}: {err}", file=sys.stderr)
    sys.exit(2)

accounted = sum(totals.values())
if accounted != expected_total:
    print(
        f"ERROR: parsed section bytes ({accounted}) != total WASM size ({expected_total})",
        file=sys.stderr,
    )
    sys.exit(2)

# Deterministic descending-size order with lexicographical tie-breaker.
rows = sorted(totals.items(), key=lambda kv: (-kv[1], kv[0]))
for name, size in rows:
    pct_wasm = (size * 100.0) / expected_total
    pct_budget = (size * 100.0) / budget
    print(f"{name}\t{size}\t{pct_wasm:.2f}%\t{pct_budget:.2f}%")
PY
)"
section_report="${section_report//$'\r'/}"

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
echo ""
echo "WASM size by section (sorted by size):"
printf "  %-30s %10s %9s %11s\n" "Section" "Bytes" "% of WASM" "% of Budget"
printf "  %-30s %10s %9s %11s\n" "------------------------------" "----------" "---------" "-----------"
while IFS=$'\t' read -r sec_name sec_bytes sec_wasm_pct sec_budget_pct; do
    printf "  %-30s %10s %9s %11s\n" "$sec_name" "$sec_bytes" "$sec_wasm_pct" "$sec_budget_pct"
done <<< "$section_report"

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
        echo
        echo "### Size breakdown by WASM section"
        echo
        echo "| Section | Bytes | % of WASM | % of budget |"
        echo "|---|---:|---:|---:|"
        while IFS=$'\t' read -r sec_name sec_bytes sec_wasm_pct sec_budget_pct; do
            echo "| \`$sec_name\` | $sec_bytes | $sec_wasm_pct | $sec_budget_pct |"
        done <<< "$section_report"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ "$headroom" -lt 0 ]]; then
    echo "" >&2
    echo "FAIL: WASM artifact is ${headroom#-} bytes over the committed budget." >&2
    echo "See docs/verification.md#wasm-size-budget--investigating-growth to investigate section growth." >&2
    echo "If the growth is intentional: rebuild, measure, update 'bytes' in $BUDGET_PATH," >&2
    echo "and explain the increase and its rationale in the PR." >&2
    exit 1
fi

echo ""
echo "OK: WASM artifact is within the committed size budget."
