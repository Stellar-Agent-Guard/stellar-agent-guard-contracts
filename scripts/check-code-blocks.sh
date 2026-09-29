#!/usr/bin/env bash
#
# scripts/check-code-blocks.sh
# Verifies embedded markdown bash code blocks tagged with ```bash-verify.
#

set -euo pipefail

# Collect target markdown files that actually exist
TARGET_FILES=()
if [ "$#" -gt 0 ]; then
  TARGET_FILES=("$@")
else
  for f in README.md SPEC.md docs/*.md; do
    if [ -f "$f" ]; then
      TARGET_FILES+=("$f")
    fi
  done
fi

TOTAL_BLOCKS=0
SYNTAX_PASSED=0
RUN_PASSED=0
FAILURES=0

TMP_BLOCK=$(mktemp)
trap 'rm -f "$TMP_BLOCK"' EXIT

for file in "${TARGET_FILES[@]}"; do
  line_no=0
  in_block=0
  block_start=0
  should_run=0

  while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    line_no=$((line_no + 1))
    line=$(printf '%s' "$raw_line" | tr -d '\r')

    if [ "$in_block" -eq 0 ]; then
      case "$line" in
        '```bash-verify'*)
          in_block=1
          block_start=$line_no
          should_run=0
          : > "$TMP_BLOCK"
          ;;
      esac
      continue
    fi

    if [ "$in_block" -eq 1 ]; then
      case "$line" in
        '```'*)
          in_block=0
          TOTAL_BLOCKS=$((TOTAL_BLOCKS + 1))

          # 1. Syntax check with bash -n
          if ! bash -n "$TMP_BLOCK" 2>&1; then
            echo "❌ Syntax error in $file:$block_start"
            FAILURES=$((FAILURES + 1))
            continue
          fi

          SYNTAX_PASSED=$((SYNTAX_PASSED + 1))
          echo "✓ Syntax valid: $file:$block_start"

          # 2. Execution check if opt-in run header is present
          if [ "$should_run" -eq 1 ]; then
            echo "⚙️  Running hermetic block from $file:$block_start..."
            if ! ( bash "$TMP_BLOCK" ); then
              echo "❌ Execution failed for block at $file:$block_start"
              FAILURES=$((FAILURES + 1))
              continue
            fi
            RUN_PASSED=$((RUN_PASSED + 1))
          fi
          ;;
        *'# run:'*)
          should_run=1
          printf "%s\n" "$line" >> "$TMP_BLOCK"
          ;;
        *)
          printf "%s\n" "$line" >> "$TMP_BLOCK"
          ;;
      esac
    fi
  done < "$file"
done

echo ""
echo "=== Code Block Verification Summary ==="
echo "Files checked:   ${TARGET_FILES[*]}"
echo "Blocks found:    $TOTAL_BLOCKS"
echo "Syntax valid:    $SYNTAX_PASSED"
echo "Executed valid:  $RUN_PASSED"
echo "Failures:        $FAILURES"

if [ "$FAILURES" -ne 0 ]; then
  exit 1
fi

echo "✅ All verified code blocks passed."
