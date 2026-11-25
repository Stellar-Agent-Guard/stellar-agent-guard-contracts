#!/usr/bin/env bash
# scripts/preflight-deploy.sh
#
# Issue #625 — deployment preflight: automate checks for network, contract
# address, policy hash, and expected admin signer before installation.
#
# Runs in dry-run mode only: it reads live contract state via `agent-tx verify`
# but submits nothing and never touches private keys.  Every check prints a
# PASS / FAIL line; the script exits 0 only when all checks pass.  Run it
# immediately after `docs/operations/deployment-runbook.md § 6.1` and again
# before any upgrade.
#
# Usage:
#   ./scripts/preflight-deploy.sh \
#       --guard      <GUARD_ID>          \  # C... contract address
#       --network    <testnet|futurenet|mainnet>  \
#       --admin      <ADMIN_G>           \  # G... expected admin address
#       [--policy-hash <64-hex-chars>]   \  # expected policy digest (optional)
#       [--agent-pubkey <64-hex-chars>]  \  # expected agent pubkey (optional)
#       [--rpc-url <url>]                \  # override the network preset
#
# Exit codes:
#   0 — all checks passed
#   1 — one or more checks failed (see output for details)
#   2 — usage error or missing dependency
#   3 — RPC transport / timeout failure
#
# Dependencies: agent-tx (from tools/agent-tx), jq
#
# Secret handling: this script requires NO secrets and prints NONE.
# It never reads AGENT_SECRET or any S... key; a surprising prompt for one
# means your shell has set AGENT_SECRET already — unset it before running.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS="✅ PASS"
FAIL="❌ FAIL"
SKIP="⬜ SKIP"

checks_passed=0
checks_failed=0

pass()  { echo "  $PASS  $*"; (( checks_passed++ )) || true; }
fail()  { echo "  $FAIL  $*" >&2; (( checks_failed++ )) || true; }
skip()  { echo "  $SKIP  $*"; }
info()  { echo "       $*"; }
title() { echo; echo "── $* ──"; }

die() { echo "ERROR: $*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

GUARD=""
NETWORK="testnet"
EXPECTED_ADMIN=""
EXPECTED_POLICY_HASH=""
EXPECTED_AGENT_PUBKEY=""
RPC_URL_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --guard)         GUARD="$2";                  shift 2 ;;
        --network)       NETWORK="$2";                shift 2 ;;
        --admin)         EXPECTED_ADMIN="$2";         shift 2 ;;
        --policy-hash)   EXPECTED_POLICY_HASH="$2";   shift 2 ;;
        --agent-pubkey)  EXPECTED_AGENT_PUBKEY="$2";  shift 2 ;;
        --rpc-url)       RPC_URL_FLAG="--rpc-url $2"; shift 2 ;;
        -h|--help)
            sed -n '2,/^set/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "Unknown flag: $1" ;;
    esac
done

[[ -n "$GUARD"          ]] || die "--guard is required"
[[ -n "$EXPECTED_ADMIN" ]] || die "--admin is required (the expected admin address G...)"

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

title "Dependency checks"

if command -v agent-tx >/dev/null 2>&1; then
    pass "agent-tx found at $(command -v agent-tx)"
else
    fail "agent-tx not found on PATH — build with: cargo build --release --manifest-path tools/agent-tx/Cargo.toml"
    exit 2
fi

if command -v jq >/dev/null 2>&1; then
    pass "jq found"
else
    fail "jq not found — install it (e.g. apt install jq / brew install jq)"
    exit 2
fi

# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

title "Input validation"

# Guard must be a C... StrKey (contract ID)
if [[ "$GUARD" =~ ^C[A-Z2-7]{55}$ ]]; then
    pass "Guard address is a well-formed C... contract ID"
else
    fail "Guard address '$GUARD' is not a valid C... StrKey — check for copy-paste errors"
fi

# Admin must be a G... StrKey (account ID)
if [[ "$EXPECTED_ADMIN" =~ ^G[A-Z2-7]{55}$ ]]; then
    pass "Expected admin address is a well-formed G... account ID"
else
    fail "Expected admin '$EXPECTED_ADMIN' is not a valid G... StrKey — check for copy-paste errors"
fi

# Policy hash — must be 64 lowercase hex chars if provided
if [[ -n "$EXPECTED_POLICY_HASH" ]]; then
    if [[ "$EXPECTED_POLICY_HASH" =~ ^[0-9a-f]{64}$ ]]; then
        pass "Expected policy hash is well-formed (64 lowercase hex)"
    else
        fail "Expected policy hash '$EXPECTED_POLICY_HASH' is not 64 lowercase hex characters"
    fi
fi

# Agent pubkey — must be 64 lowercase hex chars if provided
if [[ -n "$EXPECTED_AGENT_PUBKEY" ]]; then
    if [[ "$EXPECTED_AGENT_PUBKEY" =~ ^[0-9a-f]{64}$ ]]; then
        pass "Expected agent pubkey is well-formed (64 lowercase hex)"
    else
        fail "Expected agent pubkey '$EXPECTED_AGENT_PUBKEY' is not 64 lowercase hex characters"
    fi
fi

# Network must be a known preset (unless --rpc-url is set)
if [[ -z "$RPC_URL_FLAG" ]]; then
    case "$NETWORK" in
        testnet|futurenet|mainnet) pass "Network '$NETWORK' is a known preset" ;;
        *) fail "Network '$NETWORK' is not a known preset (testnet|futurenet|mainnet); use --rpc-url for a custom endpoint" ;;
    esac
fi

# Warn on mainnet: contract is unaudited
if [[ "$NETWORK" == "mainnet" ]]; then
    echo "  ⚠️  WARNING: this contract is UNAUDITED. Do not deploy to mainnet with real funds." >&2
fi

# ---------------------------------------------------------------------------
# Live state: call agent-tx verify
# ---------------------------------------------------------------------------

title "Live contract state (agent-tx verify — read-only, no secrets)"

VERIFY_ARGS=(--guard "$GUARD" --network "$NETWORK")
# shellcheck disable=SC2206
[[ -n "$RPC_URL_FLAG" ]] && VERIFY_ARGS+=($RPC_URL_FLAG)

VERIFY_OUTPUT=""
VERIFY_EXIT=0
VERIFY_OUTPUT=$(agent-tx verify "${VERIFY_ARGS[@]}" --json 2>/tmp/preflight-stderr.txt) || VERIFY_EXIT=$?

if [[ $VERIFY_EXIT -eq 3 || $VERIFY_EXIT -eq 4 ]]; then
    echo "  ❌ RPC failure (exit $VERIFY_EXIT). Cannot complete preflight." >&2
    cat /tmp/preflight-stderr.txt >&2
    exit 3
fi

if [[ $VERIFY_EXIT -ne 0 ]]; then
    echo "  ❌ agent-tx verify exited $VERIFY_EXIT:" >&2
    cat /tmp/preflight-stderr.txt >&2
    exit $VERIFY_EXIT
fi

pass "agent-tx verify completed successfully"

# ---------------------------------------------------------------------------
# Parse and check individual fields
# ---------------------------------------------------------------------------

title "Initialization check"

INITIALIZED=$(echo "$VERIFY_OUTPUT" | jq -r '.initialized // "null"')
if [[ "$INITIALIZED" == "true" ]]; then
    pass "Contract is initialized"
else
    fail "Contract is NOT initialized (initialized=$INITIALIZED) — run 'initialize' (deployment-runbook step 4)"
fi

title "Admin signer check"

ACTUAL_ADMIN=$(echo "$VERIFY_OUTPUT" | jq -r '.admin // "null"')
if [[ "$ACTUAL_ADMIN" == "null" ]]; then
    fail "Admin address is null — contract may not be initialized"
elif [[ "$ACTUAL_ADMIN" == "$EXPECTED_ADMIN" ]]; then
    pass "Admin matches expected: $ACTUAL_ADMIN"
else
    fail "Admin MISMATCH"
    info "  expected: $EXPECTED_ADMIN"
    info "  actual:   $ACTUAL_ADMIN"
    info "  → Rotate the key through docs/key-rotation.md if this was not intentional."
fi

title "Agent pubkey check"

ACTUAL_AGENT_PUBKEY=$(echo "$VERIFY_OUTPUT" | jq -r '.agent_pubkey // "null"')
if [[ -n "$EXPECTED_AGENT_PUBKEY" ]]; then
    if [[ "$ACTUAL_AGENT_PUBKEY" == "$EXPECTED_AGENT_PUBKEY" ]]; then
        pass "Agent pubkey matches expected"
    else
        fail "Agent pubkey MISMATCH"
        info "  expected: $EXPECTED_AGENT_PUBKEY"
        info "  actual:   $ACTUAL_AGENT_PUBKEY"
        info "  → Stop the agent loop; rotate the key through docs/key-rotation.md."
    fi
else
    skip "No expected agent pubkey provided — skipping (actual: $ACTUAL_AGENT_PUBKEY)"
fi

title "Policy hash check"

ACTUAL_POLICY_HASH=$(echo "$VERIFY_OUTPUT" | jq -r '.policy_hash // "null"')
HAS_POLICY=$(echo "$VERIFY_OUTPUT" | jq -r '.status.has_policy // "null"')

if [[ "$HAS_POLICY" == "true" ]]; then
    pass "Policy is installed (has_policy: true)"
else
    fail "No policy installed — account is default-deny. Run set_policy (deployment-runbook step 5)."
fi

if [[ -n "$EXPECTED_POLICY_HASH" ]]; then
    if [[ "$ACTUAL_POLICY_HASH" == "$EXPECTED_POLICY_HASH" ]]; then
        pass "Policy hash matches deployment record: $ACTUAL_POLICY_HASH"
    else
        # NO_POLICY_DIGEST is the well-known digest when no policy is set
        if [[ "$ACTUAL_POLICY_HASH" == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]]; then
            fail "Policy hash is NO_POLICY_DIGEST — no policy is set (expected $EXPECTED_POLICY_HASH)"
        else
            fail "Policy hash MISMATCH — policy may have changed since installation"
            info "  expected: $EXPECTED_POLICY_HASH"
            info "  actual:   $ACTUAL_POLICY_HASH"
            info "  → Compare against the intended set_policy transaction; if unexplained, pause the policy."
        fi
    fi
else
    skip "No expected policy hash provided — skipping (actual: $ACTUAL_POLICY_HASH)"
fi

title "Guard health checks"

ADMIN_FROZEN=$(echo "$VERIFY_OUTPUT"   | jq -r '.status.admin_frozen // "null"')
PAUSED=$(echo "$VERIFY_OUTPUT"         | jq -r '.status.paused // "null"')
HB_EXPIRED=$(echo "$VERIFY_OUTPUT"     | jq -r '.status.heartbeat_expired // "null"')
OUTSIDE_WINDOW=$(echo "$VERIFY_OUTPUT" | jq -r '.status.outside_active_window // "null"')

if [[ "$ADMIN_FROZEN" == "false" ]]; then
    pass "admin_frozen: false (guard is not frozen)"
elif [[ "$ADMIN_FROZEN" == "null" ]]; then
    skip "admin_frozen not in response"
else
    fail "admin_frozen: $ADMIN_FROZEN — run 'unfreeze' (admin) to clear"
fi

if [[ "$PAUSED" == "false" ]]; then
    pass "paused: false (guard is not paused)"
elif [[ "$PAUSED" == "null" ]]; then
    skip "paused not in response"
else
    fail "paused: $PAUSED — run set_policy with paused:false (admin)"
fi

if [[ "$HB_EXPIRED" == "false" || "$HB_EXPIRED" == "null" ]]; then
    pass "heartbeat_expired: false (dead-man switch is not triggered)"
else
    fail "heartbeat_expired: $HB_EXPIRED — start the agent heartbeat loop, then run 'unfreeze' (admin)"
fi

if [[ "$OUTSIDE_WINDOW" == "false" || "$OUTSIDE_WINDOW" == "null" ]]; then
    pass "outside_active_window: false (policy window covers current ledger time)"
else
    fail "outside_active_window: $OUTSIDE_WINDOW — run set_policy with a renewed active_from/active_until (admin)"
fi

# ---------------------------------------------------------------------------
# Network / ledger sanity
# ---------------------------------------------------------------------------

title "Network / ledger sanity"

ACTUAL_NETWORK=$(echo "$VERIFY_OUTPUT" | jq -r '.network // "null"')
LEDGER=$(echo "$VERIFY_OUTPUT"         | jq -r '.ledger // "null"')

if [[ "$ACTUAL_NETWORK" != "null" && "$ACTUAL_NETWORK" != "$NETWORK" && -z "$RPC_URL_FLAG" ]]; then
    fail "Network in response ('$ACTUAL_NETWORK') does not match --network ('$NETWORK')"
else
    pass "Network: $NETWORK  ledger: $LEDGER"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo
echo "═══════════════════════════════════════════"
echo "  Preflight summary"
echo "  Guard:   $GUARD"
echo "  Network: $NETWORK"
echo "  Checks passed: $checks_passed"
echo "  Checks failed: $checks_failed"
echo "═══════════════════════════════════════════"
echo

if [[ $checks_failed -eq 0 ]]; then
    echo "✅  All checks passed. Safe to proceed."
    exit 0
else
    echo "❌  $checks_failed check(s) failed. Resolve the issues above before deploying." >&2
    exit 1
fi
