#!/usr/bin/env bash
# Re-verify the recorded Phase-1 testnet fixtures against live Horizon and,
# when the ledgers are still retained, Soroban RPC events.
#
# This is deliberately a local/operator check, not part of the required CI
# gate: public network availability and RPC event retention change over time.
set -euo pipefail

readonly ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly INDEX="${ROOT_DIR}/tests/fixtures/index.json"

require_events=0
horizon=""
rpc=""

usage() {
  printf 'Usage: %s [--require-events] [--horizon URL] [--rpc URL]\n' "$0"
  printf '\n'
  printf 'Reads tests/fixtures/index.json. Horizon is authoritative for transaction\n'
  printf 'existence, success, ledger, and time; RPC getEvents is used for committed\n'
  printf 'guard events only while the fixture ledger is inside RPC retention.\n'
  printf '\n'
  printf '  --require-events  fail when a committed event cannot be re-queried\n'
  printf '                    (blocked scenarios stay informational: their events\n'
  printf '                    were diagnostic-only and were never committed)\n'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-events)
      require_events=1
      shift
      ;;
    --horizon)
      horizon="${2:-}"
      [[ -n "$horizon" ]] || { printf 'ERROR: --horizon needs a URL\n' >&2; exit 2; }
      shift 2
      ;;
    --rpc)
      rpc="${2:-}"
      [[ -n "$rpc" ]] || { printf 'ERROR: --rpc needs a URL\n' >&2; exit 2; }
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '[FAIL] required tool not found: %s\n' "$tool"
    exit 2
  fi
done

if [[ ! -f "$INDEX" ]]; then
  printf '[FAIL] fixture index is missing: %s\n' "$INDEX"
  exit 2
fi

schema="$(jq -r '.schema_version // empty' "$INDEX")"
if [[ "$schema" != "1" ]]; then
  printf '[FAIL] unsupported fixture schema_version=%s; expected 1\n' "${schema:-<missing>}"
  exit 1
fi

if [[ -z "$horizon" ]]; then
  horizon="$(jq -r '.network.horizon' "$INDEX")"
fi
if [[ -z "$rpc" ]]; then
  rpc="$(jq -r '.network.rpc' "$INDEX")"
fi
readonly expected_protocol="$(jq -r '.network.protocol' "$INDEX")"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

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

declare -A protocol_checked=()
rpc_checked=0
rpc_oldest=""
rpc_latest=""

check_protocol() {
  local ledger="$1"
  [[ -n "$ledger" ]] || return 0
  if [[ -n "${protocol_checked[$ledger]:-}" ]]; then
    return 0
  fi
  local out="${tmpdir}/ledger-${ledger}.json"
  local status
  status="$(curl -sS --max-time 20 -o "$out" -w '%{http_code}' "${horizon}/ledgers/${ledger}" || true)"
  if [[ "$status" != "200" ]]; then
    check_fail "historical ledger ${ledger} lookup returned HTTP ${status}"
    protocol_checked[$ledger]="fail"
    return 0
  fi
  local actual
  actual="$(jq -r '.protocol_version // empty' "$out")"
  if [[ "$actual" == "$expected_protocol" ]]; then
    check_pass "historical ledger ${ledger} protocol_version=${actual} matches index"
  else
    check_fail "historical ledger ${ledger} protocol_version=${actual:-<missing>} != index ${expected_protocol}"
  fi
  protocol_checked[$ledger]="checked"
}

check_tx() {
  local role="$1" hash="$2" ledger="$3" utc="$4"
  # Blocked scenarios deliberately have no hash; check_events reports their
  # diagnostic topics as informational gaps.
  [[ -n "$hash" ]] || return 0
  local out="${tmpdir}/tx-${hash}.json"
  local status
  status="$(curl -sS --max-time 20 -o "$out" -w '%{http_code}' "${horizon}/transactions/${hash}" || true)"
  if [[ "$status" != "200" ]]; then
    check_fail "${role}: tx ${hash} not found on Horizon (HTTP ${status})"
    return 0
  fi

  local actual_hash successful actual_ledger created_at
  actual_hash="$(jq -r '.id // empty' "$out")"
  successful="$(jq -r '.successful // empty' "$out")"
  actual_ledger="$(jq -r '.ledger // empty' "$out")"
  created_at="$(jq -r '.created_at // empty' "$out")"

  local problem=""
  if [[ "$actual_hash" != "$hash" ]]; then
    problem="${problem} id=${actual_hash:-<missing>}"
  fi
  if [[ "$successful" != "true" ]]; then
    problem="${problem} successful=${successful:-<missing>}"
  fi
  if [[ -n "$ledger" && "$actual_ledger" != "$ledger" ]]; then
    problem="${problem} ledger=${actual_ledger:-<missing>} expected=${ledger}"
  fi
  if [[ -n "$utc" && "$created_at" != *"$utc" ]]; then
    problem="${problem} created_at=${created_at:-<missing>} expected suffix=${utc}"
  fi

  if [[ -n "$problem" ]]; then
    check_fail "${role}: tx ${hash} Horizon mismatch:${problem}"
  else
    check_pass "${role} tx=${hash} successful=true ledger=${actual_ledger} created_at=${created_at}"
  fi
  if [[ -z "$ledger" ]]; then
    check_info "${role} index ledger was null; live ledger=${actual_ledger} created_at=${created_at}"
  fi
  check_protocol "$actual_ledger"
}

# XDR ScVal::Symbol topic encodings used by the recorded fixtures. The empty
# reason topic on an allowed decision is Symbol(""), not an absent topic.
symbol_topic() {
  case "$1" in
    '') printf '%s' 'AAAADwAAAAA=' ;;
    event_auth_checked) printf '%s' 'AAAADwAAABJldmVudF9hdXRoX2NoZWNrZWQAAA==' ;;
    allowed) printf '%s' 'AAAADwAAAAdhbGxvd2VkAA==' ;;
    blocked) printf '%s' 'AAAADwAAAAdibG9ja2VkAA==' ;;
    event_unfrozen) printf '%s' 'AAAADwAAAA5ldmVudF91bmZyb3plbgAA' ;;
    per_tx_cap_exceeded) printf '%s' 'AAAADwAAABNwZXJfdHhfY2FwX2V4Y2VlZGVkAA==' ;;
    window_cap_exceeded) printf '%s' 'AAAADwAAABN3aW5kb3dfY2FwX2V4Y2VlZGVkAA==' ;;
    recipient_not_allowed) printf '%s' 'AAAADwAAABVyZWNpcGllbnRfbm90X2FsbG93ZWQAAAA=' ;;
    heartbeat_expired) printf '%s' 'AAAADwAAABFoZWFydGJlYXRfZXhwaXJlZAAAAA==' ;;
    *) return 1 ;;
  esac
}

refresh_rpc_window() {
  if [[ "$rpc_checked" -eq 1 ]]; then
    return 0
  fi
  rpc_checked=1
  local out="${tmpdir}/get-health.json"
  local status
  status="$(
    curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' \
      -o "$out" -w '%{http_code}' "$rpc" || true
  )"
  if [[ "$status" != "200" ]]; then
    check_info "RPC event retention unavailable (HTTP ${status}); committed events were not re-queried"
    return 0
  fi
  rpc_oldest="$(jq -r '.result.oldestLedger // empty' "$out")"
  rpc_latest="$(jq -r '.result.latestLedger // empty' "$out")"
  if [[ -z "$rpc_oldest" || -z "$rpc_latest" ]]; then
    check_info "RPC getHealth returned no retention window; committed events were not re-queried"
    return 0
  fi
  check_info "RPC event retention oldest=${rpc_oldest} latest=${rpc_latest}"
}

check_events() {
  local role="$1" hash="$2" ledger="$3" topics_json="$4"
  if [[ -z "$hash" ]]; then
    check_info "${role}: no tx hash; topics ${topics_json} are diagnostic-only and were never committed"
    return 0
  fi
  if [[ -z "$topics_json" || "$topics_json" == "[]" ]]; then
    return 0
  fi

  refresh_rpc_window
  if [[ -z "$rpc_oldest" || -z "$rpc_latest" ]]; then
    if [[ "$require_events" -eq 1 ]]; then
      check_fail "${role}: --require-events set but RPC retention is unavailable"
    fi
    return 0
  fi
  if [[ -z "$ledger" ]] || (( ledger < rpc_oldest || ledger >= rpc_latest )); then
    local message="${role}: event topics not re-queried; ledger ${ledger:-unknown} outside RPC retention ${rpc_oldest}-${rpc_latest}"
    if [[ "$require_events" -eq 1 ]]; then
      check_fail "${message} (use an archive/indexer or a fresh fixture)"
    else
      check_info "$message"
    fi
    return 0
  fi

  local normalized
  normalized="$(
    jq -c 'if length == 2 and .[0] == "event_auth_checked" and .[1] == "allowed" then . + [""] else . end' \
      <<<"$topics_json"
  )"
  local encoded=()
  local symbol
  while IFS= read -r symbol; do
    if ! topic="$(symbol_topic "$symbol")"; then
      local message="${role}: no XDR topic encoder for symbol '${symbol}'"
      if [[ "$require_events" -eq 1 ]]; then
        check_fail "$message"
      else
        check_info "$message"
      fi
      return 0
    fi
    encoded+=("$topic")
  done < <(jq -r '.[]' <<<"$normalized")

  local topics_arg
  topics_arg="$(printf '%s\n' "${encoded[@]}" | jq -R . | jq -s -c .)"
  local payload
  payload="$(
    jq -nc \
      --arg guard "$(jq -r '.contracts.guard' "$INDEX")" \
      --argjson topics "$topics_arg" \
      --argjson start "$ledger" \
      --argjson end "$((ledger + 1))" \
      '{
        jsonrpc: "2.0", id: 1, method: "getEvents",
        params: {
          startLedger: $start,
          endLedger: $end,
          filters: [{
            type: "contract",
            contractIds: [$guard],
            topics: [$topics]
          }],
          pagination: {limit: 100}
        }
      }'
  )"
  local out="${tmpdir}/events-${hash}-${ledger}.json"
  local status
  status="$(
    curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
      -d "$payload" -o "$out" -w '%{http_code}' "$rpc" || true
  )"
  if [[ "$status" != "200" || -n "$(jq -r '.error // empty' "$out")" ]]; then
    local message="${role}: getEvents failed for ledger ${ledger}"
    if [[ "$require_events" -eq 1 ]]; then
      check_fail "$message"
    else
      check_info "$message"
    fi
    return 0
  fi
  local matches
  matches="$(jq -r --arg hash "$hash" '[.result.events[]? | select((.txHash // "") | ascii_downcase == $hash)] | length' "$out")"
  if [[ "$matches" -gt 0 ]]; then
    check_pass "${role}: committed event ${topics_json} confirmed at ledger ${ledger}"
  else
    check_fail "${role}: no committed event ${topics_json} for tx ${hash} at ledger ${ledger}"
  fi
}

printf 'Fixture live re-verification\n'
printf '%s\n' '============================'
printf 'Horizon: %s\n' "$horizon"
printf 'RPC: %s\n' "$rpc"
if [[ "$require_events" -eq 1 ]]; then
  printf '%s\n' 'Event mode: strict (--require-events)'
else
  printf '%s\n' 'Event mode: advisory (retention gaps are informational)'
fi
printf '\n'

# One row per fixture claim. Fields: role, tx, expected ledger, expected UTC,
# expected event topics. Null/absent values become empty strings. Allowed
# index topics are normalized to the canonical three-topic form by check_events.
while IFS=$'\037' read -r role hash ledger utc topics_json; do
  [[ -n "$role" ]] || continue
  check_tx "$role" "$hash" "$ledger" "$utc"
  check_events "$role" "$hash" "$ledger" "$topics_json"
done < <(
  jq -r '
    (
      .setup_transactions[]
      | ["setup:" + .step, .tx, (.ledger // "" | tostring), "", "[]"]
    ),
    (
      .scenarios[]
      | select(.tx != null)
      | [
          "scenario " + (.id | tostring),
          .tx,
          (.ledger // "" | tostring),
          (.recorded_utc // ""),
          (.event_topics // [] | tojson)
        ]
    ),
    (
      .scenarios[]
      | select(.tx == null)
      | [
          "scenario " + (.id | tostring) + " (blocked)",
          "",
          "",
          "",
          (.event_topics // [] | tojson)
        ]
    ),
    (
      .scenarios[]
      | select(.reversal != null)
      | [
          "scenario " + (.id | tostring) + " reversal",
          .reversal.tx,
          (.reversal.ledger // "" | tostring),
          "",
          (.reversal.event_topics // [] | tojson)
        ]
    ),
    (
      .scenarios[]
      | select(.post_reversal != null)
      | [
          "scenario " + (.id | tostring) + " post_reversal",
          .post_reversal.tx,
          (.post_reversal.ledger // "" | tostring),
          (.post_reversal.recorded_utc // ""),
          (["event_auth_checked", "allowed", ""] | tojson)
        ]
    ),
    (
      .supplemental_transactions[]
      | [
          "supplemental " + .label,
          .tx,
          (.ledger // "" | tostring),
          "",
          (["event_auth_checked", "allowed", ""] | tojson)
        ]
    )
    | join("\u001f")
  ' "$INDEX"
)

printf '\nSummary: %d passed, %d failed, %d informational\n' "$pass" "$fail" "$info"
if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
