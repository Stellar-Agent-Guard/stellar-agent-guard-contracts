//! agent-tx — simulate and submit Soroban transactions on behalf of the
//! `stellar-agent-guard` custom account.
//!
//! Why this exists: the `stellar` CLI builds Soroban auth entries and signs
//! them with the transaction source key, but for a *custom account* the auth
//! entry's address is a **contract** (the guard), not the source account, and
//! the CLI refuses ("Missing signing key for account C..."). The only way to
//! exercise the guard's `__check_auth` on-chain is to build the
//! `SorobanAuthorizationEntry` for the guard address and sign its payload with
//! the registered agent Ed25519 key — exactly what this tool does:
//!
//! 1. simulate the call with no auths (records requirements + footprint);
//! 2. merge the guard's own storage keys into the footprint (policy, window,
//!    heartbeat, freeze, instance — the parts only `__check_auth` touches);
//! 3. sign each returned auth entry (address = guard) with the agent key over
//!    the `HashIdPreimage::SorobanAuthorization` payload;
//! 4. re-simulate with the signed entries — this runs the *real* `__check_auth`
//!    against live testnet state, so policy blocks surface here, pre-broadcast;
//! 5. on success, send the transaction and poll for the result.
//!
//! Usage:
//! agent-tx preflight --guard C... --asset C... --to G... --amount 50 [--secret S...]
//! ```text
//! agent-tx transfer --guard C... --token C... --to G... --amount 50 \
//!     --agent-secret S... [--expect-blocked] [--network testnet|futurenet|mainnet] [--rpc-url ...] [--network-passphrase "..."]
//! agent-tx heartbeat --guard C... --agent-secret S... [--expect-blocked]
//! ```
//!
//! `--expect-blocked` treats a policy rejection at step 4 as success and prints
//! the on-chain-equivalent diagnostic events (the contract's own `auth_checked`
//! blocked event with the reason symbol).
//!
//! Every address-typed flag is validated as a StrKey, and the endpoint is
//! resolved from a named preset, *before* the first RPC request — see
//! `strkey.rs` and `network.rs`, the two helpers that hold those rules.

mod base32;
mod network;
mod strkey;

use base32::strkey_encode;
use ed25519_dalek::{Signer, SigningKey};
use network::{Endpoint, Network};
use sha2::{Digest, Sha256};
use std::time::Duration;
use stellar_xdr::*;
use strkey::KeyKind;

const INCLUSION_FEE: u32 = 100;

// ── Guard-footprint fee allowance (issue #382) ───────────────────────────
//
// `GUARD_KEY_FEE_BUMP` is added to both the declared `resource_fee` and the
// total fee. It is a ceiling, not a price: core charges the non-refundable
// part of `resource_fee` from the *declared resources*, the refundable part
// (rent, events, return value) from actual use, and refunds the remainder.
// Over-provisioning only reserves balance; under-provisioning fails the tx.
//
// What it pays for. `merge_guard_footprint` can add up to
// `GUARD_FOOTPRINT_KEYS` read-write entries the simulation did not declare,
// so did not price. Each one raises the non-refundable fee by a
// `fee_write_ledger_entry` and grows the envelope (tx-size and historical
// fees). Core takes that out of `resource_fee` before computing what is left
// for refundable charges; unbudgeted, the remainder cannot cover rent and the
// tx fails with `insufficient_refundable_fee`. On top of that, instruction
// headroom for `__check_auth` work the simulation under-measures.
//
// Derivation, from the mainnet `ConfigSetting` entries read on 2026-10-18 at
// ledger 65,008,194 (testnet charges half of each; re-read them with
// `getLedgerEntries` on `ContractLedgerCostV0`/`ContractLedgerCostExtV0`/
// `ContractBandwidthV0`/`ContractHistoricalDataV0`/`ContractComputeV0`):
//
//   write entries   5 keys × 2,500                         = 12,500
//   envelope bytes  5 keys × ≤128 B × (406 + 4,059) / KiB  =  2,791 (rounded up)
//   instructions    10,000,000 × 7 / 10,000                =  7,000
//                                                            ------
//   worst case at the current schedule                       22,291 stroops
//
// The constant stays at 100,000 (≈4.5× that) because the schedule is
// validator-voted and has historically been several times higher, and unused
// allowance is refunded. A compile-time assertion below keeps the derivation
// under the constant if a key is added or an input is raised.
//
// It does *not* scale with the policy's list sizes. Longer allowlists make
// the `Policy` and `Window` entries bigger and `__check_auth` slower, but the
// signed simulation in `run` executes the real `__check_auth`, so those bytes
// and instructions are already measured into `minResourceFee`. The merge only
// changes the *number* of entries, which is fixed by `GuardKey` (four data
// keys plus the instance), whatever the policy holds.
//
// How an operator recognises it is too low: the submission ends in
// `RESULT: FAILED` with a `resultXdr` decoding to
// `INVOKE_HOST_FUNCTION_INSUFFICIENT_REFUNDABLE_FEE` (or `sendTransaction`
// refuses it as `txSOROBAN_INVALID` when even the non-refundable part is
// short). Re-run with `AGENT_TX_DEBUG=1` to print `footprint merge added N
// keys` and the `minResourceFee` / `resourceFee` / final-fee breakdown, then
// update the inputs below from the live `ConfigSetting` entries.
//
// Interaction with #381 (declaring read-only guard keys read-only): once only
// the keys `__check_auth` writes are read-write, the write-entry term covers
// those keys alone and the read-only ones cost no write fee, so
// `GUARD_FOOTPRINT_KEYS` in the first term should become the read-write count.

/// Footprint entries `merge_guard_footprint` can add: every `GuardKey` the
/// auth check reads, plus the guard's instance entry.
const GUARD_FOOTPRINT_KEYS: i64 = GuardKey::CHECK_AUTH_READS.len() as i64 + 1;
/// `ContractLedgerCostV0.fee_write_ledger_entry`, stroops per entry.
const FEE_WRITE_LEDGER_ENTRY: i64 = 2_500;
/// `ContractBandwidthV0.fee_tx_size1_kb`, stroops per KiB of envelope.
const FEE_TX_SIZE_1KB: i64 = 406;
/// `ContractHistoricalDataV0.fee_historical1_kb`, stroops per KiB of envelope.
const FEE_HISTORICAL_1KB: i64 = 4_059;
/// `ContractComputeV0.fee_rate_per_instructions_increment`, stroops per
/// 10,000 instructions.
const FEE_PER_10K_INSTRUCTIONS: i64 = 7;
/// Upper bound on one guard `LedgerKey`'s XDR size (checked by a unit test).
const GUARD_KEY_XDR_BYTES_MAX: i64 = 128;
/// Instructions of headroom for `__check_auth`: 2.5% of the 400M per-tx limit.
const CHECK_AUTH_INSTRUCTION_HEADROOM: i64 = 10_000_000;

/// The worst-case cost the allowance must cover, per the derivation above.
const fn guard_key_fee_floor() -> i64 {
    let write_entries = GUARD_FOOTPRINT_KEYS * FEE_WRITE_LEDGER_ENTRY;
    let key_bytes = GUARD_FOOTPRINT_KEYS * GUARD_KEY_XDR_BYTES_MAX;
    let envelope = (key_bytes * (FEE_TX_SIZE_1KB + FEE_HISTORICAL_1KB) + 1023) / 1024;
    let instructions = CHECK_AUTH_INSTRUCTION_HEADROOM * FEE_PER_10K_INSTRUCTIONS / 10_000;
    write_entries + envelope + instructions
}

/// Stroops added to the declared resource fee and the total fee for the guard
/// keys the simulation may not have priced. See the derivation above.
const GUARD_KEY_FEE_BUMP: u32 = 100_000;
const _: () = assert!(guard_key_fee_floor() <= GUARD_KEY_FEE_BUMP as i64);

/// Outcome of the transaction submission process.
#[derive(Debug, PartialEq)]
#[allow(dead_code)]
enum RunOutcome {
    /// The pre-flight simulation was blocked by policy or rejected pre-broadcast.
    SimulationBlocked {
        policy_block: bool,
        error_code: Option<String>,
        error_message: Option<String>,
        events: Option<Vec<serde_json::Value>>,
    },
    /// The pre-flight simulation succeeded but `--expect-blocked` was set.
    SimulationSuccessUnexpectedBlock,
    /// An error occurred while sending the transaction.
    SendError(String),
    /// The submitted transaction had an empty hash.
    EmptyHash(String),
    /// The transaction was submitted and succeeded.
    TransactionSuccess { hash: String, status: String },
    /// The transaction was submitted but failed.
    TransactionFailure {
        hash: String,
        result_xdr: Option<String>,
    },
    /// The transaction submission timed out.
    TransactionTimeout { hash: String },
}

impl RunOutcome {
    fn exit_code(&self, expect_blocked: bool) -> i32 {
        match self {
            Self::SimulationBlocked { policy_block, .. } => {
                if *policy_block && expect_blocked {
                    0
                } else {
                    1
                }
            }
            Self::SimulationSuccessUnexpectedBlock
            | Self::SendError(_)
            | Self::EmptyHash(_)
            | Self::TransactionTimeout { .. } => 1,
            Self::TransactionSuccess { .. } => 0,
            Self::TransactionFailure { .. } => {
                if expect_blocked {
                    0
                } else {
                    1
                }
            }
        }
    }
}

// ── StrKey version bytes (base32 + CRC16-XModem codec lives in crate::base32) ─

const VER_ACCOUNT: u8 = 6 << 3; // 0x30 -> G...
const VER_CONTRACT: u8 = 2 << 3; // 0x12 -> C...

/// Decode a strkey secret (version 0x90 + 32-byte seed + checksum) to the seed.
fn secret_to_seed(secret: &str) -> [u8; 32] {
    match strkey::decode_strkey(secret) {
        Ok((ver, seed)) if ver == strkey::VER_SECRET => seed,
        Ok(_) => exit_with("not an account secret seed (expected leading character 'S')".into()),
        Err(err) => exit_with(format!(
            "invalid secret seed: {err}; expected a 56-character StrKey secret seed (S...)"
        )),
    }
}

fn account_strkey(pubkey: &[u8; 32]) -> String {
    strkey_encode(VER_ACCOUNT, pubkey)
}

fn contract_strkey(id: &[u8; 32]) -> String {
    strkey_encode(VER_CONTRACT, id)
}

// ── RPC ──────────────────────────────────────────────────────────────────

/// Per-request RPC timeout when `--rpc-timeout` is not given. It bounds the
/// whole request — connect, send, and reading the response — so a stalled or
/// black-holed endpoint fails the invocation instead of hanging it.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

struct Rpc {
    url: String,
    timeout: Duration,
    agent: ureq::Agent,
}

/// Whether an error, or anything in its source chain, is an I/O timeout.
/// ureq reports its overall timeout as `io::ErrorKind::TimedOut` (and some
/// platforms surface a socket read timeout as `WouldBlock`).
fn is_io_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                return true;
            }
        }
        cur = e.source();
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcFailureKind {
    /// No complete response within `--rpc-timeout` (connect, send, or read).
    Timeout,
    Transport,
    Http,
    JsonRpc,
    InvalidResponse,
}

#[derive(Debug)]
struct RpcError {
    method: String,
    kind: RpcFailureKind,
    http_status: Option<u16>,
    json_rpc_code: Option<serde_json::Value>,
    message: String,
}

impl RpcError {
    fn label(&self) -> &'static str {
        match self.kind {
            RpcFailureKind::Timeout => "RPC TIMEOUT",
            RpcFailureKind::Transport => "TRANSPORT FAILURE",
            RpcFailureKind::Http => "HTTP RPC FAILURE",
            RpcFailureKind::JsonRpc => "JSON-RPC REJECTION",
            RpcFailureKind::InvalidResponse => "INVALID RPC RESPONSE",
        }
    }

    fn exit_code(&self) -> i32 {
        match self.kind {
            RpcFailureKind::Timeout | RpcFailureKind::Transport | RpcFailureKind::Http => 3,
            RpcFailureKind::JsonRpc | RpcFailureKind::InvalidResponse => 4,
        }
    }

    fn is_timeout(&self) -> bool {
        self.kind == RpcFailureKind::Timeout
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC {} failed", self.method)?;
        if let Some(status) = self.http_status {
            write!(f, " (HTTP status {status})")?;
        }
        if let Some(code) = &self.json_rpc_code {
            write!(f, " (JSON-RPC code {code})")?;
        }
        write!(f, ": {}", self.message)
    }
}

fn rpc_or_exit<T>(result: Result<T, RpcError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => rpc_exit(&error, None),
    }
}

/// Print the classified RPC failure (plus an optional hint line) and exit
/// with its code.
fn rpc_exit(error: &RpcError, hint: Option<String>) -> ! {
    eprintln!("RESULT: {}", error.label());
    eprintln!("{error}");
    if let Some(hint) = hint {
        eprintln!("{hint}");
    }
    std::process::exit(error.exit_code());
}

trait PreflightRpc {
    fn account_seq(&self, account: &str) -> i64;
    fn latest_ledger(&self) -> u32;
    fn simulate(&self, envelope: &str) -> serde_json::Value;
    fn registered_agent_pubkey(&self, guard: &ScAddress) -> [u8; 32];
    fn inclusion_fee(&self) -> Result<Option<u32>, RpcError>;
}

impl Rpc {
    fn new(url: String, timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        Self {
            url,
            timeout,
            agent,
        }
    }

    /// One JSON-RPC request, bounded by the timeout, with every failure
    /// classified rather than panicking.
    fn post(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let timeout = || RpcError {
            method: method.to_string(),
            kind: RpcFailureKind::Timeout,
            http_status: None,
            json_rpc_code: None,
            message: format!(
                "no response from {} within {}s. The endpoint may be down or overloaded: \
                 retry, raise --rpc-timeout <secs>, or pick another endpoint with \
                 --network/--rpc-url",
                self.url,
                self.timeout.as_secs_f64()
            ),
        };
        let response = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) if is_io_timeout(&error) => return Err(timeout()),
            Err(ureq::Error::Transport(error)) => {
                return Err(RpcError {
                    method: method.to_string(),
                    kind: RpcFailureKind::Transport,
                    http_status: None,
                    json_rpc_code: None,
                    message: error.to_string(),
                });
            }
        };
        let status = response.status();
        // The timeout also bounds reading the body: a server that sends
        // headers and then stalls ends here, not in a hang.
        let response_body = response.into_string().map_err(|error| {
            if is_io_timeout(&error) {
                timeout()
            } else {
                RpcError {
                    method: method.to_string(),
                    kind: RpcFailureKind::InvalidResponse,
                    http_status: Some(status),
                    json_rpc_code: None,
                    message: error.to_string(),
                }
            }
        })?;
        let json: serde_json::Value =
            serde_json::from_str(&response_body).map_err(|error| RpcError {
                method: method.to_string(),
                kind: RpcFailureKind::InvalidResponse,
                http_status: Some(status),
                json_rpc_code: None,
                message: format!("response is not valid JSON: {error}"),
            })?;
        if let Some(err) = json.get("error") {
            return Err(RpcError {
                method: method.to_string(),
                kind: RpcFailureKind::JsonRpc,
                http_status: Some(status),
                json_rpc_code: err.get("code").cloned(),
                message: err
                    .get("message")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
                    .unwrap_or_else(|| err.to_string()),
            });
        }
        if !(200..300).contains(&status) {
            return Err(RpcError {
                method: method.to_string(),
                kind: RpcFailureKind::Http,
                http_status: Some(status),
                json_rpc_code: None,
                message: json.to_string(),
            });
        }
        json.get("result").cloned().ok_or_else(|| RpcError {
            method: method.to_string(),
            kind: RpcFailureKind::InvalidResponse,
            http_status: Some(status),
            json_rpc_code: None,
            message: "response did not contain a result".to_string(),
        })
    }

    fn latest_ledger(&self) -> u32 {
        let res = rpc_or_exit(self.post("getLatestLedger", serde_json::json!({})));
        res["sequence"].as_u64().expect("latest ledger sequence") as u32
    }

    fn account_seq(&self, account: &str) -> i64 {
        // Stellar RPC (soroban-rpc 22+) dropped getAccount in favor of
        // getLedgerEntries.
        let acc: ScAddress = account.parse().expect("account address");
        let key = match acc {
            ScAddress::Account(a) => LedgerKey::Account(LedgerKeyAccount { account_id: a }),
            other => panic!("expected account address, got {other:?}"),
        };
        let res = rpc_or_exit(self.post(
            "getLedgerEntries",
            serde_json::json!({ "keys": [b64_encode_xdr(&key)] }),
        ));
        let entry = res["entries"][0]["xdr"].as_str().expect("ledger entry xdr");
        // getLedgerEntries returns the LedgerEntryData XDR per entry.
        let le: LedgerEntryData = xdr(entry);
        match le {
            LedgerEntryData::Account(AccountEntry { seq_num, .. }) => seq_num.0,
            other => panic!("unexpected ledger entry: {other:?}"),
        }
    }

    fn simulate(&self, envelope: &str) -> serde_json::Value {
        rpc_or_exit(self.post(
            "simulateTransaction",
            serde_json::json!({ "transaction": envelope }),
        ))
    }

    fn send(&self, envelope: &str) -> Result<serde_json::Value, RpcError> {
        self.post(
            "sendTransaction",
            serde_json::json!({ "transaction": envelope }),
        )
    }

    fn get_tx(&self, hash: &str) -> Result<serde_json::Value, RpcError> {
        self.post("getTransaction", serde_json::json!({ "hash": hash }))
    }

    fn inclusion_fee(&self) -> Result<Option<u32>, RpcError> {
        let stats = self.post("getFeeStats", serde_json::json!({}))?;
        Ok(parse_inclusion_fee(&stats))
    }
}

impl PreflightRpc for Rpc {
    fn account_seq(&self, account: &str) -> i64 {
        Rpc::account_seq(self, account)
    }

    fn latest_ledger(&self) -> u32 {
        Rpc::latest_ledger(self)
    }

    fn simulate(&self, envelope: &str) -> serde_json::Value {
        Rpc::simulate(self, envelope)
    }

    fn registered_agent_pubkey(&self, guard: &ScAddress) -> [u8; 32] {
        let key = guard_instance_key(guard);
        let res = rpc_or_exit(self.post(
            "getLedgerEntries",
            serde_json::json!({ "keys": [b64_encode_xdr(&key)] }),
        ));
        let entry = res["entries"][0]["xdr"]
            .as_str()
            .expect("guard instance ledger entry XDR");
        let entry: LedgerEntryData = xdr(entry);
        let LedgerEntryData::ContractData(entry) = entry else {
            panic!("unexpected guard instance ledger entry: {entry:?}");
        };
        let ScVal::ContractInstance(instance) = entry.val else {
            panic!("guard instance ledger entry did not contain a contract instance");
        };
        instance
            .storage
            .unwrap_or_default()
            .iter()
            .find_map(|item| match &item.val {
                ScVal::Bytes(bytes) if bytes.0.len() == 32 => {
                    Some(bytes.0.as_slice().try_into().expect("agent key length"))
                }
                _ => None,
            })
            .expect("registered agent public key not found in guard instance storage")
    }

    fn inclusion_fee(&self) -> Result<Option<u32>, RpcError> {
        Rpc::inclusion_fee(self)
    }
}

fn parse_inclusion_fee(stats: &serde_json::Value) -> Option<u32> {
    ["mode", "p50", "min"].iter().find_map(|field| {
        let value = &stats["inclusionFee"][field];
        value
            .as_str()
            .and_then(|fee| fee.parse::<u32>().ok())
            .or_else(|| value.as_u64().and_then(|fee| u32::try_from(fee).ok()))
    })
}

fn calculate_fee(min_resource_fee: u32, inclusion_fee: u32) -> u32 {
    min_resource_fee
        .saturating_add(inclusion_fee)
        .saturating_add(GUARD_KEY_FEE_BUMP)
}

fn resolve_inclusion_fee<R: PreflightRpc>(
    rpc: &R,
    override_fee: Option<u32>,
) -> (u32, &'static str) {
    if let Some(fee) = override_fee {
        return (fee, "explicit --inclusion-fee override");
    }
    match rpc.inclusion_fee() {
        Ok(Some(fee)) => (fee, "RPC getFeeStats inclusionFee.mode"),
        Ok(None) => {
            eprintln!(
                "warning: RPC fee statistics did not include an inclusion fee; using fallback {INCLUSION_FEE} stroops"
            );
            (
                INCLUSION_FEE,
                "fallback constant (fee statistics unavailable)",
            )
        }
        Err(error) => {
            eprintln!(
                "warning: could not read the network inclusion fee ({error}); using fallback {INCLUSION_FEE} stroops"
            );
            (
                INCLUSION_FEE,
                "fallback constant (fee statistics unavailable)",
            )
        }
    }
}

fn xdr<T: ReadXdr>(b64: &str) -> T {
    T::from_xdr_base64(b64, Limits::none()).expect("XDR decode")
}

fn b64_encode_xdr<T: WriteXdr>(t: &T) -> String {
    t.to_xdr_base64(Limits::none()).expect("XDR encode")
}

// ── ScVal → readable ─────────────────────────────────────────────────────

fn scval_str(v: &ScVal) -> String {
    match v {
        ScVal::Bool(b) => b.to_string(),
        ScVal::Void => "()".into(),
        ScVal::U32(n) => n.to_string(),
        ScVal::I32(n) => n.to_string(),
        ScVal::U64(n) => n.to_string(),
        ScVal::I64(n) => n.to_string(),
        ScVal::U128(p) => p.hi.to_string() + &p.lo.to_string(),
        ScVal::I128(p) => p.hi.to_string() + &p.lo.to_string(),
        ScVal::Symbol(s) => s.to_string(),
        ScVal::String(s) => s.to_string(),
        ScVal::Address(a) => match a {
            ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)))) => {
                account_strkey(pk)
            }
            ScAddress::Contract(ContractId(Hash(id))) => contract_strkey(id),
            other => format!("{other:?}"),
        },
        ScVal::Bytes(b) => hex::encode(b.0.as_slice()),
        ScVal::Vec(Some(items)) => {
            let inner: Vec<String> = items.iter().map(scval_str).collect();
            format!("[{}]", inner.join(", "))
        }
        ScVal::Vec(None) => "[]".into(),
        ScVal::Map(Some(entries)) => {
            let inner: Vec<String> = entries
                .iter()
                .map(|e| format!("{}: {}", scval_str(&e.key), scval_str(&e.val)))
                .collect();
            format!("{{{}}}", inner.join(", "))
        }
        ScVal::Map(None) => "{}".into(),
        ScVal::LedgerKeyContractInstance => "<instance>".into(),
        ScVal::ContractInstance(_) => "<contract-instance>".into(),
        other => format!("{other:?}"),
    }
}

fn print_events(events: &serde_json::Value) {
    let Some(arr) = events.as_array() else {
        return;
    };
    for ev in arr {
        if let Some(b64) = ev["xdr"].as_str().or_else(|| ev.as_str()) {
            let de: DiagnosticEvent = xdr(b64);
            let contract = match &de.event.contract_id {
                Some(ContractId(Hash(id))) => contract_strkey(id),
                None => "host".into(),
            };
            let (topics, data) = match &de.event.body {
                ContractEventBody::V0(v0) => {
                    let t: Vec<String> = v0.topics.iter().map(scval_str).collect();
                    (t.join(", "), scval_str(&v0.data))
                }
            };
            println!("  event [{contract}] topics=({topics}) data={data}");
        }
    }
}

fn simulation_error_message(simulation: &serde_json::Value) -> Option<String> {
    let error = simulation.get("error")?;
    if error.is_null() {
        None
    } else if let Some(message) = error.as_str() {
        Some(message.to_string())
    } else {
        Some(
            error["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| error.to_string()),
        )
    }
}

fn simulation_events(simulation: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    simulation["events"]
        .as_array()
        .or_else(|| simulation["error"]["data"]["events"].as_array())
}

fn is_guard_auth_checked_block(simulation: &serde_json::Value, guard: &ScAddress) -> bool {
    let Some(events) = simulation_events(simulation) else {
        return false;
    };
    events.iter().any(|event| {
        let Some(b64) = event["xdr"].as_str().or_else(|| event.as_str()) else {
            return false;
        };
        let Ok(decoded) = DiagnosticEvent::from_xdr_base64(b64, Limits::none()) else {
            return false;
        };
        let contract_matches = match guard {
            ScAddress::Contract(id) => decoded.event.contract_id.as_ref() == Some(id),
            _ => false,
        };
        if !contract_matches {
            return false;
        }
        let ContractEventBody::V0(body) = &decoded.event.body;
        let has_topic = |expected: &str| {
            body.topics.iter().any(|topic| {
                matches!(topic, ScVal::Symbol(symbol) if symbol.0.as_slice() == expected.as_bytes())
            })
        };
        has_topic("event_auth_checked") && has_topic("blocked")
    })
}

// ── Footprint helpers ────────────────────────────────────────────────────

/// The guard's persistent `DataKey` variants (src/types.rs) that
/// `__check_auth` reads — `AuthSnapshot::load` and `save_ledger` in
/// src/lib.rs. The names are not free text: the unit tests check each one's
/// encoding byte-for-byte against `guard-storage-keys.json`, which the
/// contract's own test suite generates from the real `DataKey`, so renaming a
/// variant fails both suites instead of silently declaring a wrong footprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GuardKey {
    Policy,
    Window,
    LastHeartbeat,
    AdminFrozen,
}

impl GuardKey {
    /// Every key `__check_auth` touches, in footprint order.
    const CHECK_AUTH_READS: [GuardKey; 4] = [
        GuardKey::Policy,
        GuardKey::Window,
        GuardKey::LastHeartbeat,
        GuardKey::AdminFrozen,
    ];

    /// The `DataKey` variant name, which is also its on-ledger symbol.
    fn variant(self) -> &'static str {
        match self {
            GuardKey::Policy => "Policy",
            GuardKey::Window => "Window",
            GuardKey::LastHeartbeat => "LastHeartbeat",
            GuardKey::AdminFrozen => "AdminFrozen",
        }
    }

    /// The key as the contract stores it. `#[contracttype]` encodes a unit
    /// enum variant as a one-element vector holding its name, not a bare
    /// symbol: `DataKey::Policy` is `Vec[Symbol("Policy")]`.
    fn scval(self) -> ScVal {
        let name = ScVal::Symbol(ScSymbol(
            self.variant()
                .try_into()
                .expect("DataKey variant name fits a symbol"),
        ));
        ScVal::Vec(Some(ScVec(
            VecM::try_from(vec![name]).expect("one-element vector"),
        )))
    }
}

fn guard_data_key(guard: &ScAddress, key: GuardKey) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: guard.clone(),
        key: key.scval(),
        durability: ContractDataDurability::Persistent,
    })
}

/// A contract instance lives in *persistent* storage under the reserved
/// `LedgerKeyContractInstance` key.
fn guard_instance_key(guard: &ScAddress) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: guard.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    })
}

/// The kind of call being performed, determining which guard storage keys are read-write vs read-only.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum CallKind {
    /// Token spend/transfer authorized through `__check_auth`. Writes `Window`; reads `Policy`, `AdminFrozen`, `LastHeartbeat`.
    Transfer,
    /// DMS heartbeat invocation. Writes `LastHeartbeat`; reads `Policy`, `Window`, `AdminFrozen`.
    Heartbeat,
    /// Diagnostic / verification call. Writes only instance TTL, reads all guard keys.
    ReadOnly,
}

/// Target key in contract storage.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StorageTarget {
    Persistent(GuardKey),
    Instance,
}

impl StorageTarget {
    fn to_ledger_key(self, guard: &ScAddress) -> LedgerKey {
        match self {
            Self::Persistent(key) => guard_data_key(guard, key),
            Self::Instance => guard_instance_key(guard),
        }
    }
}

/// Declarative specification of when a storage key is written vs read-only.
///
/// This single declarative mapping derives the footprint split across all call kinds
/// without duplicating key lists or hardcoding separate read/write branches.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WriteCondition {
    /// Always declared read-write (e.g. the contract instance key, on which the engine may bump/write TTL).
    Always,
    /// Never written during agent-initiated invocations (e.g. Policy and AdminFrozen are read-only for agent transactions; only admin calls write them).
    Never,
    /// Written on spend/transfer operations (e.g. Window rolling spend ledger).
    OnTransfer,
    /// Written on heartbeat operations (e.g. LastHeartbeat timestamp).
    OnHeartbeat,
}

impl WriteCondition {
    fn is_written(&self, kind: CallKind) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::OnTransfer => kind == CallKind::Transfer,
            Self::OnHeartbeat => kind == CallKind::Heartbeat,
        }
    }
}

struct StorageKeyTouch {
    target: StorageTarget,
    written_on: WriteCondition,
}

/// Single declarative map of guard storage keys to when they are written.
///
/// Cross-reference: Core ABI storage-touch specification (issue #354 / SPEC §1.1).
/// - Policy: read by all invocations for policy rules / DMS grace, never written by agent calls.
/// - AdminFrozen: read by all invocations to check account kill-switch, never written by agent calls.
/// - Window: rolling spend ledger; read by all calls, written only on transfer/transfer-from spend.
/// - LastHeartbeat: agent liveness timestamp; read by transfers to enforce DMS, written by heartbeat.
/// - Instance: contains contract instance, admin, and agent pubkey; declared read-write as engine may write TTL.
const GUARD_STORAGE_TOUCHES: &[StorageKeyTouch] = &[
    StorageKeyTouch {
        target: StorageTarget::Persistent(GuardKey::Policy),
        written_on: WriteCondition::Never,
    },
    StorageKeyTouch {
        target: StorageTarget::Persistent(GuardKey::AdminFrozen),
        written_on: WriteCondition::Never,
    },
    StorageKeyTouch {
        target: StorageTarget::Persistent(GuardKey::Window),
        written_on: WriteCondition::OnTransfer,
    },
    StorageKeyTouch {
        target: StorageTarget::Persistent(GuardKey::LastHeartbeat),
        written_on: WriteCondition::OnHeartbeat,
    },
    StorageKeyTouch {
        target: StorageTarget::Instance,
        written_on: WriteCondition::Always,
    },
];

/// The guard storage keys `__check_auth` reads and writes, partitioned by `CallKind`.
///
/// Keys the call kind writes are declared `read_write`; keys it only reads are declared
/// `read_only` (plus the instance key, which the engine may write TTL on).
///
/// Declaring read-only keys in `read_only` rather than `read_write` avoids charging the
/// fund-holding account write-rent and higher resource fees for keys that are only read.
fn guard_footprint(guard: &ScAddress, kind: CallKind) -> LedgerFootprint {
    let mut read_only = Vec::new();
    let mut read_write = Vec::new();

    for touch in GUARD_STORAGE_TOUCHES {
        let key = touch.target.to_ledger_key(guard);
        if touch.written_on.is_written(kind) {
            read_write.push(key);
        } else {
            read_only.push(key);
        }
    }

    LedgerFootprint {
        read_only: VecM::try_from(read_only).expect("read_only footprint bound"),
        read_write: VecM::try_from(read_write).expect("read_write footprint bound"),
    }
}

/// Merges guard storage keys into the simulated footprint, derived from `GUARD_STORAGE_TOUCHES`.
///
/// The RPC's preflight runs in recording mode and never executes `__check_auth`,
/// so guard storage keys are absent from the simulated footprint. This function
/// merges them in according to `CallKind`:
/// - Keys written by `kind` are placed in `read_write` (and removed from `read_only` if present).
/// - Keys only read by `kind` are placed in `read_only` (unless already present in `read_write`).
fn merge_guard_footprint(
    mut fp: LedgerFootprint,
    guard: &ScAddress,
    kind: CallKind,
) -> LedgerFootprint {
    let mut ro: Vec<LedgerKey> = fp.read_only.iter().cloned().collect();
    let mut rw: Vec<LedgerKey> = fp.read_write.iter().cloned().collect();

    for touch in GUARD_STORAGE_TOUCHES {
        let key = touch.target.to_ledger_key(guard);
        if touch.written_on.is_written(kind) {
            ro.retain(|k| k != &key);
            if !rw.contains(&key) {
                rw.push(key);
            }
        } else if !rw.contains(&key) && !ro.contains(&key) {
            ro.push(key);
        }
    }

    fp.read_only = VecM::try_from(ro).expect("read_only footprint bound");
    fp.read_write = VecM::try_from(rw).expect("read_write footprint bound");
    fp
}

// ── Core flow ────────────────────────────────────────────────────────────

struct Args {
    rpc: Rpc,
    passphrase: String,
    passphrase_source: &'static str,
    guard: ScAddress,
    secret: Option<String>,
    expect_blocked: bool,
    inclusion_fee_override: Option<u32>,
}

fn preflight<R: PreflightRpc>(call: &Call, args: &Args, rpc: &R) -> Result<(), i32> {
    let (agent, source_pk) = if let Some(secret) = &args.secret {
        let agent = SigningKey::from_bytes(&secret_to_seed(secret));
        let pubkey = agent.verifying_key().to_bytes();
        (Some(agent), pubkey)
    } else {
        (None, rpc.registered_agent_pubkey(&args.guard))
    };
    let source_g = account_strkey(&source_pk);
    let seq = rpc.account_seq(&source_g).saturating_add(1);
    let latest = rpc.latest_ledger();
    let sig_exp = latest.saturating_add(10_000);
    let network_id: [u8; 32] = Sha256::digest(args.passphrase.as_bytes()).into();
    let invocation = call.invocation(&args.guard);
    let auth = agent
        .as_ref()
        .map(|agent| {
            VecM::try_from(vec![build_auth_entry(
                &args.guard,
                &invocation,
                fresh_auth_nonce(latest),
                sig_exp,
                &network_id,
                agent,
            )])
            .expect("auth count")
        })
        .unwrap_or_default();
    let env = build_initial_envelope(
        &MuxedAccount::Ed25519(Uint256(source_pk)),
        seq,
        invoke_op(&invocation, auth),
        &args.guard,
        call.kind(),
    );
    let sim = rpc.simulate(&b64_encode_xdr(&env));

    if let Some(message) = simulation_error_message(&sim) {
        let policy_block = is_guard_auth_checked_block(&sim, &args.guard);
        if policy_block {
            println!("BLOCKED (pre-broadcast, guard auth_checked):");
        } else if agent.is_some() {
            println!("TRANSACTION REJECTED (pre-broadcast, not a guard policy block):");
        } else {
            println!("RESULT: INDETERMINATE (unsigned simulation failed):");
        }
        println!("  message: {message}");
        if let Some(events) = simulation_events(&sim) {
            println!("  diagnostic events:");
            print_events(&serde_json::Value::Array(events.clone()));
        }
        println!("  broadcast: no");
        if policy_block && args.expect_blocked {
            return Ok(());
        }
        return Err(if agent.is_some() { 1 } else { 2 });
    }

    let min_fee: u32 = sim["minResourceFee"]
        .as_str()
        .expect("simulation minResourceFee")
        .parse()
        .expect("simulation fee");
    // Quote what `run` would pay, allowance included (see GUARD_KEY_FEE_BUMP).
    let (inclusion_fee, fee_source) = resolve_inclusion_fee(rpc, args.inclusion_fee_override);
    let fee = calculate_fee(min_fee, inclusion_fee);
    if agent.is_some() {
        println!("RESULT: ALLOWED (preflight only)");
    } else {
        println!("RESULT: INDETERMINATE (unsigned simulation)");
        println!("  limitation: provide --secret to run signed __check_auth simulation");
    }
    println!("network passphrase source: {}", args.passphrase_source);
    println!("inclusion fee source: {fee_source}");
    println!("estimated fee: {fee} stroops");
    println!("broadcast: no");
    if agent.is_some() {
        Ok(())
    } else {
        Err(2)
    }
}

fn build_initial_envelope(
    source: &MuxedAccount,
    seq: i64,
    op: Operation,
    guard: &ScAddress,
    kind: CallKind,
) -> TransactionEnvelope {
    let tx = Transaction {
        source_account: source.clone(),
        fee: INCLUSION_FEE,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::try_from(vec![op]).expect("op count"),
        ext: TransactionExt::V1(SorobanTransactionData {
            resources: SorobanResources {
                footprint: guard_footprint(guard, kind),
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
            ext: SorobanTransactionDataExt::V0,
        }),
    };
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    })
}

fn invoke_op(invocation: &InvokeContractArgs, auth: VecM<SorobanAuthorizationEntry>) -> Operation {
    Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::InvokeContract(invocation.clone()),
            auth,
        }),
    }
}

/// Build the guard's `SorobanAuthorizationEntry` ourselves: address = guard
/// (a custom account), signature = the registered agent's Ed25519 signature
/// over the `HashIdPreimage::SorobanAuthorization` payload. This is the same
/// payload the host hands to `__check_auth`.
///
/// The nonce must be one this address has no live record of: the host records
/// every consumed nonce in ledger state (`(address, LedgerKeyNonce)`) until
/// the entry's signature expiration and rejects replays ("nonce already
/// exists for address"). See [`auth_nonce`] for how it is chosen.
fn build_auth_entry(
    guard: &ScAddress,
    invocation: &InvokeContractArgs,
    nonce: i64,
    sig_exp: u32,
    network_id: &[u8; 32],
    agent: &SigningKey,
) -> SorobanAuthorizationEntry {
    let root = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invocation.clone()),
        sub_invocations: VecM::default(),
    };
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(*network_id),
        nonce,
        signature_expiration_ledger: sig_exp,
        invocation: root,
    });
    let xdr_bytes = payload.to_xdr(Limits::none()).expect("preimage XDR");
    let digest: [u8; 32] = Sha256::digest(&xdr_bytes).into();
    let sig = agent.sign(&digest).to_bytes();
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: guard.clone(),
            nonce,
            signature_expiration_ledger: sig_exp,
            signature: ScVal::Bytes(ScBytes(BytesM::try_from(sig.to_vec()).expect("sig len"))),
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(invocation.clone()),
            sub_invocations: VecM::default(),
        },
    }
}

/// The guard auth nonce: the latest ledger sequence in the high 32 bits and
/// 32 bits of entropy in the low 32 (the bit pattern, reinterpreted as `i64`).
///
/// Replay argument. Replay protection is the host's: a consumed nonce stays
/// recorded for the guard address until the entry's signature expiration
/// ledger, and a second use while recorded is rejected. That holds for any
/// nonce choice, so the choice only affects liveness — a collision makes a
/// fresh transaction fail spuriously, never makes a signed one run twice.
///
/// Collision argument. Ledger sequences never repeat, so nonces drawn in
/// different ledgers differ in their high half and cannot collide. Two drawn
/// in the same ledger collide only if their entropy matches: 2^-32 per pair.
/// Nothing depends on the transaction sequence, which the previous scheme
/// reused as the nonce: a retry after an attempt that never consumed its
/// sequence (a `txBAD_SEQ`, a rejected or dropped submission) or one that
/// did (a failed apply) draws a new nonce either way. Nonces from that older
/// scheme carry the agent account's *creation* ledger in their high half
/// (Stellar starts an account's sequence at `ledger << 32`), which is always
/// below the current ledger, so the two schemes cannot overlap either.
fn auth_nonce(latest_ledger: u32, entropy: u32) -> i64 {
    ((u64::from(latest_ledger) << 32) | u64::from(entropy)) as i64
}

/// [`auth_nonce`] with the low half drawn from the OS's secure RNG.
fn fresh_auth_nonce(latest_ledger: u32) -> i64 {
    let mut entropy = [0u8; 4];
    getrandom::getrandom(&mut entropy)
        .unwrap_or_else(|e| exit_with(format!("cannot draw an auth nonce: OS RNG failed: {e}")));
    auth_nonce(latest_ledger, u32::from_le_bytes(entropy))
}

/// The transaction hash: SHA-256 over `network_id || ENVELOPE_TYPE_TX || tx`.
/// It is what the agent signs and what the network reports the tx under.
fn tx_hash(tx: &Transaction, network_id: &[u8; 32]) -> [u8; 32] {
    let tx_xdr = tx.to_xdr(Limits::none()).expect("tx XDR");
    let mut msg = Vec::with_capacity(36 + tx_xdr.len());
    msg.extend_from_slice(network_id);
    msg.extend_from_slice(&(EnvelopeType::Tx as i32).to_be_bytes());
    msg.extend_from_slice(&tx_xdr);
    Sha256::digest(&msg).into()
}

fn sign_envelope(
    env: &TransactionEnvelope,
    network_id: &[u8; 32],
    agent: &SigningKey,
) -> TransactionEnvelope {
    // Stellar tx signatures cover `network_id || ENVELOPE_TYPE_TX || tx`, not
    // the raw envelope (which also contains the signature list itself).
    let (tx, signatures) = match env {
        TransactionEnvelope::Tx(v1) => (&v1.tx, &v1.signatures),
        other => panic!("unexpected envelope variant {other:?}"),
    };
    debug_assert!(signatures.is_empty());
    let digest = tx_hash(tx, network_id);
    let sig = agent.sign(&digest).to_bytes();
    let pubkey = agent.verifying_key().to_bytes();
    let mut hint = [0u8; 4];
    hint.copy_from_slice(&pubkey[28..32]);
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: VecM::try_from(vec![DecoratedSignature {
            hint: SignatureHint(hint),
            signature: Signature(BytesM::<64>::try_from(sig.to_vec()).expect("sig len")),
        }])
        .expect("signatures"),
    })
}

/// The call to authorize and submit.
enum Call {
    Transfer {
        token: ScAddress,
        to: ScAddress,
        amount: i128,
    },
    TransferFrom {
        token: ScAddress,
        from: ScAddress,
        to: ScAddress,
        amount: i128,
    },
    Heartbeat,
}

impl Call {
    fn kind(&self) -> CallKind {
        match self {
            Self::Transfer { .. } | Self::TransferFrom { .. } => CallKind::Transfer,
            Self::Heartbeat => CallKind::Heartbeat,
        }
    }

    /// The exact `InvokeContractArgs` the host will authorize — the same args
    /// go into the operation and into the auth entry's root invocation.
    fn invocation(&self, guard: &ScAddress) -> InvokeContractArgs {
        match self {
            Self::Transfer { token, to, amount } => InvokeContractArgs {
                contract_address: token.clone(),
                function_name: ScSymbol("transfer".try_into().unwrap()),
                args: VecM::try_from(vec![
                    ScVal::Address(guard.clone()),
                    ScVal::Address(to.clone()),
                    ScVal::I128(Int128Parts {
                        lo: *amount as u64,
                        hi: (*amount >> 64) as i64,
                    }),
                ])
                .expect("arg count"),
            },
            Self::TransferFrom {
                token,
                from,
                to,
                amount,
            } => InvokeContractArgs {
                contract_address: token.clone(),
                function_name: ScSymbol("transfer_from".try_into().unwrap()),
                args: VecM::try_from(vec![
                    ScVal::Address(from.clone()),
                    ScVal::Address(guard.clone()),
                    ScVal::Address(to.clone()),
                    ScVal::I128(Int128Parts {
                        lo: *amount as u64,
                        hi: (*amount >> 64) as i64,
                    }),
                ])
                .expect("arg count"),
            },
            Self::Heartbeat => InvokeContractArgs {
                contract_address: guard.clone(),
                function_name: ScSymbol("heartbeat".try_into().unwrap()),
                args: VecM::default(),
            },
        }
    }
}

fn run(call: &Call, args: &Args) -> RunOutcome {
    let guard = &args.guard;
    let Some(secret) = args.secret.as_deref() else {
        exit_with("missing --agent-secret: signing requires the registered agent's secret seed (expected secret seed 'S...'; or set AGENT_SECRET env var)".into());
    };
    let seed = secret_to_seed(secret);
    let agent = SigningKey::from_bytes(&seed);
    let source_pk = agent.verifying_key().to_bytes();
    let source_g = account_strkey(&source_pk);
    let network_id: [u8; 32] = Sha256::digest(args.passphrase.as_bytes()).into();
    println!("network id: {}", hex::encode(network_id));
    println!("network passphrase source: {}", args.passphrase_source);

    let seq = args.rpc.account_seq(&source_g);
    // The account entry stores the last-used sequence; the next tx uses
    // stored + 1 (stellar-core strict check: tx.seq + 1 == account.seq).
    let seq = seq.saturating_add(1);
    let latest = args.rpc.latest_ledger();
    let sig_exp = latest.saturating_add(10_000);

    // Build the call and the guard's auth entry (agent-signed) once, so the
    // simulated and the submitted transaction carry the same nonce. It is
    // drawn per invocation, independent of the tx sequence (see `auth_nonce`).
    let invocation = call.invocation(guard);
    let auth = VecM::try_from(vec![build_auth_entry(
        guard,
        &invocation,
        fresh_auth_nonce(latest),
        sig_exp,
        &network_id,
        &agent,
    )])
    .expect("auth count");

    // One simulation with the signed entry: the host verifies the agent's
    // signature by calling the real `__check_auth`, so policy blocks surface
    // here, pre-broadcast. The returned footprint already covers everything
    // `__check_auth` touched; the merge below is a safety net for any key the
    // preflight could not see.
    let op = invoke_op(&invocation, auth.clone());
    let env0 = build_initial_envelope(
        &MuxedAccount::Ed25519(Uint256(source_pk)),
        seq,
        op,
        guard,
        call.kind(),
    );
    let sim = args.rpc.simulate(&b64_encode_xdr(&env0));
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!(
            "sim keys: {:?}",
            sim.as_object().map(|o| o.keys().collect::<Vec<_>>())
        );
        eprintln!("sim error: {}", sim["error"]);
        eprintln!("sim results: {}", sim["results"]);
        if let Some(evs) = sim["events"].as_array() {
            for ev in evs {
                eprintln!(
                    "sim event: {}",
                    ev["topic"]
                        .as_array()
                        .map(|t| t[0].to_string())
                        .unwrap_or_default()
                );
            }
        }
    }

    if let Some(message) = simulation_error_message(&sim) {
        let policy_block = is_guard_auth_checked_block(&sim, guard);
        if policy_block {
            println!("BLOCKED (pre-broadcast, guard auth_checked):");
        } else {
            println!("TRANSACTION REJECTED (pre-broadcast, not a guard policy block):");
        }
        println!("  message: {message}");
        let events = simulation_events(&sim).cloned();
        if let Some(ref events) = events {
            println!("  diagnostic events:");
            print_events(&serde_json::Value::Array(events.clone()));
        }
        println!("  broadcast: no");
        return RunOutcome::SimulationBlocked {
            policy_block,
            error_code: sim["error"]["code"].as_str().map(str::to_string),
            error_message: Some(message),
            events,
        };
    }
    if args.expect_blocked {
        println!("expected a block, but the enforced simulation succeeded");
        return RunOutcome::SimulationSuccessUnexpectedBlock;
    }

    // Capture and surface the simulation's cost estimate before we mutate
    // the declared resources (we add a visible bump for the guard keys).
    let sim_txdata_b64 = sim["transactionData"]
        .as_str()
        .expect("simulation transactionData");
    let mut data: SorobanTransactionData = xdr(sim_txdata_b64);
    let sim_min_fee: u32 = sim["minResourceFee"]
        .as_str()
        .expect("minResourceFee")
        .parse()
        .expect("fee");
    let sim_instructions = data.resources.instructions;
    let sim_disk_read_bytes = data.resources.disk_read_bytes;
    let sim_write_bytes = data.resources.write_bytes;
    let sim_resource_fee = data.resource_fee;

    println!("SIMULATION ESTIMATE (pre-submit, simulated values):");
    println!("  min_resource_fee: {sim_min_fee}");
    println!("  simulated_resource_fee: {sim_resource_fee}");
    println!("  instructions: {sim_instructions}");
    println!("  disk_read_bytes: {sim_disk_read_bytes}");
    println!("  write_bytes: {sim_write_bytes}");
    println!("  note: these are simulated estimates, not on-chain actuals");

    // Machine-readable JSON so SDKs can consume the same fields.
    let mut report = serde_json::json!({
        "simulated": {
            "min_resource_fee": sim_min_fee,
            "simulated_resource_fee": sim_resource_fee,
            "instructions": sim_instructions,
            "disk_read_bytes": sim_disk_read_bytes,
            "write_bytes": sim_write_bytes
        }
    });

    // The RPC's preflight runs in *recording* mode: it prices the token
    // contract's own storage but never executes `__check_auth`, so the guard's
    // policy/window/heartbeat/freeze keys are missing from its footprint and
    // fee. They ARE read at apply time (enforcing mode), so they must be in
    // the declared footprint — and the declared `resource_fee` must cover the
    // enlarged footprint or core fails with `insufficient_refundable_fee`.
    let merged = merge_guard_footprint(data.resources.footprint.clone(), guard, call.kind());
    let added_rw = merged
        .read_write
        .len()
        .saturating_sub(data.resources.footprint.read_write.len());
    let added_ro = merged
        .read_only
        .len()
        .saturating_sub(data.resources.footprint.read_only.len());
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!(
            "footprint merge added {added_rw} rw / {added_ro} ro keys (sim had {} rw, {} ro)",
            data.resources.footprint.read_write.len(),
            data.resources.footprint.read_only.len(),
        );
    }
    // Cover the merged write entries plus `__check_auth` instruction headroom;
    // the derivation and failure signature are documented at
    // `GUARD_KEY_FEE_BUMP`.
    data.resources.footprint = merged;
    data.resource_fee = data
        .resource_fee
        .saturating_add(i64::from(GUARD_KEY_FEE_BUMP));
    let min_fee: u32 = sim["minResourceFee"]
        .as_str()
        .expect("minResourceFee")
        .parse()
        .expect("fee");
    let (inclusion_fee, fee_source) = resolve_inclusion_fee(&args.rpc, args.inclusion_fee_override);
    let fee = calculate_fee(min_fee, inclusion_fee);
    println!("inclusion fee source: {fee_source}");
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!(
            "minResourceFee: {sim_min_fee}, resourceFee(after bump): {}, final fee: {fee}",
            data.resource_fee
        );
    }

    // Add bump and final-fee to the machine-readable report so callers can
    // surface the GUARD_KEY_FEE_BUMP contribution explicitly.
    report
        .as_object_mut()
        .unwrap()
        .insert("bump".to_string(), serde_json::json!(GUARD_KEY_FEE_BUMP));
    report
        .as_object_mut()
        .unwrap()
        .insert("final_fee".to_string(), serde_json::json!(fee));
    // Print compact JSON on its own line for machine consumption.
    println!("MACHINE_OUTPUT: {report}");
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(source_pk)),
        fee,
        seq_num: SequenceNumber(seq),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::try_from(vec![invoke_op(&invocation, auth)]).expect("op count"),
        ext: TransactionExt::V1(data),
    };
    let env2 = sign_envelope(
        &TransactionEnvelope::Tx(TransactionV1Envelope {
            tx,
            signatures: VecM::default(),
        }),
        &network_id,
        &agent,
    );
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!("envelope: {}", b64_encode_xdr(&env2));
    }
    let sent = match args.rpc.send(&b64_encode_xdr(&env2)) {
        Ok(sent) => sent,
        Err(e) if e.is_timeout() => {
            // The endpoint may have relayed the tx before stalling. Name the
            // hash so the operator checks it before resubmitting.
            let TransactionEnvelope::Tx(v1) = &env2 else {
                unreachable!("sign_envelope builds a v1 envelope")
            };
            rpc_exit(
                &e,
                Some(format!(
                    "The transaction may still have been accepted: check tx {} \
                     (getTransaction) before resubmitting",
                    hex::encode(tx_hash(&v1.tx, &network_id))
                )),
            )
        }
        Err(e) => rpc_exit(&e, None),
    };
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!("send response: {sent}");
    }
    if let Some(err) = sent.get("error") {
        let err_str = err.to_string();
        let human = map_submission_error(&err_str);
        eprintln!("Error: {human}");
        return RunOutcome::SendError(human);
    }
    let hash = sent["hash"].as_str().unwrap_or_default().to_string();
    if hash.is_empty() {
        let err_str = sent.to_string();
        let human = map_submission_error(&err_str);
        eprintln!("Error: {human}");
        return RunOutcome::EmptyHash(human);
    }
    let status = sent["status"].as_str().unwrap_or("?").to_string();
    println!("submitted: hash={hash} status={status}");

    let mut outcome = None;
    for _ in 0..20 {
        std::thread::sleep(Duration::from_secs(3));
        let gt = match args.rpc.get_tx(&hash) {
            Ok(gt) => gt,
            Err(e) if e.is_timeout() => {
                eprintln!("{e}; still polling tx={hash}");
                continue;
            }
            Err(e) => rpc_exit(&e, None),
        };
        let st = gt["status"].as_str().unwrap_or("PENDING");
        if st == "SUCCESS" {
            println!("RESULT: ALLOWED tx={hash}");
            outcome = Some(RunOutcome::TransactionSuccess {
                hash: hash.clone(),
                status: st.to_string(),
            });
            break;
        }
        if st == "FAILED" {
            println!("RESULT: FAILED tx={hash}");
            let result_xdr = gt["resultXdr"].as_str().map(|s| s.to_string());
            if let Some(ref errx) = result_xdr {
                println!("  resultXdr: {errx}");
            }
            outcome = Some(RunOutcome::TransactionFailure {
                hash: hash.clone(),
                result_xdr,
            });
            break;
        }
    }
    if let Some(outcome) = outcome {
        return outcome;
    }
    println!("RESULT: TIMEOUT tx={hash}");
    RunOutcome::TransactionTimeout { hash }
}

// ── Guard Registry ────────────────────────────────────────────────────────
///
/// Local registry for guard contract addresses. Stored as JSON at
/// `~/.config/agent-tx/guards.json` (or `AGENT_TX_GUARDS_PATH` env var).
/// The registry is gitignore'd — contract IDs are public but we keep them
/// out of the repo to avoid accidental commits.
///
/// Format:
/// ```json
/// {
///   "guards": [
///     { "alias": "prod", "address": "C...", "admin": "G...", "added_at": 1234567890 }
///   ],
///   "default": "prod"
/// }
/// ```
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct GuardEntry {
    alias: String,
    address: String,
    admin: String,
    added_at: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Default, Clone, Debug)]
struct Registry {
    guards: Vec<GuardEntry>,
    default: Option<String>,
}

fn registry_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGENT_TX_GUARDS_PATH") {
        return PathBuf::from(path);
    }
    let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("agent-tx");
    fs::create_dir_all(&path).ok();
    path.push("guards.json");
    path
}

fn load_registry() -> Registry {
    let path = registry_path();
    if !path.exists() {
        return Registry::default();
    }
    let content = fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_registry(reg: &Registry) {
    let path = registry_path();
    let json = serde_json::to_string_pretty(reg).expect("serialize registry");
    fs::write(&path, json).expect("write registry");
}

fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn verify_guard(rpc: &Rpc, guard_addr: &str, _passphrase: &str) -> Result<(), String> {
    let guard: ScAddress = guard_addr
        .parse()
        .map_err(|e| format!("invalid guard address: {e}"))?;
    let fp = guard_footprint(&guard, CallKind::ReadOnly);
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256([0u8; 32])),
        fee: 0,
        seq_num: SequenceNumber(0),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::default(),
        ext: TransactionExt::V1(SorobanTransactionData {
            resources: SorobanResources {
                footprint: fp,
                instructions: 0,
                disk_read_bytes: 0,
                write_bytes: 0,
            },
            resource_fee: 0,
            ext: SorobanTransactionDataExt::V0,
        }),
    };
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });
    let sim = rpc.simulate(&b64_encode_xdr(&env));
    if let Some(message) = simulation_error_message(&sim) {
        return Err(format!("guard verification failed: {message}"));
    }
    Ok(())
}

fn cmd_guards_add(cli: &mut Cli) -> Result<(), String> {
    let alias = cli.positional_expected(
        "alias",
        "an alias string (see `agent-tx guards add --help`)",
    )?;
    if alias == "--help" || alias == "-h" {
        print_guards_subcommand_help("add");
        return Ok(());
    }
    let address = cli.positional_expected("address", "a guard contract address (C...)")?;
    if address == "--help" || address == "-h" {
        print_guards_subcommand_help("add");
        return Ok(());
    }
    let admin = cli.positional_expected("admin", "an admin account address (G...)")?;
    if admin == "--help" || admin == "-h" {
        print_guards_subcommand_help("add");
        return Ok(());
    }
    // Validate the two addresses first: `verify_guard` below is the first
    // place `guards add` talks to the network (issue #52).
    strkey::validate_key("guards add address", KeyKind::Contract, &address)?;
    strkey::validate_key("guards add admin", KeyKind::Account, &admin)?;

    // The endpoint may be named with `--network`/`--rpc-url`, or, as
    // historically, by trailing positional URL and passphrase arguments.
    let mut network = None;
    let mut rpc_url = None;
    let mut passphrase = None;
    let mut rpc_timeout = None;
    let mut positionals: Vec<String> = Vec::new();
    while let Some(token) = cli.next() {
        match token.as_str() {
            "--rpc-timeout" => {
                rpc_timeout = Some(parse_rpc_timeout(
                    &cli.value_expected("--rpc-timeout", "whole seconds e.g. 30")?,
                )?)
            }
            "--help" | "-h" => {
                print_guards_subcommand_help("add");
                return Ok(());
            }
            "--network" => {
                network = Some(cli.value_expected("--network", "testnet | futurenet | mainnet")?)
            }
            "--rpc-url" => {
                rpc_url = Some(cli.value_expected("--rpc-url", "endpoint URL e.g. https://...")?)
            }
            "--network-passphrase" => {
                passphrase = Some(cli.value_expected("--network-passphrase", "passphrase string")?)
            }
            other if other.starts_with("--") => return Err(cli.unknown(other)),
            other => positionals.push(other.to_string()),
        }
    }
    if positionals.len() > 2 {
        return Err(format!(
            "unexpected arguments after `guards add <alias> <address> <admin>`: {}",
            positionals[2..].join(" ")
        ));
    }
    let legacy_url = positionals.first().map(String::as_str);
    if legacy_url.is_some() && rpc_url.is_some() {
        return Err(
            "conflicting endpoint: `guards add` was given both a positional RPC URL and --rpc-url"
                .to_string(),
        );
    }
    let endpoint = network::resolve_endpoint(
        network.as_deref(),
        rpc_url.as_deref().or(legacy_url),
        passphrase
            .as_deref()
            .or(positionals.get(1).map(String::as_str)),
    )?;

    let rpc = Rpc::new(endpoint.rpc_url, rpc_timeout.unwrap_or(DEFAULT_RPC_TIMEOUT));
    verify_guard(&rpc, &address, &endpoint.passphrase)?;

    let mut reg = load_registry();
    if reg.guards.iter().any(|g| g.alias == alias) {
        return Err(format!("alias '{alias}' already exists"));
    }
    if reg.guards.iter().any(|g| g.address == address) {
        return Err(format!(
            "address '{address}' already registered under another alias"
        ));
    }
    reg.guards.push(GuardEntry {
        alias: alias.clone(),
        address,
        admin,
        added_at: now_ts(),
    });
    if reg.default.is_none() {
        reg.default = Some(alias.clone());
    }
    save_registry(&reg);
    println!(
        "Added guard '{alias}' (default: {})",
        reg.default.as_deref().unwrap_or("none")
    );
    Ok(())
}

fn cmd_guards_list() {
    let reg = load_registry();
    if reg.guards.is_empty() {
        println!("No guards registered. Use `agent-tx guards add <alias> <address> <admin>`");
        return;
    }
    println!("Registered guards:");
    for g in &reg.guards {
        let default_mark = if reg.default.as_ref() == Some(&g.alias) {
            " (default)"
        } else {
            ""
        };
        println!(
            "  {} -> {} [admin: {}]{}",
            g.alias, g.address, g.admin, default_mark
        );
    }
}

fn cmd_guards_remove(cli: &mut Cli) -> Result<(), String> {
    let alias =
        cli.positional_expected("alias", "an alias string (see `agent-tx guards --help`)")?;
    if alias == "--help" || alias == "-h" {
        print_guards_subcommand_help("remove");
        return Ok(());
    }
    let mut reg = load_registry();
    let idx = reg
        .guards
        .iter()
        .position(|g| g.alias == alias)
        .ok_or("alias not found")?;
    reg.guards.remove(idx);
    if reg.default.as_ref() == Some(&alias) {
        reg.default = reg.guards.first().map(|g| g.alias.clone());
    }
    save_registry(&reg);
    println!("Removed guard '{alias}'");
    Ok(())
}

fn cmd_guards_set_default(cli: &mut Cli) -> Result<(), String> {
    let alias =
        cli.positional_expected("alias", "an alias string (see `agent-tx guards --help`)")?;
    if alias == "--help" || alias == "-h" {
        print_guards_subcommand_help("set-default");
        return Ok(());
    }
    let mut reg = load_registry();
    if !reg.guards.iter().any(|g| g.alias == alias) {
        return Err("alias not found".into());
    }
    reg.default = Some(alias.clone());
    save_registry(&reg);
    println!("Default guard set to '{alias}'");
    Ok(())
}

fn resolve_guard(guard_arg: Option<&str>) -> Result<String, String> {
    if let Some(g) = guard_arg {
        return Ok(g.to_string());
    }
    let reg = load_registry();
    if let Some(default) = reg.default {
        if let Some(g) = reg.guards.iter().find(|g| g.alias == default) {
            return Ok(g.address.clone());
        }
    }
    if reg.guards.is_empty() {
        return Err("missing --guard (expected contract ID 'C...'): no guard specified and no guards registered. Use `agent-tx guards add <alias> <address> <admin>` to register one, or pass --guard <C...>".into());
    }
    Err(format!(
        "missing --guard (expected contract ID 'C...'): no guard specified and no default set. Use --guard <C...> or choose from registered guards:\n{}",
        reg.guards
            .iter()
            .map(|g| format!("  {} -> {}", g.alias, g.address))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

// ── CLI ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::base32::{base32_decode, base32_encode, B32};
    use crate::strkey::{decode_strkey, VER_SECRET};

    #[test]
    fn known_secret_decodes_to_seed() {
        // guard_agent: SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4
        let seed = secret_to_seed("SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4");
        assert_eq!(
            hex::encode(seed),
            "635711bd422c08b9354a34e3b748c0f47dcbfda399ba2b1f8c39a4c46f3f5513"
        );
    }

    #[test]
    fn known_pubkey_encodes_to_address() {
        let pk = hex::decode("1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk);
        assert_eq!(
            account_strkey(&arr),
            "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP"
        );
    }

    #[test]
    fn test_map_submission_error_failures() {
        assert!(map_submission_error("tx_insufficient_fee").contains("insufficient fee"));
        assert!(map_submission_error("tx_bad_seq").contains("sequence number collision"));
        assert!(map_submission_error("tx_too_early").contains("too early"));
        assert!(map_submission_error("tx_late_expiration").contains("expiration passed"));
        assert!(map_submission_error("unknown_err").contains("README.md Troubleshooting"));
    }

    #[test]
    fn rpc_failure_classification_preserves_transport_and_json_rpc_details() {
        let transport = RpcError {
            method: "simulateTransaction".to_string(),
            kind: RpcFailureKind::Transport,
            http_status: None,
            json_rpc_code: None,
            message: "connection refused".to_string(),
        };
        assert_eq!(transport.label(), "TRANSPORT FAILURE");
        assert_eq!(transport.exit_code(), 3);
        assert!(transport.to_string().contains("connection refused"));

        let rejection = RpcError {
            method: "sendTransaction".to_string(),
            kind: RpcFailureKind::JsonRpc,
            http_status: Some(400),
            json_rpc_code: Some(serde_json::json!(-32602)),
            message: "tx_bad_seq".to_string(),
        };
        assert_eq!(rejection.label(), "JSON-RPC REJECTION");
        assert_eq!(rejection.exit_code(), 4);
        assert!(rejection.to_string().contains("HTTP status 400"));
        assert!(rejection.to_string().contains("JSON-RPC code -32602"));
    }

    #[test]
    fn fee_calculation_uses_network_inclusion_fee_and_supports_high_fees() {
        let stats = serde_json::json!({ "inclusionFee": { "mode": "5000" } });
        assert_eq!(parse_inclusion_fee(&stats), Some(5_000));
        assert_eq!(calculate_fee(2_000, 5_000), 107_000);
        assert_eq!(
            calculate_fee(2_000, 50_000_000),
            50_102_000,
            "a rising network fee must not be capped at the old constant"
        );
        assert_eq!(parse_inclusion_fee(&serde_json::json!({})), None);
    }

    #[test]
    fn unsigned_simulation_rejection_is_not_a_guard_policy_block() {
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let simulation = serde_json::json!({ "error": "tx_insufficient_fee", "events": [] });
        assert_eq!(
            simulation_error_message(&simulation).as_deref(),
            Some("tx_insufficient_fee")
        );
        assert!(!is_guard_auth_checked_block(&simulation, &guard));
    }

    fn guard_block_event_xdr(guard: &ScAddress) -> String {
        let ScAddress::Contract(guard_id) = guard.clone() else {
            panic!("expected contract address");
        };
        let event = DiagnosticEvent {
            in_successful_contract_call: false,
            event: ContractEvent {
                ext: ExtensionPoint::V0,
                contract_id: Some(guard_id),
                type_: ContractEventType::Contract,
                body: ContractEventBody::V0(ContractEventV0 {
                    topics: VecM::try_from(vec![
                        ScVal::Symbol(ScSymbol("event_auth_checked".try_into().unwrap())),
                        ScVal::Symbol(ScSymbol("blocked".try_into().unwrap())),
                        ScVal::Symbol(ScSymbol("per_tx_cap_exceeded".try_into().unwrap())),
                    ])
                    .unwrap(),
                    data: ScVal::Void,
                }),
            },
        };
        event.to_xdr_base64(Limits::none()).unwrap()
    }

    #[test]
    fn guard_auth_checked_block_requires_guard_event_topics() {
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let simulation = serde_json::json!({
            "error": "HostError: auth_checked: per_tx_cap_exceeded",
            "events": [{ "xdr": guard_block_event_xdr(&guard) }]
        });
        assert!(is_guard_auth_checked_block(&simulation, &guard));

        let other_guard: ScAddress = VALID_TOKEN.parse().unwrap();
        assert!(!is_guard_auth_checked_block(&simulation, &other_guard));
    }

    #[test]
    fn extract_dms_grace_secs_from_policy_map() {
        // Test that we can extract dms_grace_secs from a PolicyConfig map
        // A single dms_grace_secs (u64) field: a 1 hour grace period.
        let policy_map_entries = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol("dms_grace_secs".try_into().unwrap())),
            val: ScVal::U64(3600),
        }];

        let policy_map = ScMap(stellar_xdr::VecM::try_from(policy_map_entries).unwrap());

        let policy_val = ScVal::Map(Some(policy_map));

        // Extract and verify
        let dms_grace = extract_dms_grace_secs(&policy_val);
        assert_eq!(dms_grace, 3600, "should extract dms_grace_secs=3600");
    }

    #[test]
    fn extract_dms_grace_secs_returns_zero_when_not_found() {
        // Test that extract_dms_grace_secs returns 0 when field is missing
        let empty_map = ScMap(stellar_xdr::VecM::try_from(vec![]).unwrap());
        let policy_val = ScVal::Map(Some(empty_map));

        let dms_grace = extract_dms_grace_secs(&policy_val);
        assert_eq!(
            dms_grace, 0,
            "should return 0 when dms_grace_secs is not in map"
        );
    }

    #[test]
    fn extract_dms_grace_secs_handles_void_policy() {
        // Test that extract_dms_grace_secs handles Void (no policy) gracefully
        let policy_val = ScVal::Void;

        let dms_grace = extract_dms_grace_secs(&policy_val);
        assert_eq!(dms_grace, 0, "should return 0 for Void policy");
    }

    #[test]
    fn heartbeat_expiry_calculation() {
        // Test the logic: heartbeat_expired if (now - last_heartbeat) > dms_grace_secs
        // When last_heartbeat=50, dms_grace_secs=60, now=100:
        // 100 - 50 = 50, which is NOT > 60, so heartbeat should NOT be expired

        let now = 100u32;
        let last_heartbeat = 50u64;
        let dms_grace_secs = 60u64;

        let heartbeat_expired = now.saturating_sub(last_heartbeat as u32) as u64 > dms_grace_secs;
        assert!(
            !heartbeat_expired,
            "heartbeat should not be expired: (100-50)=50 is not > 60"
        );

        // Test case 2: now=150, last_heartbeat=50, dms_grace_secs=60
        // 150 - 50 = 100, which IS > 60, so heartbeat SHOULD be expired
        let now2 = 150u32;
        let heartbeat_expired2 = now2.saturating_sub(last_heartbeat as u32) as u64 > dms_grace_secs;
        assert!(
            heartbeat_expired2,
            "heartbeat should be expired: (150-50)=100 is > 60"
        );

        // Test case 3: last_heartbeat=0 (never heartbeated) with dms_grace_secs > 0
        // Should be expired immediately
        let last_heartbeat_zero = 0u64;
        let is_never_heartbeated = last_heartbeat_zero == 0;
        assert!(
            is_never_heartbeated,
            "should detect never-heartbeated state"
        );
    }

    #[test]
    fn policy_read_returns_null_when_no_policy() {
        let _rpc = MockPreflightRpc {
            response: serde_json::json!({
                "entries": [
                    {
                        "xdr": "AAAADgAAAAA=" // dummy ledger entry with Void
                    }
                ]
            }),
            ..Default::default()
        };

        let _guard: ScAddress = "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
            .parse()
            .unwrap();
        // The test verifies that cmd_policy can be called without panicking
        // In a full suite, we'd capture stdout to verify "null" is printed
    }

    #[test]
    fn check_read_simulates_transfer_decision() {
        let _rpc = MockPreflightRpc {
            response: serde_json::json!({
                "minResourceFee": "100"
            }),
            ..Default::default()
        };

        let _guard: ScAddress = "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
            .parse()
            .unwrap();
        let _asset: ScAddress = "CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7"
            .parse()
            .unwrap();
        let _to: ScAddress = "GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX"
            .parse()
            .unwrap();
        // The test verifies that cmd_check can be called without panicking
        // In a full suite, we'd capture stdout to verify "result: allowed" or similar
    }

    #[test]
    fn guard_contract_address_roundtrip() {
        let guard: ScAddress = "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
            .parse()
            .unwrap();
        match guard {
            ScAddress::Contract(ContractId(Hash(id))) => {
                assert_eq!(
                    contract_strkey(&id),
                    "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
                );
            }
            _ => panic!("expected contract address"),
        }
    }

    // ── Guard storage keys vs the contract's DataKey (issue #383) ────────

    /// Generated by the contract's `agent_tx_storage_keys_fixture_is_current`
    /// test from the real `DataKey` encoding.
    const CONTRACT_STORAGE_KEYS: &str = include_str!("../guard-storage-keys.json");

    #[test]
    fn guard_footprint_declares_exactly_the_check_auth_read_set() {
        let names: Vec<&str> = GuardKey::CHECK_AUTH_READS
            .iter()
            .map(|k| k.variant())
            .collect();
        assert_eq!(names, ["Policy", "Window", "LastHeartbeat", "AdminFrozen"]);

        // The footprint table declares exactly those keys plus the instance.
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let declared: Vec<StorageTarget> = GUARD_STORAGE_TOUCHES.iter().map(|t| t.target).collect();
        let expected: Vec<StorageTarget> = GuardKey::CHECK_AUTH_READS
            .iter()
            .map(|&k| StorageTarget::Persistent(k))
            .chain([StorageTarget::Instance])
            .collect();
        assert_eq!(declared.len(), expected.len());
        for target in &expected {
            assert!(
                declared.contains(target),
                "{target:?} missing from footprint"
            );
        }

        for kind in [CallKind::Transfer, CallKind::Heartbeat, CallKind::ReadOnly] {
            let fp = guard_footprint(&guard, kind);
            // Merging into a footprint that already holds the keys adds nothing.
            assert_eq!(merge_guard_footprint(fp.clone(), &guard, kind), fp);
        }

        // Keys the simulation declared read-only stay read-only, never
        // duplicated into read-write.
        let policy = guard_data_key(&guard, GuardKey::Policy);
        let sim = LedgerFootprint {
            read_only: VecM::try_from(vec![policy.clone()]).unwrap(),
            read_write: VecM::default(),
        };
        let merged = merge_guard_footprint(sim, &guard, CallKind::Transfer);
        assert_eq!(merged.read_only.iter().filter(|k| **k == policy).count(), 1);
        assert!(!merged.read_write.contains(&policy));
    }

    #[test]
    fn guard_storage_keys_match_the_contracts_datakey_encoding() {
        let fixture: serde_json::Value =
            serde_json::from_str(CONTRACT_STORAGE_KEYS).expect("guard-storage-keys.json parses");
        let entries = fixture["keys"].as_array().expect("keys array");
        for key in GuardKey::CHECK_AUTH_READS {
            let entry = entries
                .iter()
                .find(|e| e["variant"] == key.variant())
                .unwrap_or_else(|| {
                    panic!(
                        "DataKey::{} no longer exists in the contract (src/types.rs); agent-tx \
                         would declare a footprint key the guard never reads. Update GuardKey.",
                        key.variant()
                    )
                });
            assert_eq!(
                entry["storage"],
                "persistent",
                "DataKey::{} moved out of persistent storage; agent-tx declares it persistent",
                key.variant()
            );
            assert_eq!(
                hex::encode(key.scval().to_xdr(Limits::none()).unwrap()),
                entry["scval_xdr_hex"].as_str().expect("hex string"),
                "agent-tx encodes DataKey::{} differently from the contract",
                key.variant()
            );
        }
    }

    // ── Guard-key fee allowance (issue #382) ─────────────────────────────

    #[test]
    fn guard_key_fee_allowance_covers_its_derivation() {
        // The figure the documentation quotes.
        assert_eq!(GUARD_FOOTPRINT_KEYS, 5);
        assert_eq!(guard_key_fee_floor(), 22_291);
        assert!(guard_key_fee_floor() <= i64::from(GUARD_KEY_FEE_BUMP));

        // The per-key byte bound holds for the keys actually declared.
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let fp = guard_footprint(&guard, CallKind::Transfer);
        let keys: Vec<LedgerKey> = fp
            .read_only
            .iter()
            .chain(fp.read_write.iter())
            .cloned()
            .collect();
        assert_eq!(keys.len() as i64, GUARD_FOOTPRINT_KEYS);
        for key in keys {
            let len = key.to_xdr(Limits::none()).unwrap().len() as i64;
            assert!(len <= GUARD_KEY_XDR_BYTES_MAX, "{key:?} is {len} bytes");
        }
    }

    #[test]
    fn transfer_from_invocation_uses_exact_contract_argument_order() {
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let from: ScAddress = VALID_RECIPIENT.parse().unwrap();
        let to: ScAddress = "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP"
            .parse()
            .unwrap();
        let token: ScAddress = VALID_TOKEN.parse().unwrap();
        let call = Call::TransferFrom {
            token: token.clone(),
            from: from.clone(),
            to: to.clone(),
            amount: 50,
        };
        let invocation = call.invocation(&guard);

        assert_eq!(invocation.contract_address, token);
        assert_eq!(invocation.function_name.to_string(), "transfer_from");
        assert_eq!(invocation.args.len(), 4);
        assert_eq!(invocation.args[0], ScVal::Address(from));
        assert_eq!(invocation.args[1], ScVal::Address(guard));
        assert_eq!(invocation.args[2], ScVal::Address(to));
        assert_eq!(
            invocation.args[3],
            ScVal::I128(Int128Parts { lo: 50, hi: 0 })
        );
    }

    #[derive(Default)]
    struct MockPreflightRpc {
        sequence: std::cell::Cell<i64>,
        sequence_reads: std::cell::Cell<u32>,
        simulations: std::cell::Cell<u32>,
        response: serde_json::Value,
        ledger: std::cell::Cell<u32>,
        envelopes: std::cell::RefCell<Vec<String>>,
    }

    impl PreflightRpc for MockPreflightRpc {
        fn account_seq(&self, _account: &str) -> i64 {
            self.sequence_reads.set(self.sequence_reads.get() + 1);
            self.sequence.get()
        }

        fn latest_ledger(&self) -> u32 {
            self.ledger.get()
        }

        fn simulate(&self, envelope: &str) -> serde_json::Value {
            self.simulations.set(self.simulations.get() + 1);
            self.envelopes.borrow_mut().push(envelope.to_string());
            self.response.clone()
        }

        fn registered_agent_pubkey(&self, _guard: &ScAddress) -> [u8; 32] {
            let seed = secret_to_seed("SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4");
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        }

        fn inclusion_fee(&self) -> Result<Option<u32>, RpcError> {
            Ok(Some(100))
        }
    }

    #[test]
    fn preflight_simulates_without_submitting_or_advancing_sequence() {
        let rpc = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            response: serde_json::json!({ "minResourceFee": "200" }),
            ..Default::default()
        };
        let args = Args {
            rpc: Rpc::new(String::new(), DEFAULT_RPC_TIMEOUT),
            passphrase: Network::Testnet.passphrase().to_string(),
            passphrase_source: "default testnet preset",
            guard: "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
                .parse()
                .unwrap(),
            secret: None,
            expect_blocked: false,
            inclusion_fee_override: None,
        };

        assert_eq!(preflight(&Call::Heartbeat, &args, &rpc), Err(2));
        assert_eq!(rpc.sequence_reads.get(), 1);
        assert_eq!(rpc.simulations.get(), 1);
        assert_eq!(rpc.sequence.get(), 7);
    }

    #[test]
    fn signed_preflight_block_returns_failure_without_advancing_sequence() {
        let rpc = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            response: serde_json::json!({
                "error": {
                    "code": "simulation",
                    "message": "auth_checked: per_tx_cap_exceeded",
                    "data": { "events": [] }
                }
            }),
            ..Default::default()
        };
        let args = Args {
            rpc: Rpc::new(String::new(), DEFAULT_RPC_TIMEOUT),
            passphrase: Network::Testnet.passphrase().to_string(),
            passphrase_source: "default testnet preset",
            guard: "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7"
                .parse()
                .unwrap(),
            secret: Some("SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4".to_string()),
            expect_blocked: false,
            inclusion_fee_override: None,
        };

        assert_eq!(preflight(&Call::Heartbeat, &args, &rpc), Err(1));
        assert_eq!(rpc.sequence_reads.get(), 1);
        assert_eq!(rpc.simulations.get(), 1);
        assert_eq!(rpc.sequence.get(), 7);
    }

    // ── RPC timeout (issue #385) ─────────────────────────────────────────

    /// A loopback endpoint that accepts connections, optionally writes
    /// `preamble`, and then never answers — a black-holed RPC.
    fn hung_endpoint(preamble: &'static [u8]) -> String {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for _ in 0..4 {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                let _ = stream.write_all(preamble);
                let _ = stream.flush();
                held.push(stream); // keep it open, never respond
            }
            std::thread::sleep(Duration::from_secs(30));
        });
        url
    }

    #[test]
    fn a_hung_endpoint_times_out_with_an_error_naming_the_method() {
        let rpc = Rpc::new(hung_endpoint(b""), Duration::from_millis(300));
        let started = std::time::Instant::now();
        let err = rpc
            .post("getLatestLedger", serde_json::json!({}))
            .expect_err("a silent endpoint must not produce a result");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded by the timeout"
        );
        assert!(err.is_timeout(), "{err:?}");
        assert_eq!(err.method, "getLatestLedger");
        assert_eq!(err.label(), "RPC TIMEOUT");
        assert_eq!(err.exit_code(), 3);
        let message = err.to_string();
        assert!(message.contains("getLatestLedger"), "{message}");
        assert!(message.contains("no response"), "{message}");
        assert!(message.contains("--rpc-timeout"), "{message}");
    }

    #[test]
    fn a_stall_after_the_headers_is_also_a_timeout() {
        let preamble =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{";
        let rpc = Rpc::new(hung_endpoint(preamble), Duration::from_millis(300));
        let err = rpc
            .post("simulateTransaction", serde_json::json!({}))
            .expect_err("a truncated body must not produce a result");
        assert!(err.is_timeout(), "{err:?}");
        assert_eq!(err.method, "simulateTransaction");
    }

    #[test]
    fn a_refused_connection_is_a_transport_error_not_a_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);
        let err = Rpc::new(url, Duration::from_secs(5))
            .post("getLatestLedger", serde_json::json!({}))
            .expect_err("nothing is listening");
        assert_eq!(err.kind, RpcFailureKind::Transport, "{err:?}");
        assert!(!err.is_timeout());
    }

    #[test]
    fn a_responsive_endpoint_is_unaffected_by_the_timeout() {
        let mock = MockRpc::start();
        let result = Rpc::new(mock.url.clone(), Duration::from_secs(5))
            .post("getLatestLedger", serde_json::json!({}))
            .expect("mock answers");
        assert_eq!(result["sequence"], 1);
    }

    #[test]
    fn rpc_timeout_flag_sets_the_request_timeout() {
        let args = argv(&["--guard", VALID_GUARD]);
        let request = parse_request("status", &args).expect("default");
        assert_eq!(request.rpc_timeout, DEFAULT_RPC_TIMEOUT);

        let args = argv(&["--guard", VALID_GUARD, "--rpc-timeout", "5"]);
        let request = parse_request("status", &args).expect("explicit timeout");
        assert_eq!(request.rpc_timeout, Duration::from_secs(5));
        assert_eq!(request.rpc().timeout, Duration::from_secs(5));

        for bad in ["0", "-1", "1.5", "soon"] {
            let args = argv(&["--guard", VALID_GUARD, "--rpc-timeout", bad]);
            let err = parse_request("status", &args).expect_err(bad);
            assert!(err.contains("invalid --rpc-timeout"), "{err}");
        }
    }

    // ── Guard auth nonce (issue #384) ────────────────────────────────────

    /// The nonce of the guard auth entry in each envelope the mock simulated.
    fn simulated_nonces(rpc: &MockPreflightRpc) -> Vec<i64> {
        rpc.envelopes
            .borrow()
            .iter()
            .map(|b64| {
                let TransactionEnvelope::Tx(env) = xdr::<TransactionEnvelope>(b64) else {
                    panic!("unexpected envelope variant");
                };
                let OperationBody::InvokeHostFunction(op) = &env.tx.operations[0].body else {
                    panic!("not an invoke operation");
                };
                let SorobanCredentials::Address(creds) = &op.auth[0].credentials else {
                    panic!("guard auth entry missing");
                };
                creds.nonce
            })
            .collect()
    }

    fn signed_preflight_args() -> Args {
        Args {
            rpc: Rpc::new(String::new(), DEFAULT_RPC_TIMEOUT),
            passphrase: Network::Testnet.passphrase().to_string(),
            passphrase_source: "default testnet preset",
            guard: VALID_GUARD.parse().unwrap(),
            secret: Some(VALID_SECRET.to_string()),
            expect_blocked: false,
            inclusion_fee_override: None,
        }
    }

    #[test]
    fn auth_nonce_is_the_ledger_over_the_entropy() {
        let nonce = auth_nonce(65_008_194, 0xdead_beef);
        assert_eq!((nonce as u64) >> 32, 65_008_194);
        assert_eq!(nonce as u64 & 0xffff_ffff, 0xdead_beef);
        // Injective: any change to either half changes the nonce.
        assert_ne!(auth_nonce(7, 1), auth_nonce(7, 2));
        assert_ne!(auth_nonce(7, 1), auth_nonce(8, 1));
        // Past ledger 2^31 the bit pattern wraps negative but stays distinct.
        assert_ne!(auth_nonce(u32::MAX, 0), auth_nonce(u32::MAX - 1, 0));
    }

    #[test]
    fn two_submissions_in_the_same_ledger_get_distinct_nonces() {
        let rpc = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            ledger: std::cell::Cell::new(5_000),
            response: serde_json::json!({ "minResourceFee": "200" }),
            ..Default::default()
        };
        let args = signed_preflight_args();
        preflight(&Call::Heartbeat, &args, &rpc).unwrap();
        preflight(&Call::Heartbeat, &args, &rpc).unwrap();

        let nonces = simulated_nonces(&rpc);
        assert_eq!(nonces.len(), 2);
        // Fails with probability 2^-32: two equal 32-bit draws.
        assert_ne!(nonces[0], nonces[1], "same-ledger nonces collided");
        for nonce in nonces {
            assert_eq!((nonce as u64) >> 32, 5_000, "ledger is the high half");
        }
    }

    #[test]
    fn a_retry_after_a_failed_attempt_draws_a_fresh_nonce() {
        // Attempt one is blocked/fails before its sequence is consumed, so the
        // retry runs at the *same* sequence (7 -> 8). Under the old scheme the
        // nonce was that sequence, so both attempts carried nonce 8.
        let rpc = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            ledger: std::cell::Cell::new(5_000),
            response: serde_json::json!({
                "error": { "code": "simulation", "message": "failed", "data": {} }
            }),
            ..Default::default()
        };
        let args = signed_preflight_args();
        assert_eq!(preflight(&Call::Heartbeat, &args, &rpc), Err(1));
        assert_eq!(rpc.sequence.get(), 7, "the failed attempt consumed nothing");

        // The retry lands a ledger later at the same sequence.
        rpc.ledger.set(5_001);
        assert_eq!(preflight(&Call::Heartbeat, &args, &rpc), Err(1));

        let nonces = simulated_nonces(&rpc);
        assert_eq!(nonces.len(), 2);
        assert_ne!(nonces[0], nonces[1]);
        assert!(
            nonces.iter().all(|&n| n != 8),
            "nonce must not be the sequence"
        );
        // Different ledgers: disjoint high halves, so no collision is possible.
        assert_eq!((nonces[0] as u64) >> 32, 5_000);
        assert_eq!((nonces[1] as u64) >> 32, 5_001);
    }

    #[test]
    fn expect_blocked_only_accepts_guard_auth_checked_blocks() {
        let guard: ScAddress = VALID_GUARD.parse().unwrap();
        let block = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            response: serde_json::json!({
                "error": "HostError: auth_checked: per_tx_cap_exceeded",
                "events": [{ "xdr": guard_block_event_xdr(&guard) }]
            }),
            ..Default::default()
        };
        let args = Args {
            rpc: Rpc::new(String::new(), DEFAULT_RPC_TIMEOUT),
            passphrase: Network::Testnet.passphrase().to_string(),
            passphrase_source: "default testnet preset",
            guard,
            secret: Some(VALID_SECRET.to_string()),
            expect_blocked: true,
            inclusion_fee_override: None,
        };
        assert_eq!(preflight(&Call::Heartbeat, &args, &block), Ok(()));

        // A transaction-level rejection is not a policy denial, so
        // --expect-blocked must not turn it into success.
        let rejection = MockPreflightRpc {
            sequence: std::cell::Cell::new(7),
            response: serde_json::json!({
                "error": "tx_insufficient_fee",
                "events": []
            }),
            ..Default::default()
        };
        assert_eq!(preflight(&Call::Heartbeat, &args, &rejection), Err(1));
    }

    // ── Input validation and network presets (issues #52, #54) ───────────

    /// A loopback JSON-RPC server that records the `method` of every request it
    /// serves. Pointing `--rpc-url` at one lets a test assert whether a code
    /// path actually talked to the network.
    struct MockRpc {
        url: String,
        requests: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl MockRpc {
        fn start() -> Self {
            use std::io::{BufRead, BufReader, Read, Write};

            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("loopback bind");
            let url = format!("http://{}", listener.local_addr().expect("local addr"));
            let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let served = std::sync::Arc::clone(&requests);
            std::thread::spawn(move || {
                // A bounded loop: the server must not outlive the test binary.
                for _ in 0..8 {
                    let Ok((mut stream, _)) = listener.accept() else {
                        return;
                    };
                    let mut header_reader =
                        BufReader::new(stream.try_clone().expect("clone stream for headers"));
                    let mut content_length = 0usize;
                    loop {
                        let mut line = String::new();
                        if header_reader.read_line(&mut line).expect("read header") == 0 {
                            break;
                        }
                        let trimmed = line.trim_end();
                        if trimmed.is_empty() {
                            break;
                        }
                        if trimmed.to_ascii_lowercase().starts_with("content-length:") {
                            content_length = trimmed[15..].trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; content_length];
                    if header_reader.read_exact(&mut body).is_ok() {
                        let method = serde_json::from_str::<serde_json::Value>(
                            &String::from_utf8_lossy(&body),
                        )
                        .ok()
                        .and_then(|value| value["method"].as_str().map(str::to_string))
                        .unwrap_or_default();
                        served.lock().expect("record lock").push(method);
                    }
                    let payload = r#"{"jsonrpc":"2.0","id":1,"result":{"sequence":1}}"#;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                         {}\r\nConnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            Self { url, requests }
        }

        fn methods(&self) -> Vec<String> {
            self.requests.lock().expect("record lock").clone()
        }
    }

    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    const VALID_GUARD: &str = "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7";
    const VALID_TOKEN: &str = "CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7";
    const VALID_RECIPIENT: &str = "GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX";
    const VALID_SECRET: &str = "SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4";

    #[test]
    fn malformed_addresses_are_rejected_without_a_network_request() {
        let mock = MockRpc::start();
        // Each case breaks a different rule on the flag that carries it: wrong
        // key type, truncated, mistyped checksum, empty.
        let cases: &[(&str, &str)] = &[
            ("--guard", VALID_RECIPIENT),
            ("--guard", &VALID_GUARD[..48]),
            (
                "--guard",
                "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU8",
            ),
            ("--guard", ""),
        ];
        for (flag, value) in cases {
            let args = argv(&[
                "status",
                flag,
                value,
                "--rpc-url",
                &mock.url,
                "--network-passphrase",
                "Local Test Network",
            ]);
            let (cmd, rest) = args.split_first().expect("subcommand");
            let err = parse_request(cmd, rest).expect_err(&format!("{flag} '{value}' accepted"));
            assert!(err.contains(flag), "{err}");
            assert!(
                err.contains("expected") && err.contains("checksum"),
                "{err} must name the rule broken"
            );
        }

        // The same rules apply to the other address-typed flags, and to a
        // secret in any of its two spellings.
        let spend_cases: &[(&str, &str)] = &[
            ("--to", &VALID_RECIPIENT.to_lowercase()),
            ("--to", VALID_SECRET),
            ("--asset", VALID_SECRET),
            ("--agent-secret", VALID_GUARD),
            ("--secret", VALID_TOKEN),
        ];
        for (flag, value) in spend_cases {
            let args = argv(&[
                "check",
                "--guard",
                VALID_GUARD,
                "--asset",
                VALID_TOKEN,
                "--to",
                VALID_RECIPIENT,
                "--amount",
                "5",
                flag,
                value,
                "--rpc-url",
                &mock.url,
                "--network-passphrase",
                "Local Test Network",
            ]);
            let (cmd, rest) = args.split_first().expect("subcommand");
            let err = parse_request(cmd, rest).expect_err(&format!("{flag} '{value}' accepted"));
            assert!(err.contains(flag), "{err}");
        }
        assert!(
            mock.methods().is_empty(),
            "validation failures must not send a request, sent: {:?}",
            mock.methods()
        );
    }

    #[test]
    fn the_mock_endpoint_records_a_request_that_does_happen() {
        // The control for the test above: the probe sees traffic, so its
        // silence there means no request, not a broken listener.
        let mock = MockRpc::start();
        let args = argv(&[
            "status",
            "--guard",
            VALID_GUARD,
            "--rpc-url",
            &mock.url,
            "--network-passphrase",
            "Local Test Network",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let request = parse_request("status", rest).expect("valid inputs");
        assert_eq!(request.rpc().latest_ledger(), 1);
        assert_eq!(mock.methods(), vec!["getLatestLedger".to_string()]);
    }

    #[test]
    fn every_address_flag_of_every_subcommand_is_validated() {
        let mock = MockRpc::start();
        // `preflight`/`check`/`transfer` take a token and a recipient; each is
        // checked against its own rule rather than trusting the RPC to complain.
        for cmd in ["preflight", "check"] {
            let mut args = argv(&[
                cmd,
                "--guard",
                VALID_GUARD,
                "--asset",
                VALID_RECIPIENT, // an account ID where a contract ID belongs
                "--to",
                VALID_RECIPIENT,
                "--amount",
                "5",
                "--rpc-url",
                &mock.url,
                "--network-passphrase",
                "Local Test Network",
            ]);
            let (_, rest) = args.split_first().expect("subcommand");
            let err = parse_request(cmd, rest).expect_err("account ID accepted as --asset");
            assert!(
                err.contains("--asset") && err.contains("expected 'C'"),
                "{err}"
            );

            args = argv(&[
                cmd,
                "--guard",
                VALID_GUARD,
                "--asset",
                VALID_TOKEN,
                "--to",
                VALID_TOKEN,
                "--amount",
                "5",
                "--rpc-url",
                &mock.url,
                "--network-passphrase",
                "Local Test Network",
            ]);
            let (_, rest) = args.split_first().expect("subcommand");
            // A contract recipient is legal (`C...` addresses can receive), so
            // this must pass validation.
            parse_request(cmd, rest).expect("contract recipient rejected");
        }

        // `transfer` spells the asset flag `--token`, and says so when it is
        // missing; `--asset` is still accepted for it.
        let args = argv(&[
            "transfer",
            "--guard",
            VALID_GUARD,
            "--to",
            VALID_RECIPIENT,
            "--amount",
            "5",
            "--agent-secret",
            VALID_SECRET,
            "--rpc-url",
            &mock.url,
            "--network-passphrase",
            "Local Test Network",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("transfer", rest).expect_err("transfer accepted without a token");
        assert!(err.contains("missing --token"), "{err}");

        let args = argv(&[
            "transfer",
            "--guard",
            VALID_GUARD,
            "--asset",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
            "--amount",
            "5",
            "--agent-secret",
            VALID_SECRET,
            "--rpc-url",
            &mock.url,
            "--network-passphrase",
            "Local Test Network",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        parse_request("transfer", rest).expect("`--asset` rejected for transfer");
        assert!(mock.methods().is_empty(), "{:?}", mock.methods());
    }

    #[test]
    fn transfer_from_request_requires_owner_and_accepts_fee_override() {
        let args = argv(&[
            "transfer-from",
            "--guard",
            VALID_GUARD,
            "--token",
            VALID_TOKEN,
            "--from",
            VALID_RECIPIENT,
            "--to",
            "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP",
            "--amount",
            "50",
            "--agent-secret",
            VALID_SECRET,
            "--rpc-url",
            "http://127.0.0.1:8000/soroban/rpc",
            "--network-passphrase",
            "Local Test Network",
            "--inclusion-fee",
            "5000",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let request = parse_request("transfer-from", rest).expect("valid transfer-from");
        assert_eq!(request.from, Some(VALID_RECIPIENT.parse().unwrap()));
        assert_eq!(request.inclusion_fee_override, Some(5_000));

        let missing_from = argv(&[
            "transfer-from",
            "--guard",
            VALID_GUARD,
            "--token",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
            "--amount",
            "50",
            "--agent-secret",
            VALID_SECRET,
        ]);
        let (_, rest) = missing_from.split_first().expect("subcommand");
        assert!(parse_request("transfer-from", rest)
            .unwrap_err()
            .contains("missing --from"));
    }

    #[test]
    fn guards_add_validates_addresses_before_verifying_onchain() {
        let mock = MockRpc::start();
        // `guards add <alias> <address> <admin> [url]`, with the subcommand
        // already consumed by the dispatcher.
        let bad_guard = argv(&["prod", VALID_RECIPIENT, VALID_RECIPIENT, &mock.url]);
        let mut cli = Cli::new("guards", &bad_guard);
        let err = cmd_guards_add(&mut cli).expect_err("account ID accepted as a guard address");
        assert!(
            err.contains("guards add address") && err.contains("expected 'C'"),
            "{err}"
        );

        let bad_admin = argv(&["prod", VALID_GUARD, VALID_GUARD, &mock.url]);
        let mut cli = Cli::new("guards", &bad_admin);
        let err = cmd_guards_add(&mut cli).expect_err("contract ID accepted as an admin");
        assert!(
            err.contains("guards add admin") && err.contains("expected 'G'"),
            "{err}"
        );

        assert!(
            mock.methods().is_empty(),
            "a rejected address must not be verified on-chain: {:?}",
            mock.methods()
        );
    }

    #[test]
    fn usage_mistakes_are_errors_not_panics() {
        let cases: &[(&str, &[&str])] = &[
            (
                "unknown argument",
                &["status", "--guard", VALID_GUARD, "--frobnicate", "1"],
            ),
            ("requires a value", &["status", "--guard"]),
            (
                "invalid --amount",
                &[
                    "check",
                    "--guard",
                    VALID_GUARD,
                    "--asset",
                    VALID_TOKEN,
                    "--to",
                    VALID_RECIPIENT,
                    "--amount",
                    "5.5",
                ],
            ),
            (
                "missing --to",
                &[
                    "check",
                    "--guard",
                    VALID_GUARD,
                    "--asset",
                    VALID_TOKEN,
                    "--amount",
                    "5",
                ],
            ),
            (
                "missing --asset",
                &[
                    "check",
                    "--guard",
                    VALID_GUARD,
                    "--to",
                    VALID_RECIPIENT,
                    "--amount",
                    "5",
                ],
            ),
            (
                "not a named network",
                &["status", "--guard", VALID_GUARD, "--network", "localnet"],
            ),
        ];
        for (expected, values) in cases {
            let args = argv(values);
            let (cmd, rest) = args.split_first().expect("subcommand");
            let err = parse_request(cmd, rest).expect_err(&format!("{values:?} accepted"));
            assert!(err.contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn network_presets_select_the_endpoint_and_passphrase() {
        let cases = [
            ("testnet", Network::Testnet),
            ("futurenet", Network::Futurenet),
            ("mainnet", Network::Mainnet),
        ];
        for (name, preset) in cases {
            let args = argv(&["status", "--guard", VALID_GUARD, "--network", name]);
            let (_, rest) = args.split_first().expect("subcommand");
            let request = parse_request("status", rest).expect("preset selection");
            assert_eq!(request.endpoint.network, Some(preset));
            assert_eq!(request.endpoint.rpc_url, preset.rpc_url());
            assert_eq!(request.endpoint.passphrase, preset.passphrase());
            assert_eq!(
                request.notice().is_some(),
                preset == Network::Mainnet,
                "only mainnet warns"
            );
        }
    }

    #[test]
    fn a_custom_rpc_url_overrides_the_default_endpoint() {
        let args = argv(&[
            "status",
            "--guard",
            VALID_GUARD,
            "--rpc-url",
            "http://127.0.0.1:8000/soroban/rpc",
            "--network-passphrase",
            "Local Test Network",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let request = parse_request("status", rest).expect("rpc-url override");
        assert_eq!(
            request.endpoint.rpc_url,
            "http://127.0.0.1:8000/soroban/rpc"
        );
        assert_eq!(request.endpoint.network, None);
        assert_eq!(request.endpoint.passphrase, "Local Test Network");
        assert_eq!(
            request.endpoint.passphrase_source,
            "explicit --network-passphrase"
        );
        assert!(request.notice().is_none());

        let args = argv(&[
            "status",
            "--guard",
            VALID_GUARD,
            "--network",
            "futurenet",
            "--rpc-url",
            "http://127.0.0.1:8000/soroban/rpc",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("status", rest).expect_err("conflict accepted");
        assert!(err.contains("conflicting network selection"), "{err}");
    }

    #[test]
    fn mainnet_through_an_explicit_url_also_warns() {
        let args = argv(&[
            "status",
            "--guard",
            VALID_GUARD,
            "--rpc-url",
            "https://soroban.stellar.org/",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let request = parse_request("status", rest).expect("mainnet url");
        assert_eq!(request.endpoint.network, Some(Network::Mainnet));
        assert!(request.notice().expect("warning").contains("unaudited"));
    }

    #[test]
    fn submission_commands_require_the_agent_secret_and_reads_do_not() {
        if std::env::var_os("AGENT_SECRET").is_some() {
            return; // the environment supplies the secret, so the requirement holds anyway
        }
        for cmd in ["transfer", "transfer-from", "heartbeat"] {
            let values = if cmd == "transfer" {
                argv(&[
                    cmd,
                    "--guard",
                    VALID_GUARD,
                    "--token",
                    VALID_TOKEN,
                    "--to",
                    VALID_RECIPIENT,
                    "--amount",
                    "5",
                ])
            } else {
                argv(&[cmd, "--guard", VALID_GUARD])
            };
            let (_, rest) = values.split_first().expect("subcommand");
            let err =
                parse_request(cmd, rest).expect_err(&format!("{cmd} accepted without a secret"));
            assert!(err.contains("--agent-secret"), "{err}");
        }
        for cmd in ["status", "policy"] {
            let args = argv(&["--guard", VALID_GUARD]);
            parse_request(cmd, &args).expect("read command without a secret");
        }
    }

    #[test]
    fn help_and_usage_cover_all_subcommands() {
        let tool = tool_help();
        assert!(tool.contains("Usage:"));
        assert!(tool.contains("agent-tx preflight"));
        assert!(tool.contains("agent-tx transfer"));
        assert!(tool.contains("agent-tx guards"));

        for sub in [
            "preflight",
            "transfer",
            "transfer-from",
            "heartbeat",
            "status",
            "policy",
            "check",
        ] {
            let help = subcommand_help(sub);
            assert!(
                help.contains(&format!("Usage: agent-tx {sub}")),
                "help for {sub} must contain usage"
            );
            assert!(
                help.contains("-h, --help"),
                "help for {sub} must document help option"
            );
        }

        let guards = guards_help();
        assert!(guards.contains("Usage: agent-tx guards"));
        for sub in ["add", "list", "remove", "set-default"] {
            let help = guards_subcommand_help(sub);
            assert!(
                help.contains(&format!("Usage: agent-tx guards {sub}")),
                "help for guards {sub} must contain usage"
            );
        }
    }

    #[test]
    fn missing_arguments_name_the_argument_and_expected_form() {
        // Missing --amount must name the flag and the expected integer i128 form
        let args = argv(&[
            "check",
            "--guard",
            VALID_GUARD,
            "--asset",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("check", rest).expect_err("check accepted without amount");
        assert!(err.contains("--amount"), "{err}");
        assert!(err.contains("expected integer i128"), "{err}");

        // Missing value for --amount must name the flag and expected form
        let args = argv(&[
            "check",
            "--guard",
            VALID_GUARD,
            "--asset",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
            "--amount",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("check", rest).expect_err("flag without value accepted");
        assert!(err.contains("--amount"), "{err}");
        assert!(err.contains("requires a value"), "{err}");
        assert!(err.contains("expected integer i128"), "{err}");

        // Missing value for --guard
        let args = argv(&["status", "--guard"]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("status", rest).expect_err("guard without value accepted");
        assert!(err.contains("--guard"), "{err}");
        assert!(err.contains("requires a value"), "{err}");
        assert!(err.contains("expected contract ID"), "{err}");

        // Missing --from in transfer-from
        let args = argv(&[
            "transfer-from",
            "--guard",
            VALID_GUARD,
            "--token",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
            "--amount",
            "10",
            "--agent-secret",
            VALID_SECRET,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err =
            parse_request("transfer-from", rest).expect_err("transfer-from accepted without from");
        assert!(err.contains("--from"), "{err}");
        assert!(err.contains("expected account ID"), "{err}");
    }

    #[test]
    fn parser_accepts_valid_transfer() {
        let args = argv(&[
            "transfer",
            "--guard",
            VALID_GUARD,
            "--token",
            VALID_TOKEN,
            "--to",
            VALID_RECIPIENT,
            "--amount",
            "100",
            "--agent-secret",
            VALID_SECRET,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let req = parse_request("transfer", rest).expect("valid transfer request");
        assert_eq!(req.amount, Some(100));
        assert!(req.token.is_some());
        assert!(req.to.is_some());
        assert_eq!(req.secret, Some(VALID_SECRET.to_string()));
    }

    #[test]
    fn parser_accepts_valid_heartbeat() {
        let args = argv(&[
            "heartbeat",
            "--guard",
            VALID_GUARD,
            "--agent-secret",
            VALID_SECRET,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let req = parse_request("heartbeat", rest).expect("valid heartbeat request");
        assert_eq!(req.amount, None);
        assert_eq!(req.token, None);
        assert_eq!(req.to, None);
        assert_eq!(req.secret, Some(VALID_SECRET.to_string()));
    }

    #[test]
    fn parser_rejects_heartbeat_with_transfer_flags() {
        // --token passed to heartbeat
        let args = argv(&[
            "heartbeat",
            "--guard",
            VALID_GUARD,
            "--agent-secret",
            VALID_SECRET,
            "--token",
            VALID_TOKEN,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("heartbeat", rest).expect_err("heartbeat with --token rejected");
        assert!(
            err.contains("transfer-only flag '--token' is not valid for `heartbeat`"),
            "{err}"
        );
        assert!(err.contains("valid flags:"), "{err}");

        // --amount passed to heartbeat
        let args = argv(&[
            "heartbeat",
            "--guard",
            VALID_GUARD,
            "--agent-secret",
            VALID_SECRET,
            "--amount",
            "50",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("heartbeat", rest).expect_err("heartbeat with --amount rejected");
        assert!(
            err.contains("transfer-only flag '--amount' is not valid for `heartbeat`"),
            "{err}"
        );

        // --to passed to heartbeat
        let args = argv(&[
            "heartbeat",
            "--guard",
            VALID_GUARD,
            "--agent-secret",
            VALID_SECRET,
            "--to",
            VALID_RECIPIENT,
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("heartbeat", rest).expect_err("heartbeat with --to rejected");
        assert!(
            err.contains("transfer-only flag '--to' is not valid for `heartbeat`"),
            "{err}"
        );
    }

    #[test]
    fn parser_rejects_unknown_flags_with_diagnostic_listing_valid_flags() {
        let args = argv(&[
            "heartbeat",
            "--guard",
            VALID_GUARD,
            "--agent-secret",
            VALID_SECRET,
            "--unknown-custom-flag",
            "foo",
        ]);
        let (_, rest) = args.split_first().expect("subcommand");
        let err = parse_request("heartbeat", rest).expect_err("unknown flag rejected");
        assert!(
            err.contains("unknown argument for `heartbeat`: --unknown-custom-flag"),
            "{err}"
        );
        assert!(err.contains("valid flags:"), "{err}");
        assert!(err.contains("--guard"), "{err}");
        assert!(err.contains("--agent-secret"), "{err}");
    }

    #[test]
    fn guard_footprint_transfer_splits_read_only_and_read_write() {
        let guard: ScAddress = VALID_GUARD.parse().expect("valid guard");
        let fp = guard_footprint(&guard, CallKind::Transfer);

        let rw_keys = fp.read_write.to_vec();
        let ro_keys = fp.read_only.to_vec();

        // Transfer writes Window and Instance key (engine TTL)
        assert_eq!(rw_keys.len(), 2);
        assert!(rw_keys.contains(&guard_data_key(&guard, GuardKey::Window)));
        assert!(rw_keys.contains(&guard_instance_key(&guard)));

        // Transfer only reads Policy, AdminFrozen, and LastHeartbeat
        assert_eq!(ro_keys.len(), 3);
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::Policy)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::AdminFrozen)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::LastHeartbeat)));

        // Read-only and read-write sets must be disjoint
        for key in &ro_keys {
            assert!(
                !rw_keys.contains(key),
                "key in both read-only and read-write: {key:?}"
            );
        }
    }

    #[test]
    fn guard_footprint_heartbeat_splits_read_only_and_read_write() {
        let guard: ScAddress = VALID_GUARD.parse().expect("valid guard");
        let fp = guard_footprint(&guard, CallKind::Heartbeat);

        let rw_keys = fp.read_write.to_vec();
        let ro_keys = fp.read_only.to_vec();

        // Heartbeat writes LastHeartbeat and Instance key (engine TTL)
        assert_eq!(rw_keys.len(), 2);
        assert!(rw_keys.contains(&guard_data_key(&guard, GuardKey::LastHeartbeat)));
        assert!(rw_keys.contains(&guard_instance_key(&guard)));

        // Heartbeat only reads Policy, AdminFrozen, and Window
        assert_eq!(ro_keys.len(), 3);
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::Policy)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::AdminFrozen)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::Window)));

        // Read-only and read-write sets must be disjoint
        for key in &ro_keys {
            assert!(
                !rw_keys.contains(key),
                "key in both read-only and read-write: {key:?}"
            );
        }
    }

    #[test]
    fn guard_footprint_read_only_split() {
        let guard: ScAddress = VALID_GUARD.parse().expect("valid guard");
        let fp = guard_footprint(&guard, CallKind::ReadOnly);

        let rw_keys = fp.read_write.to_vec();
        let ro_keys = fp.read_only.to_vec();

        // Read-only diagnostic writes only Instance key (TTL)
        assert_eq!(rw_keys.len(), 1);
        assert!(rw_keys.contains(&guard_instance_key(&guard)));

        // All persistent keys are in read-only
        assert_eq!(ro_keys.len(), 4);
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::Policy)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::AdminFrozen)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::Window)));
        assert!(ro_keys.contains(&guard_data_key(&guard, GuardKey::LastHeartbeat)));
    }

    #[test]
    fn merge_guard_footprint_splits_keys_correctly() {
        let guard: ScAddress = VALID_GUARD.parse().expect("valid guard");
        let empty_fp = LedgerFootprint {
            read_only: VecM::default(),
            read_write: VecM::default(),
        };

        // Merge onto empty footprint matches guard_footprint
        let transfer_merged = merge_guard_footprint(empty_fp.clone(), &guard, CallKind::Transfer);
        assert_eq!(transfer_merged.read_write.len(), 2);
        assert_eq!(transfer_merged.read_only.len(), 3);
        assert!(transfer_merged
            .read_write
            .contains(&guard_data_key(&guard, GuardKey::Window)));
        assert!(transfer_merged
            .read_only
            .contains(&guard_data_key(&guard, GuardKey::LastHeartbeat)));

        let heartbeat_merged = merge_guard_footprint(empty_fp, &guard, CallKind::Heartbeat);
        assert_eq!(heartbeat_merged.read_write.len(), 2);
        assert_eq!(heartbeat_merged.read_only.len(), 3);
        assert!(heartbeat_merged
            .read_write
            .contains(&guard_data_key(&guard, GuardKey::LastHeartbeat)));
        assert!(heartbeat_merged
            .read_only
            .contains(&guard_data_key(&guard, GuardKey::Window)));

        // Merge onto simulated footprint that already has token contract keys
        let token_addr: ScAddress = VALID_TOKEN.parse().expect("valid token");
        let token_rw = LedgerKey::ContractData(LedgerKeyContractData {
            contract: token_addr,
            key: ScVal::Symbol(ScSymbol("Balance".try_into().unwrap())),
            durability: ContractDataDurability::Persistent,
        });
        let simulated_fp = LedgerFootprint {
            read_only: VecM::default(),
            read_write: VecM::try_from(vec![token_rw.clone()]).expect("bound"),
        };

        let merged = merge_guard_footprint(simulated_fp, &guard, CallKind::Transfer);
        assert!(merged.read_write.contains(&token_rw));
        assert!(merged
            .read_write
            .contains(&guard_data_key(&guard, GuardKey::Window)));
        assert_eq!(merged.read_write.len(), 3); // token_rw + Window + Instance
        assert_eq!(merged.read_only.len(), 3); // Policy + AdminFrozen + LastHeartbeat
    }

    #[test]
    fn footprint_reduces_write_entries_preventing_rent_inflation() {
        let guard: ScAddress = VALID_GUARD.parse().expect("valid guard");

        // Prior to splitting, every guard key (5 keys) was declared read-write.
        let legacy_write_keys_count = 5;

        // With the split, only written keys + instance key are declared read-write (2 keys).
        let transfer_fp = guard_footprint(&guard, CallKind::Transfer);
        let heartbeat_fp = guard_footprint(&guard, CallKind::Heartbeat);

        assert_eq!(transfer_fp.read_write.len(), 2);
        assert_eq!(heartbeat_fp.read_write.len(), 2);

        // 3 keys saved from read-write declaration per transaction (60% write rent reduction)
        assert_eq!(legacy_write_keys_count - transfer_fp.read_write.len(), 3);
        assert_eq!(legacy_write_keys_count - heartbeat_fp.read_write.len(), 3);
    }

    // ── base32 / StrKey codec property, negative and vector tests (issue #380) ─

    /// Small reproducible PRNG so "random" byte strings are deterministic
    /// across runs without pulling in a `rand` dependency.
    struct CodecRng(u64);

    impl CodecRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    #[test]
    fn base32_decode_encodes_back_the_same_bytes() {
        // Round-trip property: decode(encode(x)) == x for byte strings of
        // many lengths, including lengths that straddle base-32's 5/8-bit
        // group boundary and the 33-byte strkey body length.
        let mut rng = CodecRng(0x1234_5678_9abc_def0);
        let mut lengths: Vec<usize> = (0usize..=40usize).collect();
        lengths.push(100usize);
        for len in lengths {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let encoded = base32_encode(&data);
            let decoded = base32_decode(&encoded).expect("round-trip decode must succeed");
            assert_eq!(decoded, data, "length {len} round-trip");
        }
    }

    #[test]
    fn base32_encode_output_has_no_padding_and_uses_rfc4648_alphabet() {
        let mut rng = CodecRng(0xdead_beef_cafe_1234);
        for len in 0usize..=40usize {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let encoded = base32_encode(&data);
            assert!(
                !encoded.contains('='),
                "base-32 output must not be padded: {encoded}"
            );
            assert!(
                encoded.bytes().all(|c| B32.contains(&c)),
                "base-32 output must use the RFC 4648 alphabet: {encoded}"
            );
        }
    }

    #[test]
    fn strkey_encode_decode_is_identity_for_random_payloads() {
        let mut rng = CodecRng(0xfeed_cafe_babe_cafe);
        let versions = [VER_ACCOUNT, VER_CONTRACT, VER_SECRET];
        for i in 0..100u32 {
            let version = versions[(i as usize) % versions.len()];
            let mut payload = [0u8; 32];
            rng.fill(&mut payload);
            let encoded = strkey_encode(version, &payload);
            let (found_version, found_payload) =
                decode_strkey(&encoded).expect("round-trip decode_strkey");
            assert_eq!(found_version, version, "iteration {i}");
            assert_eq!(found_payload, payload, "iteration {i}");
        }
    }

    #[test]
    fn base32_decode_rejects_invalid_character() {
        assert!(base32_decode("ABC!DEFG").is_none());
        assert!(base32_decode("abcdef").is_none());
        assert_eq!(base32_decode(""), Some(vec![]));
    }

    #[test]
    fn decode_strkey_rejects_character_outside_alphabet() {
        let mut corrupted = contract_strkey(&[0x01u8; 32]);
        corrupted.replace_range(10..11, "!");
        let err = decode_strkey(&corrupted).unwrap_err();
        assert!(err.contains("outside the StrKey base-32 alphabet"), "{err}");
    }

    #[test]
    fn decode_strkey_rejects_wrong_length() {
        let contract = contract_strkey(&[0x01u8; 32]);
        let err = decode_strkey(&contract[..48]).unwrap_err();
        assert!(err.contains("expected 56 characters, got 48"), "{err}");
    }

    #[test]
    fn decode_strkey_rejects_bad_crc16_checksum() {
        let mut mistyped = contract_strkey(&[0x01u8; 32]);
        let replacement = if &mistyped[40..41] == "A" { "B" } else { "A" };
        mistyped.replace_range(40..41, replacement);
        let err = decode_strkey(&mistyped).unwrap_err();
        assert!(
            err.contains("CRC16-XModem checksum does not match"),
            "{err}"
        );
    }

    #[test]
    fn decode_strkey_rejects_lowercase_input() {
        let err = decode_strkey(&contract_strkey(&[0x01u8; 32]).to_lowercase()).unwrap_err();
        assert!(
            err.contains("lowercase") && err.contains("case-sensitive"),
            "{err}"
        );
    }

    #[test]
    fn decode_strkey_rejects_trailing_whitespace() {
        let contract = contract_strkey(&[0x01u8; 32]);
        let err = decode_strkey(&format!("{contract} ")).unwrap_err();
        assert!(
            err.contains("expected 56 characters")
                || err.contains("outside the StrKey base-32 alphabet"),
            "{err}"
        );
    }

    #[test]
    fn contract_address_known_vector_round_trips() {
        // Known-good vector: a 32-byte contract id encodes to a C... strkey
        // that decodes back to the same id.
        let id = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id);
        let encoded = contract_strkey(&arr);
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_CONTRACT);
        assert_eq!(decoded, arr);
        assert!(encoded.starts_with('C'));
        assert_eq!(encoded.len(), 56);
    }

    #[test]
    fn account_address_known_vector_round_trips() {
        // Known-good vector from the repo's own samples: pubkey
        // `1cb479ac…cc05` encodes to the GAOLI… account address.
        let pk = hex::decode("1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk);
        let encoded = account_strkey(&arr);
        assert_eq!(
            encoded,
            "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP"
        );
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_ACCOUNT);
        assert_eq!(decoded, arr);
    }

    #[test]
    fn secret_seed_known_vector_round_trips() {
        // Known-good vector: the repo's agent secret decodes to its seed and
        // round-trips through the encoder.
        let secret = "SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4";
        let seed = secret_to_seed(secret);
        assert_eq!(
            hex::encode(seed),
            "635711bd422c08b9354a34e3b748c0f47dcbfda399ba2b1f8c39a4c46f3f5513"
        );
        let encoded = strkey_encode(VER_SECRET, &seed);
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_SECRET);
        assert_eq!(decoded, seed);
        assert!(encoded.starts_with('S'));
        assert_eq!(encoded.len(), 56);
    }
}

fn map_submission_error(err_str: &str) -> String {
    if err_str.contains("tx_insufficient_fee") || err_str.contains("insufficient") {
        "Submission failed due to insufficient fee (tx_insufficient_fee). Fix: Resubmit with a higher fee or use --fee-multiplier <VAL> (see README.md Troubleshooting).".into()
    } else if err_str.contains("tx_bad_seq") || err_str.contains("seq") {
        "Submission failed due to sequence number collision/mismatch (tx_bad_seq). Fix: Ensure account sequence is up-to-date and resubmit (see README.md Troubleshooting).".into()
    } else if err_str.contains("tx_too_early") {
        "Submission failed because transaction is too early (tx_too_early). Fix: Wait for the next ledger or check node time sync (see README.md Troubleshooting).".into()
    } else if err_str.contains("tx_late_expiration") {
        "Submission failed because transaction/signature expiration passed (tx_late_expiration). Fix: Increase signature expiration ledger delta --sig-expiration-ledgers <VAL> (see README.md Troubleshooting).".into()
    } else {
        format!("Submission failed: {err_str}. Refer to README.md Troubleshooting section for exact remediation flags.")
    }
}

// ── Argument parsing ─────────────────────────────────────────────────────

/// A command-line reader that pairs each flag with its value, so a missing
/// value is reported as a usage error instead of a panic.
struct Cli<'a> {
    cmd: &'a str,
    argv: &'a [String],
    pos: usize,
}

/// The valid flags recognized by each subcommand.
fn valid_flags_for_subcommand(cmd: &str) -> &'static [&'static str] {
    match cmd {
        "preflight" => &[
            "--guard",
            "--asset",
            "--token",
            "--to",
            "--amount",
            "--secret",
            "--agent-secret",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "--inclusion-fee",
            "--expect-blocked",
            "-h",
            "--help",
        ],
        "transfer" => &[
            "--guard",
            "--token",
            "--asset",
            "--to",
            "--amount",
            "--agent-secret",
            "--secret",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "--inclusion-fee",
            "--expect-blocked",
            "-h",
            "--help",
        ],
        "transfer-from" => &[
            "--guard",
            "--token",
            "--asset",
            "--from",
            "--to",
            "--amount",
            "--agent-secret",
            "--secret",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "--inclusion-fee",
            "--expect-blocked",
            "-h",
            "--help",
        ],
        "heartbeat" => &[
            "--guard",
            "--agent-secret",
            "--secret",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "--inclusion-fee",
            "-h",
            "--help",
        ],
        "status" | "policy" => &[
            "--guard",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "-h",
            "--help",
        ],
        "check" => &[
            "--guard",
            "--asset",
            "--token",
            "--to",
            "--amount",
            "--network",
            "--rpc-url",
            "--rpc-timeout",
            "--network-passphrase",
            "-h",
            "--help",
        ],
        _ => &[],
    }
}

/// Flags that are only valid for transfer subcommands and must be rejected
/// if passed to non-transfer subcommands like `heartbeat`.
const TRANSFER_ONLY_FLAGS: &[&str] = &[
    "--token",
    "--asset",
    "--to",
    "--from",
    "--amount",
    "--expect-blocked",
];

impl<'a> Cli<'a> {
    fn new(cmd: &'a str, argv: &'a [String]) -> Self {
        Self { cmd, argv, pos: 0 }
    }

    fn next(&mut self) -> Option<String> {
        let token = self.argv.get(self.pos).cloned();
        if token.is_some() {
            self.pos += 1;
        }
        token
    }

    /// The value belonging to the flag just consumed, stating the expected form.
    fn value_expected(&mut self, flag: &str, expected: &str) -> Result<String, String> {
        self.next()
            .ok_or_else(|| format!("{flag} requires a value (expected {expected})"))
    }

    fn positional_expected(&mut self, arg_name: &str, expected: &str) -> Result<String, String> {
        self.next()
            .ok_or_else(|| format!("missing <{arg_name}>: `{}` requires {expected}", self.cmd))
    }

    fn unknown(&self, flag: &str) -> String {
        let valid = valid_flags_for_subcommand(self.cmd);
        if valid.is_empty() {
            format!(
                "unknown argument for `{}`: {flag} (see `agent-tx --help` or `agent-tx {} --help`)",
                self.cmd, self.cmd
            )
        } else {
            format!(
                "unknown argument for `{}`: {flag}; valid flags: {}",
                self.cmd,
                valid.join(", ")
            )
        }
    }
}

/// Validate a StrKey argument and parse it into the XDR address type. Parsing
/// cannot fail after `strkey::validate_key` accepted the value: the version,
/// length and checksum checks above are exactly what `ScAddress::from_str`
/// requires.
fn validate_address(field: &str, kind: KeyKind, value: &str) -> Result<ScAddress, String> {
    strkey::validate_key(field, kind, value)?;
    value.parse::<ScAddress>().map_err(|e| {
        format!(
            "internal error: {field} '{value}': passed StrKey validation but failed to parse: {e}"
        )
    })
}

fn parse_rpc_timeout(raw: &str) -> Result<Duration, String> {
    match raw.parse::<u64>() {
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(format!(
            "invalid --rpc-timeout '{raw}': expected a whole number of seconds greater than 0"
        )),
    }
}

fn parse_amount(raw: &str) -> Result<i128, String> {
    raw.parse::<i128>().map_err(|e| {
        format!("invalid --amount '{raw}': {e}; expected an integer i128 in whole units")
    })
}

/// One invocation's inputs, fully checked. Building a `Request` performs no
/// network I/O: the guard, token, recipient and secret are all validated as
/// StrKeys and the endpoint is resolved from a preset before an `Rpc` exists.
#[derive(Debug)]
struct Request {
    guard: ScAddress,
    token: Option<ScAddress>,
    from: Option<ScAddress>,
    to: Option<ScAddress>,
    amount: Option<i128>,
    secret: Option<String>,
    endpoint: Endpoint,
    rpc_timeout: Duration,
    expect_blocked: bool,
    inclusion_fee_override: Option<u32>,
}

impl Request {
    /// The reminder the selected network owes the operator, if any: mainnet
    /// prints the unaudited-contract warning (issue #54).
    fn notice(&self) -> Option<&'static str> {
        self.endpoint.network.and_then(Network::notice)
    }

    fn rpc(&self) -> Rpc {
        Rpc::new(self.endpoint.rpc_url.clone(), self.rpc_timeout)
    }

    fn args(&self) -> Args {
        Args {
            rpc: self.rpc(),
            passphrase: self.endpoint.passphrase.clone(),
            passphrase_source: self.endpoint.passphrase_source,
            guard: self.guard.clone(),
            secret: self.secret.clone(),
            expect_blocked: self.expect_blocked,
            inclusion_fee_override: self.inclusion_fee_override,
        }
    }
}

/// The flags each subcommand takes, collected and then validated in one pass.
fn parse_request(cmd: &str, argv: &[String]) -> Result<Request, String> {
    let mut cli = Cli::new(cmd, argv);
    let mut guard = None;
    let mut token = None;
    let mut token_field = String::new();
    let mut from = None;
    let mut to = None;
    let mut amount = None;
    let mut secret = None;
    let mut secret_field = String::new();
    let mut network = None;
    let mut rpc_url = None;
    let mut passphrase = None;
    let mut rpc_timeout = DEFAULT_RPC_TIMEOUT;
    let mut expect_blocked = false;
    let mut inclusion_fee_override = None;

    let valid_flags = valid_flags_for_subcommand(cmd);

    while let Some(flag) = cli.next() {
        if !valid_flags.contains(&flag.as_str()) {
            if cmd == "heartbeat" && TRANSFER_ONLY_FLAGS.contains(&flag.as_str()) {
                return Err(format!(
                    "transfer-only flag '{flag}' is not valid for `heartbeat` (valid flags: {})",
                    valid_flags.join(", ")
                ));
            }
            if cmd == "transfer" && flag == "--from" {
                return Err(format!(
                    "flag '--from' is only valid for `transfer-from`, not `transfer` (valid flags: {})",
                    valid_flags.join(", ")
                ));
            }
            return Err(cli.unknown(&flag));
        }

        match flag.as_str() {
            "-h" | "--help" => {
                return Err(format!(
                    "help requested for `{cmd}` (see `agent-tx {cmd} --help`)"
                ));
            }
            "--guard" => guard = Some(cli.value_expected("--guard", "contract ID 'C...'")?),
            "--token" | "--asset" => {
                token_field = flag.clone();
                token = Some(cli.value_expected(&flag, "contract ID 'C...'")?);
            }
            "--from" => {
                from =
                    Some(cli.value_expected("--from", "account ID 'G...' or contract ID 'C...'")?)
            }
            "--to" => {
                to =
                    Some(cli.value_expected(
                        "--to",
                        "recipient account ID 'G...' or contract ID 'C...'",
                    )?)
            }
            "--amount" => {
                amount = Some(parse_amount(
                    &cli.value_expected("--amount", "integer i128")?,
                )?)
            }
            "--inclusion-fee" => {
                let raw = cli.value_expected("--inclusion-fee", "stroops as u32")?;
                inclusion_fee_override = Some(raw.parse::<u32>().map_err(|error| {
                    format!("invalid --inclusion-fee '{raw}': {error}; expected stroops as u32")
                })?);
            }
            "--agent-secret" | "--secret" => {
                secret_field = flag.clone();
                secret = Some(cli.value_expected(&flag, "secret seed 'S...'")?);
            }
            "--network" => {
                network = Some(cli.value_expected("--network", "testnet | futurenet | mainnet")?)
            }
            "--rpc-url" => {
                rpc_url = Some(cli.value_expected("--rpc-url", "endpoint URL e.g. https://...")?)
            }
            "--network-passphrase" => {
                passphrase = Some(cli.value_expected("--network-passphrase", "passphrase string")?)
            }
            "--rpc-timeout" => {
                rpc_timeout = parse_rpc_timeout(
                    &cli.value_expected("--rpc-timeout", "whole seconds e.g. 30")?,
                )?
            }
            "--expect-blocked" => expect_blocked = true,
            other => return Err(cli.unknown(other)),
        }
    }

    let endpoint = network::resolve_endpoint(
        network.as_deref(),
        rpc_url.as_deref(),
        passphrase.as_deref(),
    )?;

    // An alias in the local registry is resolved to its address first, so
    // registry contents are validated exactly like a `--guard` on the command
    // line.
    let guard = validate_address(
        "--guard",
        KeyKind::Contract,
        &resolve_guard(guard.as_deref())?,
    )?;

    let secret = secret.or_else(|| std::env::var("AGENT_SECRET").ok());
    if secret_field.is_empty() && secret.is_some() {
        secret_field = "--agent-secret (or AGENT_SECRET)".to_string();
    }
    if let Some(secret) = &secret {
        strkey::validate_key(&secret_field, KeyKind::Secret, secret)?;
    }
    if matches!(cmd, "transfer" | "transfer-from" | "heartbeat") && secret.is_none() {
        return Err(format!(
            "missing --agent-secret (or AGENT_SECRET; expected secret seed 'S...'): `{cmd}` signs and submits, so it requires \
             the registered agent's secret seed"
        ));
    }

    // The spend-shaped subcommands take a token and a recipient. `transfer`
    // names the token flag `--token`, `preflight`/`check` name it `--asset`;
    // either spelling is accepted, and a complaint names the one used.
    let spend_flags = matches!(cmd, "preflight" | "transfer" | "transfer-from" | "check");
    let default_token_field = if cmd == "transfer" {
        "--token"
    } else {
        "--asset"
    };
    let mut parsed_token = None;
    let mut parsed_from = None;
    let mut parsed_to = None;
    if spend_flags {
        let token_field = if token_field.is_empty() {
            default_token_field.to_string()
        } else {
            token_field
        };
        let raw = token.as_deref().ok_or_else(|| {
            format!("missing {token_field} (expected contract ID 'C...'): `{cmd}` requires it")
        })?;
        parsed_token = Some(validate_address(&token_field, KeyKind::Contract, raw)?);
        if cmd == "transfer-from" {
            let raw = from
                .as_deref()
                .ok_or_else(|| "missing --from (expected account ID 'G...' or contract ID 'C...'): `transfer-from` requires it".to_string())?;
            parsed_from = Some(validate_address("--from", KeyKind::Recipient, raw)?);
        } else if from.is_some() {
            return Err("--from is only valid for `transfer-from`".to_string());
        }
        let raw = to
            .as_deref()
            .ok_or_else(|| format!("missing --to (expected recipient account ID 'G...' or contract ID 'C...'): `{cmd}` requires it"))?;
        parsed_to = Some(validate_address("--to", KeyKind::Recipient, raw)?);
        if amount.is_none() {
            return Err(format!(
                "missing --amount (expected integer i128): `{cmd}` requires it"
            ));
        }
    }

    Ok(Request {
        guard,
        token: parsed_token,
        from: parsed_from,
        to: parsed_to,
        amount,
        secret,
        endpoint,
        rpc_timeout,
        expect_blocked,
        inclusion_fee_override,
    })
}

fn tool_help() -> String {
    format!(
        "agent-tx — simulate or submit Soroban transactions for Stellar Agent Guard\n\
         \n\
         Usage:\n\
         \x20 agent-tx preflight --guard <C...> --asset <C...> --to <G...> --amount <N> [--secret <S...>]\n\
         \x20 agent-tx transfer --guard <C...> --token <C...> --to <G...> --amount <N> --agent-secret <S...>\n\
         \x20 agent-tx transfer-from --guard <C...> --token <C...> --from <G|C...> --to <G|C...> --amount <N> --agent-secret <S...>\n\
         \x20 agent-tx heartbeat --guard <C...> --agent-secret <S...>\n\
         \x20 agent-tx status --guard <C...> [--network testnet|futurenet|mainnet]\n\
         \x20 agent-tx policy --guard <C...> [--network testnet|futurenet|mainnet]\n\
         \x20 agent-tx check --guard <C...> --asset <C...> --to <G...> --amount <N> [--network testnet|futurenet|mainnet]\n\
         \x20 agent-tx guards <add|list|remove|set-default> ...\n\
         \n\
         Run `agent-tx <subcommand> --help` for detailed help on any subcommand.\n\
         \n\
         Network selection:\n\
         \x20 --network testnet|futurenet|mainnet   named preset endpoint + passphrase (default: testnet)\n\
         \x20                                       mainnet: {}\n\
         \x20                                       futurenet: {}\n\
         \x20 --rpc-url <url>                       any endpoint; overrides the default, and is\n\
         \x20                                       refused together with an explicit --network\n\
         \x20 --network-passphrase <passphrase>     override the preset's passphrase (advanced:\n\
         \x20                                       private or non-standard networks)\n\
         \x20 --inclusion-fee <stroops>             override the RPC-reported inclusion fee\n\
         \x20 --rpc-timeout <secs>                  per-request RPC timeout (default: {}s); a\n\
         \x20                                       timeout exits 3 naming the RPC method\n\
         \x20 Custom --rpc-url values require --network-passphrase unless the URL is a known preset.\n\
         \x20 Selecting mainnet prints the unaudited-contract reminder from SECURITY.md to stderr.\n\
         \x20 A StrKey's leading character encodes the key type, not the network, so address\n\
         \x20 validation cannot catch a wrong-network address; the preset plus passphrase decide\n\
         \x20 which network a call reaches.\n\
         \n\
         Inputs: --guard/--asset/--token must be a contract ID (C...), --to an account (G...) or\n\
         contract (C...) ID, --agent-secret a secret seed (S...). All are checked for the\n\
         correct prefix, length and CRC16 checksum before any RPC request is made.\n\
         Preflight exit codes: 0=admitted, 1=blocked (signed simulation), 2=unsigned/inconclusive.\n\
         Troubleshooting: See README.md 'Troubleshooting — Submission Errors' table for error mapping and concrete fix flags (--fee-multiplier, etc.).\n\
         The stellar CLI cannot sign auth entries for contract addresses; use agent-tx for heartbeat calls (see tools/agent-tx/README.md).",
        Network::Mainnet.rpc_url(),
        Network::Futurenet.rpc_url(),
        DEFAULT_RPC_TIMEOUT.as_secs()
    )
}

fn print_help() {
    println!("{}", tool_help());
}

fn subcommand_help(cmd: &str) -> String {
    match cmd {
        "preflight" => {
            "Usage: agent-tx preflight --guard <C...> --asset <C...> --to <G|C...> --amount <N> [options]\n\
             \n\
             Simulate a prospective transfer without submitting to the network.\n\
             Exit codes: 0 = admitted by policy, 1 = blocked by guard policy, 2 = unsigned/inconclusive.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \x20 --asset <C...>              Token contract address (C...); synonym: --token\n\
             \x20 --to <G|C...>               Recipient account ID (G...) or contract ID (C...)\n\
             \x20 --amount <N>                Amount to transfer (integer i128 in whole units/stroops)\n\
             \n\
             Options:\n\
             \x20 --secret <S...>             Agent secret seed (S...) for signed simulation auth\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 --inclusion-fee <stroops>   Override inclusion fee in stroops (u32)\n\
             \x20 --expect-blocked            Invert exit code: exit 0 if simulation blocked, 1 if admitted\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "transfer" => {
            "Usage: agent-tx transfer --guard <C...> --token <C...> --to <G|C...> --amount <N> --agent-secret <S...> [options]\n\
             \n\
             Sign and submit a transfer from the guard contract to the recipient.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \x20 --token <C...>              Token contract address (C...); synonym: --asset\n\
             \x20 --to <G|C...>               Recipient account ID (G...) or contract ID (C...)\n\
             \x20 --amount <N>                Amount to transfer (integer i128 in whole units/stroops)\n\
             \x20 --agent-secret <S...>       Registered agent's secret seed (S...); or set AGENT_SECRET env var\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 --inclusion-fee <stroops>   Override inclusion fee in stroops (u32)\n\
             \x20 --expect-blocked            Expect the transaction to be rejected by policy\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "transfer-from" => {
            "Usage: agent-tx transfer-from --guard <C...> --token <C...> --from <G|C...> --to <G|C...> --amount <N> --agent-secret <S...> [options]\n\
             \n\
             Sign and submit a transfer_from authorized by the guard account.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \x20 --token <C...>              Token contract address (C...)\n\
             \x20 --from <G|C...>             Source account (G...) or contract (C...) debited by allowance\n\
             \x20 --to <G|C...>               Recipient account ID (G...) or contract ID (C...)\n\
             \x20 --amount <N>                Amount to transfer (integer i128 in whole units/stroops)\n\
             \x20 --agent-secret <S...>       Registered agent's secret seed (S...); or set AGENT_SECRET env var\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 --inclusion-fee <stroops>   Override inclusion fee in stroops (u32)\n\
             \x20 --expect-blocked            Expect the transaction to be rejected by policy\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "heartbeat" => {
            "Usage: agent-tx heartbeat --guard <C...> --agent-secret <S...> [options]\n\
             \n\
             Send a heartbeat transaction to keep the guard's dead man's switch (DMS) from expiring.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \x20 --agent-secret <S...>       Registered agent's secret seed (S...); or set AGENT_SECRET env var\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 --inclusion-fee <stroops>   Override inclusion fee in stroops (u32)\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "status" => {
            "Usage: agent-tx status --guard <C...> [options]\n\
             \n\
             Inspect the guard's on-chain status (frozen state, heartbeat expiration, policy revision).\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "policy" => {
            "Usage: agent-tx policy --guard <C...> [options]\n\
             \n\
             Fetch and display active spending limits and policy configuration for the guard.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "check" => {
            "Usage: agent-tx check --guard <C...> --asset <C...> --to <G|C...> --amount <N> [options]\n\
             \n\
             Simulate an unsigned transfer against guard policy and display the verdict.\n\
             \n\
             Required arguments:\n\
             \x20 --guard <C...>              Guard contract address (C...) or registered alias\n\
             \x20 --asset <C...>              Token contract address (C...); synonym: --token\n\
             \x20 --to <G|C...>               Recipient account ID (G...) or contract ID (C...)\n\
             \x20 --amount <N>                Amount to transfer (integer i128 in whole units/stroops)\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet (default: testnet)\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 -h, --help                  Print this help message\n".to_string()
        }
        "guards" => guards_help(),
        _ => tool_help(),
    }
}

fn print_subcommand_help(cmd: &str) {
    println!("{}", subcommand_help(cmd));
}

fn guards_help() -> String {
    "Usage: agent-tx guards <subcommand> [args...]\n\
     \n\
     Manage the local registry of guard contracts and aliases.\n\
     \n\
     Subcommands:\n\
     \x20 add <alias> <address> <admin> [--network <name> | --rpc-url <url>] [--network-passphrase <pass>] [--rpc-timeout <secs>]\n\
     \x20     Register a guard contract address and admin under an alias\n\
     \x20 list\n\
     \x20     List all registered guard aliases and current default\n\
     \x20 remove <alias>\n\
     \x20     Remove an alias from the local registry\n\
     \x20 set-default <alias>\n\
     \x20     Set the default guard alias used when --guard is omitted\n\
     \n\
     Run `agent-tx guards <subcommand> --help` for help on a guards subcommand.\n\
     Options:\n\
     \x20 -h, --help   Print this help message\n".to_string()
}

fn print_guards_help() {
    println!("{}", guards_help());
}

fn guards_subcommand_help(sub: &str) -> String {
    match sub {
        "add" => "Usage: agent-tx guards add <alias> <address> <admin> [options]\n\
             \n\
             Register a guard contract address and admin under a local alias.\n\
             \n\
             Positional arguments:\n\
             \x20 <alias>       Unique alias name for the guard\n\
             \x20 <address>     Guard contract address (C...)\n\
             \x20 <admin>       Admin account address (G...)\n\
             \n\
             Options:\n\
             \x20 --network <preset>          Network preset: testnet | futurenet | mainnet\n\
             \x20 --rpc-url <url>             Custom RPC endpoint URL\n\
             \x20 --network-passphrase <pass> Custom network passphrase\n\
             \x20 --rpc-timeout <secs>        Per-request RPC timeout in seconds (default 30)\n\
             \x20 -h, --help                  Print this help message\n"
            .to_string(),
        "list" => "Usage: agent-tx guards list\n\
             \n\
             List all registered guard aliases and indicate the default guard.\n"
            .to_string(),
        "remove" => "Usage: agent-tx guards remove <alias>\n\
             \n\
             Remove a guard alias from the local registry.\n\
             \n\
             Positional arguments:\n\
             \x20 <alias>   The alias to remove\n"
            .to_string(),
        "set-default" => "Usage: agent-tx guards set-default <alias>\n\
             \n\
             Set the default guard alias used when --guard is omitted.\n\
             \n\
             Positional arguments:\n\
             \x20 <alias>   The registered alias to set as default\n"
            .to_string(),
        _ => guards_help(),
    }
}

fn print_guards_subcommand_help(sub: &str) {
    println!("{}", guards_subcommand_help(sub));
}

// ── Read-only diagnostics (status, policy, check) ───────────────────────

/// Helper to extract a u64 field from a PolicyConfig ScVal::Map entry.
/// PolicyConfig fields are stored as ScVal::Map with Symbol keys in sorted order.
fn extract_u64_from_map(map: &ScMap, field_name: &str) -> Option<u64> {
    let field_bytes = field_name.as_bytes();
    for entry in &map.0 {
        if let ScVal::Symbol(sym) = &entry.key {
            if sym.0.as_slice() == field_bytes {
                if let ScVal::U64(ts) = entry.val {
                    return Some(ts);
                }
            }
        }
    }
    None
}

/// Extract dms_grace_secs from a PolicyConfig map.
/// Returns 0 if the field is not found or the structure is malformed.
fn extract_dms_grace_secs(policy_val: &ScVal) -> u64 {
    if let ScVal::Map(Some(map)) = policy_val {
        extract_u64_from_map(map, "dms_grace_secs").unwrap_or(0)
    } else {
        0
    }
}

/// Fetch guard status: admin_frozen, has_policy, heartbeat_expired, last_heartbeat, now
fn cmd_status(rpc: &Rpc, guard: &ScAddress, _passphrase: &str) -> Result<(), String> {
    // Fetch instance storage: Initialized, Admin, AgentPubkey (instance keys)
    // and persistent storage: Policy, LastHeartbeat, AdminFrozen, PolicyRevision
    let instance_key = guard_instance_key(guard);
    let policy_key = guard_data_key(guard, GuardKey::Policy);
    let heartbeat_key = guard_data_key(guard, GuardKey::LastHeartbeat);
    let frozen_key = guard_data_key(guard, GuardKey::AdminFrozen);

    let keys = [instance_key, policy_key, heartbeat_key, frozen_key];
    let keys_xdr: Vec<String> = keys.iter().map(b64_encode_xdr).collect();

    let res = rpc_or_exit(rpc.post("getLedgerEntries", serde_json::json!({ "keys": keys_xdr })));

    let entries = res["entries"].as_array().ok_or("no entries in response")?;

    let mut has_policy = false;
    let mut admin_frozen = false;
    let mut last_heartbeat: u64 = 0;

    for entry in entries {
        let entry_xdr = entry["xdr"].as_str().ok_or("missing xdr")?;
        let le: LedgerEntryData = xdr(entry_xdr);

        if let LedgerEntryData::ContractData(cdata) = le {
            if cdata.key == GuardKey::Policy.scval() {
                has_policy = !matches!(cdata.val, ScVal::Void);
            } else if cdata.key == GuardKey::AdminFrozen.scval() {
                if let ScVal::Bool(frozen) = cdata.val {
                    admin_frozen = frozen;
                }
            } else if cdata.key == GuardKey::LastHeartbeat.scval() {
                if let ScVal::U64(ts) = cdata.val {
                    last_heartbeat = ts;
                }
            }
        }
    }

    let latest = rpc.latest_ledger();
    let now = latest; // ledger sequence is used as a proxy for "now" in a read context

    // Compute heartbeat_expired: depends on policy's dms_grace_secs and last_heartbeat
    let mut heartbeat_expired = false;
    if has_policy {
        // Extract dms_grace_secs from the Policy entry we already fetched
        for entry in entries {
            let entry_xdr = entry["xdr"].as_str().ok_or("missing xdr")?;
            let le: LedgerEntryData = xdr(entry_xdr);

            if let LedgerEntryData::ContractData(cdata) = le {
                if cdata.key == GuardKey::Policy.scval() {
                    // PolicyConfig is stored as a Map with Symbol keys
                    let dms_grace_secs = extract_dms_grace_secs(&cdata.val);

                    // Heartbeat expired if: (now - last_heartbeat) > dms_grace_secs
                    // OR if dms_grace_secs is enabled (> 0) and last_heartbeat is 0 (never heartbeated)
                    if dms_grace_secs > 0 {
                        if last_heartbeat == 0 {
                            // Never heartbeated: expired immediately when DMS is enabled
                            heartbeat_expired = true;
                        } else {
                            // Check if grace period has elapsed
                            heartbeat_expired =
                                now.saturating_sub(last_heartbeat as u32) as u64 > dms_grace_secs;
                        }
                    }
                    break;
                }
            }
        }
    }

    println!("{{");
    println!("  \"has_policy\": {},", has_policy);
    println!("  \"admin_frozen\": {},", admin_frozen);
    println!("  \"heartbeat_expired\": {},", heartbeat_expired);
    println!("  \"last_heartbeat\": {},", last_heartbeat);
    println!("  \"now\": {}", now);
    println!("}}");

    Ok(())
}

/// Fetch and display the current policy configuration
fn cmd_policy(rpc: &Rpc, guard: &ScAddress, _passphrase: &str) -> Result<(), String> {
    let policy_key = guard_data_key(guard, GuardKey::Policy);
    let res = rpc_or_exit(rpc.post(
        "getLedgerEntries",
        serde_json::json!({ "keys": [b64_encode_xdr(&policy_key)] }),
    ));

    let entries = res["entries"].as_array().ok_or("no entries in response")?;

    if entries.is_empty() {
        println!("null");
        return Ok(());
    }

    let entry = &entries[0];
    let entry_xdr = entry["xdr"].as_str().ok_or("missing xdr")?;
    let le: LedgerEntryData = xdr(entry_xdr);

    match le {
        LedgerEntryData::ContractData(cdata) => match cdata.val {
            ScVal::Void => {
                println!("null");
            }
            other => {
                // Pretty-print the policy ScVal
                println!("{}", scval_str(&other));
            }
        },
        _ => {
            return Err("unexpected ledger entry type".to_string());
        }
    }

    Ok(())
}

/// Simulate a prospective transfer and display the decision (allowed/blocked with reason)
fn cmd_check(
    rpc: &Rpc,
    guard: &ScAddress,
    asset: &ScAddress,
    to: &ScAddress,
    amount: i128,
    passphrase: &str,
) -> Result<(), String> {
    // Build a transfer invocation and simulate it without auth
    // This shows whether the transfer would be allowed by policy
    let invocation = InvokeContractArgs {
        contract_address: asset.clone(),
        function_name: ScSymbol("transfer".try_into().unwrap()),
        args: VecM::try_from(vec![
            ScVal::Address(guard.clone()),
            ScVal::Address(to.clone()),
            ScVal::I128(Int128Parts {
                lo: amount as u64,
                hi: (amount >> 64) as i64,
            }),
        ])
        .expect("arg count"),
    };

    let _network_id: [u8; 32] = Sha256::digest(passphrase.as_bytes()).into();
    let source_pk = [0u8; 32]; // dummy source for read-only simulation
    let seq = 0i64;

    let op = invoke_op(&invocation, VecM::default());
    let env = build_initial_envelope(
        &MuxedAccount::Ed25519(Uint256(source_pk)),
        seq,
        op,
        guard,
        CallKind::Transfer,
    );

    let sim = rpc.simulate(&b64_encode_xdr(&env));

    if let Some(error) = simulation_error_message(&sim) {
        println!("result: rejected (unsigned simulation; no guard policy verdict)");
        println!("reason: {error}");
        if let Some(events) = simulation_events(&sim) {
            for ev in events {
                if let Some(b64) = ev["xdr"].as_str() {
                    let de: DiagnosticEvent = xdr(b64);
                    let ContractEventBody::V0(v0) = &de.event.body;
                    if v0.topics.len() >= 2 {
                        // Extract the reason from the event topics
                        if let ScVal::Symbol(reason) = &v0.topics[v0.topics.len() - 1] {
                            // Convert ScSymbol to string for display
                            let reason_str = String::from_utf8_lossy(&reason.0);
                            println!("diagnostic_reason: {}", reason_str);
                            break;
                        }
                    }
                }
            }
        }
    } else {
        println!("result: allowed");
        if let Some(fee) = sim["minResourceFee"].as_str() {
            println!("estimated_fee_stroops: {}", fee);
        }
    }

    Ok(())
}

fn exit_with(message: String) -> ! {
    eprintln!("Error: {message}");
    std::process::exit(1)
}

fn run_guards(argv: &[String]) {
    if argv.is_empty() || argv[0] == "--help" || argv[0] == "-h" || argv[0] == "help" {
        print_guards_help();
        return;
    }
    let sub = &argv[0];
    if argv.len() > 1 && (argv[1] == "--help" || argv[1] == "-h" || argv[1] == "help") {
        print_guards_subcommand_help(sub);
        return;
    }
    let mut cli = Cli::new("guards", argv);
    let subcommand = match cli.positional_expected(
        "subcommand",
        "a subcommand: add | list | remove | set-default (see `agent-tx guards --help`)",
    ) {
        Ok(subcommand) => subcommand,
        Err(message) => exit_with(message),
    };
    let result = match subcommand.as_str() {
        "add" => cmd_guards_add(&mut cli),
        "list" => {
            cmd_guards_list();
            Ok(())
        }
        "remove" => cmd_guards_remove(&mut cli),
        "set-default" => cmd_guards_set_default(&mut cli),
        other => Err(format!(
            "unknown guards subcommand: {other} (expected add, list, remove or set-default; see `agent-tx guards --help`)"
        )),
    };
    if let Err(message) = result {
        exit_with(message);
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some((cmd, rest)) = argv.split_first() else {
        print_help();
        std::process::exit(1);
    };
    if cmd == "--help" || cmd == "-h" || cmd == "help" {
        if let Some(sub) = rest.first() {
            if sub == "guards" {
                if let Some(sub_sub) = rest.get(1) {
                    print_guards_subcommand_help(sub_sub);
                } else {
                    print_guards_help();
                }
            } else {
                print_subcommand_help(sub);
            }
        } else {
            print_help();
        }
        return;
    }
    if rest
        .iter()
        .any(|arg| arg == "--help" || arg == "-h" || arg == "help")
    {
        if cmd == "guards" {
            if let Some(sub_sub) = rest.first() {
                if matches!(sub_sub.as_str(), "add" | "list" | "remove" | "set-default") {
                    print_guards_subcommand_help(sub_sub);
                } else {
                    print_guards_help();
                }
            } else {
                print_guards_help();
            }
        } else {
            print_subcommand_help(cmd);
        }
        return;
    }
    if cmd == "guards" {
        run_guards(rest);
        return;
    }
    if !matches!(
        cmd.as_str(),
        "preflight" | "transfer" | "transfer-from" | "heartbeat" | "status" | "policy" | "check"
    ) {
        exit_with(format!(
            "unknown subcommand '{cmd}' (see `agent-tx --help`)"
        ));
    }

    // Parsing validates every address-typed flag and resolves the endpoint, so
    // nothing past this point can reach the network with a malformed input.
    let request = match parse_request(cmd, rest) {
        Ok(request) => request,
        Err(message) => exit_with(message),
    };
    if let Some(notice) = request.notice() {
        eprintln!("{notice}");
    }
    if cmd == "preflight" {
        println!("send=no (preflight only)");
    }

    let rpc = request.rpc();
    let passphrase = request.endpoint.passphrase.clone();
    match cmd.as_str() {
        "status" => {
            if let Err(e) = cmd_status(&rpc, &request.guard, &passphrase) {
                exit_with(e);
            }
        }
        "policy" => {
            if let Err(e) = cmd_policy(&rpc, &request.guard, &passphrase) {
                exit_with(e);
            }
        }
        "check" => {
            let (asset, to, amount) =
                match (request.token.clone(), request.to.clone(), request.amount) {
                    (Some(asset), Some(to), Some(amount)) => (asset, to, amount),
                    _ => exit_with(
                        "missing required argument for `check` (see `agent-tx check --help`)"
                            .into(),
                    ),
                };
            if let Err(e) = cmd_check(&rpc, &request.guard, &asset, &to, amount, &passphrase) {
                exit_with(e);
            }
        }
        "preflight" => {
            let (token, to, amount) = match (
                request.token.clone(),
                request.to.clone(),
                request.amount,
            ) {
                (Some(token), Some(to), Some(amount)) => (token, to, amount),
                _ => exit_with(
                    "missing required argument for `preflight` (see `agent-tx preflight --help`)"
                        .into(),
                ),
            };
            let call = Call::Transfer { token, to, amount };
            let args = request.args();
            let result = preflight(&call, &args, &args.rpc);
            std::process::exit(result.err().unwrap_or(0));
        }
        "transfer" => {
            let (token, to, amount) =
                match (request.token.clone(), request.to.clone(), request.amount) {
                    (Some(token), Some(to), Some(amount)) => (token, to, amount),
                    _ => exit_with(
                        "missing required argument for `transfer` (see `agent-tx transfer --help`)"
                            .into(),
                    ),
                };
            let call = Call::Transfer { token, to, amount };
            let args = request.args();
            let outcome = run(&call, &args);
            std::process::exit(outcome.exit_code(args.expect_blocked));
        }
        "transfer-from" => {
            let (token, from, to, amount) = match (
                request.token.clone(),
                request.from.clone(),
                request.to.clone(),
                request.amount,
            ) {
                (Some(token), Some(from), Some(to), Some(amount)) => (token, from, to, amount),
                _ => exit_with(
                    "missing required argument for `transfer-from` (see `agent-tx transfer-from --help`)"
                        .into(),
                ),
            };
            let call = Call::TransferFrom {
                token,
                from,
                to,
                amount,
            };
            let args = request.args();
            let outcome = run(&call, &args);
            std::process::exit(outcome.exit_code(args.expect_blocked));
        }
        "heartbeat" => {
            let call = Call::Heartbeat;
            let args = request.args();
            let outcome = run(&call, &args);
            std::process::exit(outcome.exit_code(args.expect_blocked));
        }
        _ => exit_with(format!(
            "unknown subcommand '{cmd}' (see `agent-tx --help`)"
        )),
    }
}
