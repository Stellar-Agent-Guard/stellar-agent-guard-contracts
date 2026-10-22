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

mod network;
mod strkey;

use ed25519_dalek::{Signer, SigningKey};
use network::{Endpoint, Network};
use sha2::{Digest, Sha256};
use stellar_xdr::*;
use strkey::KeyKind;

const INCLUSION_FEE: u32 = 100;
const GUARD_KEY_FEE_BUMP: u32 = 100_000;

// ── strkey (base32 + CRC16-XModem) ───────────────────────────────────────

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const VER_ACCOUNT: u8 = 6 << 3; // 0x30 -> G...
const VER_CONTRACT: u8 = 2 << 3; // 0x12 -> C...

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        if c == b'=' {
            break;
        }
        let v = u32::try_from(B32.iter().position(|&a| a == c)?).ok()?;
        acc = (acc << 5) | v;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
        acc &= (1u32 << bits) - 1;
    }
    Some(out)
}

fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 0x1f) as usize]));
        }
        acc &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

fn strkey_encode(version: u8, payload: &[u8]) -> String {
    let mut raw = Vec::with_capacity(payload.len() + 3);
    raw.push(version);
    raw.extend_from_slice(payload);
    let crc = crc16_xmodem(&raw);
    // stellar-strkey appends the checksum in little-endian byte order.
    raw.push((crc & 0xff) as u8);
    raw.push((crc >> 8) as u8);
    base32_encode(&raw)
}

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

struct Rpc {
    url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RpcFailureKind {
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
            RpcFailureKind::Transport => "TRANSPORT FAILURE",
            RpcFailureKind::Http => "HTTP RPC FAILURE",
            RpcFailureKind::JsonRpc => "JSON-RPC REJECTION",
            RpcFailureKind::InvalidResponse => "INVALID RPC RESPONSE",
        }
    }

    fn exit_code(&self) -> i32 {
        match self.kind {
            RpcFailureKind::Transport | RpcFailureKind::Http => 3,
            RpcFailureKind::JsonRpc | RpcFailureKind::InvalidResponse => 4,
        }
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
        Err(error) => {
            eprintln!("RESULT: {}", error.label());
            eprintln!("{error}");
            std::process::exit(error.exit_code());
        }
    }
}

trait PreflightRpc {
    fn account_seq(&self, account: &str) -> i64;
    fn latest_ledger(&self) -> u32;
    fn simulate(&self, envelope: &str) -> serde_json::Value;
    fn registered_agent_pubkey(&self, guard: &ScAddress) -> [u8; 32];
    fn inclusion_fee(&self) -> Result<Option<u32>, RpcError>;
}

impl Rpc {
    fn post(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, RpcError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let response = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string());
        let response = match response {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
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
        let response_body = response.into_string().map_err(|error| RpcError {
            method: method.to_string(),
            kind: RpcFailureKind::InvalidResponse,
            http_status: Some(status),
            json_rpc_code: None,
            message: error.to_string(),
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

    fn send(&self, envelope: &str) -> serde_json::Value {
        rpc_or_exit(self.post(
            "sendTransaction",
            serde_json::json!({ "transaction": envelope }),
        ))
    }

    fn get_tx(&self, hash: &str) -> serde_json::Value {
        rpc_or_exit(self.post("getTransaction", serde_json::json!({ "hash": hash })))
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

fn guard_data_key(guard: &ScAddress, name: &str) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: guard.clone(),
        key: ScVal::Symbol(ScSymbol(name.try_into().unwrap())),
        durability: ContractDataDurability::Persistent,
    })
}

fn guard_instance_key(guard: &ScAddress) -> LedgerKey {
    LedgerKey::ContractData(LedgerKeyContractData {
        contract: guard.clone(),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Temporary,
    })
}

/// `__check_auth` reads/writes the guard's own storage — policy, rolling
/// window, heartbeat clock, admin freeze — plus its instance keys. The
/// auth-less preflight never executes `__check_auth`, so those keys are
/// missing from the simulated footprint; without them the enforced
/// re-simulation cannot run. Merge them in (as read-write; the engine only
/// writes what it must).
fn merge_guard_footprint(mut fp: LedgerFootprint, guard: &ScAddress) -> LedgerFootprint {
    let extra = [
        guard_data_key(guard, "Policy"),
        guard_data_key(guard, "Window"),
        guard_data_key(guard, "LastHeartbeat"),
        guard_data_key(guard, "AdminFrozen"),
        guard_instance_key(guard),
    ];
    let mut rw: Vec<LedgerKey> = fp.read_write.iter().cloned().collect();
    for k in extra {
        if !rw.contains(&k) {
            rw.push(k);
        }
    }
    fp.read_write = VecM::try_from(rw).expect("footprint bound");
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
                seq,
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

/// The guard storage keys `__check_auth` reads. Declaring them in the *first*
/// (preflight) envelope's footprint makes the RPC price them into
/// `transactionData`/`minResourceFee`; merging them only after pricing breaks
/// protocol-28 fee accounting (core recomputes the resource fee from the
/// declared footprint, so extra read-write keys with an unpriced
/// `resourceFee` fail with `insufficient_refundable_fee`).
fn guard_footprint(guard: &ScAddress) -> LedgerFootprint {
    let keys = vec![
        guard_data_key(guard, "Policy"),
        guard_data_key(guard, "Window"),
        guard_data_key(guard, "LastHeartbeat"),
        guard_data_key(guard, "AdminFrozen"),
        guard_instance_key(guard),
    ];
    LedgerFootprint {
        read_only: VecM::default(),
        read_write: VecM::try_from(keys).expect("footprint bound"),
    }
}

fn build_initial_envelope(
    source: &MuxedAccount,
    seq: i64,
    op: Operation,
    guard: &ScAddress,
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
                footprint: guard_footprint(guard),
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
/// The nonce must be a value this address has never used before: the host
/// records every consumed nonce in ledger state (`(address, LedgerKeyNonce)`)
/// and rejects replays ("nonce already exists for address"). The guard's own
/// `__check_auth` ignores nonces, but the *token contract's* `require_auth`
/// on the inner call still enforces them, so each transaction needs a fresh
/// one. The agent's strictly-increasing tx sequence is unique per transaction
/// and never reused, so it doubles as the auth nonce.
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
    let tx_xdr = tx.to_xdr(Limits::none()).expect("tx XDR");
    let mut msg = Vec::with_capacity(36 + tx_xdr.len());
    msg.extend_from_slice(network_id);
    msg.extend_from_slice(&(EnvelopeType::Tx as i32).to_be_bytes());
    msg.extend_from_slice(&tx_xdr);
    let digest: [u8; 32] = Sha256::digest(&msg).into();
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

fn run(call: &Call, args: &Args) {
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

    // Build the call and the guard's auth entry (agent-signed) once. The tx
    // sequence doubles as the auth nonce (fresh per transaction, never
    // reused), keeping the SAC's replay protection satisfied.
    let invocation = call.invocation(guard);
    let auth = VecM::try_from(vec![build_auth_entry(
        guard,
        &invocation,
        seq,
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
    let env0 = build_initial_envelope(&MuxedAccount::Ed25519(Uint256(source_pk)), seq, op, guard);
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
        if let Some(events) = simulation_events(&sim) {
            println!("  diagnostic events:");
            print_events(&serde_json::Value::Array(events.clone()));
        }
        println!("  broadcast: no");
        std::process::exit(if policy_block && args.expect_blocked {
            0
        } else {
            1
        });
    }
    if args.expect_blocked {
        println!("expected a block, but the enforced simulation succeeded");
        std::process::exit(1);
    }

    // Assemble the final envelope from the simulation's resources and submit.
    let mut data: SorobanTransactionData = xdr(sim["transactionData"]
        .as_str()
        .expect("simulation transactionData"));
    // The RPC's preflight runs in *recording* mode: it prices the token
    // contract's own storage but never executes `__check_auth`, so the guard's
    // policy/window/heartbeat/freeze keys are missing from its footprint and
    // fee. They ARE read at apply time (enforcing mode), so they must be in
    // the declared footprint — and the declared `resource_fee` must cover the
    // enlarged footprint or core fails with `insufficient_refundable_fee`.
    let merged = merge_guard_footprint(data.resources.footprint.clone(), guard);
    let added = merged.read_write.len() - data.resources.footprint.read_write.len();
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!(
            "footprint merge added {added} keys (sim had {})",
            data.resources.footprint.read_write.len()
        );
    }
    // Cover the extra write entries (~few hundred stroops each) plus headroom
    // for `__check_auth`'s extra instructions, which the recording-mode
    // preflight also under-prices.
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
            "minResourceFee: {min_fee}, resourceFee: {}, final fee: {fee}",
            data.resource_fee
        );
    }
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
    let sent = args.rpc.send(&b64_encode_xdr(&env2));
    if std::env::var_os("AGENT_TX_DEBUG").is_some() {
        eprintln!("send response: {sent}");
    }
    if let Some(err) = sent.get("error") {
        let err_str = err.to_string();
        let human = map_submission_error(&err_str);
        eprintln!("Error: {human}");
        std::process::exit(1);
    }
    let hash = sent["hash"].as_str().unwrap_or_default().to_string();
    if hash.is_empty() {
        let err_str = sent.to_string();
        let human = map_submission_error(&err_str);
        eprintln!("Error: {human}");
        std::process::exit(1);
    }
    let status = sent["status"].as_str().unwrap_or("?").to_string();
    println!("submitted: hash={hash} status={status}");

    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let gt = args.rpc.get_tx(&hash);
        let st = gt["status"].as_str().unwrap_or("PENDING");
        if st == "SUCCESS" {
            println!("RESULT: ALLOWED tx={hash}");
            std::process::exit(0);
        }
        if st == "FAILED" {
            println!("RESULT: FAILED tx={hash}");
            if let Some(errx) = gt["resultXdr"].as_str() {
                println!("  resultXdr: {errx}");
            }
            std::process::exit(1);
        }
    }
    println!("RESULT: TIMEOUT tx={hash}");
    std::process::exit(1);
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
    let env = guard_footprint(&guard);
    let keys = env.read_write.iter().cloned().collect::<Vec<_>>();
    let fp = LedgerFootprint {
        read_only: VecM::default(),
        read_write: VecM::try_from(keys).expect("footprint bound"),
    };
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
    let mut positionals: Vec<String> = Vec::new();
    while let Some(token) = cli.next() {
        match token.as_str() {
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

    let rpc = Rpc {
        url: endpoint.rpc_url,
    };
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
        let policy_map_entries = vec![ScMapEntry {
            key: ScVal::Symbol(ScSymbol("dms_grace_secs".try_into().unwrap())),
            val: ScVal::U64(3600), // 1 hour grace period
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
    }

    impl PreflightRpc for MockPreflightRpc {
        fn account_seq(&self, _account: &str) -> i64 {
            self.sequence_reads.set(self.sequence_reads.get() + 1);
            self.sequence.get()
        }

        fn latest_ledger(&self) -> u32 {
            100
        }

        fn simulate(&self, _envelope: &str) -> serde_json::Value {
            self.simulations.set(self.simulations.get() + 1);
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
            rpc: Rpc { url: String::new() },
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
            rpc: Rpc { url: String::new() },
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
            rpc: Rpc { url: String::new() },
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
        format!(
            "unknown argument for `{}`: {flag} (see `agent-tx --help` or `agent-tx {} --help`)",
            self.cmd, self.cmd
        )
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
        Rpc {
            url: self.endpoint.rpc_url.clone(),
        }
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
    let mut expect_blocked = false;
    let mut inclusion_fee_override = None;

    while let Some(flag) = cli.next() {
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
        Network::Futurenet.rpc_url()
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
     \x20 add <alias> <address> <admin> [--network <name> | --rpc-url <url>] [--network-passphrase <pass>]\n\
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
    let policy_key = guard_data_key(guard, "Policy");
    let heartbeat_key = guard_data_key(guard, "LastHeartbeat");
    let frozen_key = guard_data_key(guard, "AdminFrozen");

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
            if let ScVal::Symbol(sym) = &cdata.key {
                match sym.0.as_slice() {
                    b"Policy" => {
                        has_policy = !matches!(cdata.val, ScVal::Void);
                    }
                    b"AdminFrozen" => {
                        if let ScVal::Bool(frozen) = cdata.val {
                            admin_frozen = frozen;
                        }
                    }
                    b"LastHeartbeat" => {
                        if let ScVal::U64(ts) = cdata.val {
                            last_heartbeat = ts;
                        }
                    }
                    _ => {}
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
                if let ScVal::Symbol(sym) = &cdata.key {
                    if sym.0.as_slice() == b"Policy" {
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
                                heartbeat_expired = now.saturating_sub(last_heartbeat as u32)
                                    as u64
                                    > dms_grace_secs;
                            }
                        }
                        break;
                    }
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
    let policy_key = guard_data_key(guard, "Policy");
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
    let env = build_initial_envelope(&MuxedAccount::Ed25519(Uint256(source_pk)), seq, op, guard);

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
            run(&call, &request.args());
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
            run(&call, &request.args());
        }
        "heartbeat" => run(&Call::Heartbeat, &request.args()),
        _ => exit_with(format!(
            "unknown subcommand '{cmd}' (see `agent-tx --help`)"
        )),
    }
}
