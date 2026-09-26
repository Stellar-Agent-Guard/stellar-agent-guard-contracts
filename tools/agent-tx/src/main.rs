//! agent-tx — sign and submit Soroban transactions on behalf of the
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
//! ```text
//! agent-tx transfer --guard C... --token C... --to G... --amount 50 \
//!     --agent-secret S... [--expect-blocked] [--rpc-url ...] [--network-passphrase "..."]
//! agent-tx heartbeat --guard C... --agent-secret S... [--expect-blocked]
//! ```
//!
//! `--expect-blocked` treats a policy rejection at step 4 as success and prints
//! the on-chain-equivalent diagnostic events (the contract's own `auth_checked`
//! blocked event with the reason symbol).

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use stellar_xdr::*;

const DEFAULT_RPC: &str = "https://soroban-testnet.stellar.org";
const DEFAULT_PASSPHRASE: &str = "Test SDF Network ; September 2015";
const INCLUSION_FEE: u32 = 100;

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
    let raw = base32_decode(secret).expect("invalid strkey secret");
    assert_eq!(raw.len(), 35, "strkey secret must decode to 35 bytes");
    assert_eq!(raw[0], 0x90, "not a strkey secret key");
    raw[1..33].try_into().expect("seed length")
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

impl Rpc {
    fn post(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = ureq::post(&self.url)
            .set("Content-Type", "application/json")
            .send_string(&body.to_string())
            .unwrap_or_else(|e| panic!("RPC {method} request failed: {e}"));
        let json: serde_json::Value =
            serde_json::from_reader(resp.into_reader()).expect("RPC response JSON");
        if let Some(err) = json.get("error") {
            panic!("RPC {method} error: {err}");
        }
        json["result"].clone()
    }

    fn latest_ledger(&self) -> u32 {
        let res = self.post("getLatestLedger", serde_json::json!({}));
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
        let res = self.post(
            "getLedgerEntries",
            serde_json::json!({ "keys": [b64_encode_xdr(&key)] }),
        );
        let entry = res["entries"][0]["xdr"].as_str().expect("ledger entry xdr");
        // getLedgerEntries returns the LedgerEntryData XDR per entry.
        let le: LedgerEntryData = xdr(entry);
        match le {
            LedgerEntryData::Account(AccountEntry { seq_num, .. }) => seq_num.0,
            other => panic!("unexpected ledger entry: {other:?}"),
        }
    }

    fn simulate(&self, envelope: &str) -> serde_json::Value {
        self.post(
            "simulateTransaction",
            serde_json::json!({ "transaction": envelope }),
        )
    }

    fn send(&self, envelope: &str) -> serde_json::Value {
        self.post(
            "sendTransaction",
            serde_json::json!({ "transaction": envelope }),
        )
    }

    fn get_tx(&self, hash: &str) -> serde_json::Value {
        self.post("getTransaction", serde_json::json!({ "hash": hash }))
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
            let inner: Vec<String> = items.iter().map(|x| scval_str(x)).collect();
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
        if !rw.iter().any(|e| *e == k) {
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
    guard: ScAddress,
    secret: String,
    expect_blocked: bool,
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
    let seed = secret_to_seed(&args.secret);
    let agent = SigningKey::from_bytes(&seed);
    let source_pk = agent.verifying_key().to_bytes();
    let source_g = account_strkey(&source_pk);
    let network_id: [u8; 32] = Sha256::digest(args.passphrase.as_bytes()).into();

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
        seq as i64,
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

    if let Some(err) = sim.get("error") {
        println!("BLOCKED (pre-broadcast, enforced simulation):");
        if let Some(code) = err["code"].as_str() {
            println!("  error code: {code}");
        }
        if let Some(msg) = err["message"].as_str() {
            println!("  message: {msg}");
        }
        if let Some(events) = err["data"]["events"].as_array() {
            println!("  diagnostic events:");
            print_events(&serde_json::Value::Array(events.clone()));
        }
        std::process::exit(if args.expect_blocked { 0 } else { 1 });
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
    const GUARD_KEY_FEE_BUMP: i64 = 100_000;
    data.resources.footprint = merged;
    data.resource_fee = data.resource_fee.saturating_add(GUARD_KEY_FEE_BUMP);
    let min_fee: u32 = sim["minResourceFee"]
        .as_str()
        .expect("minResourceFee")
        .parse()
        .expect("fee");
    let fee = min_fee
        .saturating_add(INCLUSION_FEE)
        .saturating_add(GUARD_KEY_FEE_BUMP as u32);
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
    let hash = sent["hash"].as_str().expect("tx hash").to_string();
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
            std::process::exit(if args.expect_blocked { 0 } else { 1 });
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
    let guard: ScAddress = guard_addr.parse().map_err(|e| format!("invalid guard address: {e}"))?;
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
    let env = TransactionEnvelope::Tx(TransactionV1Envelope { tx, signatures: VecM::default() });
    let sim = rpc.simulate(&b64_encode_xdr(&env));
    if let Some(err) = sim.get("error") {
        let msg = err["message"].as_str().unwrap_or("unknown error");
        return Err(format!("guard verification failed: {msg}"));
    }
    Ok(())
}

fn cmd_guards_add<I: Iterator<Item = String>>(args: &mut I) -> Result<(), String> {
    let alias = args.next().ok_or("missing alias")?;
    let address = args.next().ok_or("missing address")?;
    let admin = args.next().ok_or("missing admin")?;
    let rpc_url = args.next().unwrap_or_else(|| DEFAULT_RPC.to_string());
    let passphrase = args.next().unwrap_or_else(|| DEFAULT_PASSPHRASE.to_string());

    let rpc = Rpc { url: rpc_url };
    verify_guard(&rpc, &address, &passphrase)?;

    let mut reg = load_registry();
    if reg.guards.iter().any(|g| g.alias == alias) {
        return Err(format!("alias '{alias}' already exists"));
    }
    if reg.guards.iter().any(|g| g.address == address) {
        return Err(format!("address '{address}' already registered under another alias"));
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
    println!("Added guard '{alias}' (default: {})", reg.default.as_deref().unwrap_or("none"));
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
        let default_mark = if reg.default.as_ref() == Some(&g.alias) { " (default)" } else { "" };
        println!("  {} -> {} [admin: {}]{}", g.alias, g.address, g.admin, default_mark);
    }
}

fn cmd_guards_remove<I: Iterator<Item = String>>(args: &mut I) -> Result<(), String> {
    let alias = args.next().ok_or("missing alias")?;
    let mut reg = load_registry();
    let idx = reg.guards.iter().position(|g| g.alias == alias).ok_or("alias not found")?;
    reg.guards.remove(idx);
    if reg.default.as_ref() == Some(&alias) {
        reg.default = reg.guards.first().map(|g| g.alias.clone());
    }
    save_registry(&reg);
    println!("Removed guard '{alias}'");
    Ok(())
}

fn cmd_guards_set_default<I: Iterator<Item = String>>(args: &mut I) -> Result<(), String> {
    let alias = args.next().ok_or("missing alias")?;
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
        return Err("no guard specified and no guards registered. Use `agent-tx guards add <alias> <address> <admin>` to register one, or pass --guard".into());
    }
    Err(format!(
        "no guard specified and no default set. Registered guards:\n{}",
        reg.guards.iter()
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
}

fn main() {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().expect("subcommand: transfer | heartbeat | guards");

    match cmd.as_str() {
        "guards" => {
            let subcmd = it.next().expect("guards subcommand: add | list | remove | set-default");
            let result = match subcmd.as_str() {
                "add" => cmd_guards_add(&mut it),
                "list" => { cmd_guards_list(); Ok(()) }
                "remove" => cmd_guards_remove(&mut it),
                "set-default" => cmd_guards_set_default(&mut it),
                other => Err(format!("unknown guards subcommand: {other}")),
            };
            if let Err(e) = result {
                eprintln!("Error: {e}");
                std::process::exit(1);
            }
            return;
        }
        "transfer" | "heartbeat" => {}
        other => panic!("unknown subcommand {other}"),
    }

    let mut guard_s = None;
    let mut token_s = None;
    let mut to_s = None;
    let mut amount: Option<i128> = None;
    let mut secret = None;
    let mut rpc_url = DEFAULT_RPC.to_string();
    let mut passphrase = DEFAULT_PASSPHRASE.to_string();
    let mut expect_blocked = false;

    while let Some(a) = it.next() {
        let mut val = || it.next().expect(&format!("value for {a}"));
        match a.as_str() {
            "--guard" => guard_s = Some(val()),
            "--token" => token_s = Some(val()),
            "--to" => to_s = Some(val()),
            "--amount" => amount = Some(val().parse().expect("amount")),
            "--agent-secret" => secret = Some(val()),
            "--rpc-url" => rpc_url = val(),
            "--network-passphrase" => passphrase = val(),
            "--expect-blocked" => expect_blocked = true,
            other => panic!("unknown argument {other}"),
        }
    }

    let guard_addr = resolve_guard(guard_s.as_deref()).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });
    let secret = secret
        .or_else(|| std::env::var("AGENT_SECRET").ok())
        .expect("--agent-secret");
    let guard: ScAddress = guard_addr.parse().expect("guard address");
    let args = Args {
        rpc: Rpc { url: rpc_url },
        passphrase,
        guard: guard.clone(),
        secret,
        expect_blocked,
    };

    match cmd.as_str() {
        "transfer" => {
            let token: ScAddress = token_s.expect("--token").parse().expect("token address");
            let to: ScAddress = to_s.expect("--to").parse().expect("to address");
            let amount = amount.expect("--amount");
            run(&Call::Transfer { token, to, amount }, &args);
        }
        "heartbeat" => {
            run(&Call::Heartbeat, &args);
        }
        _ => unreachable!(),
    }
}
