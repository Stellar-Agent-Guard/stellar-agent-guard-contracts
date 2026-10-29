//! End-to-end shape of the `--json` output mode (issue #390).
//!
//! The unit tests in `src/main.rs` pin what a verdict maps to; these run the
//! built binary against a loopback RPC stub and pin what actually reaches each
//! stream — one JSON object on stdout under `--json` (prose preserved on
//! stderr), and the untouched prose on stdout without it, which is the
//! guarantee the fixtures prose depends on.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

/// The binary under test, built by cargo before this test target runs.
const BIN: &str = env!("CARGO_BIN_EXE_agent-tx");
const VALID_GUARD: &str = "CAYJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4CU7";
const VALID_TOKEN: &str = "CBLQLJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGTJC7";
const VALID_RECIPIENT: &str = "GDUYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRRX";

/// A loopback JSON-RPC stub that answers every request with `result` and
/// records the `method` of each one, so a test can assert both what the binary
/// was told and what it did with it.
fn stub_rpc(result: Value) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback bind");
    let url = format!("http://{}", listener.local_addr().expect("local addr"));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let served = Arc::clone(&requests);
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
                let method = serde_json::from_slice::<Value>(&body)
                    .ok()
                    .and_then(|value| value["method"].as_str().map(str::to_string))
                    .unwrap_or_default();
                served.lock().expect("record lock").push(method);
            }
            let payload = json!({ "jsonrpc": "2.0", "id": 1, "result": result }).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
                 {}\r\nConnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    (url, requests)
}

/// Run `agent-tx check` against the stub and return its streams verbatim.
fn run_check(url: &str, json: bool) -> (String, String, Option<i32>) {
    let mut command = Command::new(BIN);
    command.args([
        "check",
        "--guard",
        VALID_GUARD,
        "--asset",
        VALID_TOKEN,
        "--to",
        VALID_RECIPIENT,
        "--amount",
        "10",
        "--rpc-url",
        url,
        // A custom endpoint needs an explicit passphrase; this is the testnet
        // one, but the URL is not a preset so the object carries no `network`.
        "--network-passphrase",
        "Test SDF Network ; September 2015",
    ]);
    if json {
        command.arg("--json");
    }
    let output = command
        // A stale AGENT_SECRET in the caller's environment would be validated
        // as a flag value and fail the run; the test must control its inputs.
        .env_remove("AGENT_SECRET")
        .output()
        .expect("agent-tx runs");
    (
        String::from_utf8(output.stdout).expect("stdout is UTF-8"),
        String::from_utf8(output.stderr).expect("stderr is UTF-8"),
        output.status.code(),
    )
}

#[test]
fn json_mode_writes_exactly_one_allowed_object_to_stdout() {
    let (url, requests) = stub_rpc(json!({ "minResourceFee": "100" }));
    let (stdout, stderr, code) = run_check(&url, true);

    assert_eq!(
        code,
        Some(0),
        "check reports a verdict, it does not fail: {stderr}"
    );
    // Parsing the whole of stdout proves nothing else was written to it.
    let value: Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(value["outcome"], "allowed");
    // The stub is a custom `--rpc-url`, not a named preset, so the endpoint's
    // network is unknown and the field is omitted rather than guessed (the
    // preset case — `network: "testnet"` — is pinned by the unit tests).
    assert!(value.get("network").is_none(), "{value}");
    assert!(value.get("reason").is_none(), "{value}");
    assert!(value.get("tx_hash").is_none(), "{value}");
    assert!(
        value.get("ledger").is_none(),
        "`check` never queries a ledger, so it must not claim one: {value}"
    );
    assert_eq!(
        value.as_object().expect("one JSON object").len(),
        1,
        "unexpected fields: {value}"
    );

    // The human-readable report survives — on stderr, where it cannot break a
    // consumer parsing stdout.
    assert!(stderr.contains("result: allowed"), "prose moved: {stderr}");
    assert!(
        stderr.contains("estimated_fee_stroops: 100"),
        "prose moved: {stderr}"
    );
    assert_eq!(
        requests.lock().expect("record lock").clone(),
        vec!["simulateTransaction".to_string()],
        "`check` is read-only: one simulation, nothing else"
    );
}

#[test]
fn json_mode_writes_the_reason_symbol_when_the_transfer_is_blocked() {
    let (url, _) = stub_rpc(json!({
        "error": {
            "code": "simulation",
            "message": "auth_checked: per_tx_cap_exceeded",
            "data": { "events": [] }
        }
    }));
    let (stdout, stderr, _code) = run_check(&url, true);

    let value: Value = serde_json::from_str(&stdout).expect("stdout is one JSON object");
    assert_eq!(value["outcome"], "blocked");
    assert_eq!(value["reason"], "per_tx_cap_exceeded");
    assert!(
        value.get("network").is_none(),
        "custom stub endpoint: {value}"
    );
    assert!(
        value.get("tx_hash").is_none(),
        "a blocked run submits nothing: {value}"
    );
    assert_eq!(
        value.as_object().expect("one JSON object").len(),
        2,
        "unexpected fields: {value}"
    );
    // The default prose still exists for a debugging operator, on stderr.
    assert!(stderr.contains("result: blocked"), "{stderr}");
    assert!(stderr.contains("reason: simulation"), "{stderr}");
}

#[test]
fn without_the_flag_the_human_readable_output_is_unchanged() {
    let (url, _) = stub_rpc(json!({ "minResourceFee": "100" }));
    let (stdout, stderr, code) = run_check(&url, false);

    assert_eq!(code, Some(0), "{stderr}");
    assert_eq!(
        stdout, "result: allowed\nestimated_fee_stroops: 100\n",
        "the default output must be byte-for-byte the prose fixtures record"
    );
    assert!(
        stderr.is_empty(),
        "the default mode keeps stderr free of report prose: {stderr}"
    );
}

#[test]
fn the_registry_subcommands_refuse_the_flag_rather_than_ignoring_it() {
    // `guards` edits a local registry and has no verdict to report, so it
    // errors instead of accepting `--json` and printing prose anyway.
    let output = Command::new(BIN)
        .args(["guards", "list", "--json"])
        .output()
        .expect("agent-tx runs");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("`--json` is not supported"), "{stderr}");
    assert!(
        String::from_utf8(output.stdout)
            .expect("stdout is UTF-8")
            .is_empty(),
        "a rejected flag prints nothing to stdout"
    );
}
