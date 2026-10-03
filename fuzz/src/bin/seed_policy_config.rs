use soroban_sdk::testutils::Address as _;
use soroban_sdk::{xdr::ToXdr, Address, Env, Symbol, Vec};
use std::{fs, path::PathBuf};
use stellar_agent_guard_contracts::PolicyConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::default();
    let valid_empty_policy = PolicyConfig {
        per_tx_cap: 0,
        window_secs: 0,
        window_cap: 0,
        assets: Vec::new(&env),
        protocols: Vec::new(&env),
        recipients: Vec::new(&env),
        recipient_window_caps: Vec::new(&env),
        blocked_recipients: Vec::new(&env),
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };

    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join("policy_config_deserialization");
    fs::create_dir_all(&corpus)?;
    fs::write(
        corpus.join("valid_empty_policy"),
        valid_empty_policy.to_xdr(&env).to_alloc_vec(),
    )?;
    let mut assets = Vec::new(&env);
    assets.push_back(Address::generate(&env));
    let mut protocols = Vec::new(&env);
    let mut allowed_functions = Vec::new(&env);
    allowed_functions.push_back(Symbol::new(&env, "swap"));
    protocols.push_back(stellar_agent_guard_contracts::ProtocolRule {
        contract: Address::generate(&env),
        fns: Some(allowed_functions),
    });
    let valid_nonempty_policy = PolicyConfig {
        per_tx_cap: 100,
        window_secs: 60,
        window_cap: 500,
        assets,
        protocols,
        recipients: Vec::new(&env),
        recipient_window_caps: Vec::new(&env),
        blocked_recipients: Vec::new(&env),
        allow_any_recipient: false,
        active_from: 1,
        active_until: 100,
        paused: false,
        dms_grace_secs: 300,
        protocol_calls_per_window: 5,
    };
    fs::write(
        corpus.join("valid_nonempty_policy"),
        valid_nonempty_policy.to_xdr(&env).to_alloc_vec(),
    )?;
    Ok(())
}
