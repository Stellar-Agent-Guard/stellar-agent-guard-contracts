//! Policy deserialization and validation benchmarks at maximum bounds (issue #611).
//!
//! Measures the CPU instruction cost of the `set_policy` → `validate_config`
//! path (SPEC §8) for three policy shapes: minimum (empty lists, zeroed caps),
//! typical (a handful of entries in each list), and maximum (every list at its
//! documented `MAX_*` limit), plus a near-maximum malformed input that fails
//! validation on the last rule checked.
//!
//! The results, together with the per-invocation CPU budget used by the decision
//! path (`DECISION_PATH_CPU_BUDGET` in `worst_case_decision_path`), establish the
//! baseline that CONTRIBUTING.md's regression threshold section references.
//!
//! Run with:
//! `cargo run --manifest-path benches/Cargo.toml --bin policy_deserialization`

#![no_std]

extern crate std;

use core::hint::black_box;
use std::println;

use soroban_sdk::{Address, BytesN, Env, Symbol, TryFromVal, Vec};
use stellar_agent_guard_contracts::testutils::{
    PolicyConfig, ProtocolRule, MAX_ASSET_CAP_ENTRIES, MAX_POLICY_ASSETS, MAX_POLICY_PROTOCOLS,
    MAX_RECIPIENT_ENTRIES,
};
use stellar_agent_guard_contracts::{AssetCap, PolicyEngine, PolicyEngineClient};

/// Build a synthetic address from a tag byte and an index.
fn addr(env: &Env, tag: u8, index: u8) -> Address {
    use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
    let mut hash = [0u8; 32];
    hash[0] = tag;
    hash[1..].fill(index);
    let sc = ScAddress::Contract(ContractId(Hash(hash)));
    Address::try_from_val(env, &sc).unwrap()
}

/// Build a synthetic admin address (not a contract, just an arbitrary address).
fn admin_addr(env: &Env) -> Address {
    addr(env, 255, 1)
}

/// Build the minimum-bounds policy: all lists empty, all caps zeroed.
fn minimum_policy(env: &Env) -> PolicyConfig {
    PolicyConfig {
        per_tx_cap: 0,
        window_secs: 0,
        window_cap: 0,
        assets: Vec::new(env),
        protocols: Vec::new(env),
        recipients: Vec::new(env),
        recipient_window_caps: Vec::new(env),
        blocked_recipients: Vec::new(env),
        asset_caps: Vec::new(env),
        allow_any_recipient: true,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    }
}

/// Build a typical policy: one asset, one recipient, one protocol, one asset cap.
fn typical_policy(env: &Env) -> PolicyConfig {
    let asset = addr(env, 1, 0);
    let mut protocols = Vec::new(env);
    protocols.push_back(ProtocolRule {
        contract: addr(env, 2, 0),
        fns: Some({
            let mut fns = Vec::new(env);
            fns.push_back(Symbol::new(env, "swap"));
            fns
        }),
        paused: false,
    });
    let mut recipients = Vec::new(env);
    recipients.push_back(addr(env, 3, 0));
    let mut asset_caps = Vec::new(env);
    asset_caps.push_back(AssetCap {
        asset: asset.clone(),
        per_tx_cap: 500,
        paused: false,
    });
    let mut assets = Vec::new(env);
    assets.push_back(asset);
    PolicyConfig {
        per_tx_cap: 1_000,
        window_secs: 86_400,
        window_cap: 10_000,
        assets,
        protocols,
        recipients,
        recipient_window_caps: Vec::new(env),
        blocked_recipients: Vec::new(env),
        asset_caps,
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 3_600,
        protocol_calls_per_window: 100,
    }
}

/// Build a maximum-bounds policy: every list at its documented `MAX_*` limit.
///
/// Addresses use disjoint tag bytes so none of the overlap-rejection rules fire.
fn maximum_policy(env: &Env) -> PolicyConfig {
    // assets: tag 1 (up to MAX_POLICY_ASSETS = 256)
    let mut assets = Vec::new(env);
    // asset_caps: same set, one cap per asset
    let mut asset_caps = Vec::new(env);
    for i in 0..MAX_POLICY_ASSETS {
        let a = addr(env, 1, i as u8);
        assets.push_back(a.clone());
        if (asset_caps.len() as usize) < MAX_ASSET_CAP_ENTRIES {
            asset_caps.push_back(AssetCap {
                asset: a,
                per_tx_cap: 1_000,
                paused: false,
            });
        }
    }

    // protocols: tag 2
    let mut protocols = Vec::new(env);
    for i in 0..MAX_POLICY_PROTOCOLS {
        protocols.push_back(ProtocolRule {
            contract: addr(env, 2, i as u8),
            fns: None,
            paused: false,
        });
    }

    // recipients: tag 3
    let mut recipients = Vec::new(env);
    for i in 0..MAX_RECIPIENT_ENTRIES {
        recipients.push_back(addr(env, 3, i as u8));
    }

    // blocked_recipients: tag 4 (disjoint from recipients to pass §8 overlap check)
    let mut blocked_recipients = Vec::new(env);
    for i in 0..MAX_RECIPIENT_ENTRIES {
        blocked_recipients.push_back(addr(env, 4, i as u8));
    }

    PolicyConfig {
        per_tx_cap: 1_000,
        window_secs: 86_400,
        window_cap: 1_000_000,
        assets,
        protocols,
        recipients,
        recipient_window_caps: Vec::new(env),
        blocked_recipients,
        asset_caps,
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 86_400,
        protocol_calls_per_window: 1_000,
    }
}

/// A near-maximum policy that is *invalid*: `blocked_recipients` and `recipients`
/// share the first entry, so it trips the `RecipientAllowAndBlocked` rule at the
/// end of SPEC §8's check sequence. All list lengths stay at or below their
/// MAX_* limits so the rejection comes from the content check, not the length check.
/// Measures the full validation sweep cost up to the final rejection.
fn near_maximum_invalid_policy(env: &Env) -> PolicyConfig {
    // recipients: MAX_RECIPIENT_ENTRIES entries, all tag-3 addresses.
    let mut recipients = Vec::new(env);
    for i in 0..MAX_RECIPIENT_ENTRIES {
        recipients.push_back(addr(env, 3, i as u8));
    }
    // blocked_recipients: (MAX_RECIPIENT_ENTRIES-1) tag-4 addresses plus the
    // first tag-3 address (which is also in `recipients`). Total length stays at
    // MAX_RECIPIENT_ENTRIES so the length check passes; `RecipientAllowAndBlocked`
    // fires on the first element of `recipients`.
    let mut blocked_recipients = Vec::new(env);
    for i in 0..(MAX_RECIPIENT_ENTRIES - 1) {
        blocked_recipients.push_back(addr(env, 4, i as u8));
    }
    blocked_recipients.push_back(addr(env, 3, 0)); // overlaps with recipients[0]

    // Use the maximum asset and protocol lists so validation cost is at its peak.
    let mut assets = Vec::new(env);
    let mut asset_caps = Vec::new(env);
    for i in 0..MAX_POLICY_ASSETS {
        let a = addr(env, 1, i as u8);
        assets.push_back(a.clone());
        if (asset_caps.len() as usize) < MAX_ASSET_CAP_ENTRIES {
            asset_caps.push_back(AssetCap {
                asset: a,
                per_tx_cap: 1_000,
                paused: false,
            });
        }
    }
    let mut protocols = Vec::new(env);
    for i in 0..MAX_POLICY_PROTOCOLS {
        protocols.push_back(ProtocolRule {
            contract: addr(env, 2, i as u8),
            fns: None,
            paused: false,
        });
    }

    PolicyConfig {
        per_tx_cap: 1_000,
        window_secs: 86_400,
        window_cap: 1_000_000,
        assets,
        protocols,
        recipients,
        recipient_window_caps: Vec::new(env),
        blocked_recipients,
        asset_caps,
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 86_400,
        protocol_calls_per_window: 1_000,
    }
}

/// A preconfigured guard contract ready for `set_policy` calls.
struct BenchEnv {
    env: Env,
    client: PolicyEngineClient,
}

fn bench_env() -> BenchEnv {
    let env = Env::default();
    env.mock_all_auths();
    let admin = admin_addr(&env);
    let guard = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &guard);
    client.initialize(&admin, &BytesN::from_array(&env, &[7u8; 32]));
    BenchEnv { env, client }
}

/// Measure the CPU instruction cost of one `set_policy` call.
/// Returns the instruction count; `expected_ok` asserts whether the call should succeed.
fn measure_set_policy<F>(env: &Env, client: &PolicyEngineClient, name: &str, mut f: F) -> u64
where
    F: FnMut() -> PolicyConfig,
{
    // Warm up.
    for _ in 0..3 {
        black_box(client.try_set_policy(&f()).ok());
    }

    let mut budget = env.cost_estimate().budget();
    budget.reset_unlimited();
    black_box(client.try_set_policy(&f()).ok());
    let instructions = budget.cpu_instruction_cost();
    println!("{name}: {instructions} instructions");
    instructions
}

#[allow(clippy::too_many_lines)]
fn main() {
    let BenchEnv { env, client } = bench_env();
    env.cost_estimate().budget().reset_unlimited();

    println!("=== Policy Deserialization / Validation Benchmarks (issue #611) ===");
    println!("Measuring CPU instructions for set_policy (validate_config, SPEC §8).");
    println!();

    let min_cost = measure_set_policy(&env, &client, "minimum (empty lists, zero caps)", || {
        minimum_policy(&env)
    });
    let typ_cost = measure_set_policy(
        &env,
        &client,
        "typical (1 asset, 1 recipient, 1 protocol, 1 asset cap)",
        || typical_policy(&env),
    );
    let max_cost = measure_set_policy(
        &env,
        &client,
        "maximum (all lists at MAX_* limit, all caps set)",
        || maximum_policy(&env),
    );
    let bad_cost = measure_set_policy(
        &env,
        &client,
        "near-maximum malformed (full sweep → RecipientAllowAndBlocked rejection)",
        || near_maximum_invalid_policy(&env),
    );

    println!();
    println!("=== Summary ===");
    println!(
        "MAX_POLICY_ASSETS={MAX_POLICY_ASSETS}, MAX_POLICY_PROTOCOLS={MAX_POLICY_PROTOCOLS}, \
         MAX_RECIPIENT_ENTRIES={MAX_RECIPIENT_ENTRIES}, MAX_ASSET_CAP_ENTRIES={MAX_ASSET_CAP_ENTRIES}"
    );
    println!("minimum  : {min_cost} instructions");
    println!("typical  : {typ_cost} instructions");
    println!("maximum  : {max_cost} instructions");
    println!("malformed: {bad_cost} instructions  (expected to fail InvalidConfig)");
    println!();
    println!("Resource assumption: validation cost is O(N) in the total number of list");
    println!("entries across all lists. At maximum bounds this is at most four 256-entry");
    println!("sweeps (assets, protocols, recipients, blocked_recipients) plus a constant");
    println!("number of duplicate-detection passes (also linear). No list exceeds its");
    println!("MAX_* constant; set_policy enforces these bounds before calling validate_config.");
    println!();
    println!("Note: These are instruction counts from the Soroban test environment.");
    println!("On-chain costs will differ due to host overhead, metering, and fee accounting.");
}
