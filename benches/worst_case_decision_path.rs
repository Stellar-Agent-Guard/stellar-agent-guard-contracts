//! Worst-case decision-path benchmarks for the §6.2 SAC-transfer rules
//! (issue #118).
//!
//! Measures the CPU instruction cost of one `decide` call when every recipient
//! list `set_policy` will accept is filled to exactly `MAX_RECIPIENT_ENTRIES`
//! (256, SPEC §8) and the transfer destination is in none of them — the
//! configuration that makes the linear allowlist/denylist sweeps the dominant
//! term in the decision path.
//!
//! Two shapes, because the escape hatch is the whole point of the comparison:
//! - **escape off** (`allow_any_recipient = false`): §6.2 rule 1 sweeps the
//!   full 256-entry denylist, then rule 2 sweeps the full 256-entry allowlist,
//!   missing on the last element of each. No early exit — the expensive case.
//! - **escape on** (`allow_any_recipient = true`): rule 2 is skipped, so only
//!   the denylist is swept before the caps and window run — the price of the
//!   escape hatch.
//!
//! The fixtures come from the crate's `testutils` so this bench and
//! `engine::tests::worst_case_decision_path_measured_cost` measure exactly the
//! same scenario; SPEC §6.2 quotes both numbers.
//!
//! Run with:
//! `cargo run --manifest-path benches/Cargo.toml --bin worst_case_decision_path`

#![no_std]

extern crate std;

use core::hint::black_box;
use std::format;
use std::println;

use soroban_sdk::{
    auth::{Context, ContractContext},
    vec, Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};
use stellar_agent_guard_contracts::testutils::{
    decide, worst_case_transfer_policy, worst_case_transfer_target, AccountState, Ledger,
};

/// Per-instruction CPU budget one Soroban invocation is metered against.
/// Kept in step with the assertion in `engine::tests::worst_case_decision_path_measured_cost`.
const DECISION_PATH_CPU_BUDGET: u64 = 100_000_000;

/// Alive account state (not frozen, no heartbeat expiry).
fn alive() -> AccountState {
    AccountState {
        admin_frozen: false,
        last_heartbeat: 0,
    }
}

/// Measure the CPU instructions of a single `decide` call in isolation.
///
/// The budget is reset after the scenario is built and after a warm-up, so
/// only the decision path itself is charged.
fn measure_decide<F>(env: &Env, mut f: F) -> u64
where
    F: FnMut(&mut Ledger) -> std::vec::Vec<stellar_agent_guard_contracts::testutils::Decision>,
{
    let mut warmup = Ledger::empty(env);
    for _ in 0..10 {
        black_box(f(&mut warmup));
    }

    let mut ledger = Ledger::empty(env);
    env.cost_estimate().budget().reset_unlimited();
    let verdicts = f(&mut ledger);
    black_box(&verdicts);
    env.cost_estimate().budget().cpu_instruction_cost()
}

/// Build the `transfer(from, to, amount)` auth context for the given policy.
fn transfer_ctx(env: &Env, asset: &Address, to: &Address, amount: i128) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(addr(env, 200).into_val(env)); // from — the guard itself
    args.push_back(to.clone().into_val(env));
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

/// The guard's own address, matching `addr(env, 200)` in the decision path.
fn addr(env: &Env, n: u8) -> Address {
    use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
    let sc = ScAddress::Contract(ContractId(Hash([n; 32])));
    Address::try_from_val(env, &sc).unwrap()
}

fn main() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let self_addr = addr(&env, 200);

    println!("=== Worst-Case Decision-Path Benchmarks (SPEC §6.2, issue #118) ===");
    println!("Lists filled to MAX_RECIPIENT_ENTRIES; destination in neither list.");
    println!();

    let target = worst_case_transfer_target(&env);
    let escape_off = worst_case_transfer_policy(&env, false);
    let escape_on = worst_case_transfer_policy(&env, true);

    let n = escape_off.recipients.len();
    let denied = escape_off.blocked_recipients.len();
    assert_eq!(
        (n as usize, denied as usize),
        (
            stellar_agent_guard_contracts::testutils::MAX_RECIPIENT_ENTRIES,
            stellar_agent_guard_contracts::testutils::MAX_RECIPIENT_ENTRIES
        ),
        "the measured scenario must sit at the documented maximum cardinality"
    );

    let off_ctx = transfer_ctx(&env, &escape_off.assets.first().unwrap(), &target, 5);
    let off = measure_decide(&env, |ledger| {
        decide(
            &env,
            &self_addr,
            Some(&escape_off),
            &alive(),
            ledger,
            1_000,
            vec![&env, off_ctx.clone()],
        )
    });

    let on_ctx = transfer_ctx(&env, &escape_on.assets.first().unwrap(), &target, 5);
    let on = measure_decide(&env, |ledger| {
        decide(
            &env,
            &self_addr,
            Some(&escape_on),
            &alive(),
            ledger,
            1_000,
            vec![&env, on_ctx.clone()],
        )
    });

    println!("lists: recipients={n} blocked_recipients={denied}");
    println!("escape_off_full_scan: {off} instructions");
    println!("escape_on: {on} instructions");
    println!();

    println!("=== Summary ===");
    println!("worst-case evaluation ~= {off} CPU instructions (escape off, full 2x{n} scan).");
    println!(
        "Escape hatch saves {} instructions by skipping the {n}-entry allowlist.",
        off.saturating_sub(on)
    );
    println!("Per-invocation CPU budget: {DECISION_PATH_CPU_BUDGET}.");
    // Integer basis points: a u64 instruction count does not survive an f64
    // round trip, and the ratio is only ever printed. Rounded (not truncated)
    // so the figure matches the one SPEC §6.2 quotes.
    let percent = |v: u64| {
        let budget = u128::from(DECISION_PATH_CPU_BUDGET);
        let basis_points = (u128::from(v) * 10_000 + budget / 2) / budget;
        format!("{}.{:02}", basis_points / 100, basis_points % 100)
    };
    println!(
        "Headroom at the documented maximum: escape_off {}%, escape_on {}% of budget.",
        percent(off),
        percent(on)
    );
    println!();
    println!("Note: These are instruction counts from the Soroban test environment.");
    println!("On-chain costs will differ due to host overhead, metering, and fee accounting.");
    println!(
        "The same scenario is asserted against the budget by \
         `cargo test worst_case_decision_path_measured_cost`."
    );
}
