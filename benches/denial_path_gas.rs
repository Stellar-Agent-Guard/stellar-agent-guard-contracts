//! Denial-path gas benchmarks for `__check_auth`.
//!
//! Measures the CPU instruction cost of a blocked authorization at each
//! of the 7 decision gates (SPEC §4), plus the allowed path with window pruning.
//!
//! Run with: `cargo run --manifest-path benches/Cargo.toml --bin denial_path_gas`

#![no_std]

extern crate std;

use core::hint::black_box;
use std::println;

use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    auth::{Context, ContractContext},
    vec, Address, Env, IntoVal, Symbol, TryFromVal, Val, Vec,
};
use stellar_agent_guard_contracts::testutils::{
    decide, AccountState, Decision, Ledger, PolicyConfig, ProtocolRule, RecipientCap,
};

/// Build a test contract address from a byte
fn addr(env: &Env, n: u8) -> Address {
    use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
    let sc = ScAddress::Contract(ContractId(Hash([n; 32])));
    Address::try_from_val(env, &sc).unwrap()
}

/// Build a transfer Context for the given asset, recipient, and amount
fn transfer_ctx(env: &Env, asset: u8, to: u8, amount: i128) -> Context {
    transfer_ctx_to(env, asset, &addr(env, to), amount)
}

fn transfer_ctx_to(env: &Env, asset: u8, to: &Address, amount: i128) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(addr(env, 9).into_val(env)); // from (ignored)
    args.push_back(to.into_val(env));
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: addr(env, asset),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

/// Build a protocol call Context
fn proto_ctx(env: &Env, contract: u8, fname: &str) -> Context {
    Context::Contract(ContractContext {
        contract: addr(env, contract),
        fn_name: Symbol::new(env, fname),
        args: Vec::new(env),
    })
}

/// Base policy with no restrictions (allows everything)
fn base_policy(env: &Env) -> PolicyConfig {
    PolicyConfig {
        per_tx_cap: 0,
        window_secs: 86_400,
        window_cap: 0,
        assets: vec![env, addr(env, 1)],
        protocols: Vec::new(env),
        recipients: vec![env, addr(env, 2)],
        recipient_window_caps: Vec::new(env),
        blocked_recipients: Vec::new(env),
        asset_caps: Vec::new(env),
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    }
}

/// Alive account state (not frozen, no heartbeat expiry)
fn alive() -> AccountState {
    AccountState {
        admin_frozen: false,
        last_heartbeat: 0,
    }
}

/// Measure CPU instructions for a single `decide` call
fn measure_decide<F>(env: &Env, name: &str, mut f: F) -> u64
where
    F: FnMut() -> std::vec::Vec<Decision>,
{
    // Warm up
    for _ in 0..10 {
        black_box(f());
    }

    let mut budget = env.cost_estimate().budget();
    budget.reset_unlimited();

    // Run the measured operation
    let result = f();
    black_box(result);

    let instructions = budget.cpu_instruction_cost();
    println!("{name}: {instructions} instructions");
    instructions
}

fn assert_cpu_ceiling(name: &str, actual: u64, ceiling: u64) {
    assert!(
        actual <= ceiling,
        "{name} used {actual} CPU instructions; ceiling is {ceiling}"
    );
}

#[allow(clippy::too_many_lines, unused_mut, clippy::similar_names)]
fn main() {
    let env = Env::default();
    env.cost_estimate().budget().reset_unlimited();
    let self_addr = addr(&env, 200);

    println!("=== Denial-Path Gas Benchmarks ===");
    println!("Measuring CPU instructions for blocked authorization at each gate");
    println!();

    // ─── Gate 1: AdminFrozen ───
    let p = base_policy(&env);
    let mut ledger = Ledger::empty(&env);
    let frozen_state = AccountState {
        admin_frozen: true,
        last_heartbeat: 0,
    };
    measure_decide(&env, "Gate 1: AdminFrozen", || {
        decide(
            &env,
            &self_addr,
            Some(&p),
            &frozen_state,
            &mut ledger,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Gate 2: HeartbeatExpired (dead-man switch) ───
    let mut p2 = base_policy(&env);
    p2.dms_grace_secs = 100;
    let expired_state = AccountState {
        admin_frozen: false,
        last_heartbeat: 500,
    };
    measure_decide(&env, "Gate 2: HeartbeatExpired", || {
        decide(
            &env,
            &self_addr,
            Some(&p2),
            &expired_state,
            &mut ledger,
            700,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Gate 3: NoPolicy ───
    let mut ledger3 = Ledger::empty(&env);
    measure_decide(&env, "Gate 3: NoPolicy", || {
        decide(
            &env,
            &self_addr,
            None,
            &alive(),
            &mut ledger3,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Gate 4: Paused ───
    let mut p4 = base_policy(&env);
    p4.paused = true;
    measure_decide(&env, "Gate 4: Paused", || {
        decide(
            &env,
            &self_addr,
            Some(&p4),
            &alive(),
            &mut ledger,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Gate 5: OutsideActiveWindow ───
    let mut p5 = base_policy(&env);
    p5.active_from = 1000;
    p5.active_until = 2000;
    measure_decide(&env, "Gate 5: OutsideActiveWindow (before)", || {
        decide(
            &env,
            &self_addr,
            Some(&p5),
            &alive(),
            &mut ledger,
            500, // before active_from
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });
    measure_decide(&env, "Gate 5: OutsideActiveWindow (after)", || {
        decide(
            &env,
            &self_addr,
            Some(&p5),
            &alive(),
            &mut ledger,
            3000, // after active_until
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Gate 6: Self-call not allowed (only heartbeat allowed) ───
    let mut ledger6 = Ledger::empty(&env);
    measure_decide(&env, "Gate 6: SelfFunctionNotAllowed (set_policy)", || {
        decide(
            &env,
            &self_addr,
            Some(&base_policy(&env)),
            &alive(),
            &mut ledger6,
            1000,
            vec![
                &env,
                Context::Contract(ContractContext {
                    contract: self_addr.clone(),
                    fn_name: Symbol::new(&env, "set_policy"),
                    args: Vec::new(&env),
                }),
            ],
        )
    });

    // ─── Gate 7: Per-context classification blocks ───
    // 7a: AssetNotAllowed (unlisted asset)
    let mut ledger7a = Ledger::empty(&env);
    measure_decide(&env, "Gate 7a: AssetNotAllowed (unlisted asset)", || {
        decide(
            &env,
            &self_addr,
            Some(&base_policy(&env)),
            &alive(),
            &mut ledger7a,
            1000,
            vec![&env, transfer_ctx(&env, 7, 2, 5)],
        )
    });

    // 7b: RecipientNotAllowed
    let mut ledger7b = Ledger::empty(&env);
    measure_decide(&env, "Gate 7b: RecipientNotAllowed", || {
        decide(
            &env,
            &self_addr,
            Some(&base_policy(&env)),
            &alive(),
            &mut ledger7b,
            1000,
            vec![&env, transfer_ctx(&env, 1, 99, 5)],
        )
    });

    // 7c: PerTxCapExceeded
    let mut p7c = base_policy(&env);
    p7c.per_tx_cap = 10;
    let mut ledger7c = Ledger::empty(&env);
    measure_decide(&env, "Gate 7c: PerTxCapExceeded", || {
        decide(
            &env,
            &self_addr,
            Some(&p7c),
            &alive(),
            &mut ledger7c,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 11)],
        )
    });

    // 7d: WindowCapExceeded
    let mut p7d = base_policy(&env);
    p7d.window_cap = 100;
    p7d.window_secs = 86_400;
    let mut ledger7d = Ledger::empty(&env);
    measure_decide(&env, "Gate 7d: WindowCapExceeded", || {
        decide(
            &env,
            &self_addr,
            Some(&p7d),
            &alive(),
            &mut ledger7d,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 150)],
        )
    });

    // 7e: ProtocolNotAllowed
    let p7e = base_policy(&env);
    let mut ledger7e = Ledger::empty(&env);
    measure_decide(&env, "Gate 7e: ProtocolNotAllowed", || {
        decide(
            &env,
            &self_addr,
            Some(&p7e),
            &alive(),
            &mut ledger7e,
            1000,
            vec![&env, proto_ctx(&env, 4, "swap")],
        )
    });

    // 7f: FunctionNotAllowed
    let mut p7f = base_policy(&env);
    p7f.protocols = vec![
        &env,
        ProtocolRule {
            contract: addr(&env, 3),
            fns: Some(vec![&env, Symbol::new(&env, "swap")]),
        },
    ];
    let mut ledger7f = Ledger::empty(&env);
    measure_decide(&env, "Gate 7f: FunctionNotAllowed", || {
        decide(
            &env,
            &self_addr,
            Some(&p7f),
            &alive(),
            &mut ledger7f,
            1000,
            vec![&env, proto_ctx(&env, 3, "drain")],
        )
    });

    // 7g: UnknownContract
    let mut ledger7g = Ledger::empty(&env);
    measure_decide(&env, "Gate 7g: UnknownContract", || {
        decide(
            &env,
            &self_addr,
            Some(&base_policy(&env)),
            &alive(),
            &mut ledger7g,
            1000,
            vec![&env, proto_ctx(&env, 5, "anything")],
        )
    });

    // ─── Allowed path with window pruning ───
    let mut p_allowed = base_policy(&env);
    p_allowed.window_cap = 1000;
    p_allowed.window_secs = 86_400;
    let mut ledger_allowed = Ledger::empty(&env);
    // Pre-populate with some expired entries to test pruning
    for i in 0..100 {
        ledger_allowed.admit(i * 100, 10);
    }
    measure_decide(&env, "Allowed: transfer with window pruning", || {
        decide(
            &env,
            &self_addr,
            Some(&p_allowed),
            &alive(),
            &mut ledger_allowed,
            50_000, // far in future, triggers pruning
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Allowed path without window (baseline) ───
    let mut ledger_baseline = Ledger::empty(&env);
    measure_decide(&env, "Allowed: transfer (no window)", || {
        decide(
            &env,
            &self_addr,
            Some(&base_policy(&env)),
            &alive(),
            &mut ledger_baseline,
            1000,
            vec![&env, transfer_ctx(&env, 1, 2, 5)],
        )
    });

    // ─── Worst-case bounded input sizes for CI/reference tracking ───
    let mut p_max_lists = base_policy(&env);
    p_max_lists.assets = Vec::new(&env);
    p_max_lists.recipients = Vec::new(&env);
    p_max_lists.blocked_recipients = Vec::new(&env);
    p_max_lists.protocols = Vec::new(&env);
    p_max_lists.recipient_window_caps = Vec::new(&env);
    for i in 0_u8..=u8::MAX {
        p_max_lists.assets.push_back(addr(&env, i));
        let recipient = Address::generate(&env);
        p_max_lists
            .blocked_recipients
            .push_back(Address::generate(&env));
        p_max_lists.recipient_window_caps.push_back(RecipientCap {
            recipient: recipient.clone(),
            cap: 0,
        });
        p_max_lists.recipients.push_back(recipient);
        p_max_lists.protocols.push_back(ProtocolRule {
            contract: addr(&env, i),
            fns: None,
        });
    }
    let last_recipient = p_max_lists.recipients.get(255).unwrap();
    let mut max_list_ledger = Ledger::empty(&env);
    let max_asset_list_cost = measure_decide(
        &env,
        "Stress: 256-entry lists, successful tail lookup",
        || {
            decide(
                &env,
                &self_addr,
                Some(&p_max_lists),
                &alive(),
                &mut max_list_ledger,
                1000,
                vec![&env, transfer_ctx_to(&env, 255, &last_recipient, 1)],
            )
        },
    );
    assert_cpu_ceiling(
        "256-entry asset/recipient/deny/override lists",
        max_asset_list_cost,
        1_250_000,
    );

    let mut max_protocol_ledger = Ledger::empty(&env);
    let max_protocol_list_cost = measure_decide(
        &env,
        "Stress: 256-entry protocol list, successful tail lookup",
        || {
            decide(
                &env,
                &self_addr,
                Some(&p_max_lists),
                &alive(),
                &mut max_protocol_ledger,
                1000,
                vec![&env, proto_ctx(&env, 255, "swap")],
            )
        },
    );
    assert_cpu_ceiling("256-entry protocol list", max_protocol_list_cost, 500_000);

    for size in [0_u32, 100, 8192] {
        let mut policy = base_policy(&env);
        policy.window_cap = 1_000_000;
        policy.window_secs = 10_000;
        let mut ledger = Ledger::empty(&env);
        for i in 0..size {
            ledger.admit(u64::from(i), 1);
        }
        let ceiling = match size {
            0 | 100 => 35_000,
            8192 => 60_000,
            _ => unreachable!(),
        };
        let cost = measure_decide(
            &env,
            &std::format!("Stress: {size} live window entries"),
            || {
                decide(
                    &env,
                    &self_addr,
                    Some(&policy),
                    &alive(),
                    &mut ledger,
                    u64::from(size) + 1,
                    vec![&env, transfer_ctx(&env, 1, 2, 1)],
                )
            },
        );
        assert_cpu_ceiling(&std::format!("{size}-entry rolling window"), cost, ceiling);
    }

    let mut p_batch = base_policy(&env);
    p_batch.protocols = vec![
        &env,
        ProtocolRule {
            contract: addr(&env, 3),
            fns: Some(vec![&env, Symbol::new(&env, "swap")]),
        },
    ];
    let mut contexts = Vec::new(&env);
    for _ in 0..16 {
        contexts.push_back(proto_ctx(&env, 3, "swap"));
    }
    let mut batch_ledger = Ledger::empty(&env);
    let batch_cost = measure_decide(&env, "Stress: 16-context protocol batch", || {
        decide(
            &env,
            &self_addr,
            Some(&p_batch),
            &alive(),
            &mut batch_ledger,
            1000,
            contexts.clone(),
        )
    });
    assert_cpu_ceiling("16-context protocol batch", batch_cost, 150_000);

    println!();
    println!("=== Summary ===");
    println!("Gate order in SPEC §4 is semantic-first (admin freeze → dead-man → policy gates → classification).");
    println!("This benchmark measures the actual CPU cost at each gate to verify if a cheaper gate could run earlier.");
    println!();
    println!("Note: These are instruction counts from the Soroban test environment.");
    println!("On-chain costs will differ due to host overhead, metering, and fee accounting.");
}
