//! Exhaustive reference-model checks for the SPEC §4 decision table.

use crate::engine::{decide, AccountState, Decision};
use crate::types::{Error, PolicyConfig, ProtocolRule};
use crate::window::Ledger;
use soroban_sdk::auth::{
    Context, ContractContext, ContractExecutable, CreateContractHostFnContext,
};
use soroban_sdk::{vec, Address, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec};

const NOW: u64 = 1_000;
const SELF_ADDRESS: u8 = 200;
const ASSET_ADDRESS: u8 = 1;
const PROTOCOL_ADDRESS: u8 = 3;
const RECIPIENT_ADDRESS: u8 = 2;

#[derive(Clone, Copy, Debug)]
enum CallKind {
    SelfCall,
    AssetTransfer,
    AssetOther,
    Protocol,
    CreateContract,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct GateRow {
    admin_frozen: bool,
    dms_expired: bool,
    no_policy: bool,
    paused: bool,
    outside_window: bool,
}

#[derive(Clone, Copy, Debug)]
struct ContextInput {
    self_call_ok: bool,
    kind: CallKind,
    valid_detail: bool,
}

fn address(env: &Env, id: u8) -> Address {
    use soroban_sdk::xdr::{ContractId, Hash, ScAddress};
    Address::try_from_val(env, &ScAddress::Contract(ContractId(Hash([id; 32])))).unwrap()
}

fn policy(env: &Env, paused: bool, outside_window: bool, dms_expired: bool) -> PolicyConfig {
    PolicyConfig {
        per_tx_cap: 0,
        window_secs: 86_400,
        window_cap: 0,
        assets: vec![env, address(env, ASSET_ADDRESS)],
        protocols: vec![
            env,
            ProtocolRule {
                contract: address(env, PROTOCOL_ADDRESS),
                fns: Some(vec![env, Symbol::new(env, "swap")]),
            },
        ],
        recipients: vec![env, address(env, RECIPIENT_ADDRESS)],
        recipient_window_caps: Vec::new(env),
        blocked_recipients: Vec::new(env),
        asset_caps: Vec::new(env),
        allow_any_recipient: false,
        active_from: if outside_window { NOW + 1 } else { 0 },
        active_until: 0,
        paused,
        dms_grace_secs: if dms_expired { 10 } else { 0 },
        protocol_calls_per_window: 0,
    }
}

fn context(env: &Env, self_call_ok: bool, kind: CallKind, valid_detail: bool) -> Context {
    if let CallKind::CreateContract = kind {
        return Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(BytesN::from_array(env, &[0; 32])),
            salt: BytesN::from_array(env, &[1; 32]),
        });
    }

    let (contract, fn_name, args) = match kind {
        CallKind::SelfCall => (
            address(env, SELF_ADDRESS),
            if self_call_ok {
                "heartbeat"
            } else {
                "set_policy"
            },
            Vec::new(env),
        ),
        CallKind::AssetTransfer => {
            let mut args: Vec<Val> = Vec::new(env);
            args.push_back(address(env, 9).into_val(env));
            args.push_back(address(env, RECIPIENT_ADDRESS).into_val(env));
            args.push_back(if valid_detail { 5_i128 } else { 0_i128 }.into_val(env));
            (address(env, ASSET_ADDRESS), "transfer", args)
        }
        CallKind::AssetOther => (address(env, ASSET_ADDRESS), "mint", Vec::new(env)),
        CallKind::Protocol => (
            address(env, PROTOCOL_ADDRESS),
            if valid_detail { "swap" } else { "drain" },
            Vec::new(env),
        ),
        CallKind::CreateContract => unreachable!(),
        CallKind::Unknown => (address(env, 99), "invoke", Vec::new(env)),
    };
    Context::Contract(ContractContext {
        contract,
        fn_name: Symbol::new(env, fn_name),
        args,
    })
}

fn reference_model(row: GateRow, input: ContextInput) -> Decision {
    // These predicates follow the numbered SPEC §4 rules, then the matching §6 rule.
    // DMS requires stored policy data, so it cannot be enabled when policy is absent.
    let reason = if row.admin_frozen {
        Some(Error::AdminFrozen)
    } else if row.dms_expired && !row.no_policy {
        Some(Error::HeartbeatExpired)
    } else if row.no_policy {
        Some(Error::NoPolicy)
    } else if row.paused {
        Some(Error::Paused)
    } else if row.outside_window {
        Some(Error::OutsideActiveWindow)
    } else {
        match input.kind {
            CallKind::SelfCall if !input.self_call_ok => Some(Error::SelfFunctionNotAllowed),
            CallKind::AssetTransfer if !input.valid_detail => Some(Error::InvalidAmount),
            CallKind::AssetOther => Some(Error::AssetFnNotAllowed),
            CallKind::Protocol if !input.valid_detail => Some(Error::FunctionNotAllowed),
            CallKind::CreateContract => Some(Error::CreateContractNotAllowed),
            CallKind::Unknown => Some(Error::UnknownContract),
            _ => None,
        }
    };

    match reason {
        Some(error) => Decision::Blocked(error),
        None => Decision::Allowed,
    }
}

#[test]
fn decide_matches_specification_truth_table() {
    let env = Env::default();
    let self_address = address(&env, SELF_ADDRESS);
    let kinds = [
        CallKind::SelfCall,
        CallKind::AssetTransfer,
        CallKind::AssetOther,
        CallKind::Protocol,
        CallKind::CreateContract,
        CallKind::Unknown,
    ];
    let mut checked_rows = 0_u32;

    for gate_bits in 0_u8..32 {
        let row = GateRow {
            admin_frozen: gate_bits & 1 != 0,
            dms_expired: gate_bits & 2 != 0,
            no_policy: gate_bits & 4 != 0,
            paused: gate_bits & 8 != 0,
            outside_window: gate_bits & 16 != 0,
        };
        for self_call_ok in [false, true] {
            for kind in kinds {
                for valid_detail in [false, true] {
                    let input = ContextInput {
                        self_call_ok,
                        kind,
                        valid_detail,
                    };
                    let config = policy(&env, row.paused, row.outside_window, row.dms_expired);
                    let account_state = AccountState {
                        admin_frozen: row.admin_frozen,
                        last_heartbeat: u64::from(row.dms_expired),
                    };
                    let contexts = vec![&env, context(&env, self_call_ok, kind, valid_detail)];
                    let mut ledger = Ledger::empty(&env);
                    let actual = decide(
                        &env,
                        &self_address,
                        if row.no_policy { None } else { Some(&config) },
                        &account_state,
                        &mut ledger,
                        NOW,
                        contexts,
                    );
                    let expected = reference_model(row, input);
                    assert_eq!(
                        actual.first(),
                        Some(&expected),
                        "decision-table mismatch: row={checked_rows}, gates={row:?}, context={input:?}, actual={actual:?}, expected={expected:?}"
                    );
                    checked_rows += 1;
                }
            }
        }
    }

    assert_eq!(checked_rows, 768, "unexpected truth-table matrix size");
}
