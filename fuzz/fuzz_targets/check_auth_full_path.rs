#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};
use stellar_agent_guard_contracts::{Error, PolicyConfig, PolicyEngine, PolicyEngineClient};

const FIXED_KEY: [u8; 32] = [7; 32];
const MAX_CONTEXTS: usize = 32;
const PER_TX_CAP: i128 = 100;
const WINDOW_CAP: i128 = 500;

fn model_decide(input: &[u8]) -> bool {
    let count = input.first().copied().unwrap_or(0) as usize % (MAX_CONTEXTS + 1);
    let mut window_total = 0i128;
    for index in 0..count {
        let selector = input.get(index * 4 + 1).copied().unwrap_or(0) % 6;
        let copies = if input.get(index * 4 + 2).copied().unwrap_or(0) & 1 == 1 {
            2
        } else {
            1
        };
        for _ in 0..copies {
            match selector {
                0 | 1 => {
                    let amount = i128::from(input.get(index * 4 + 3).copied().unwrap_or(1));
                    if amount <= 0 || amount > PER_TX_CAP {
                        return false;
                    }
                    window_total = window_total.saturating_add(amount);
                    if window_total > WINDOW_CAP {
                        return false;
                    }
                }
                2 => {}
                _ => return false,
            }
        }
    }
    true
}

fn contexts(env: &Env, guard: &Address, asset: &Address, input: &[u8]) -> Vec<Context> {
    let count = input.first().copied().unwrap_or(0) as usize % (MAX_CONTEXTS + 1);
    let mut result = Vec::new(env);
    for index in 0..count {
        let selector = input.get(index * 4 + 1).copied().unwrap_or(0) % 6;
        let amount = i128::from(input.get(index * 4 + 3).copied().unwrap_or(1));
        let context = match selector {
            0 => transfer_context(env, asset, amount),
            1 => transfer_from_context(env, asset, amount),
            2 => Context::Contract(ContractContext {
                contract: guard.clone(),
                fn_name: Symbol::new(env, "heartbeat"),
                args: Vec::new(env),
            }),
            3 => Context::Contract(ContractContext {
                contract: asset.clone(),
                fn_name: Symbol::new(env, "mint"),
                args: Vec::new(env),
            }),
            4 => Context::Contract(ContractContext {
                contract: guard.clone(),
                fn_name: Symbol::new(env, "hostile"),
                args: Vec::new(env),
            }),
            _ => Context::Contract(ContractContext {
                contract: Address::generate(env),
                fn_name: Symbol::new(env, "unknown"),
                args: Vec::new(env),
            }),
        };
        result.push_back(context.clone());
        if input.get(index * 4 + 2).copied().unwrap_or(0) & 1 == 1 {
            result.push_back(context);
        }
    }
    result
}

fn transfer_context(env: &Env, asset: &Address, amount: i128) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(asset.clone().into_val(env));
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

fn transfer_from_context(env: &Env, asset: &Address, amount: i128) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer_from"),
        args,
    })
}

fn setup(env: &Env) -> (Address, Address, SigningKey) {
    let key = SigningKey::from_bytes(&FIXED_KEY);
    let guard = env.register(PolicyEngine, ());
    let admin = Address::generate(env);
    env.mock_all_auths();
    let client = PolicyEngineClient::new(env, &guard);
    client.initialize(
        &admin,
        &BytesN::from_array(env, &key.verifying_key().to_bytes()),
    );
    let asset = Address::generate(env);
    client.set_policy(&PolicyConfig {
        per_tx_cap: PER_TX_CAP,
        window_secs: 60,
        window_cap: WINDOW_CAP,
        assets: soroban_sdk::vec![env, asset.clone()],
        protocols: Vec::new(env),
        recipients: Vec::new(env),
        allow_any_recipient: true,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
    });
    (guard, asset, key)
}

fuzz_target!(|input: &[u8]| {
    let env = Env::default();
    let (guard, asset, signing_key) = setup(&env);
    let contexts = contexts(&env, &guard, &asset, input);
    let payload = env.crypto().sha256(&Bytes::from_slice(&env, b"fuzz-payload"));
    let signature = BytesN::from_array(
        &env,
        &signing_key.sign(&payload.to_array()).to_bytes(),
    );
    let result = env.as_contract(&guard, || {
        <PolicyEngine as CustomAccountInterface>::__check_auth(
            env.clone(),
            payload.clone(),
            signature.clone(),
            contexts,
        )
    });

    if let Err(error) = result {
        assert!(matches!(
            error,
            Error::AdminFrozen
                | Error::HeartbeatExpired
                | Error::NoPolicy
                | Error::Paused
                | Error::OutsideActiveWindow
                | Error::RecipientNotAllowed
                | Error::PerTxCapExceeded
                | Error::WindowCapExceeded
                | Error::ProtocolNotAllowed
                | Error::FunctionNotAllowed
                | Error::UnknownContract
                | Error::SelfFunctionNotAllowed
                | Error::CreateContractNotAllowed
                | Error::InvalidAmount
        ));
    }
    assert_eq!(result.is_ok(), model_decide(input));

    if !model_decide(input) {
        let valid_context = transfer_context(&env, &asset, 1);
        let valid_payload = env.crypto().sha256(&Bytes::from_slice(&env, b"follow-up"));
        let valid_signature = BytesN::from_array(
            &env,
            &signing_key.sign(&valid_payload.to_array()).to_bytes(),
        );
        let follow_up = env.as_contract(&guard, || {
            <PolicyEngine as CustomAccountInterface>::__check_auth(
                env.clone(),
                valid_payload,
                valid_signature,
                soroban_sdk::vec![&env, valid_context],
            )
        });
        assert!(follow_up.is_ok());
    }
});