#![no_main]

//! Fuzz heartbeat freshness and malformed authorization contexts.
//!
//! Issue #607: time-based emergency paths get the same malformed-input
//! pressure as policy deserialization. The target under test is the real
//! `PolicyEngine::__check_auth`, not a mock: the host verifies the agent's
//! Ed25519 signature and the production engine applies the account gates
//! (admin freeze, dead-man switch, pause, active window) before classifying
//! every authorization context.
//!
//! Input layout (all multi-byte integers little-endian; missing bytes read as
//! zero, so short inputs stay valid cases rather than being rejected):
//!
//! ```text
//! byte 0      flags: bit0 admin_frozen, bit1 install policy,
//!                    bit2 paused, bit3 active_from gate in the future
//! bytes 1..5  u32 dms_grace_secs
//! bytes 5..13 u64 LastHeartbeat (absolute unix seconds, 0 = never)
//! bytes 13..21 u64 current ledger timestamp
//! byte 21     number of contexts (mod MAX_CONTEXTS + 1)
//! then 2 bytes per context: shape selector (mod 9), parameter byte
//! ```
//!
//! Shapes: 0 heartbeat, 1 heartbeat with an extra arg, 2 heartbeat with two
//! extra args, 3 `self_lock`, 4 another self-function, 5 valid asset transfer,
//! 6 malformed asset transfer, 7 malformed `transfer_from`, 8 unknown contract.
//!
//! Bounded: input longer than [`MAX_INPUT_BYTES`] is ignored and at most
//! [`MAX_CONTEXTS`] contexts are built, so host work stays proportional to the
//! fuzzer's `-max_len`.

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::testutils::{Address as _, Ledger as _};
use soroban_sdk::{Address, Bytes, BytesN, Env, IntoVal, Symbol, Val, Vec};
use std::vec::Vec as StdVec;
use stellar_agent_guard_contracts::testutils::DataKey;
use stellar_agent_guard_contracts::{Error, PolicyConfig, PolicyEngine, PolicyEngineClient};

const FIXED_KEY: [u8; 32] = [11; 32];
const MAX_INPUT_BYTES: usize = 4_096;
const MAX_CONTEXTS: usize = 16;
const PER_TX_CAP: i128 = 1_000;

/// One authorization context the fuzzer asked for, kept in the same order as
/// the `Context`s built for the host so the model can predict each verdict.
#[derive(Clone, Copy)]
enum Shape {
    Heartbeat,
    HeartbeatWithOneArg,
    HeartbeatWithTwoArgs,
    SelfLock,
    OtherSelfFunction,
    ValidTransfer,
    MalformedTransfer,
    MalformedTransferFrom,
    UnknownContract,
}

impl Shape {
    fn from_byte(byte: u8) -> Self {
        match byte % 9 {
            0 => Self::Heartbeat,
            1 => Self::HeartbeatWithOneArg,
            2 => Self::HeartbeatWithTwoArgs,
            3 => Self::SelfLock,
            4 => Self::OtherSelfFunction,
            5 => Self::ValidTransfer,
            6 => Self::MalformedTransfer,
            7 => Self::MalformedTransferFrom,
            _ => Self::UnknownContract,
        }
    }

    /// Reason this context is denied once the account-level gates pass, or
    /// `None` when the policy engine admits it. Only `heartbeat`, `self_lock`,
    /// and a well-formed positive transfer inside `per_tx_cap` are admitted.
    fn denial(self) -> Option<Error> {
        match self {
            Self::Heartbeat
            | Self::HeartbeatWithOneArg
            | Self::HeartbeatWithTwoArgs
            | Self::SelfLock
            | Self::ValidTransfer => None,
            Self::OtherSelfFunction => Some(Error::SelfFunctionNotAllowed),
            Self::MalformedTransfer | Self::MalformedTransferFrom | Self::UnknownContract => {
                Some(Error::UnknownContract)
            }
        }
    }
}

struct Plan {
    admin_frozen: bool,
    has_policy: bool,
    paused: bool,
    active_window_gate: bool,
    grace: u64,
    last_heartbeat: u64,
    now: u64,
    shapes: StdVec<Shape>,
}

impl Plan {
    fn parse(input: &[u8]) -> Self {
        let flags = byte_at(input, 0);
        let shape_count = usize::from(byte_at(input, 21)) % (MAX_CONTEXTS + 1);
        let mut shapes = StdVec::with_capacity(shape_count);
        for index in 0..shape_count {
            shapes.push(Shape::from_byte(byte_at(input, 22 + index * 2)));
        }
        Self {
            admin_frozen: flags & 0b0001 != 0,
            has_policy: flags & 0b0010 != 0,
            paused: flags & 0b0100 != 0,
            active_window_gate: flags & 0b1000 != 0,
            grace: u64::from(u32_at(input, 1)) % (MAX_DMS_GRACE_SECS + 1),
            last_heartbeat: u64_at(input, 5),
            now: u64_at(input, 13),
            shapes,
        }
    }

    /// Expected result of `__check_auth` for this plan.
    ///
    /// `__check_auth` short-circuits a missing policy before the decision
    /// engine runs, and the engine's account gates only emit a verdict per
    /// context, so an empty batch is admitted even while frozen. After the
    /// gates, the first blocked context decides the whole call.
    fn expected(&self) -> Option<Error> {
        if !self.has_policy {
            return Some(Error::NoPolicy);
        }
        if self.shapes.is_empty() {
            return None;
        }
        if self.admin_frozen {
            return Some(Error::AdminFrozen);
        }
        let dms_expired = self.grace != 0
            && self.last_heartbeat != 0
            && self.now.saturating_sub(self.last_heartbeat) > self.grace;
        if dms_expired {
            return Some(Error::HeartbeatExpired);
        }
        if self.paused {
            return Some(Error::Paused);
        }
        if self.active_window_gate {
            return Some(Error::OutsideActiveWindow);
        }
        self.shapes.iter().find_map(|shape| shape.denial())
    }
}

const MAX_DMS_GRACE_SECS: u64 = 315_360_000;

fn byte_at(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or(0)
}

fn u32_at(input: &[u8], index: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (offset, slot) in bytes.iter_mut().enumerate() {
        *slot = byte_at(input, index + offset);
    }
    u32::from_le_bytes(bytes)
}

fn u64_at(input: &[u8], index: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (offset, slot) in bytes.iter_mut().enumerate() {
        *slot = byte_at(input, index + offset);
    }
    u64::from_le_bytes(bytes)
}

fn heartbeat_context(env: &Env, guard: &Address, extra_args: usize) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    for _ in 0..extra_args {
        args.push_back(1u32.into_val(env));
    }
    Context::Contract(ContractContext {
        contract: guard.clone(),
        fn_name: Symbol::new(env, "heartbeat"),
        args,
    })
}

fn self_context(env: &Env, guard: &Address, fn_name: &str) -> Context {
    Context::Contract(ContractContext {
        contract: guard.clone(),
        fn_name: Symbol::new(env, fn_name),
        args: Vec::new(env),
    })
}

fn transfer_context(env: &Env, asset: &Address, amount: i128) -> Context {
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(Address::generate(env).into_val(env)); // from
    args.push_back(Address::generate(env).into_val(env)); // to
    args.push_back(amount.into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

fn malformed_transfer_context(env: &Env, asset: &Address) -> Context {
    // Wrong arity: a `transfer` the engine refuses to partially parse. This is
    // the malformed shape the production classifier must default-deny.
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(Address::generate(env).into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    })
}

fn malformed_transfer_from_context(env: &Env, asset: &Address) -> Context {
    // `transfer_from` with a plausible but non-address `to`/non-i128 amount
    // shape is still rejected: the engine requires exact arity and types. The
    // amount is a valid Symbol of the wrong type (symbols allow only
    // alphanumerics/underscores, so `Symbol::new` itself stays panic-free).
    let mut args: Vec<Val> = Vec::new(env);
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(Address::generate(env).into_val(env));
    args.push_back(Symbol::new(env, "amount").into_val(env));
    Context::Contract(ContractContext {
        contract: asset.clone(),
        fn_name: Symbol::new(env, "transfer_from"),
        args,
    })
}

fn build_contexts(env: &Env, plan: &Plan, guard: &Address, asset: &Address) -> Vec<Context> {
    let mut contexts = Vec::new(env);
    for shape in &plan.shapes {
        contexts.push_back(match shape {
            Shape::Heartbeat => heartbeat_context(env, guard, 0),
            Shape::HeartbeatWithOneArg => heartbeat_context(env, guard, 1),
            Shape::HeartbeatWithTwoArgs => heartbeat_context(env, guard, 2),
            Shape::SelfLock => self_context(env, guard, "self_lock"),
            Shape::OtherSelfFunction => self_context(env, guard, "set_policy"),
            Shape::ValidTransfer => transfer_context(env, asset, 1),
            Shape::MalformedTransfer => malformed_transfer_context(env, asset),
            Shape::MalformedTransferFrom => malformed_transfer_from_context(env, asset),
            Shape::UnknownContract => Context::Contract(ContractContext {
                contract: Address::generate(env),
                fn_name: Symbol::new(env, "unknown"),
                args: Vec::new(env),
            }),
        });
    }
    contexts
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT_BYTES {
        return;
    }

    let plan = Plan::parse(input);
    let env = Env::default();
    env.ledger().set_timestamp(plan.now);

    let key = SigningKey::from_bytes(&FIXED_KEY);
    let guard = env.register(PolicyEngine, ());
    let admin = Address::generate(&env);
    env.mock_all_auths();
    let client = PolicyEngineClient::new(&env, &guard);
    client.initialize(
        &admin,
        &BytesN::from_array(&env, &key.verifying_key().to_bytes()),
    );

    let asset = Address::generate(&env);
    if plan.has_policy {
        client.set_policy(&PolicyConfig {
            per_tx_cap: PER_TX_CAP,
            window_secs: 60,
            window_cap: 0,
            assets: soroban_sdk::vec![&env, asset.clone()],
            asset_caps: Vec::new(&env),
            protocols: Vec::new(&env),
            recipients: Vec::new(&env),
            recipient_window_caps: Vec::new(&env),
            blocked_recipients: Vec::new(&env),
            allow_any_recipient: true,
            active_from: if plan.active_window_gate {
                plan.now.saturating_add(1)
            } else {
                0
            },
            active_until: 0,
            paused: plan.paused,
            dms_grace_secs: plan.grace,
            protocol_calls_per_window: 0,
        });
    }

    // Pin the exact DMS clocks under test and the freeze flag. Writing the
    // storage keys directly (instead of calling `freeze`/`heartbeat`) keeps
    // the setup independent of the path being fuzzed, so the target measures
    // `__check_auth` only.
    env.as_contract(&guard, || {
        env.storage()
            .persistent()
            .set(&DataKey::LastHeartbeat, &plan.last_heartbeat);
        env.storage()
            .persistent()
            .set(&DataKey::AdminFrozen, &plan.admin_frozen);
    });

    let contexts = build_contexts(&env, &plan, &guard, &asset);
    let payload = env
        .crypto()
        .sha256(&Bytes::from_slice(&env, b"heartbeat-fuzz-payload"));
    let signature = BytesN::from_array(&env, &key.sign(&payload.to_array()).to_bytes());

    let result = env.as_contract(&guard, || {
        <PolicyEngine as CustomAccountInterface>::__check_auth(
            env.clone(),
            payload,
            signature,
            contexts,
        )
    });

    let expected = plan.expected();
    assert_eq!(
        result.as_ref().err().copied(),
        expected,
        "unexpected heartbeat decision: {result:?} (expected {expected:?})"
    );
});
