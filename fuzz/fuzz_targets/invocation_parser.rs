#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::auth::{
    Context, ContractContext, ContractExecutable, CreateContractHostFnContext,
    CreateContractWithConstructorHostFnContext,
};
use soroban_sdk::{vec, Address, Bytes, BytesN, Env, IntoVal, Symbol, TryFromVal, Val, Vec};
use stellar_agent_guard_contracts::testutils::{
    decide, parse_call, AccountState, Decision, Error, Ledger, ParsedCall, PolicyConfig,
    ProtocolRule,
};
use stellar_xdr::{ContractId, Hash, Limits, ReadXdr, ScAddress, ScSymbol, ScVal, StringM};

const MAX_INPUT_BYTES: usize = 2_048;
const MAX_XDR_DEPTH: u32 = 32;
const PER_TX_CAP: i128 = 100;
const WINDOW_CAP: i128 = 500;

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.bytes.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_i128(&mut self) -> i128 {
        let mut buf = [0u8; 16];
        for slot in &mut buf {
            *slot = self.next_u8();
        }
        i128::from_le_bytes(buf)
    }

    fn next_slice(&mut self, max_len: usize) -> &'a [u8] {
        let remaining = self.bytes.get(self.pos..).unwrap_or(&[]);
        let take = remaining.len().min(max_len);
        self.pos = self.pos.saturating_add(take);
        &remaining[..take]
    }
}

fn addr(env: &Env, id: u8) -> Address {
    let sc = ScAddress::Contract(ContractId(Hash([id; 32])));
    Address::try_from_val(env, &sc).expect("fixed contract address must convert")
}

fn try_decode_symbol_from_bytes(env: &Env, raw: &[u8]) -> Option<Symbol> {
    // Exercise raw XDR ScVal::Symbol decoding as well as ASCII ScSymbol conversion.
    let limits = Limits {
        depth: MAX_XDR_DEPTH,
        len: raw.len(),
    };
    if let Ok(scval @ ScVal::Symbol(_)) = ScVal::from_xdr(raw, limits) {
        return Symbol::try_from_val(env, &scval).ok();
    }
    let bounded_len = raw.len().min(32);
    let candidate = &raw[..bounded_len];
    let is_valid_symbol_ascii = candidate
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_');
    if !is_valid_symbol_ascii {
        return None;
    }
    let string_m = StringM::try_from(candidate).ok()?;
    let scval = ScVal::Symbol(ScSymbol(string_m));
    Symbol::try_from_val(env, &scval).ok()
}

fn decode_fn_symbol(env: &Env, cursor: &mut Cursor<'_>) -> Symbol {
    match cursor.next_u8() % 12 {
        0 => Symbol::new(env, "transfer"),
        1 => Symbol::new(env, "transfer_from"),
        2 => Symbol::new(env, "heartbeat"),
        3 => Symbol::new(env, "self_lock"),
        4 => Symbol::new(env, "set_policy"),
        5 => Symbol::new(env, "mint"),
        6 => Symbol::new(env, "burn"),
        7 => Symbol::new(env, "swap"),
        8 => Symbol::new(env, "drain"),
        9 => Symbol::new(env, "approve"),
        10 => {
            let len = usize::from(cursor.next_u8() % 40);
            let raw = cursor.next_slice(len);
            try_decode_symbol_from_bytes(env, raw)
                .unwrap_or_else(|| Symbol::new(env, "invalid_sym"))
        }
        _ => {
            // Build an arbitrary valid symbol string directly from fuzzer bytes.
            let len = usize::from(cursor.next_u8() % 33);
            let raw = cursor.next_slice(len);
            let mut buf = [b'a'; 32];
            for (index, byte) in raw.iter().take(32).enumerate() {
                const ALPHABET: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
                buf[index] = ALPHABET[usize::from(*byte) % ALPHABET.len()];
            }
            let text = core::str::from_utf8(&buf[..raw.len().min(32)]).unwrap_or("sym");
            Symbol::new(env, text)
        }
    }
}

fn decode_arbitrary_val(env: &Env, cursor: &mut Cursor<'_>, allowed_recipient: &Address) -> Val {
    match cursor.next_u8() % 11 {
        0 => ().into_val(env),
        1 => (cursor.next_u8() & 1 == 1).into_val(env),
        2 => i32::from(cursor.next_u8()).into_val(env),
        3 => u32::from(cursor.next_u8()).into_val(env),
        4 => i64::from(cursor.next_u8()).into_val(env),
        5 => u64::from(cursor.next_u8()).into_val(env),
        6 => {
            let amount = match cursor.next_u8() % 7 {
                0 => 0_i128,
                1 => -1_i128,
                2 => 1_i128,
                3 => PER_TX_CAP,
                4 => PER_TX_CAP + 1,
                5 => i128::MIN,
                _ => cursor.next_i128(),
            };
            amount.into_val(env)
        }
        7 => match cursor.next_u8() % 3 {
            0 => allowed_recipient.clone().into_val(env),
            1 => addr(env, 42).into_val(env),
            _ => addr(env, cursor.next_u8()).into_val(env),
        },
        8 => decode_fn_symbol(env, cursor).into_val(env),
        9 => {
            let len = usize::from(cursor.next_u8() % 32);
            Bytes::from_slice(env, cursor.next_slice(len)).into_val(env)
        }
        _ => {
            let len = usize::from(cursor.next_u8() % 64);
            let raw = cursor.next_slice(len);
            let limits = Limits {
                depth: MAX_XDR_DEPTH,
                len: raw.len(),
            };
            ScVal::from_xdr(raw, limits)
                .ok()
                .and_then(|scval| Val::try_from_val(env, &scval).ok())
                .unwrap_or_else(|| ().into_val(env))
        }
    }
}

fn build_context(
    env: &Env,
    self_addr: &Address,
    asset: &Address,
    protocol: &Address,
    allowed_recipient: &Address,
    cursor: &mut Cursor<'_>,
) -> Context {
    match cursor.next_u8() % 8 {
        0 => Context::CreateContractHostFn(CreateContractHostFnContext {
            executable: ContractExecutable::Wasm(BytesN::from_array(env, &[cursor.next_u8(); 32])),
            salt: BytesN::from_array(env, &[cursor.next_u8(); 32]),
        }),
        1 => {
            let arg_count = usize::from(cursor.next_u8() % 5);
            let mut constructor_args = Vec::new(env);
            for _ in 0..arg_count {
                constructor_args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
            }
            Context::CreateContractWithCtorHostFn(CreateContractWithConstructorHostFnContext {
                executable: ContractExecutable::Wasm(BytesN::from_array(
                    env,
                    &[cursor.next_u8(); 32],
                )),
                salt: BytesN::from_array(env, &[cursor.next_u8(); 32]),
                constructor_args,
            })
        }
        selector => {
            let contract = match selector {
                2 => self_addr.clone(),
                3 | 4 => asset.clone(),
                5 => protocol.clone(),
                _ => {
                    let id = cursor.next_u8();
                    match id {
                        1 | 3 | 200 => addr(env, 99),
                        other => addr(env, other),
                    }
                }
            };
            let fn_name = decode_fn_symbol(env, cursor);
            let shape_mode = cursor.next_u8() % 4;
            let mut args: Vec<Val> = Vec::new(env);
            match shape_mode {
                // Canonical 3-arg SAC transfer shape with fuzzed recipient/amount.
                0 => {
                    args.push_back(self_addr.clone().into_val(env));
                    args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
                    args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
                }
                // Canonical 4-arg SAC transfer_from shape with fuzzed recipient/amount.
                1 => {
                    args.push_back(self_addr.clone().into_val(env));
                    args.push_back(addr(env, 8).into_val(env));
                    args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
                    args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
                }
                // Arbitrary arity (0..=6) and arbitrary arg Val types.
                _ => {
                    let arity = usize::from(cursor.next_u8() % 7);
                    for _ in 0..arity {
                        args.push_back(decode_arbitrary_val(env, cursor, allowed_recipient));
                    }
                }
            }
            Context::Contract(ContractContext {
                contract,
                fn_name,
                args,
            })
        }
    }
}

fn check_invariants(
    env: &Env,
    self_addr: &Address,
    policy: &PolicyConfig,
    allowed_recipient: &Address,
    ctx: &Context,
) {
    let parsed = parse_call(env, self_addr, ctx, policy);
    let mut ledger = Ledger::empty(env);
    let state = AccountState {
        admin_frozen: false,
        last_heartbeat: 0,
    };
    let verdicts = decide(
        env,
        self_addr,
        Some(policy),
        &state,
        &mut ledger,
        1_000,
        vec![env, ctx.clone()],
    );
    assert_eq!(verdicts.len(), 1, "one context must yield one verdict");
    let verdict = &verdicts[0];

    let expected = match &parsed {
        ParsedCall::SelfCall { fname } => {
            if fname == &Symbol::new(env, "heartbeat") || fname == &Symbol::new(env, "self_lock") {
                Decision::Allowed
            } else {
                Decision::Blocked(Error::SelfFunctionNotAllowed)
            }
        }
        ParsedCall::CreateContract => Decision::Blocked(Error::CreateContractNotAllowed),
        ParsedCall::Unknown { .. } => Decision::Blocked(Error::UnknownContract),
        ParsedCall::AssetOther { .. } => Decision::Blocked(Error::AssetFnNotAllowed),
        ParsedCall::Protocol { fname, .. } => {
            if fname == &Symbol::new(env, "swap") {
                Decision::Allowed
            } else {
                Decision::Blocked(Error::FunctionNotAllowed)
            }
        }
        ParsedCall::AssetTransfer { to, amount, .. } => {
            if *amount <= 0 {
                Decision::Blocked(Error::InvalidAmount)
            } else if to != allowed_recipient {
                Decision::Blocked(Error::RecipientNotAllowed)
            } else if *amount > PER_TX_CAP {
                Decision::Blocked(Error::PerTxCapExceeded)
            } else if *amount > WINDOW_CAP {
                Decision::Blocked(Error::WindowCapExceeded)
            } else {
                Decision::Allowed
            }
        }
    };

    assert_eq!(
        verdict, &expected,
        "parsed call {parsed:?} resolved to unexpected verdict {verdict:?}"
    );
    if matches!(verdict, Decision::Blocked(_)) {
        assert_eq!(
            ledger.total, 0,
            "blocked invocation must never mutate rolling window state"
        );
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() > MAX_INPUT_BYTES {
        return;
    }
    let env = Env::default();
    let self_addr = addr(&env, 200);
    let asset = addr(&env, 1);
    let allowed_recipient = addr(&env, 2);
    let protocol = addr(&env, 3);
    let policy = PolicyConfig {
        per_tx_cap: PER_TX_CAP,
        window_secs: 60,
        window_cap: WINDOW_CAP,
        assets: vec![&env, asset.clone()],
        protocols: vec![
            &env,
            ProtocolRule {
                contract: protocol.clone(),
                fns: Some(vec![&env, Symbol::new(&env, "swap")]),
                paused: false,
            },
        ],
        recipients: vec![&env, allowed_recipient.clone()],
        recipient_window_caps: Vec::new(&env),
        blocked_recipients: Vec::new(&env),
        asset_caps: Vec::new(&env),
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };

    // Exercise raw symbol decoding directly on the entire input slice without panicking.
    let _ = try_decode_symbol_from_bytes(&env, input);

    let mut cursor = Cursor::new(input);
    let ctx = build_context(
        &env,
        &self_addr,
        &asset,
        &protocol,
        &allowed_recipient,
        &mut cursor,
    );
    check_invariants(&env, &self_addr, &policy, &allowed_recipient, &ctx);
});
