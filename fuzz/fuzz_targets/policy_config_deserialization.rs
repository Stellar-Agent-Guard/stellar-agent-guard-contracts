#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::Env;
use stellar_agent_guard_contracts::{testutils::validate_policy_config_scval, Error, PolicyEngine};
use stellar_xdr::{Limits, ReadXdr, ScVal};

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_XDR_DEPTH: u32 = 64;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    // Decode through stellar-xdr directly so invalid bytes are a normal
    // rejection. Bound recursion and allocation by the fuzzer input.
    let limits = Limits {
        depth: MAX_XDR_DEPTH,
        len: data.len(),
    };
    let Ok(scval) = ScVal::from_xdr(data, limits) else {
        return;
    };

    // NOTE: a panic here is *not* recoverable, so this target must not rely on
    // `catch_unwind`. libfuzzer-sys installs a panic hook that abort()s before
    // unwinding (so libFuzzer can symbolize the stack), which makes any
    // in-target panic handler dead code — a `ConversionError` panic inside
    // `Vec::get` would kill the process all the same. Preventing those panics
    // is `validate_policy_config_scval`'s job: its ScVal shape guard pins the
    // element type of every lazily-converted vector before the SDK builds a
    // `PolicyConfig`, so a malformed element is a normal `InvalidConfig`
    // rejection instead of an abort. Keep this target panic-free by keeping
    // that guard exhaustive; see `scval_vec_is_addresses`.
    let env = Env::default();
    let contract_id = env.register_contract(None, PolicyEngine);
    let result = env.as_contract(&contract_id, || validate_policy_config_scval(&env, &scval));
    assert!(
        matches!(result, Ok(()) | Err(Error::InvalidConfig)),
        "policy decoding and validation returned an unstable error: {result:?}"
    );
});
