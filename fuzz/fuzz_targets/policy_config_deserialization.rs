#![no_main]

use libfuzzer_sys::fuzz_target;
use soroban_sdk::Env;
use stellar_agent_guard_contracts::{testutils::validate_policy_config_scval, Error, PolicyEngine};
use stellar_xdr::{Limits, ReadXdr, ScVal};

const MAX_INPUT_BYTES: usize = 4_096;
const MAX_XDR_DEPTH: u32 = 64;
fn panic_is_conversion_error(payload: &(dyn std::any::Any + Send)) -> bool {
    payload
        .downcast_ref::<String>()
        .is_some_and(|message| message.contains("ConversionError"))
        || payload
            .downcast_ref::<&str>()
            .is_some_and(|message| message.contains("ConversionError"))
}

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

    let env = Env::default();
    let contract_id = env.register_contract(None, PolicyEngine);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        env.as_contract(&contract_id, || validate_policy_config_scval(&env, &scval))
    }));
    let result = match result {
        Ok(result) => result,
        Err(payload) if panic_is_conversion_error(payload.as_ref()) => Err(Error::InvalidConfig),
        Err(payload) => std::panic::resume_unwind(payload),
    };
    assert!(
        matches!(result, Ok(()) | Err(Error::InvalidConfig)),
        "policy decoding and validation returned an unstable error: {result:?}"
    );
});
