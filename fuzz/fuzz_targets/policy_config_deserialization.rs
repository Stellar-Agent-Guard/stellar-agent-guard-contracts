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

    let env = Env::default();
    let contract_id = env.register_contract(None, PolicyEngine);
    let result = env.as_contract(&contract_id, || validate_policy_config_scval(&env, &scval));

    assert!(
        matches!(result, Ok(()) | Err(Error::InvalidConfig)),
        "policy decoding and validation returned an unstable error: {result:?}"
    );
});
