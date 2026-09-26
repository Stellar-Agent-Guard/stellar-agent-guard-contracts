//! Snapshot test for `PolicyConfig` Debug output (issue #120).
//!
//! This test ensures the Debug implementation produces deterministic, stable
//! field order. The expected output is the exact string produced by the manual
//! `Debug` impl in `src/types.rs`. If this test fails due to field order
//! changes, the snapshot must be updated deliberately (and the impl comment
//! updated).

use stellar_agent_guard_contracts::types::{PolicyConfig, ProtocolRule};
use soroban_sdk::{Address, BytesN, Symbol, Vec};

#[test]
fn policy_config_debug_snapshot() {
    // Construct a fully-populated PolicyConfig instance with deterministic addresses.
    let env = soroban_sdk::Env::default();

    // Use fixed 32-byte arrays for deterministic addresses
    let asset_a = Address::from_contract_id(&BytesN::from_array(&env, &[1u8; 32]));
    let asset_b = Address::from_contract_id(&BytesN::from_array(&env, &[2u8; 32]));
    let proto_a = Address::from_contract_id(&BytesN::from_array(&env, &[3u8; 32]));
    let proto_b = Address::from_contract_id(&BytesN::from_array(&env, &[4u8; 32]));
    let recip_a = Address::from_contract_id(&BytesN::from_array(&env, &[5u8; 32]));
    let recip_b = Address::from_contract_id(&BytesN::from_array(&env, &[6u8; 32]));

    let config = PolicyConfig {
        per_tx_cap: 1000,
        window_secs: 86_400,
        window_cap: 50_000,
        assets: Vec::from_array(&env, [asset_a.clone(), asset_b]),
        protocols: Vec::from_array(
            &env,
            [
                ProtocolRule {
                    contract: proto_a,
                    fns: Some(Vec::from_array(&env, [Symbol::new(&env, "swap")])),
                },
                ProtocolRule {
                    contract: proto_b,
                    fns: None,
                },
            ],
        ),
        recipients: Vec::from_array(&env, [recip_a, recip_b]),
        allow_any_recipient: false,
        active_from: 1_700_000_000,
        active_until: 1_800_000_000,
        paused: true,
        dms_grace_secs: 3600,
    };

    let debug_output = format!("{:?}", config);

    // Snapshot: exact Debug output with stable field order.
    // This must match the manual Debug impl field order exactly.
    // Field order: per_tx_cap, window_secs, window_cap, assets, protocols,
    // recipients, allow_any_recipient, active_from, active_until, paused, dms_grace_secs
    let expected = r#"PolicyConfig { per_tx_cap: 1000, window_secs: 86400, window_cap: 50000, assets: [Address([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), Address([2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2])], protocols: [ProtocolRule { contract: Address([3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]), fns: Some([Symbol("swap")]) }, ProtocolRule { contract: Address([4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]), fns: None }], recipients: [Address([5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5]), Address([6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6])], allow_any_recipient: false, active_from: 1700000000, active_until: 1800000000, paused: true, dms_grace_secs: 3600 }"#;

    assert_eq!(
        debug_output, expected,
        "PolicyConfig Debug output changed — field order or formatting shifted.\n\
         If intentional, update this snapshot and the Debug impl comment in src/types.rs.\n\
         If accidental, revert the Debug impl to match declaration order."
    );
}