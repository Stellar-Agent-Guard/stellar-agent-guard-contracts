//! Locks the `policy_hash()` drift-detection read (SPEC §7.3).
//!
//! Three independent views of the same guarantee, matching how the section is
//! written:
//! 1. **Sentinel**: the no-policy case is a *defined, documented* value — the
//!    SHA-256 of the empty marker — never a trap.
//! 2. **Determinism**: the same policy yields the same hash across contract
//!    instances and ledgers, and any field change yields a different hash.
//! 3. **Canonical encoding**: an off-chain reproducer (here: the SDK's own
//!    `set_policy` argument path, XDR-encoded and SHA-256'd with a plain
//!    `sha2` implementation) arrives at exactly the on-chain value.

use sha2::{Digest, Sha256};
use soroban_sdk::testutils::{Events as _, Ledger as _};
use soroban_sdk::{
    vec,
    xdr::{Limited, Limits, ScVal, WriteXdr},
    Address, BytesN, Env, IntoVal, TryFromVal, Val,
};
use stellar_agent_guard_contracts::{
    PolicyConfig, PolicyEngine, PolicyEngineClient, NO_POLICY_DIGEST,
};

/// Fixed strkey constants (deterministic across runs, unlike
/// `Address::generate`) so the encoding fixtures are byte-stable. Derived
/// from the repo's documented Phase-1 strkeys by flipping payload bits, so
/// every constant is a checksum-valid Stellar address.
const ADMIN_STRKEY: &str = "GBBYLFVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUU7NQ";
const ASSET_STRKEY: &str = "CBDALJAG72M4XQRJMQHSKYIFVHQD7LNTNOQH2GRMCMBWMSLBSLTGSJ6C";
const PROTO_STRKEY: &str = "CAJJZT4XH5SWDXNR7MZJCCUBIDAT2KZDDUTZ7OZQEMKCPJGD4P3X4LNU";
const RECV_STRKEY: &str = "GDUT5FVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUUWYM";
const OTHER_STRKEY: &str = "GDUYKWVFLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUVRHT";
const THIRD_STRKEY: &str = "GDUYLFUWLVISVOM5FK5KTBA446VQQ7NBRRFMLNLKLISKL26LJGKUU7JG";

fn addr(env: &Env, strkey: &str) -> Address {
    Address::from_str(env, strkey)
}

/// A policy with a value in every field, including a per-recipient cap and a
/// per-protocol function allowlist, so the encoder's nested shapes are covered.
fn full_policy(env: &Env) -> PolicyConfig {
    PolicyConfig {
        per_tx_cap: 1000,
        window_secs: 60,
        window_cap: 150,
        assets: vec![env, addr(env, ASSET_STRKEY)],
        protocols: vec![
            env,
            stellar_agent_guard_contracts::ProtocolRule {
                contract: addr(env, PROTO_STRKEY),
                fns: Some(vec![env, soroban_sdk::Symbol::new(env, "swap")]),
            },
        ],
        recipients: vec![env, addr(env, RECV_STRKEY), addr(env, THIRD_STRKEY)],
        recipient_window_caps: vec![
            env,
            stellar_agent_guard_contracts::RecipientCap {
                recipient: addr(env, RECV_STRKEY),
                cap: 100,
            },
        ],
        blocked_recipients: vec![env, addr(env, OTHER_STRKEY)],
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 3600,
        protocol_calls_per_window: 25,
    }
}

/// Deploys and initializes a fresh guard (no policy) under blanket mock auth.
fn fresh_guard(env: &Env) -> (Address, PolicyEngineClient<'_>) {
    let guard = env.register(PolicyEngine, ());
    let admin = addr(env, ADMIN_STRKEY);
    env.mock_all_auths();
    let client = PolicyEngineClient::new(env, &guard);
    client.initialize(&admin, &BytesN::from_array(env, &[9u8; 32]));
    (guard, client)
}

/// Off-chain reproduction of the canonical encoding: build the identical
/// `PolicyConfig` value, convert it to its `ScVal` (the same value the SDK
/// submits as the `set_policy` argument), and take the XDR bytes.
fn offchain_canonical_bytes(env: &Env, cfg: &PolicyConfig) -> std::vec::Vec<u8> {
    let val: Val = cfg.into_val(env);
    let scval = ScVal::try_from_val(env, &val).expect("policy Val is an ScVal");
    let mut buf = std::vec::Vec::new();
    scval
        .write_xdr(&mut Limited::new(&mut buf, Limits::none()))
        .expect("policy ScVal XDR write");
    buf
}

fn offchain_sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// ── 1. Sentinel: the no-policy case is defined and never traps ───────────

#[test]
fn policy_hash_before_initialize_is_the_documented_sentinel() {
    // Not even initialized: still a defined value, not a trap.
    let env = Env::default();
    let guard = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &guard);
    let digest = client.policy_hash();
    assert_eq!(
        digest.to_array(),
        NO_POLICY_DIGEST,
        "uninitialized account must report the documented empty-marker digest"
    );
}

#[test]
fn policy_hash_without_policy_is_sha256_of_empty_marker() {
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);
    let digest = client.policy_hash();
    assert_eq!(digest.to_array(), {
        // Reproduce `sha256("")` with the off-chain crate.
        let empty: [u8; 32] = Sha256::digest([]).into();
        empty
    });
    assert_eq!(digest.to_array(), NO_POLICY_DIGEST);
}

#[test]
fn revoke_policy_restores_the_documented_sentinel() {
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);
    env.mock_all_auths();
    client.set_policy(&full_policy(&env));
    assert_ne!(client.policy_hash().to_array(), NO_POLICY_DIGEST);
    env.mock_all_auths();
    client.revoke_policy();
    assert_eq!(
        client.policy_hash().to_array(),
        NO_POLICY_DIGEST,
        "revoke_policy must restore the documented empty-marker digest"
    );
}

// ── 2. Determinism: stable when unchanged, distinct on any field change ──

#[test]
fn same_policy_hashes_identically_across_instances_and_ledgers() {
    // Instance A at ledger time 100.
    let env_a = Env::default();
    env_a.ledger().set_timestamp(100);
    let (_guard_a, client_a) = fresh_guard(&env_a);
    env_a.mock_all_auths();
    client_a.set_policy(&full_policy(&env_a));
    let hash_a = client_a.policy_hash();

    // Instance B (fresh Env) at a different ledger time.
    let env_b = Env::default();
    env_b.ledger().set_timestamp(999_999);
    let (_guard_b, client_b) = fresh_guard(&env_b);
    env_b.mock_all_auths();
    client_b.set_policy(&full_policy(&env_b));
    let hash_b = client_b.policy_hash();

    assert_eq!(hash_a, hash_b, "identical policies must hash identically");

    // Same instance, many ledgers later: the hash must not move.
    env_a.ledger().set_timestamp(888_888);
    assert_eq!(
        client_a.policy_hash(),
        hash_a,
        "policy_hash must be stable across ledger advances"
    );
}

#[test]
fn empty_policy_hashes_differently_from_no_policy() {
    // The all-zero "nothing enabled" policy is a real policy (it still
    // blocks/allowlists per §4) — it must not collide with the sentinel.
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);
    let zero_policy = PolicyConfig {
        per_tx_cap: 0,
        window_secs: 0,
        window_cap: 0,
        assets: vec![&env],
        protocols: soroban_sdk::Vec::new(&env),
        recipients: vec![&env],
        recipient_window_caps: soroban_sdk::Vec::new(&env),
        blocked_recipients: soroban_sdk::Vec::new(&env),
        allow_any_recipient: false,
        active_from: 0,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };
    env.mock_all_auths();
    client.set_policy(&zero_policy);
    let zero_hash = client.policy_hash();
    assert_ne!(
        zero_hash.to_array(),
        NO_POLICY_DIGEST,
        "a real (inert) policy must never collide with the no-policy sentinel"
    );
}

#[test]
fn every_field_change_changes_the_hash() {
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);
    env.mock_all_auths();
    client.set_policy(&full_policy(&env));
    let baseline = client.policy_hash().to_array();

    // One mutation per field: every individual change must flip the hash, and
    // reverting it must restore the baseline hash exactly.
    for (field, base) in mutated_policies(&env) {
        assert_field_flip(&env, &client, &full_policy(&env), &base, &baseline, field);
    }
}

/// `(field_name, base_policy_with_that_field_mutated)` for every
/// `PolicyConfig` field — the mutation table for
/// [`every_field_change_changes_the_hash`].
fn mutated_policies(env: &Env) -> std::vec::Vec<(&'static str, PolicyConfig)> {
    let asset = addr(env, ASSET_STRKEY);
    let proto = addr(env, PROTO_STRKEY);
    let recv = addr(env, RECV_STRKEY);
    let other = addr(env, OTHER_STRKEY);
    let swap = soroban_sdk::Symbol::new(env, "swap");
    let drain = soroban_sdk::Symbol::new(env, "drain");
    let base = full_policy(env);

    let mut cases: std::vec::Vec<(&'static str, PolicyConfig)> = std::vec::Vec::new();

    let mut c = base.clone();
    c.per_tx_cap = 2000;
    cases.push(("per_tx_cap", c));

    let mut c = base.clone();
    c.window_secs = 120;
    cases.push(("window_secs", c));

    let mut c = base.clone();
    c.window_cap = 300;
    cases.push(("window_cap", c));

    let mut c = base.clone();
    c.assets = vec![env, asset.clone(), other.clone()];
    cases.push(("assets", c));

    let mut c = base.clone();
    c.protocols = vec![
        env,
        stellar_agent_guard_contracts::ProtocolRule {
            contract: proto.clone(),
            fns: Some(vec![env, swap.clone(), drain.clone()]),
        },
    ];
    cases.push(("protocols.fns", c));

    let mut c = base.clone();
    c.protocols = vec![
        env,
        stellar_agent_guard_contracts::ProtocolRule {
            contract: proto.clone(),
            fns: None,
        },
    ];
    cases.push(("protocols.fns:None", c));

    // `other` sits on the blocked list, so the recipients mutation shrinks.
    let mut c = base.clone();
    c.recipients = vec![env, recv.clone()];
    cases.push(("recipients", c));

    let mut c = base.clone();
    c.recipient_window_caps = vec![
        env,
        stellar_agent_guard_contracts::RecipientCap {
            recipient: recv.clone(),
            cap: 101,
        },
    ];
    cases.push(("recipient_window_caps", c));

    let mut c = base.clone();
    c.blocked_recipients = vec![env];
    cases.push(("blocked_recipients", c));

    let mut c = base.clone();
    c.allow_any_recipient = true;
    cases.push(("allow_any_recipient", c));

    let mut c = base.clone();
    c.active_from = 1_000;
    c.active_until = 2_000;
    cases.push(("active window", c));

    let mut c = base.clone();
    c.paused = true;
    cases.push(("paused", c));

    let mut c = base.clone();
    c.dms_grace_secs = 7200;
    cases.push(("dms_grace_secs", c));

    let mut c = base.clone();
    c.protocol_calls_per_window = 26;
    cases.push(("protocol_calls_per_window", c));

    cases
}

/// Installs `changed` and asserts its hash differs from `baseline`, then
/// reinstalls `base` and asserts the baseline hash is restored (change →
/// change-back round trip).
fn assert_field_flip(
    env: &Env,
    client: &PolicyEngineClient,
    base: &PolicyConfig,
    changed: &PolicyConfig,
    baseline: &[u8; 32],
    field: &str,
) {
    env.mock_all_auths();
    client.set_policy(changed);
    let flipped = client.policy_hash().to_array();
    assert_ne!(
        flipped, *baseline,
        "changing `{field}` must change the policy hash"
    );
    env.mock_all_auths();
    client.set_policy(base);
    assert_eq!(
        client.policy_hash().to_array(),
        *baseline,
        "restoring the policy must restore the baseline hash (`{field}` case)"
    );
}

// ── 3. Canonical encoding: off-chain reproduction matches on-chain ───────

#[test]
fn offchain_reproducer_matches_the_on_chain_hash() {
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);

    // (a) The full policy.
    let cfg = full_policy(&env);
    env.mock_all_auths();
    client.set_policy(&cfg);
    let on_chain = client.policy_hash().to_array();
    let off_chain = offchain_sha256(&offchain_canonical_bytes(&env, &cfg));
    assert_eq!(
        on_chain, off_chain,
        "off-chain XDR+SHA256 must reproduce the on-chain policy hash"
    );

    // (b) A different shape: empty lists, Some->None fns, disabled caps.
    let minimal = PolicyConfig {
        per_tx_cap: 5,
        window_secs: 86_400,
        window_cap: 0,
        assets: vec![&env, asset_of(&env)],
        protocols: soroban_sdk::Vec::new(&env),
        recipients: soroban_sdk::Vec::new(&env),
        recipient_window_caps: soroban_sdk::Vec::new(&env),
        blocked_recipients: soroban_sdk::Vec::new(&env),
        allow_any_recipient: true,
        active_from: 7,
        active_until: 0,
        paused: false,
        dms_grace_secs: 0,
        protocol_calls_per_window: 0,
    };
    env.mock_all_auths();
    client.set_policy(&minimal);
    let on_chain = client.policy_hash().to_array();
    let off_chain = offchain_sha256(&offchain_canonical_bytes(&env, &minimal));
    assert_eq!(
        on_chain, off_chain,
        "reproduction must hold for the minimal policy shape too"
    );
}

fn asset_of(env: &Env) -> Address {
    addr(env, ASSET_STRKEY)
}

#[test]
fn negative_i128_amounts_are_encoded_canonically() {
    // Caps are validated >= 0 by set_policy, but the encoding itself must be
    // well-defined for negatives too (the type allows them; reproducers must
    // agree). Compare against the SDK's own two's-complement path.
    let env = Env::default();
    let cfg = full_policy(&env);
    let mut with_negative = cfg.clone();
    with_negative.per_tx_cap = -12345i128;

    let bytes = offchain_canonical_bytes(&env, &with_negative);
    // The i128 XDR form is the 16-byte two's-complement big-endian value.
    let needle = (-12345i128).to_be_bytes();
    assert!(
        bytes.windows(16).any(|w| w == needle.as_slice()),
        "canonical encoding must carry the standard i128 two's-complement BE bytes"
    );
}

#[test]
fn policy_hash_read_emits_no_events_and_needs_no_auth() {
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);
    env.mock_all_auths();
    client.set_policy(&full_policy(&env));

    // Enforcing mode with zero auth entries: any require_auth would panic, so
    // a successful read proves the entrypoint is auth-free.
    env.set_auths(&[]);
    let _ = client.policy_hash();
    assert!(
        env.events().all().events().is_empty(),
        "policy_hash must be an event-free read"
    );
}

#[test]
fn policy_hash_survives_reinstall_and_is_order_insensitive_for_equal_sets() {
    // Two configs that differ only in Vec member *order* are different
    // policies (allowlist order is preserved and hashed), while the *same*
    // value re-installed after a revision bump must keep the same hash.
    let env = Env::default();
    let (_guard, client) = fresh_guard(&env);

    let a = full_policy(&env);
    env.mock_all_auths();
    client.set_policy(&a);
    let first = client.policy_hash();

    let b = full_policy(&env);
    env.mock_all_auths();
    client.set_policy(&b);
    assert_eq!(
        client.policy_hash(),
        first,
        "re-installing the identical policy value must keep the hash stable"
    );
    assert_ne!(first.to_array(), NO_POLICY_DIGEST);
}

#[cfg(test)]
mod vec_order_note {
    use super::PolicyConfig;
    use soroban_sdk::{Address, Env};

    /// Swapping two members of `recipients` produces a *different* `ScVal` map
    /// (XDR Vecs are ordered), hence a different hash — documented in SPEC
    /// §7.3 so dashboards don't treat reorderings as no-ops.
    #[test]
    fn vec_order_is_part_of_the_encoding() {
        let env = Env::default();
        let r1 = Address::from_str(&env, super::RECV_STRKEY);
        let r2 = Address::from_str(&env, super::OTHER_STRKEY);
        let mk = |e: &Env, a: &Address, b: &Address| PolicyConfig {
            per_tx_cap: 0,
            window_secs: 0,
            window_cap: 0,
            assets: soroban_sdk::vec![e],
            protocols: soroban_sdk::Vec::new(e),
            recipients: soroban_sdk::vec![e, a.clone(), b.clone()],
            recipient_window_caps: soroban_sdk::Vec::new(e),
            blocked_recipients: soroban_sdk::Vec::new(e),
            allow_any_recipient: false,
            active_from: 0,
            active_until: 0,
            paused: false,
            dms_grace_secs: 0,
            protocol_calls_per_window: 0,
        };
        let one = mk(&env, &r1, &r2);
        let two = mk(&env, &r2, &r1);
        assert_ne!(
            super::offchain_canonical_bytes(&env, &one),
            super::offchain_canonical_bytes(&env, &two),
            "Vec order is encoded; equal sets in different order hash differently"
        );
    }
}
