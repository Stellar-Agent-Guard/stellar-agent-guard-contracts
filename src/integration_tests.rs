//! Contract-level integration tests (SPEC §11).
//!
//! These drive the *real host routing*: `require_auth` on the guard contract
//! makes the host invoke `PolicyEngine::__check_auth` with a signature payload
//! computed by the host over the authorized invocation. Each test signs that
//! exact payload with the registered agent's Ed25519 key (replicating the
//! protocol's `HashIdPreimage::SorobanAuthorization` hashing), attaches it as
//! `SorobanCredentials::Address`, and runs the call in **enforcing** auth
//! mode (`Env::set_auths`). A blocked policy decision therefore surfaces as a
//! failed `require_auth`, exactly as it would on-chain.
//!
//! # Mechanics of Host-Routed Testing
//!
//! Writing a host-routed test requires understanding how Soroban routes and
//! verifies authorization for custom accounts:
//!
//! 1. **The Preimage the Host Hashes**:
//!    When a contract (or host function) invokes `from.require_auth()`, the
//!    Soroban host constructs a `HashIdPreimage::SorobanAuthorization`
//!    containing:
//!    - `network_id`: SHA-256 hash of the Stellar network passphrase (e.g.
//!      Testnet vs Mainnet), preventing cross-network signature replay.
//!    - `nonce`: An `i64` sequence number tracked per address, preventing replay
//!      of identical authorizations within the network.
//!    - `signature_expiration_ledger`: A `u32` ledger sequence after which the
//!      authorization entry expires. In the harness, this is set via
//!      `ledger.sequence() + max_ttl`.
//!    - `invocation`: A `SorobanAuthorizedInvocation` specifying the target
//!      contract address, function name, arguments (`VecM<ScVal>`), and any
//!      child `sub_invocations`.
//!
//! 2. **Why the Signature Covers the Preimage**:
//!    The host writes the `HashIdPreimage` to XDR and computes its SHA-256
//!    digest. It then calls the custom account's `__check_auth` method, passing
//!    this 32-byte hash as `signature_payload`. The guard contract uses
//!    `env.crypto().ed25519_verify()` to assert that the provided signature
//!    was signed by the registered agent's Ed25519 public key over that exact
//!    32-byte payload. Only after cryptographic verification passes does the
//!    guard evaluate the policy rules against the invocation contexts.
//!
//! 3. **The Role of the Nonce**:
//!    The nonce ensures replay protection. The host rejects stale, out-of-order,
//!    or reused nonces. In `Harness`, `self.guard_nonce` and `self.admin_nonce`
//!    are monotonically incremented each time an entry is generated via
//!    `guard_entry()` or `admin_entry()`. Reusing an entry or failing to increment
//!    the nonce triggers an immediate host rejection.
//!
//! 4. **Invocation Trees and Sub-invocations**:
//!    `SorobanAuthorizedInvocation` captures the call tree. For direct calls
//!    to the guard (e.g. `heartbeat`), the invocation targets the guard directly
//!    with empty sub-invocations. For Stellar Asset Contract (SAC) transfers,
//!    the invocation targets `MockAsset::transfer(guard, to, amount)`. When
//!    the contract call triggers further contract calls that also require auth,
//!    they must be included in `sub_invocations`. A mismatch between the
//!    invocation tree in the auth entry and what the host observes causes the
//!    host to fail authorization before `__check_auth` is reached.
//!
//! # Env Modes: `mock_all_auths()` vs `set_auths()`
//!
//! This is the single most common source of confusion in the test harness:
//!
//! - **`env.mock_all_auths()` (Blanket Mocking)**:
//!   Bypasses all signature verification and completely skips calling
//!   `__check_auth`. Every `require_auth()` unconditionally succeeds.
//!   *When correct*: Test setup and administrative configuration
//!   (`initialize`, `set_policy`, `revoke_policy`). `Harness::new()` enters
//!   mock mode during setup so tests do not need to hand-craft signatures
//!   just to initialize state.
//!   *The trap*: Testing guarded operations under mock mode is a false positive!
//!   Policy checks will never execute. Never assert that a transfer or policy
//!   block works while `mock_all_auths()` is active.
//!
//! - **`env.set_auths(&[entries])` / `Harness::enforce(entry)` (Enforcing Mode)**:
//!   Flips the `Env` from mocking mode into strict enforcing mode for the
//!   specified authorization entries. The host will look up matching entries,
//!   validate nonces and expiration, and invoke `PolicyEngine::__check_auth`.
//!   *When correct*: All tests asserting that an operation is allowed or
//!   blocked by policy or signature validation.
//!   *The trap*: Once `set_auths` is called, subsequent calls without matching
//!   auth entries will fail. If you need to perform admin ops after entering
//!   enforcing mode, use `Harness::set_policy_enforcing()` (which provides an
//!   admin entry) or call `h.env.mock_all_auths()` to explicitly re-enable mocking.
//!
//! # Available Harness Helpers to Reuse
//!
//! When writing new integration tests, reuse these existing building blocks:
//!
//! | Category | Helper | Purpose |
//! |---|---|---|
//! | **Setup** | `Harness::new()` | Initializes env, registers `MockAdmin`, `MockAsset`, `PolicyEngine`, generates agent keypair, runs `initialize()`. |
//! | | `Harness::base_policy()` | Returns a standard baseline policy with `MockAsset` and allowed recipient `h.recv`. |
//! | | `h.install_policy(&cfg)` | Installs policy in mock mode. |
//! | | `h.set_policy_enforcing(&cfg)` | Updates policy when already in enforcing mode. |
//! | | `Harness::new_enforced_auth()` | Fresh registration under *real* host auth: `initialize` runs with an explicit admin entry and no `mock_all_auths()` call. |
//! | **Invocations** | `h.transfer_invocation(from, to, amount)` | Constructs `SorobanAuthorizedInvocation` for `MockAsset::transfer`. |
//! | | `h.heartbeat_invocation()` | Constructs invocation for `heartbeat()`. |
//! | | `h.invocation(contract, fn, args)` | Low-level invocation builder for arbitrary contracts/methods. |
//! | **Auth Entries** | `h.guard_entry(&root)` | Hashes preimage, signs with agent key, bumps nonce, returns `SorobanAuthorizationEntry`. |
//! | | `h.guard_entry_with(key, &root)` | Signs with an arbitrary key (for testing wrong or rotated keys). |
//! | | `h.admin_entry(&root)` | Builds auth entry for `MockAdmin` (void signature). |
//! | | `h.non_admin_entry(account, &root)` | Builds auth entry for an arbitrary (non-admin) account. |
//! | **Execution** | `h.enforce(entry)` | Calls `env.set_auths(&[entry])`, activating enforcing mode. |
//! | | `h.transfer(to, amount)` | High-level: builds entry, enforces, executes transfer, asserts success. |
//! | | `h.transfer_expect_blocked(to, amount)` | High-level: builds entry, enforces, executes transfer, asserts panic. |
//! | | `h.transfer_blocked_reason(to, amount)` | High-level: executes and returns panic string containing `Error::reason()`. |
//! | | `h.heartbeat()` / `h.heartbeat_expect_blocked()` | High-level heartbeat runners in enforcing mode. |
//! | | `h.unfreeze()` | Admin unfreeze in enforcing mode. |
//!
//! # Minimal Worked Example
//!
//! Adding a new host-routed test using `Harness`:
//!
//! ```rust,ignore
//! #[test]
//! fn test_transfer_above_per_tx_cap_blocked_host_routed() {
//!     // 1. Initialize harness (starts in mock mode for setup)
//!     let mut h = Harness::new();
//!
//!     // 2. Configure policy while still in mock mode
//!     let mut policy = h.base_policy();
//!     policy.per_tx_cap = 100; // max 100 stroops per tx
//!     h.install_policy(&policy);
//!
//!     // 3. Construct the authorized invocation the host will route
//!     let root = h.transfer_invocation(&h.guard, &h.recv, 150);
//!
//!     // 4. Build and sign the auth entry (increments nonce, computes preimage hash, signs with Ed25519)
//!     let entry = h.guard_entry(&root);
//!
//!     // 5. Flip the environment from mocking to enforcing mode with the signed entry
//!     h.enforce(entry);
//!
//!     // 6. Invoke the SAC transfer; host routes through __check_auth, which rejects the cap breach
//!     let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
//!         MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &h.recv, &150);
//!     }));
//!     assert!(res.is_err(), "transfer exceeding per-tx cap must be blocked by host require_auth");
//! }
//! ```
//!
//! Or using the high-level helper `h.transfer_blocked_reason()`:
//!
//! ```rust,ignore
//! #[test]
//! fn test_transfer_above_cap_concise() {
//!     let mut h = Harness::new();
//!     let mut policy = h.base_policy();
//!     policy.per_tx_cap = 100;
//!     h.install_policy(&policy);
//!
//!     let log = h.transfer_blocked_reason(&h.recv, 150);
//!     assert!(log.contains(GuardError::PerTxCapExceeded.reason()));
//! }
//! ```
//!
//! # Declarative Scenarios and the Shared Scenario Matrix
//!
//! For multi-step scenarios or tests mapped to the SPEC §4 decision table,
//! use the `GuardScenario` builder (issue #63):
//!
//! ```rust,ignore
//! GuardScenario::new()
//!     .policy(|p| p.per_tx_cap = 100)
//!     .expect_transfer(&recv, 50)
//!     .expect_block(GuardError::PerTxCapExceeded, &recv, 150);
//! ```
//!
//! Cross-reference `docs/scenario-matrix.md` (the canonical scenario matrix)
//! and `decision-table.json` when adding tests to ensure every decision-table
//! row and call kind is accounted for.
//!
//! # Helper Contracts
//!
//! - `MockAsset` plays a Stellar Asset Contract: `transfer(from, to, amount)`
//!   does `from.require_auth()`, so authorizing a transfer from the guard
//!   routes through the guard's `__check_auth` with the real context shape.
//! - `MockAdmin` is a trivial custom account (`Signature = ()`, always
//!   approves) so admin calls can be enforced in the same env without key
//!   material.
//! - `MockDeployer` exercises host contract creation routing (`CreateContractV2HostFn`).
//!
//! Protocol allowlist coverage (SPEC §6.3): `ProtocolRule.fns` has three
//! states — `None` (any fn on that contract), `Some(list)` with a match, and
//! `Some(list)` without a match. The tests below pin each state plus the
//! unknown-contract denial and the empty-`Some([])` config rejection, and
//! assert that the allowlist check runs *before* any arg inspection (a
//! protocol named like an SAC is still classified as a protocol, not a
//! transfer).

use crate::types::{
    AssetCap, BatchTransfer, CheckResult, DataKey, DmsHealthStatus, Error as GuardError,
    PolicyConfig, PolicyRuleId, ProtocolRule, RecipientCap, ValidationOutcome, WindowState,
};
use crate::{AuthSnapshot, PolicyEngine, PolicyEngineClient};

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _};
use soroban_sdk::xdr::{
    self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limited, Limits,
    ScBytes, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, WriteXdr,
};
use soroban_sdk::{
    contract, contractimpl, vec, Address, BytesN, Env, FromVal, IntoVal, Symbol, Val,
};
use std::format;

/// A `ScVal::Symbol` built from a plain string (event names / map keys).
fn symbol_val(s: &str) -> ScVal {
    ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(s)).unwrap())
}

/// Off-chain reproduction of the contract's key fingerprint (SPEC §9):
/// `sha256(pubkey)[0..8]`, as the `ScVal::Bytes` an event data map carries.
fn fingerprint(pubkey: &[u8; 32]) -> ScVal {
    let digest = Sha256::digest(pubkey);
    ScVal::Bytes(ScBytes::try_from(digest[..8].to_vec()).unwrap())
}

/// `(at, expires_at)` recorded by the most recent `heartbeat` event (SPEC §9).
/// Returns `None` when no heartbeat event has been published yet.
fn last_heartbeat_payload(env: &Env) -> Option<(u64, u64)> {
    let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("event_heartbeat")).unwrap());
    let recorded = env.events().all();
    let found = recorded.events().iter().rfind(
        |e| matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want)),
    )?;
    let xdr::ContractEventBody::V0(v0) = &found.body;
    let xdr::ScVal::Map(Some(map)) = &v0.data else {
        panic!("event_heartbeat data must be a Map");
    };
    let read = |name: &str| -> u64 {
        let key = symbol_val(name);
        let entry = map
            .0
            .iter()
            .find(|e| e.key == key)
            .unwrap_or_else(|| panic!("event_heartbeat data is missing `{name}`"));
        let xdr::ScVal::U64(value) = entry.val else {
            panic!(
                "event_heartbeat `{name}` must be a U64, got {:?}",
                entry.val
            )
        };
        value
    };
    Some((read("at"), read("expires_at")))
}

/// Number of `heartbeat` events published by the last contract invocation.
fn heartbeat_event_count(env: &Env) -> usize {
    let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("event_heartbeat")).unwrap());
    env.events()
        .all()
        .events()
        .iter()
        .filter(|e| {
            matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want))
        })
        .count()
}

// ── Test contracts ───────────────────────────────────────────────────────

#[contract]
pub struct MockAsset;

#[contractimpl]
#[allow(clippy::needless_pass_by_value)] // contract ABI requires owned args
impl MockAsset {
    /// SAC-shaped `transfer`: requires auth from the sender. The guard
    /// contract is the `from`, so this routes through `__check_auth`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        #[allow(deprecated)] // test-only helper; not part of the shipped surface
        env.events()
            .publish((Symbol::new(&env, "transfer_ok"),), (to, amount));
    }
}

/// Admin account contract: approves every authorization it is asked to
/// verify (`Signature = ()`, no key material needed in tests).
#[contract]
pub struct MockAdmin;

#[contractimpl]
#[allow(
    clippy::needless_pass_by_value, // trait ABI requires owned args
    clippy::used_underscore_binding // trait-required params, deliberately unused
)]
impl CustomAccountInterface for MockAdmin {
    type Signature = ();
    type Error = GuardError;

    #[allow(clippy::used_underscore_binding)] // trait-required params, deliberately unused
    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signatures: Self::Signature,
        _auth_contexts: soroban_sdk::Vec<Context>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ── Harness ──────────────────────────────────────────────────────────────

struct Harness {
    env: Env,
    guard: Address,
    admin: Address,
    asset: Address,
    agent: SigningKey,
    recv: Address,
    other: Address,
    guard_nonce: i64,
    admin_nonce: i64,
}

impl Harness {
    fn new() -> Self {
        Self::with_env(Env::default())
    }

    fn with_short_persistent_ttl() -> Self {
        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(2);
        env.ledger().set_max_entry_ttl(10);
        // Exercise the host's max-TTL semantics away from ledger sequence 0.
        env.ledger().set_sequence_number(1_000);
        Self::with_env(env)
    }

    fn with_env(env: Env) -> Self {
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let admin = env.register(MockAdmin, ());
        let asset = env.register(MockAsset, ());
        let guard = env.register(PolicyEngine, ());
        // Recipients/others are arbitrary addresses used only as data.
        let recv = Address::generate(&env);
        let other = Address::generate(&env);

        // soroban-sdk 27 test env defaults to *enforcing* auth: `require_auth`
        // only passes with explicit entries. The default harness intentionally
        // uses blanket mocking for the rest of the suite because the majority of
        // tests care about policy behavior, not the auth bootstrap path; this is
        // the documented exception for the suite, not an accidental omission.
        // A dedicated test can choose explicit `set_auths` entries to verify the
        // real `require_auth` flow when admin/agent semantics matter.
        env.mock_all_auths();
        let client = PolicyEngineClient::new(&env, &guard);
        let pk = agent.verifying_key().to_bytes();
        client.initialize(&admin, &BytesN::from_array(&env, &pk));

        Harness {
            env,
            guard,
            admin,
            asset,
            agent,
            recv,
            other,
            guard_nonce: 1,
            admin_nonce: 1,
        }
    }

    /// Fresh registration under real host auth: initialize and the first policy
    /// set both require explicit admin entries, with no blanket `mock_all_auths`
    /// call in this harness.
    fn new_enforced_auth() -> Self {
        let env = Env::default();
        let agent = SigningKey::from_bytes(&[7u8; 32]);
        let admin = env.register(MockAdmin, ());
        let asset = env.register(MockAsset, ());
        let guard = env.register(PolicyEngine, ());
        let recv = Address::generate(&env);
        let other = Address::generate(&env);

        let mut h = Harness {
            env,
            guard,
            admin,
            asset,
            agent,
            recv,
            other,
            guard_nonce: 1,
            admin_nonce: 1,
        };

        let pk = h.agent.verifying_key().to_bytes();
        let init_root = h.invocation(
            &h.guard,
            "initialize",
            std::vec![
                h.admin.clone().into_val(&h.env),
                BytesN::from_array(&h.env, &pk).into_val(&h.env),
            ],
        );
        let init_entry = {
            let h = &mut h;
            h.admin_entry(&init_root)
        };
        h.env.set_auths(&[init_entry]);
        PolicyEngineClient::new(&h.env, &h.guard)
            .initialize(&h.admin, &BytesN::from_array(&h.env, &pk));

        h
    }

    /// Base policy: asset = `MockAsset`, one allowed recipient, no caps.
    fn base_policy(&self) -> PolicyConfig {
        PolicyConfig {
            per_tx_cap: 0,
            window_secs: 86_400,
            window_cap: 0,
            assets: soroban_sdk::vec![&self.env, self.asset.clone()],
            protocols: soroban_sdk::Vec::new(&self.env),
            recipients: soroban_sdk::vec![&self.env, self.recv.clone()],
            recipient_window_caps: soroban_sdk::Vec::new(&self.env),
            blocked_recipients: soroban_sdk::Vec::new(&self.env),
            allow_any_recipient: false,
            active_from: 0,
            active_until: 0,
            paused: false,
            dms_grace_secs: 0,
            protocol_calls_per_window: 0,
        }
    }

    fn set_time(&self, ts: u64) {
        self.env.ledger().set_timestamp(ts);
    }

    // ── Admin ops (mock mode: before any `set_auths`) ────────────────────
    fn install_policy(&self, cfg: &PolicyConfig) {
        PolicyEngineClient::new(&self.env, &self.guard).set_policy(&cfg.clone());
    }

    fn revoke_policy(&self) {
        PolicyEngineClient::new(&self.env, &self.guard).revoke_policy();
    }

    // ── Auth-entry construction ──────────────────────────────────────────

    fn invocation(
        &self,
        contract: &Address,
        fn_name: &str,
        args: std::vec::Vec<Val>,
    ) -> SorobanAuthorizedInvocation {
        let sc_args: std::vec::Vec<ScVal> = args
            .into_iter()
            .map(|v| xdr::ScVal::from_val(&self.env, &v))
            .collect();
        SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: xdr::ScAddress::from(contract),
                function_name: ScSymbol::try_from(fn_name.as_bytes().to_vec()).unwrap(),
                args: xdr::VecM::try_from(sc_args).unwrap(),
            }),
            sub_invocations: xdr::VecM::default(),
        }
    }

    fn transfer_invocation(
        &self,
        from: &Address,
        to: &Address,
        amount: i128,
    ) -> SorobanAuthorizedInvocation {
        let args = std::vec![
            from.clone().into_val(&self.env),
            to.clone().into_val(&self.env),
            amount.into_val(&self.env),
        ];
        self.invocation(&self.asset, "transfer", args)
    }

    fn heartbeat_invocation(&self) -> SorobanAuthorizedInvocation {
        self.invocation(&self.guard, "heartbeat", std::vec![])
    }

    fn unfreeze_invocation(&self) -> SorobanAuthorizedInvocation {
        self.invocation(&self.guard, "unfreeze", std::vec![])
    }

    fn signature_expiration_ledger(&self) -> u32 {
        self.env
            .ledger()
            .sequence()
            .saturating_add(self.env.storage().max_ttl())
    }

    fn payload(&self, nonce: i64, invocation: &SorobanAuthorizedInvocation) -> [u8; 32] {
        let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: xdr::Hash(self.env.ledger().network_id().to_array()),
            nonce,
            signature_expiration_ledger: self.signature_expiration_ledger(),
            invocation: invocation.clone(),
        });
        let mut buf: std::vec::Vec<u8> = std::vec::Vec::new();
        preimage
            .write_xdr(&mut Limited::new(&mut buf, Limits::none()))
            .unwrap();
        Sha256::digest(&buf).into()
    }

    /// Build an auth entry for the guard signed by the agent's key over the
    /// host-computed signature payload.
    fn guard_entry(&mut self, root: &SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
        let key = self.agent.clone(); // entry builder takes &mut self
        self.guard_entry_with(&key, root)
    }

    /// Build a guard auth entry signed by an arbitrary key — for tests that
    /// must present a rotated-out or never-registered key to the account.
    fn guard_entry_with(
        &mut self,
        key: &SigningKey,
        root: &SorobanAuthorizedInvocation,
    ) -> SorobanAuthorizationEntry {
        let nonce = self.guard_nonce;
        self.guard_nonce += 1;
        let payload = self.payload(nonce, root);
        let sig = key.sign(&payload).to_bytes();
        let signature_expiration_ledger = self.signature_expiration_ledger();
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.guard),
                nonce,
                signature_expiration_ledger,
                signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
            }),
            root_invocation: root.clone(),
        }
    }

    /// Build an auth entry for the (signature-less) admin account.
    fn admin_entry(&mut self, root: &SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
        let nonce = self.admin_nonce;
        self.admin_nonce += 1;
        let signature_expiration_ledger = self.signature_expiration_ledger();
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address: xdr::ScAddress::from(&self.admin),
                nonce,
                signature_expiration_ledger,
                signature: ScVal::Void,
            }),
            root_invocation: root.clone(),
        }
    }

    /// Switch the env into enforcing auth mode with exactly one entry.
    fn enforce(&mut self, entry: SorobanAuthorizationEntry) {
        self.env.set_auths(&[entry]);
    }

    // ── Guarded operations (enforcing) ───────────────────────────────────

    fn transfer(&mut self, to: &Address, amount: i128) {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        MockAssetClient::new(&self.env, &self.asset).transfer(&self.guard, to, &amount);
    }

    fn transfer_expect_blocked(&mut self, to: &Address, amount: i128) {
        let root = self.transfer_invocation(&self.guard, to, amount);
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MockAssetClient::new(&self.env, &self.asset).transfer(&self.guard, to, &amount);
        }));
        assert!(res.is_err(), "expected the transfer to be blocked");
    }

    fn heartbeat(&mut self) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
    }

    fn heartbeat_expect_blocked(&mut self) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry(&root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
        }));
        assert!(res.is_err(), "expected the heartbeat to be blocked");
    }

    fn heartbeat_with(&mut self, key: &SigningKey) {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry_with(key, &root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
    }

    /// Send a heartbeat signed by a specific key and assert the guard blocks
    /// it. Returns the panic payload (the host's `HostError` event log), so
    /// callers can assert which reason blocked it — e.g. a signature failure
    /// vs the DMS `HeartbeatExpired`.
    fn heartbeat_with_expect_blocked(&mut self, key: &SigningKey) -> std::string::String {
        let root = self.heartbeat_invocation();
        let entry = self.guard_entry_with(key, &root);
        self.enforce(entry);
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PolicyEngineClient::new(&self.env, &self.guard).heartbeat();
        }));
        if let Err(payload) = res {
            payload
                .downcast_ref::<std::string::String>()
                .cloned()
                .unwrap_or_default()
        } else {
            panic!("expected the heartbeat to be blocked")
        }
    }

    fn unfreeze(&mut self) {
        let root = self.unfreeze_invocation();
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).unfreeze();
    }

    /// `set_policy` once the harness has entered enforcing auth mode: the
    /// plain `install_policy` relies on mock auth and would be rejected.
    fn set_policy_enforcing(&mut self, cfg: &PolicyConfig) {
        let root = self.invocation(
            &self.guard,
            "set_policy",
            std::vec![cfg.clone().into_val(&self.env)],
        );
        let entry = self.admin_entry(&root);
        self.enforce(entry);
        PolicyEngineClient::new(&self.env, &self.guard).set_policy(cfg);
    }

    fn status(&self) -> crate::types::Status {
        PolicyEngineClient::new(&self.env, &self.guard).status()
    }

    /// Did the guard emit an `auth_checked` event with `result = allowed`?
    /// `#[contractevent]` prepends the event name to the topic list, so the
    /// `result` topic (SPEC §9) is at index 1.
    fn emitted_allowed_auth(&self) -> bool {
        let want = ScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from("allowed")).unwrap());
        self.env
            .events()
            .all()
            .events()
            .iter()
            .any(|e| match &e.body {
                xdr::ContractEventBody::V0(v0) => v0.topics.get(1) == Some(&want),
            })
    }

    /// The `(old, new)` key fingerprints carried by the most recent
    /// `agent_rotated` event (SPEC §9), as raw `ScVal`s. Panics if the event
    /// is absent or malformed.
    fn agent_rotated_fingerprints(&self) -> (ScVal, ScVal) {
        let event_name = symbol_val("event_agent_rotated");
        for event in self.env.events().all().events().iter().rev() {
            let xdr::ContractEventBody::V0(v0) = &event.body;
            if v0.topics.first() != Some(&event_name) {
                continue;
            }
            let ScVal::Map(Some(map)) = &v0.data else {
                panic!("agent_rotated data is not a map");
            };
            let mut old = None;
            let mut new = None;
            for entry in &map.0 {
                if entry.key == symbol_val("old_fingerprint") {
                    old = Some(entry.val.clone());
                } else if entry.key == symbol_val("new_fingerprint") {
                    new = Some(entry.val.clone());
                }
            }
            return (
                old.expect("agent_rotated is missing old_fingerprint"),
                new.expect("agent_rotated is missing new_fingerprint"),
            );
        }
        panic!("no agent_rotated event was emitted");
    }

    /// The address pair carried by the most recent admin-rotation event with
    /// the given name (SPEC §7.2 / §9), as raw `ScVal`s. Panics if the event
    /// is absent or malformed.
    fn admin_rotation_event(&self, event: &str, first: &str, second: &str) -> (ScVal, ScVal) {
        let want = symbol_val(event);
        for e in self.env.events().all().events().iter().rev() {
            let xdr::ContractEventBody::V0(v0) = &e.body;
            if v0.topics.first() != Some(&want) {
                continue;
            }
            let ScVal::Map(Some(map)) = &v0.data else {
                panic!("{event} data is not a map");
            };
            let mut a = None;
            let mut b = None;
            for entry in &map.0 {
                if entry.key == symbol_val(first) {
                    a = Some(entry.val.clone());
                } else if entry.key == symbol_val(second) {
                    b = Some(entry.val.clone());
                }
            }
            return (
                a.unwrap_or_else(|| panic!("{event} is missing {first}")),
                b.unwrap_or_else(|| panic!("{event} is missing {second}")),
            );
        }
        panic!("no {event} event was emitted");
    }

    /// The on-chain `Admin` / `PendingAdmin` slots, read directly from the
    /// guard's instance storage.
    fn stored_admins(&self) -> (Option<Address>, Option<Address>) {
        self.env.as_contract(&self.guard, || {
            let instance = self.env.storage().instance();
            (
                instance.get(&DataKey::Admin),
                instance.get(&DataKey::PendingAdmin),
            )
        })
    }
}

// ── Full lifecycle under real host auth (issue #438) ──────────────────────
//
// The rest of this suite mocks auth on purpose (see the harness header):
// most tests care about policy *behaviour*, not about how the account is
// authorized, and hand-signing every admin call would bury that intent.
//
// The blanket mock hides a whole class of regressions, though: a
// `require_auth` that no longer matches the recorded admin, an auth entry
// built against the wrong invocation tree, a signature over the wrong
// payload. None of them can show up while `mock_all_auths()` short-circuits
// every authorization.
//
// The test below closes that gap for the registration path. It runs the
// whole lifecycle — `initialize`, `set_policy`, and an agent-signed
// transfer — under *real* host auth, with explicit `set_auths` entries and
// no `mock_all_auths()` call anywhere in the flow.

/// A fresh registration must be usable end to end under real host auth: the
/// admin authorizes `initialize` and `set_policy`, the agent authorizes a
/// guarded transfer, and the installed policy decides it.
#[test]
fn full_lifecycle_runs_under_real_host_auth() {
    // 1. Registration under a real admin auth entry.
    let mut h = Harness::new_enforced_auth();
    let (admin, pending) = h.stored_admins();
    assert_eq!(
        admin,
        Some(h.admin.clone()),
        "initialize must store the admin that authorized it"
    );
    assert_eq!(
        pending, None,
        "no admin rotation is pending after initialize"
    );
    assert!(
        !h.status().has_policy,
        "a fresh registration has no policy yet"
    );

    // 2. Policy install under a real admin auth entry.
    let mut p = h.base_policy();
    p.per_tx_cap = 50;
    h.set_policy_enforcing(&p);
    let status = h.status();
    assert!(status.has_policy, "set_policy must install the policy");
    assert_eq!(
        status.policy_revision, 1,
        "the first policy install is revision 1"
    );

    // 3. An agent-signed transfer under the installed policy is allowed.
    let recv = h.recv.clone();
    h.transfer(&recv, 20);
    assert!(
        h.emitted_allowed_auth(),
        "the guarded transfer must be decided by the policy, not mocked away"
    );

    // 4. The same policy blocks an over-cap transfer in the same lifecycle.
    let reason = h.transfer_blocked_reason(&recv, 51);
    assert!(
        reason.contains("per_tx_cap_exceeded"),
        "an over-cap transfer must be blocked with the cap reason, got {reason}"
    );

    // 5. The admin authorization is enforced, not merely present: an entry
    //    belonging to a different account must not be able to set a policy.
    let impostor = h.env.register(MockAdmin, ());
    let root = h.set_policy_invocation(&p);
    let entry = h.non_admin_entry(&impostor, &root);
    h.enforce(entry);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    }));
    assert!(
        res.is_err(),
        "a non-admin entry must not be able to install a policy"
    );
    assert_eq!(
        h.status().policy_revision,
        1,
        "the rejected install must leave the installed policy untouched"
    );
}

// ── GuardScenario: declarative scenario builder (issue #63) ──────────────
//
// Each call maps 1:1 onto a step of the SPEC §11 scenario walkthrough, so a
// scenario reads as one block instead of repeating harness wiring:
//
//   | Builder call                        | SPEC §11 step                                |
//   |-------------------------------------|----------------------------------------------|
//   | `GuardScenario::new()`              | deploy guard + MockAsset, register agent key |
//   | `.at(t)`                            | advance the ledger clock to timestamp `t`     |
//   | `.policy(|p| { .. })`              | install/modify the policy (`set_policy`)     |
//   | `.expect_transfer(&to, amt)`        | signed SAC transfer expected **Allowed**     |
//   | `.expect_block(reason, &to, amt)`   | signed SAC transfer expected **Blocked(reason)** |
//   | `.heartbeat()` / `.heartbeat_blocked()` / `.unfreeze()` | agent/admin ops under enforcing auth |
//
// `expect_block` asserts the *reason*, not just the verdict, by matching the
// host log a blocked `require_auth` produces (the same technique as
// `heartbeat_with_expect_blocked`). Building consumes `self`, so a scenario is
// a single expression.
struct GuardScenario {
    h: Harness,
}

impl GuardScenario {
    fn new() -> Self {
        Self { h: Harness::new() }
    }

    /// Advance the ledger clock to `ts`.
    fn at(self, ts: u64) -> Self {
        self.h.set_time(ts);
        self
    }

    /// Install a policy built from the harness base policy and mutated by `f`.
    fn policy(self, f: impl FnOnce(&mut PolicyConfig)) -> Self {
        let mut p = self.h.base_policy();
        f(&mut p);
        self.h.install_policy(&p);
        self
    }

    /// A signed SAC transfer expected to be **Allowed**.
    fn expect_transfer(mut self, to: &Address, amount: i128) -> Self {
        self.h.transfer(to, amount);
        self
    }

    /// A signed SAC transfer expected to be **Blocked** for `reason`.
    fn expect_block(mut self, reason: GuardError, to: &Address, amount: i128) -> Self {
        let expected = reason.reason();
        let log = self.h.transfer_blocked_reason(to, amount);
        assert!(
            log.contains(expected),
            "expected block reason {expected:?}, but the host log was: {log}"
        );
        self
    }

    /// A signed heartbeat expected to be **Allowed**.
    fn heartbeat(mut self) -> Self {
        self.h.heartbeat();
        self
    }

    /// A signed heartbeat expected to be **Blocked**.
    fn heartbeat_blocked(mut self) -> Self {
        self.h.heartbeat_expect_blocked();
        self
    }

    /// Admin `unfreeze` under enforcing auth (the DMS reversal path, SPEC §5).
    fn unfreeze(mut self) -> Self {
        self.h.unfreeze();
        self
    }

    fn recipient(&self) -> Address {
        self.h.recv.clone()
    }

    fn other(&self) -> Address {
        self.h.other.clone()
    }

    fn status(&self) -> crate::types::Status {
        self.h.status()
    }

    /// Shared env handle, for event assertions that read `env.events()`.
    fn env(&self) -> &Env {
        &self.h.env
    }

    /// Assert the guard emitted an `auth_checked` event with `result = allowed`.
    fn assert_allowed_auth_emitted(&self) -> &Self {
        assert!(
            self.h.emitted_allowed_auth(),
            "expected an allowed auth_checked event"
        );
        self
    }
}

// ── Scenarios ────────────────────────────────────────────────────────────

#[test]
fn lifecycle_initialize_once_then_status() {
    let h = Harness::new();
    // Second initialize must fail even under mock auth.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.initialize(&h.admin, &BytesN::from_array(&h.env, &[9u8; 32]));
    }));
    assert!(res.is_err(), "initialize must be exactly-once");

    let st = client.status();
    assert!(!st.has_policy);
    assert_eq!(st.policy_revision, 0);
    assert!(!st.admin_frozen);
    assert!(!st.heartbeat_expired);
    assert_eq!(st.now, 0);
}

#[test]
fn persistent_read_refreshes_ttl_below_half_life() {
    let h = Harness::with_short_persistent_ttl();
    h.set_time(1_000);
    h.install_policy(&h.base_policy());

    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let initial_sequence = h.env.ledger().sequence();
    h.env.ledger().set_sequence_number(initial_sequence + 6);

    assert!(client.policy().is_some());
    let policy_ttl = h.env.as_contract(&h.guard, || {
        h.env.storage().persistent().get_ttl(&DataKey::Policy)
    });
    assert_eq!(
        policy_ttl, 10,
        "a successful read should restore the TTL to max"
    );
}

#[test]
fn archived_policy_window_and_heartbeat_restore_without_resetting_limits() {
    let mut h = Harness::with_short_persistent_ttl();
    let recv = h.recv.clone();
    let mut policy = h.base_policy();
    policy.window_cap = 100;
    policy.dms_grace_secs = 60;
    h.set_time(1_000);
    h.install_policy(&policy);
    h.set_time(1_010);
    h.transfer(&recv, 80);

    // Let Policy, Window, LastHeartbeat, and AdminFrozen all pass their
    // deliberately short test TTL. Protocol 23+ restores archived persistent
    // entries from the invocation's restore footprint before contract code.
    let expired_sequence = h.env.ledger().sequence() + 11;
    h.env.ledger().set_sequence_number(expired_sequence);

    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(client.policy(), Some(policy));

    // The check does not change spend accounting but succeeds as an invocation,
    // so it commits TTL refreshes. The 80 units in Window must still block 30.
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 30)
    });
    assert_eq!(
        detail.result,
        CheckResult::Blocked(Symbol::new(&h.env, "window_cap_exceeded"))
    );

    let status = client.status();
    assert!(!status.admin_frozen);
    assert_eq!(status.last_heartbeat, 1_000);
    h.set_time(1_100);
    assert!(client.status().heartbeat_expired);

    let ttls = h.env.as_contract(&h.guard, || {
        let persistent = h.env.storage().persistent();
        (
            persistent.get_ttl(&DataKey::Policy),
            persistent.get_ttl(&DataKey::Window),
            persistent.get_ttl(&DataKey::LastHeartbeat),
            persistent.get_ttl(&DataKey::AdminFrozen),
        )
    });
    assert_eq!(ttls, (10, 10, 10, 10));
}

#[test]
fn allowed_transaction_succeeds() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 50);
    assert!(h.emitted_allowed_auth());
    let st = h.status();
    assert!(!st.heartbeat_expired);
}

#[test]
fn detailed_check_reports_exact_headroom_and_effective_caps() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.per_tx_cap = 75;
    policy.window_cap = 100;
    h.install_policy(&policy);
    h.set_time(1_000);
    let recv = h.recv.clone();
    h.transfer(&recv, 40);

    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 10)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
    assert_eq!(detail.remaining_window, Some(60));
    assert_eq!(detail.per_tx_cap, Some(75));
    assert_eq!(detail.effective_per_tx_cap, Some(75));
    assert_eq!(detail.effective_window_cap, Some(100));
}

#[test]
fn detailed_check_reports_none_for_disabled_caps() {
    let h = Harness::new();
    h.install_policy(&h.base_policy());
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), h.recv.clone(), 10)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
    assert_eq!(detail.remaining_window, None);
    assert_eq!(detail.per_tx_cap, None);
    assert_eq!(detail.effective_per_tx_cap, None);
    assert_eq!(detail.effective_window_cap, None);
}

#[test]
fn blocked_detailed_check_reports_headroom_without_writing_window() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.window_cap = 100;
    h.install_policy(&policy);
    h.set_time(1_000);
    let recv = h.recv.clone();
    h.transfer(&recv, 40);

    let first = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 70)
    });
    assert_eq!(
        first.result,
        CheckResult::Blocked(Symbol::new(&h.env, "window_cap_exceeded"))
    );
    assert_eq!(first.remaining_window, Some(60));
    let second = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(second.remaining_window, Some(60));
}

#[test]
fn batch_check_stages_admissions_and_matches_auth_outcome() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.window_cap = 100;
    h.install_policy(&policy);
    h.set_time(1_000);

    let first = BatchTransfer {
        to: h.recv.clone(),
        amount: 60,
    };
    let second = BatchTransfer {
        to: h.recv.clone(),
        amount: 50,
    };
    let batch = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_batch(
            h.env.clone(),
            h.asset.clone(),
            soroban_sdk::vec![&h.env, first.clone(), second.clone()],
        )
    });
    assert_eq!(batch.verdicts.len(), 2);
    assert_eq!(batch.verdicts.get(0), Some(CheckResult::Allowed));
    assert_eq!(
        batch.verdicts.get(1),
        Some(CheckResult::Blocked(Symbol::new(
            &h.env,
            "window_cap_exceeded",
        )))
    );
    assert!(!batch.admissible);

    h.transfer(&h.recv.clone(), first.amount);
    let second_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        h.transfer(&h.recv.clone(), second.amount);
    }));
    assert!(
        second_result.is_err(),
        "the same staged window must reject the second transfer"
    );
}

#[test]
fn policy_revision_increments_across_set_and_revoke() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // 0 pre-first-set
    let mut st = client.status();
    assert_eq!(st.policy_revision, 0);

    // 1 after set
    h.env.mock_all_auths();
    client.set_policy(&h.base_policy());
    st = client.status();
    assert_eq!(st.policy_revision, 1);

    // 2 after revoke
    h.env.mock_all_auths();
    client.revoke_policy();
    st = client.status();
    assert_eq!(st.policy_revision, 2);

    // 3 after second set
    h.env.mock_all_auths();
    client.set_policy(&h.base_policy());
    st = client.status();
    assert_eq!(st.policy_revision, 3);
}

#[test]
fn no_policy_is_default_deny_on_chain() {
    let mut h = Harness::new();
    // initialize only — no policy ever installed.
    let recv = h.recv.clone();
    h.set_time(1_000);
    h.transfer_expect_blocked(&recv, 10);
}

#[test]
fn per_tx_cap_violation_blocked_without_window_effect() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 50;
    p.window_cap = 100; // also watch the window: blocked txs must not spend it
    h.install_policy(&p);
    h.set_time(1_000);

    h.transfer(&recv, 20); // ok: window total 20
    h.transfer_expect_blocked(&recv, 60); // per-tx cap (60 > 50); window must stay 20
    h.transfer(&recv, 30); // ok: total 50 — would fail if the blocked 60 had hit the window (110 > 100)
    h.transfer(&recv, 50); // ok: total exactly 100
    h.transfer_expect_blocked(&recv, 1); // window ledger is genuinely full: proves the 60 never counted
}

/// SPEC §6.2 rule 3: `per_tx_cap` comparison is exclusive-of-blocking (inclusive cap):
/// a transfer with `amount == per_tx_cap` is admitted; `amount == per_tx_cap + 1` is
/// blocked with `per_tx_cap_exceeded`.
#[test]
fn per_tx_cap_boundary_admitted_at_cap_and_blocked_at_cap_plus_one() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 50;
    // Generous window cap so only the per-tx cap is exercised.
    p.window_cap = 1_000;
    h.install_policy(&p);
    h.set_time(1_000);

    // amount == per_tx_cap (50): admitted.
    h.transfer(&recv, 50);

    // amount == per_tx_cap + 1 (51): blocked with per_tx_cap_exceeded.
    let reason = h.transfer_blocked_reason(&recv, 51);
    assert!(
        reason.contains("per_tx_cap_exceeded"),
        "expected per_tx_cap_exceeded for amount == per_tx_cap + 1, got: {reason}"
    );

    // Preflight simulation check() also agrees on the boundary.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(client.check(&h.asset, &recv, &50), CheckResult::Allowed);
    assert_eq!(
        client.check(&h.asset, &recv, &51),
        CheckResult::Blocked(Symbol::new(&h.env, "per_tx_cap_exceeded"))
    );
}

#[test]
fn rolling_window_cap_blocks_and_recovers_after_expiry() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 100;
    p.window_cap = 50;
    h.install_policy(&p);

    h.set_time(0);
    h.transfer(&recv, 30); // ok
    h.set_time(50);
    h.transfer_expect_blocked(&recv, 30); // 60 > 50 within a 100s span
    h.set_time(150); // first spend (ts 0) has expired: 150-100 = 50 >= 0
    h.transfer(&recv, 30); // ok again -> window is genuinely rolling
}

#[test]
fn disabled_window_cap_writes_no_window_entries() {
    // Issue #20: `window_cap = 0` disables the rolling window, so a caps-only
    // policy (per_tx_cap set, window off) must not accrue spend rows —
    // otherwise every allowed transfer would grow persistent storage forever.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 100; // caps-only policy
    p.window_cap = 0; // window disabled
    h.install_policy(&p);
    h.set_time(1_000);

    for _ in 0..5 {
        h.transfer(&recv, 10); // N allowed transfers
    }

    let window = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    // The ledger is either absent or entirely empty: no global rows, no cached
    // total, and no per-recipient ledgers left behind.
    if let Some(w) = window {
        assert_eq!(w.total, 0);
        assert!(w.entries.is_empty(), "window disabled: no spend rows");
        assert!(w.recipients.is_empty());
    }
}

#[test]
fn enabled_window_cap_accrues_with_per_tx_cap_disabled() {
    // Issue #20, converse: with `per_tx_cap = 0` the rolling window still
    // accrues and enforces.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.per_tx_cap = 0; // per-tx cap disabled
    p.window_secs = 60;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);

    h.transfer(&recv, 40);
    h.transfer(&recv, 30); // same second -> coalesces into a single entry

    let window = h
        .env
        .as_contract(&h.guard, || {
            h.env
                .storage()
                .persistent()
                .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
        })
        .expect("an enabled window must persist its ledger");
    assert_eq!(window.total, 70);
    assert_eq!(window.entries.len(), 1);

    h.transfer_expect_blocked(&recv, 31); // 70 + 31 = 101 > 100
}

#[test]
fn recipient_allowlist_blocked() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    h.install_policy(&h.base_policy()); // only h.recv allowed
    h.set_time(1_000);
    h.transfer_expect_blocked(&other, 5);
    h.transfer(&recv, 5); // allowlisted recipient still fine
}

#[test]
fn blocked_recipient_wins_over_escape_hatch() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    // With the escape hatch on, any recipient would be allowed — except the
    // explicit denylist. `other` is neither allowed nor in the blocklist by
    // default, so it would pass under `allow_any_recipient`.
    p.allow_any_recipient = true;
    p.blocked_recipients = soroban_sdk::vec![&h.env, other.clone()];
    h.install_policy(&p);
    h.set_time(1_000);

    // Denylist beats the escape hatch.
    h.transfer_expect_blocked(&other, 5);
    // Non-blocked recipients still pass through the escape hatch.
    h.transfer(&recv, 5);
}

#[test]
fn blocked_recipients_contradiction_rejected_at_set_policy() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.recv.clone(), h.other.clone()];
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.other.clone()];

    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(&p);
    }));
    assert!(
        res.is_err(),
        "contradictory recipient config must be rejected"
    );
}

#[test]
fn allow_any_recipient_escape_hatch_still_capped() {
    let mut h = Harness::new();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.allow_any_recipient = true;
    p.per_tx_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&other, 5); // non-allowlisted recipient passes
    h.transfer_expect_blocked(&other, 101); // but the cap still binds
}

#[test]
fn dead_man_switch_freeze_and_admin_reversal() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    // Install at a realistic (non-zero) ledger time: `set_policy` starts the
    // DMS clock at install time, and the `LastHeartbeat != 0` sentinel (SPEC
    // §4 rule 2) is only meaningful off the epoch — ledger ts 0 would collide
    // with "never heartbeated".
    h.set_time(1_000_000);
    h.install_policy(&p); // LastHeartbeat = 1_000_000

    // Within grace: fine.
    h.set_time(1_000_010);
    h.transfer(&recv, 5);

    // Grace (60s) elapsed: transfers and even heartbeats are blocked.
    h.set_time(1_000_100);
    h.transfer_expect_blocked(&recv, 5);
    h.heartbeat_expect_blocked(); // silence cannot self-revive (SPEC §5)

    // Admin unfreeze is the reversal path (SPEC §5). The DMS grace had
    // elapsed, so the admin's signature re-arms the liveness clock — the
    // event must carry `rearmed_dms: true` to make that side effect
    // auditable (SPEC §5 recorded decision).
    h.unfreeze(); // sets LastHeartbeat = now (1_000_100)
    assert_unfrozen_event_rearmed(&h.env, true);
    h.heartbeat(); // a subsequently-heartbeating agent keeps it alive
    h.transfer(&recv, 5); // revived
}

/// Reads the most recent `event_unfrozen` data map and asserts the value of
/// its `rearmed_dms` field (SPEC §5 / §9).
fn assert_unfrozen_event_rearmed(env: &Env, expected: bool) {
    let want = symbol_val("event_unfrozen");
    let all = env.events().all();
    let events = all.events();
    let event = events
        .iter()
        .rfind(|e| {
            matches!(&e.body, xdr::ContractEventBody::V0(v0) if v0.topics.first() == Some(&want))
        })
        .expect("event_unfrozen not found");
    let xdr::ContractEventBody::V0(v0) = &event.body;
    let ScVal::Map(Some(map)) = &v0.data else {
        panic!("event_unfrozen data must be a Map");
    };
    let entry = map
        .0
        .iter()
        .find(|entry| entry.key == symbol_val("rearmed_dms"))
        .expect("event_unfrozen must carry rearmed_dms");
    let rearmed = match &entry.val {
        ScVal::Bool(b) => *b,
        _ => panic!("event_unfrozen rearmed_dms must be a Bool"),
    };
    assert_eq!(
        rearmed, expected,
        "event_unfrozen rearmed_dms mismatch (LastHeartbeat side effect)"
    );
}

/// The admin brake cycle while the agent is live: a fresh heartbeat, then
/// `freeze` + `unfreeze` in the same ledger second. `LastHeartbeat` already
/// equals `now` at unfreeze time, so the event must carry `rearmed_dms:
/// false` — the flag distinguishes the two jobs `unfreeze` performs (SPEC §5).
#[test]
fn unfreeze_while_dms_fresh_emits_rearmed_dms_false() {
    let mut h = Harness::new();
    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    h.set_time(1_000_000);
    h.install_policy(&p); // LastHeartbeat = 1_000_000
    h.set_time(1_000_010);
    h.heartbeat(); // agent live: LastHeartbeat = 1_000_010, DMS fresh

    // Admin brake cycle in the same second as the heartbeat: unfreeze writes
    // `LastHeartbeat = now` but the value is already `now` — no re-arm.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    h.env.mock_all_auths();
    client.freeze();
    h.unfreeze();
    assert_unfrozen_event_rearmed(&h.env, false);
    assert_eq!(h.status().last_heartbeat, 1_000_010);
}

#[test]
fn admin_freeze_blocks_immediately_and_unfreeze_restores() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 5);

    // freeze() is an admin call; re-enable blanket mocking for it, then
    // re-enforce for the guard flow that follows.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    h.env.mock_all_auths();
    client.freeze();
    let st = h.status();
    assert!(st.admin_frozen);

    // Frozen: even a valid agent-signed transfer is blocked.
    h.transfer_expect_blocked(&recv, 5);
    assert!(h.status().admin_frozen);

    h.env.mock_all_auths();
    client.unfreeze();
    let st = h.status();
    assert!(!st.admin_frozen);
    h.transfer(&recv, 5); // restored
}

#[test]
fn wrong_signature_is_rejected_by_host_crypto() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Build an entry signed by a *different* key than the registered agent.
    let wrong = SigningKey::from_bytes(&[42u8; 32]);
    let root = h.transfer_invocation(&h.guard, &recv, 5);
    let nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let payload = h.payload(nonce, &root);
    let sig = wrong.sign(&payload).to_bytes();
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
        }),
        root_invocation: root,
    };
    h.env.set_auths(&[entry]);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);
    }));
    assert!(
        res.is_err(),
        "a signature by an unregistered key must not authorize"
    );

    // The registered agent still works afterwards.
    h.transfer(&recv, 5);
}

/// SPEC §10.1: a signature captured for tx A binds to A's host-computed
/// payload digest (invocation + nonce + expiry ledger + network) and cannot
/// authorize tx B — even though tx B is policy-admissible on its own, so
/// the only possible cause of rejection is the binding.
#[test]
fn captured_signature_cannot_authorize_different_tx() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Tx A: the transfer the agent actually signed (policy-admissible).
    let root_a = h.transfer_invocation(&h.guard, &recv, 5);
    let nonce_a = h.guard_nonce;
    h.guard_nonce += 1;
    let payload_a = h.payload(nonce_a, &root_a);
    let sig_a = h.agent.sign(&payload_a).to_bytes();

    // Tx B: a different transfer — also admissible, once correctly signed.
    let root_b = h.transfer_invocation(&h.guard, &recv, 10);
    let nonce_b = h.guard_nonce;
    h.guard_nonce += 1;
    let payload_b = h.payload(nonce_b, &root_b);
    assert_ne!(
        payload_a, payload_b,
        "distinct transactions must produce distinct payload digests"
    );

    // Cross-context confusion: tx A's signature presented inside tx B's entry.
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let replay = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: nonce_b,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig_a.to_vec()).unwrap()),
        }),
        root_invocation: root_b,
    };
    h.env.set_auths(&[replay]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &10);
    }));
    let err = res.expect_err("a signature captured for tx A must not authorize tx B");
    let msg = err
        .downcast_ref::<std::string::String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        msg.contains("failed ED25519 verification"),
        "tx B must be rejected at signature verification, not by policy: {msg}"
    );

    // Control 1: the very same sig_a still authorizes tx A — it is valid,
    // just bound to A's payload.
    let honest_a = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: nonce_a,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig_a.to_vec()).unwrap()),
        }),
        root_invocation: root_a,
    };
    h.env.set_auths(&[honest_a]);
    MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);

    // Control 2: tx B's shape passes policy when signed over its own payload —
    // so the rejection above was the signature binding, not the policy.
    h.transfer(&recv, 10);
}

/// SPEC §10.1: `__check_auth` step 1 verifies the signature against the
/// exact payload it is presented — the matching pair approves, the
/// cross-context mismatch traps before any policy evaluation.
#[test]
fn check_auth_binds_signature_to_the_exact_payload() {
    let h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    let root_a = h.transfer_invocation(&h.guard, &recv, 5);
    let root_b = h.transfer_invocation(&h.guard, &recv, 10);
    let payload_a = h.payload(1, &root_a);
    let payload_b = h.payload(2, &root_b);
    assert_ne!(payload_a, payload_b);

    // The agent's signature over tx A's payload only.
    let sig_a = h.agent.sign(&payload_a).to_bytes();
    let signatures = BytesN::from_array(&h.env, &sig_a);
    let contexts = soroban_sdk::vec![
        &h.env,
        Context::Contract(soroban_sdk::auth::ContractContext {
            contract: h.asset.clone(),
            fn_name: Symbol::new(&h.env, "transfer"),
            args: soroban_sdk::vec![
                &h.env,
                h.guard.into_val(&h.env),
                recv.into_val(&h.env),
                5i128.into_val(&h.env),
            ],
        }),
    ];

    let check = |payload: [u8; 32]| {
        let payload = BytesN::from_array(&h.env, &payload);
        h.env.as_contract(&h.guard, || {
            <PolicyEngine as CustomAccountInterface>::__check_auth(
                h.env.clone(),
                unsafe {
                    std::mem::transmute::<BytesN<32>, soroban_sdk::crypto::Hash<32>>(payload)
                },
                signatures.clone(),
                contexts.clone(),
            )
        })
    };

    // Matching pair: sig over payload A presented with payload A → approved.
    assert!(
        check(payload_a).is_ok(),
        "the signature over payload A must verify against payload A"
    );

    // Mismatch: the same signature presented with tx B's payload → trap.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(payload_b)));
    assert!(
        res.is_err(),
        "a signature over payload A must not verify against payload B"
    );
}

/// SPEC §10.1: the agent's signature never satisfies the admin path —
/// `require_auth(Admin)` checks a different address's auth entry, so an
/// agent-signed payload whose root invocation is an admin-only call
/// confers no admin authority.
#[test]
fn agent_signature_does_not_confer_admin_authority() {
    let mut h = Harness::new();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // The agent signs a payload whose root invocation is an admin-only write.
    let root = h.unfreeze_invocation();
    let nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let payload = h.payload(nonce, &root);
    let sig = h.agent.sign(&payload).to_bytes();
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(sig.to_vec()).unwrap()),
        }),
        root_invocation: root,
    };
    h.env.set_auths(&[entry]);

    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).unfreeze();
    }));
    let err = res.expect_err("an agent-signed entry must not satisfy require_auth(Admin)");
    let msg = err
        .downcast_ref::<std::string::String>()
        .cloned()
        .unwrap_or_default();
    assert!(
        msg.contains("Unauthorized function call for address"),
        "the admin path must fail on the admin's missing authentication: {msg}"
    );

    // Control: the admin's own auth entry authorizes the identical call.
    h.unfreeze();
}

#[test]
fn rotate_agent_key_event_carries_old_and_new_fingerprints() {
    let h = Harness::new();
    let old_pk = h.agent.verifying_key().to_bytes();
    let new_pk = SigningKey::from_bytes(&[11u8; 32])
        .verifying_key()
        .to_bytes();

    // First rotation: the `old` fingerprint is the key set at `initialize`.
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    let (old_fp, new_fp) = h.agent_rotated_fingerprints();
    assert_eq!(old_fp, fingerprint(&old_pk));
    assert_eq!(new_fp, fingerprint(&new_pk));
    assert_ne!(old_fp, new_fp, "old and new keys must be distinguishable");
}

#[test]
fn rotated_agent_key_binds() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    // Admin rotates the key before enforcement begins.
    let new_key = SigningKey::from_bytes(&[11u8; 32]);
    let new_pk = new_key.verifying_key().to_bytes();
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    // Old agent key no longer authorizes.
    let old_root = h.transfer_invocation(&h.guard, &recv, 5);
    let old_nonce = h.guard_nonce;
    h.guard_nonce += 1;
    let old_payload = h.payload(old_nonce, &old_root);
    let old_sig = h.agent.sign(&old_payload).to_bytes();
    let signature_expiration_ledger = h.signature_expiration_ledger();
    let old_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: xdr::ScAddress::from(&h.guard),
            nonce: old_nonce,
            signature_expiration_ledger,
            signature: ScVal::Bytes(ScBytes::try_from(old_sig.to_vec()).unwrap()),
        }),
        root_invocation: old_root,
    };
    h.env.set_auths(&[old_entry]);
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &5);
    }));
    assert!(res.is_err(), "rotated-out key must not authorize");

    // Swap the harness agent to the new key and confirm it works.
    h.agent = new_key;
    h.transfer(&recv, 5);
}

#[test]
fn rotate_agent_key_next_heartbeat_validity_spec_5_7() {
    // Edge: the DMS clock keeps counting from heartbeats *signed by the old
    // key* while a rotation lands inside a nearly-expired grace (SPEC §5).
    // Post-rotate, the new key is the only accepted signer (SPEC §7), and the
    // DMS rule #2 still gates the new key's heartbeats: fine within grace,
    // `HeartbeatExpired` once the grace elapses. Unit-level counterpart of the
    // on-chain agent-key-rotation proof (issue #5, SPEC §11 scenario 6).
    let mut h = Harness::new();
    let old = h.agent.clone();
    let new = SigningKey::from_bytes(&[11u8; 32]);

    let mut p = h.base_policy();
    p.dms_grace_secs = 60;
    h.set_time(1_000_000);
    h.install_policy(&p); // `set_policy` starts the DMS clock: LastHeartbeat = 1_000_000

    // Baseline: the current (old) key heartbeats fine while in grace.
    h.set_time(1_000_010);
    h.heartbeat_with(&old);
    assert_eq!(h.status().last_heartbeat, 1_000_010);

    // Admin rotates mid-grace (50s of 60s used, 10s remain). The rotation
    // itself neither resets nor consumes the heartbeat clock (SPEC §7).
    let new_pk = new.verifying_key().to_bytes();
    h.env.mock_all_auths(); // admin call, not the guarded agent flow
    PolicyEngineClient::new(&h.env, &h.guard)
        .rotate_agent_key(&BytesN::from_array(&h.env, &new_pk));

    // 1. Old key is rejected immediately post-rotate. `rotate_agent_key`
    //    stores the new key *first*, so even a validly signed old-key
    //    heartbeat now fails signature verification in `__check_auth` —
    //    and the DMS clock is untouched (still the pre-rotate heartbeat).
    h.set_time(1_000_050);
    let blocked = h.heartbeat_with_expect_blocked(&old);
    assert!(blocked.contains("failed ED25519 verification"));
    assert_eq!(h.status().last_heartbeat, 1_000_010);

    // 2. New key is accepted while grace remains (signature verifies against
    //    the new stored key; 45 of 60s elapsed — rule #2 still passes).
    h.set_time(1_000_055);
    h.heartbeat_with(&new);
    assert_eq!(h.status().last_heartbeat, 1_000_055);

    // 3. Once the grace elapses, the (correctly signed) new-key heartbeat is
    //    blocked — DMS rule #2 fires with `HeartbeatExpired`. This pins that
    //    the DMS is not reset by a valid signature alone; only a heartbeat
    //    admitted by the engine restarts the clock. The host event log records
    //    the emitted `auth_checked` reason (`heartbeat_expired`) even though
    //    the failing frame rolls the event back from the ledger events API.
    h.set_time(1_000_120);
    let blocked = h.heartbeat_with_expect_blocked(&new);
    assert!(blocked.contains("heartbeat_expired"));
    assert_eq!(h.status().last_heartbeat, 1_000_055);
}

#[test]
fn redundant_same_second_heartbeat_is_a_measured_no_op() {
    // No policy/initialize needed: `heartbeat` itself only touches
    // `LastHeartbeat`; the policy gates live in `__check_auth`, which mock auth
    // bypasses. This isolates the storage-write path the optimization targets.
    let env = Env::default();
    env.mock_all_auths();
    let guard = env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&env, &guard);
    env.ledger().set_timestamp(1_000);

    // First heartbeat of the second: a real write + one event.
    client.heartbeat();
    let fresh_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    assert_eq!(
        heartbeat_event_count(&env),
        1,
        "fresh heartbeat writes + emits"
    );

    // Second heartbeat in the same ledger second: skipped entirely.
    client.heartbeat();
    let redundant_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    assert_eq!(
        heartbeat_event_count(&env),
        0,
        "the no-op heartbeat must not emit"
    );

    std::println!(
        "heartbeat cpu instructions: fresh={fresh_cpu} redundant_same_second={redundant_cpu}\
         saved={}",
        fresh_cpu.saturating_sub(redundant_cpu)
    );
    assert!(
        redundant_cpu < fresh_cpu,
        "skipping the redundant write must cost less (fresh={fresh_cpu}, \
         redundant={redundant_cpu})"
    );

    // Behaviour matches a write: `LastHeartbeat` is still `now`.
    let st = client.status();
    assert_eq!(st.last_heartbeat, 1_000);
    assert_eq!(st.now, 1_000);
}

#[test]
fn revoke_policy_is_instant_default_deny() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);
    h.transfer(&recv, 5);
    // The transfer above left the env in enforcing mode; revoke is an admin op
    // under blanket mocking, so re-enable it before the admin call.
    h.env.mock_all_auths();
    h.revoke_policy();
    h.transfer_expect_blocked(&recv, 5);
}

/// SPEC §8: the contract's own address is rejected in **all three** policy
/// lists. An `assets`/`protocols` self-entry is a nonsensical allowlist (the
/// account's self-calls are governed by the fixed §6.1 rule, not policy), and
/// a `recipients` self-entry is a pay-itself no-op loop that almost certainly
/// signals a mis-pasted address — rejected as `InvalidConfig` (fail-closed)
/// rather than admitted as a meaningless allowlist entry.
#[test]
fn self_address_rejected_in_every_list() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Every case must fail `set_policy` with `InvalidConfig` (fail-closed:
    // the previously installed policy, if any, stays unchanged).
    //
    // `set_policy` returns `()` and signals rejection by panicking through
    // `panic_with_error!`, so the SDK generates no `try_set_policy` client
    // method to assert on; `catch_unwind` + `AssertUnwindSafe` is this crate's
    // established way to assert a rejected call (same as
    // `transfer_expect_blocked` / `heartbeat_expect_blocked`). Asserting only
    // "it panicked" would also pass for an unrelated panic, so each case
    // additionally asserts the fail-closed invariant: the rejected policy was
    // never written to storage.
    let expect_invalid = |cfg: &PolicyConfig, list: &str| {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_policy(cfg);
        }));
        assert!(
            res.is_err(),
            "self-address in `{list}` must fail set_policy with InvalidConfig"
        );
        assert!(
            client.policy().is_none(),
            "self-address in `{list}` must leave the policy uninstalled (fail-closed)"
        );
    };

    // assets: the guard itself listed as an SAC token.
    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.guard.clone()];
    expect_invalid(&p, "assets");

    // protocols: the guard itself listed as an allowlisted protocol contract.
    let mut p = h.base_policy();
    let rule = ProtocolRule {
        contract: h.guard.clone(),
        fns: None,
    };
    p.protocols = soroban_sdk::vec![&h.env, rule];
    expect_invalid(&p, "protocols");

    // recipients: the guard transferring to itself — a no-op loop.
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    expect_invalid(&p, "recipients");

    // Sanity: the same env still installs a self-free policy cleanly, proving
    // the rejections above came from the self-address rule and not from an
    // unrelated validation defect in the harness.
    client.set_policy(&h.base_policy());
    assert!(client.policy().is_some());
}

#[test]
fn error_and_block_reason_round_trip() {
    let all_errors = [
        GuardError::Unauthorized,
        GuardError::AlreadyInitialized,
        GuardError::NotInitialized,
        GuardError::InvalidConfig,
        GuardError::InvalidAmount,
        GuardError::AdminFrozen,
        GuardError::HeartbeatExpired,
        GuardError::NoPolicy,
        GuardError::Paused,
        GuardError::OutsideActiveWindow,
        GuardError::AssetNotAllowed,
        GuardError::RecipientNotAllowed,
        GuardError::RecipientBlocked,
        GuardError::PerTxCapExceeded,
        GuardError::WindowCapExceeded,
        GuardError::ProtocolNotAllowed,
        GuardError::FunctionNotAllowed,
        GuardError::UnknownContract,
        GuardError::SelfFunctionNotAllowed,
        GuardError::CreateContractNotAllowed,
    ];

    for err in all_errors {
        let reason = err.to_block_reason();
        let round_tripped = GuardError::from_block_reason(&reason);
        assert_eq!(
            Some(err),
            round_tripped,
            "failed round trip for error {err:?} with symbol {reason:?}"
        );
    }
}

#[test]
fn agent_runtime_lifecycle_simulation_continuous_heartbeat_loop_and_spends() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut policy = h.base_policy();
    policy.window_secs = 100;
    policy.window_cap = 100;
    policy.dms_grace_secs = 50;

    let mut now = 1_000_000u64;
    h.set_time(now);
    h.install_policy(&policy);

    // Span ≥3 window periods and ≥5 heartbeats
    // Window is 100s, so 3 windows = 300s. Let's run for 350s with heartbeats every 40s (total 9 heartbeats).
    for _i in 0..9 {
        h.set_time(now);
        h.heartbeat();

        // Spend some budget within caps (e.g. 20 per heartbeat)
        h.set_time(now + 5);
        h.transfer(&recv, 20);

        now += 40;
    }

    // Verify budget recovery across rolled-out windows: windows have rolled, so we can spend again despite prior cumulative totals.
    h.set_time(now);
    h.heartbeat();
    h.set_time(now + 5);
    h.transfer(&recv, 30);

    // Stop heartbeats and assert freeze at grace expiry
    // Last heartbeat was at roughly now - 40. Grace is 50s. Advancing time by 60s should expire grace.
    now += 60;
    h.set_time(now);
    let st = h.status();
    assert!(
        st.heartbeat_expired,
        "heartbeat should have expired after grace"
    );

    // Assert transfers and heartbeats are frozen
    h.transfer_expect_blocked(&recv, 10);
    h.heartbeat_expect_blocked();

    // Unfreeze
    h.unfreeze();
    let st_after = h.status();
    assert!(!st_after.heartbeat_expired, "guard should be unfreezed");

    // Resume normal ops
    h.set_time(now + 10);
    h.heartbeat();
    h.transfer(&recv, 10);
}

#[test]
fn policy_config_debug_snapshot() {
    let env = Env::default();
    env.mock_all_auths();

    let asset_a = Address::generate(&env);
    let asset_b = Address::generate(&env);
    let proto_a = Address::generate(&env);
    let proto_b = Address::generate(&env);
    let recip_a = Address::generate(&env);
    let recip_b = Address::generate(&env);

    let config = PolicyConfig {
        per_tx_cap: 1000,
        window_secs: 86_400,
        window_cap: 50_000,
        assets: vec![&env, asset_a.clone(), asset_b],
        protocols: vec![
            &env,
            ProtocolRule {
                contract: proto_a,
                fns: Some(vec![&env, Symbol::new(&env, "swap")]),
            },
            ProtocolRule {
                contract: proto_b,
                fns: None,
            },
        ],
        recipients: vec![&env, recip_a.clone(), recip_b],
        recipient_window_caps: vec![
            &env,
            crate::types::RecipientCap {
                recipient: recip_a,
                cap: 10_000,
            },
        ],
        blocked_recipients: vec![&env],
        allow_any_recipient: false,
        active_from: 1_700_000_000,
        active_until: 1_800_000_000,
        paused: true,
        dms_grace_secs: 3600,
        protocol_calls_per_window: 0,
    };

    let debug_output = format!("{config:?}");

    let fields = [
        "per_tx_cap",
        "window_secs",
        "window_cap",
        "assets",
        "protocols",
        "recipients",
        "recipient_window_caps",
        "blocked_recipients",
        "allow_any_recipient",
        "active_from",
        "active_until",
        "paused",
        "dms_grace_secs",
    ];

    let mut last_pos = 0;
    for field in fields {
        let pos = debug_output
            .find(field)
            .unwrap_or_else(|| panic!("field {field} not found in debug output"));
        assert!(
            pos >= last_pos,
            "field {field} appears before previous field (order: {fields:?})"
        );
        last_pos = pos;
    }
}

#[test]
fn batch_events_emit_in_order_with_context_index() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.per_tx_cap = 100;
    p.window_cap = 0;
    p.allow_any_recipient = true;
    h.install_policy(&p);

    let to = Address::generate(&h.env);

    let ctx1 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            50i128.into_val(&h.env),
        ],
    });

    let ctx2 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            200i128.into_val(&h.env),
        ],
    });

    let ctx3 = soroban_sdk::auth::Context::Contract(soroban_sdk::auth::ContractContext {
        contract: h.asset.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args: soroban_sdk::vec![
            &h.env,
            h.guard.into_val(&h.env),
            to.into_val(&h.env),
            10i128.into_val(&h.env),
        ],
    });

    let contexts = soroban_sdk::vec![&h.env, ctx1, ctx2, ctx3];

    let payload_bytes = [0u8; 32];
    let payload = soroban_sdk::BytesN::from_array(&h.env, &payload_bytes);
    let sig = h.agent.sign(&payload_bytes).to_bytes();
    let signatures = soroban_sdk::BytesN::from_array(&h.env, &sig);

    let res = h.env.as_contract(&h.guard, || {
        <PolicyEngine as soroban_sdk::auth::CustomAccountInterface>::__check_auth(
            h.env.clone(),
            unsafe {
                std::mem::transmute::<soroban_sdk::BytesN<32>, soroban_sdk::crypto::Hash<32>>(
                    payload.clone(),
                )
            },
            signatures.clone(),
            contexts.clone(),
        )
    });
    assert!(res.is_err());

    // Verify events
    let want_allowed = soroban_sdk::xdr::ScVal::Symbol(
        soroban_sdk::xdr::ScSymbol::try_from(std::vec::Vec::from("allowed")).unwrap(),
    );
    let want_blocked = soroban_sdk::xdr::ScVal::Symbol(
        soroban_sdk::xdr::ScSymbol::try_from(std::vec::Vec::from("blocked")).unwrap(),
    );

    let mut auth_events = std::vec::Vec::new();
    for e in h.env.events().all().events() {
        let soroban_sdk::xdr::ContractEventBody::V0(v0) = &e.body;
        if v0.topics.len() == 3 {
            let res = v0.topics.get(1).unwrap();
            if res == &want_allowed || res == &want_blocked {
                auth_events.push((v0.topics.clone(), v0.data.clone()));
            }
        }
    }

    assert_eq!(auth_events.len(), 3);

    let build_map = |idx: u32, revision: u64| {
        use soroban_sdk::xdr::{ScMap, ScMapEntry, ScSymbol, ScVal as XdrScVal, VecM};
        let entry = |key: &str, val: XdrScVal| ScMapEntry {
            key: XdrScVal::Symbol(ScSymbol::try_from(std::vec::Vec::from(key)).unwrap()),
            val,
        };
        // `auth_checked` data: {context_index, revision} (issue #38: the
        // policy revision in force at decision time joins the event to the
        // policy generation that produced it).
        XdrScVal::Map(Some(ScMap(
            VecM::try_from(std::vec::Vec::from([
                entry("context_index", XdrScVal::U32(idx)),
                entry("revision", XdrScVal::U64(revision)),
            ]))
            .unwrap(),
        )))
    };

    // The policy was installed once, so every decision in this batch runs
    // under revision 1 (issue #38).
    let revision = 1;

    // ctx1: allowed
    assert_eq!(auth_events[0].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[0].1, build_map(0, revision));

    // ctx2: blocked, PerTxCapExceeded
    assert_eq!(auth_events[1].0.get(1).unwrap(), &want_blocked);
    assert_eq!(auth_events[1].1, build_map(1, revision));

    // ctx3: allowed (even though the batch fails, decide evaluates all contexts and emits for all)
    assert_eq!(auth_events[2].0.get(1).unwrap(), &want_allowed);
    assert_eq!(auth_events[2].1, build_map(2, revision));
}

#[test]
fn per_recipient_window_cap_enforced_on_chain() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, recv.clone(), other.clone()];
    p.window_cap = 1_000; // loose global cap
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 100,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // Within the per-recipient cap.
    h.transfer(&recv, 60);
    // Second transfer to the same recipient exceeds its per-recipient cap.
    h.transfer_expect_blocked(&recv, 50);
    // A different recipient uses the global cap and is still allowed.
    h.transfer(&other, 500);
}

#[test]
fn per_recipient_window_cap_falls_back_to_global() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, recv.clone(), other.clone()];
    p.window_cap = 100;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 1_000,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // `recv` has a generous override but is still bound by the global cap.
    h.transfer(&recv, 60);
    h.transfer_expect_blocked(&recv, 50); // would exceed global 100
                                          // `other` has no override and uses the global cap.
    h.transfer_expect_blocked(&other, 101);
    h.transfer(&other, 30);
}

#[test]
fn per_recipient_window_cap_with_allow_any_recipient() {
    let mut h = Harness::new();
    let other = h.other.clone();
    let mut p = h.base_policy();
    p.allow_any_recipient = true;
    p.window_cap = 1_000;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: other.clone(),
            cap: 50,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);

    // Unlisted recipient with an override cap.
    h.transfer(&other, 30);
    h.transfer_expect_blocked(&other, 25); // exceeds per-recipient 50

    // Another unlisted recipient has no override, so it falls back to global.
    let third = Address::generate(&h.env);
    h.transfer(&third, 500);
}

#[test]
fn invalid_recipient_window_cap_rejected() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: -1,
        },
    ];
    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    }));
    assert!(res.is_err(), "negative per-recipient cap must be rejected");
}

#[test]
fn invalid_duplicate_recipient_window_cap_rejected() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: 100,
        },
        crate::types::RecipientCap {
            recipient: h.recv.clone(),
            cap: 200,
        },
    ];
    h.env.mock_all_auths();
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    }));
    assert!(res.is_err(), "duplicate per-recipient cap must be rejected");
}

#[test]
fn detailed_check_reports_per_recipient_headroom() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 1_000;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 100,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 40);

    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 10)
    });
    assert_eq!(detail.result, crate::types::CheckResult::Allowed);
    assert_eq!(detail.remaining_window, Some(60)); // 100 cap - 40 already admitted
    assert_eq!(detail.effective_window_cap, Some(100));
}

// ── status() operational fields (issue #29) ──────────────────────────────

#[test]
fn status_without_policy_reports_null_operational_fields() {
    let h = Harness::new();
    let st = h.status();
    assert!(!st.has_policy);
    // Default-deny has nothing to pause, no cap to project headroom from, and
    // no active window to sit outside of — all three must be inert.
    assert!(!st.paused);
    assert_eq!(st.window_remaining, None);
    assert!(!st.outside_active_window);
}

#[test]
fn status_reports_paused_flag_from_policy() {
    let h = Harness::new();
    let mut p = h.base_policy();
    h.install_policy(&p);
    assert!(!h.status().paused);

    p.paused = true;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    assert!(h.status().paused);
}

#[test]
fn status_window_remaining_full_partial_and_disabled() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);

    // Full headroom before any spend.
    let st = h.status();
    assert_eq!(st.window_remaining, Some(100));

    // Partially spent window: 40 admitted, headroom drops to 60. This must
    // agree with the `remaining_window` `check_detailed` reports for a
    // recipient without a per-recipient override.
    h.transfer(&recv, 40);
    let st = h.status();
    assert_eq!(st.window_remaining, Some(60));
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(detail.remaining_window, st.window_remaining);

    // Spent to exactly the cap: headroom floors at 0 (never negative).
    h.transfer(&recv, 60);
    let st = h.status();
    assert_eq!(st.window_remaining, Some(0));
    assert_eq!(st.now, h.env.ledger().timestamp());

    // Disabled global cap (window_cap = 0): None, even with a live policy.
    p.window_cap = 0;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    assert_eq!(h.status().window_remaining, None);
}

#[test]
fn status_window_remaining_ignores_expired_entries() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_secs = 100;
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 80);
    assert_eq!(h.status().window_remaining, Some(20));

    // 200s later the whole window has rolled over: headroom must be back to
    // full even though the ledger still *stores* the expired entry, because
    // `status` prunes on read exactly like the decision path.
    h.set_time(1_200);
    assert_eq!(h.status().window_remaining, Some(100));
}

#[test]
fn status_window_remaining_agrees_with_check_detailed_for_recipient_override_too() {
    // A recipient *with* a per-recipient override gets its own tighter ledger;
    // the global `window_remaining` must still track the global cap/total so
    // the two reads can never disagree about the global picture.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 1_000;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        crate::types::RecipientCap {
            recipient: recv.clone(),
            cap: 100,
        },
    ];
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 40);

    assert_eq!(h.status().window_remaining, Some(960));
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    // The recipient-targeted read is tighter — that difference is the point.
    assert_eq!(detail.remaining_window, Some(60));
}

#[test]
fn status_outside_active_window_tracks_bounds() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.active_from = 1_500;
    p.active_until = 1_600;
    h.install_policy(&p);

    // Before the window opens.
    h.set_time(1_499);
    // Inclusive open boundary (now == active_from is inside).
    h.set_time(1_500);
    assert!(!h.status().outside_active_window);
    h.set_time(1_600);
    assert!(!h.status().outside_active_window);
    // Inclusive close boundary (now == active_until is inside), then after.
    h.set_time(1_601);
    assert!(h.status().outside_active_window);

    // Unrestricted windows never read as outside.
    p.active_from = 0;
    p.active_until = 0;
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).set_policy(&p);
    h.set_time(1_700);
    assert!(!h.status().outside_active_window);
}

#[test]
fn status_outside_active_window_matches_check_block_reason() {
    // The flag must agree with the §4 gate: when `check` blocks with
    // `outside_active_window`, `status` must say so — and vice versa.
    let h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.active_from = 1_400;
    p.active_until = 1_500;
    h.install_policy(&p);
    h.set_time(1_000);
    assert!(h.status().outside_active_window);
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(
        detail.result,
        CheckResult::Blocked(Symbol::new(&h.env, "outside_active_window"))
    );

    // Inside the window: flag clears and the same transfer is allowed.
    h.set_time(1_450);
    assert!(!h.status().outside_active_window);
    let detail = h.env.as_contract(&h.guard, || {
        PolicyEngine::check_detailed(h.env.clone(), h.asset.clone(), recv.clone(), 1)
    });
    assert_eq!(detail.result, CheckResult::Allowed);
}

#[test]
fn status_reads_never_write_window_or_emit_events() {
    // `status` is an event-free, write-free read. `env.events().all()` holds
    // only the most recent top-level invocation's events, so a status() call
    // followed by an empty event list proves that invocation emitted nothing.
    // Write-freedom is asserted directly on the persisted window ledger.
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.window_cap = 100;
    h.install_policy(&p);
    h.set_time(1_000);
    h.transfer(&recv, 40);

    let ledger_before = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    for _ in 0..3 {
        assert_eq!(h.status().window_remaining, Some(60));
        assert!(
            h.env.events().all().events().is_empty(),
            "status must not emit (an auth_checked event here is a bug)"
        );
    }
    let ledger_after = h.env.as_contract(&h.guard, || {
        h.env
            .storage()
            .persistent()
            .get::<DataKey, crate::types::WindowState>(&DataKey::Window)
    });
    assert_eq!(
        ledger_after, ledger_before,
        "status must not rewrite the window ledger"
    );

    // And spend accounting was untouched: a further 60 transfer must still fit.
    h.transfer(&recv, 60);
    assert_eq!(h.status().window_remaining, Some(0));
}

// ── heartbeat `expires_at` (SPEC §9) ───────────────────────────────────
// The event records the deadline the heartbeat was attested under, derived
// from the policy current at emission time, so a consumer never has to
// recompute it from `at` with a later policy's grace.

#[test]
fn heartbeat_event_reports_expiry_from_current_grace() {
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.dms_grace_secs = 60;
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();

    let (at, expires_at) = last_heartbeat_payload(&h.env).expect("heartbeat event");
    assert_eq!(at, 1_000, "at is the ledger timestamp at emission");
    assert_eq!(
        expires_at, 1_060,
        "with grace=60 the attested deadline is at + 60"
    );
}

#[test]
fn heartbeat_event_reports_zero_expiry_when_dms_disabled() {
    let mut h = Harness::new();
    // base_policy leaves dms_grace_secs == 0, which is how "DMS disabled" is
    // encoded (engine::dms_health returns Ok without consulting the clock).
    let policy = h.base_policy();
    assert_eq!(policy.dms_grace_secs, 0);
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();

    let (at, expires_at) = last_heartbeat_payload(&h.env).expect("heartbeat event");
    assert_eq!(at, 1_000);
    assert_eq!(
        expires_at, 0,
        "a disabled dead-man switch attests no deadline, so expires_at is 0 (not at + 0)"
    );
}

#[test]
fn heartbeat_event_uses_grace_current_at_emission_not_a_stale_one() {
    // This is the behaviour the issue exists for: a consumer that recomputed
    // expiry as `at + <current policy grace>` gets the wrong answer for every
    // heartbeat emitted before a `set_policy` that changes the grace.
    let mut h = Harness::new();
    let mut policy = h.base_policy();
    policy.dms_grace_secs = 60;
    h.install_policy(&policy);

    h.set_time(1_000);
    h.heartbeat();
    let (first_at, first_expiry) = last_heartbeat_payload(&h.env).expect("first heartbeat event");
    assert_eq!((first_at, first_expiry), (1_000, 1_060));

    // The admin shortens the grace. The already-emitted event must keep the
    // deadline it was attested under.
    let mut tightened = h.base_policy();
    tightened.dms_grace_secs = 30;
    h.set_policy_enforcing(&tightened);

    // A later heartbeat is stamped with the grace in force at *its* emission.
    // Stay inside the tightened 30s window, since a heartbeat past the grace
    // is (correctly) rejected by the DMS gate before any event is published.
    h.set_time(1_010);
    h.heartbeat();
    let (second_at, second_expiry) =
        last_heartbeat_payload(&h.env).expect("second heartbeat event");
    assert_eq!(
        (second_at, second_expiry),
        (1_010, 1_040),
        "a heartbeat must use the grace current at its own emission time"
    );

    // And the earlier event is untouched: a naive `at + current_grace`
    // recomputation would read 1_000 + 30 = 1_030, not the attested 1_060.
    assert_eq!(
        first_expiry, 1_060,
        "the earlier heartbeat keeps the deadline it was attested under"
    );

    // Disabling the switch entirely is the third state: 0 again, distinct from
    // any real timestamp.
    let mut disabled = h.base_policy();
    disabled.dms_grace_secs = 0;
    h.set_policy_enforcing(&disabled);
    h.set_time(1_020);
    h.heartbeat();
    let (third_at, third_expiry) = last_heartbeat_payload(&h.env).expect("third heartbeat event");
    assert_eq!((third_at, third_expiry), (1_020, 0));
}

// ── Issue #35: `validate_policy` per-rule identifiability ─────────────────
//
// SPEC §8 validation rules reject a candidate policy at `set_policy`, but the
// on-chain surface collapses every rejection into the single stable
// `InvalidConfig` code. The `validate_policy` read is the identifiable
// counterpart: it dry-runs the same rules over a *candidate* config and names
// the first failing rule in §8 order, so SDKs and dashboards can preflight a
// policy without paying a rejected on-chain call. Each test pins one rule via
// the dry-run read and re-asserts the on-chain path stays fail-closed for the
// same config (panic + policy never installed).

/// Dry-run names the exact rule, and `set_policy` still rejects fail-closed.
fn assert_rejects_with(h: &Harness, cfg: &PolicyConfig, want: &PolicyRuleId) {
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(
        client.validate_policy(cfg),
        ValidationOutcome::Invalid(want.clone()),
        "validate_policy must identify the failing rule"
    );
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(cfg);
    }));
    assert!(res.is_err(), "set_policy must still reject this config");
    assert!(
        client.policy().is_none(),
        "a rejected config must never be installed (fail-closed)"
    );
}

#[test]
fn validate_policy_reports_amount_sign() {
    let h = Harness::new();

    let mut p = h.base_policy();
    p.per_tx_cap = -1;
    assert_rejects_with(&h, &p, &PolicyRuleId::AmountSign);

    let mut p = h.base_policy();
    p.window_cap = -1;
    assert_rejects_with(&h, &p, &PolicyRuleId::AmountSign);
}

#[test]
fn validate_policy_reports_window_requires_width() {
    let h = Harness::new();

    // Global form: a spend cap with no window to spend within.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.window_cap = 100;
    assert_rejects_with(&h, &p, &PolicyRuleId::WindowRequiresWidth);

    // Per-recipient form: an override cap with no window is the same rule.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 50,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::WindowRequiresWidth);
}

#[test]
fn validate_policy_reports_per_tx_cap_exceeds_window_cap() {
    let h = Harness::new();

    // When both caps are enabled (> 0) and per_tx_cap > window_cap:
    // rejected as PolicyRuleId::PerTxCapExceedsWindowCap in validate_policy
    // and as InvalidConfig in set_policy (fail-closed; issue #33).
    let mut p = h.base_policy();
    p.per_tx_cap = 200;
    p.window_cap = 100;
    assert_rejects_with(&h, &p, &PolicyRuleId::PerTxCapExceedsWindowCap);
}

#[test]
fn validate_policy_accepts_equal_per_tx_and_window_caps() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // When both caps are enabled and equal, the config is valid and installable.
    let mut p = h.base_policy();
    p.per_tx_cap = 100;
    p.window_cap = 100;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    let installed = client.policy().expect("policy installed");
    assert_eq!(installed.per_tx_cap, 100);
    assert_eq!(installed.window_cap, 100);
}

#[test]
fn validate_policy_skips_cap_comparison_when_either_is_zero() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // 1. per_tx_cap > 0, window_cap == 0: per-tx limit only (window cap disabled).
    let mut p = h.base_policy();
    p.per_tx_cap = 500;
    p.window_cap = 0;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    assert_eq!(client.policy().expect("policy installed").per_tx_cap, 500);

    // 2. per_tx_cap == 0, window_cap > 0: window limit only (per-tx cap disabled).
    let mut p = h.base_policy();
    p.per_tx_cap = 0;
    p.window_cap = 500;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    assert_eq!(client.policy().expect("policy installed").window_cap, 500);

    // 3. per_tx_cap == 0, window_cap == 0: both disabled.
    let mut p = h.base_policy();
    p.per_tx_cap = 0;
    p.window_cap = 0;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    assert_eq!(client.policy().expect("policy installed").per_tx_cap, 0);
    assert_eq!(client.policy().expect("policy installed").window_cap, 0);
}

#[test]
fn validate_policy_accepts_per_tx_cap_less_than_window_cap() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Normal configuration: per_tx_cap < window_cap.
    let mut p = h.base_policy();
    p.per_tx_cap = 50;
    p.window_cap = 100;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    let installed = client.policy().expect("policy installed");
    assert_eq!(installed.per_tx_cap, 50);
    assert_eq!(installed.window_cap, 100);
}

#[test]
fn validate_policy_reports_active_window_order() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.active_from = 100;
    p.active_until = 100; // end equal to start is not "after"
    assert_rejects_with(&h, &p, &PolicyRuleId::ActiveWindowOrder);
}

#[test]
fn validate_policy_reports_self_address_in_list() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // assets
    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // protocols
    let mut p = h.base_policy();
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.guard.clone(),
            fns: None,

            paused: false,
        },
    ];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // recipients
    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // recipient_window_caps
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.guard.clone(),
            cap: 10,
        },
    ];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );

    // blocked_recipients
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.guard.clone()];
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::SelfAddressInList)
    );
}

#[test]
fn validate_policy_reports_duplicate_address_in_list() {
    let h = Harness::new();

    let mut p = h.base_policy();
    p.assets = soroban_sdk::vec![&h.env, h.asset.clone(), h.asset.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateAddressInList);

    let mut p = h.base_policy();
    p.recipients = soroban_sdk::vec![&h.env, h.recv.clone(), h.recv.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateAddressInList);
}

#[test]
fn validate_policy_reports_duplicate_recipient_cap() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 10,
        },
        RecipientCap {
            recipient: h.recv.clone(),
            cap: 20,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::DuplicateRecipientCap);
}

#[test]
fn validate_policy_reports_recipient_list_too_long() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Bound is inclusive: exactly the limit is still valid.
    let mut at_limit = soroban_sdk::Vec::new(&h.env);
    for _ in 0..256u32 {
        at_limit.push_back(Address::generate(&h.env));
    }
    let mut p = h.base_policy();
    p.blocked_recipients = at_limit;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);

    // One more exceeds it; the dry run names the list-length rule.
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env];
    for _ in 0..257u32 {
        p.blocked_recipients.push_back(Address::generate(&h.env));
    }
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientListTooLong);
}

#[test]
fn policy_asset_protocol_and_recipient_limits_are_inclusive_and_fail_closed() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    let baseline = h.base_policy();
    client.set_policy(&baseline);

    let mut assets = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_POLICY_ASSETS {
        assets.push_back(Address::generate(&h.env));
    }
    let mut at_limit = baseline.clone();
    at_limit.assets = assets.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    assets.push_back(Address::generate(&h.env));
    let mut over_limit = at_limit.clone();
    over_limit.assets = assets;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::AssetListTooLong,
    );

    let mut protocols = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_POLICY_PROTOCOLS {
        protocols.push_back(ProtocolRule {
            contract: Address::generate(&h.env),
            fns: None,

            paused: false,
        });
    }
    let mut at_limit = baseline.clone();
    at_limit.protocols = protocols.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    protocols.push_back(ProtocolRule {
        contract: Address::generate(&h.env),
        fns: None,

        paused: false,
    });
    let mut over_limit = at_limit.clone();
    over_limit.protocols = protocols;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::ProtocolListTooLong,
    );

    let mut recipients = soroban_sdk::Vec::new(&h.env);
    for _ in 0..crate::types::MAX_RECIPIENT_ENTRIES {
        recipients.push_back(Address::generate(&h.env));
    }
    let mut at_limit = baseline;
    at_limit.recipients = recipients.clone();
    assert_eq!(client.validate_policy(&at_limit), ValidationOutcome::Valid);
    client.set_policy(&at_limit);
    assert_eq!(client.policy(), Some(at_limit.clone()));
    recipients.push_back(Address::generate(&h.env));
    let mut over_limit = at_limit.clone();
    over_limit.recipients = recipients;
    assert_rejects_preserving_policy(
        &h.env,
        &h.guard,
        &over_limit,
        &at_limit,
        &PolicyRuleId::RecipientListTooLong,
    );
}

fn assert_rejects_preserving_policy(
    env: &Env,
    guard: &Address,
    candidate: &PolicyConfig,
    installed: &PolicyConfig,
    rule: &PolicyRuleId,
) {
    let client = PolicyEngineClient::new(env, guard);
    assert_eq!(
        client.validate_policy(candidate),
        ValidationOutcome::Invalid(rule.clone())
    );
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.set_policy(candidate);
    }));
    assert!(
        res.is_err(),
        "over-limit policy must fail with InvalidConfig"
    );
    assert_eq!(client.policy(), Some(installed.clone()));
}

#[test]
fn validate_policy_reports_recipient_cap_sign() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.recipient_window_caps = soroban_sdk::vec![
        &h.env,
        RecipientCap {
            recipient: h.recv.clone(),
            cap: -5,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientCapSign);
}

#[test]
fn validate_policy_reports_recipient_allow_and_blocked() {
    let h = Harness::new();
    let mut p = h.base_policy();
    p.blocked_recipients = soroban_sdk::vec![&h.env, h.recv.clone()];
    assert_rejects_with(&h, &p, &PolicyRuleId::RecipientAllowAndBlocked);
}

#[test]
fn validate_policy_reports_protocol_contract_duplicate() {
    let h = Harness::new();
    let mut p = h.base_policy();
    let rule = ProtocolRule {
        contract: h.asset.clone(),
        fns: None,

        paused: false,
    };
    p.protocols = soroban_sdk::vec![&h.env, rule.clone(), rule];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolContractDuplicate);
}

#[test]
fn validate_policy_reports_protocol_fn_list_invalid() {
    let h = Harness::new();

    // An explicit `Some` fn list may not be empty.
    let mut p = h.base_policy();
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.asset.clone(),
            fns: Some(soroban_sdk::Vec::new(&h.env)),

            paused: false,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolFnListInvalid);

    // ...nor contain duplicate fn names.
    let mut p = h.base_policy();
    let fns = soroban_sdk::vec![
        &h.env,
        Symbol::new(&h.env, "transfer"),
        Symbol::new(&h.env, "transfer"),
    ];
    p.protocols = soroban_sdk::vec![
        &h.env,
        ProtocolRule {
            contract: h.asset.clone(),
            fns: Some(fns),

            paused: false,
        },
    ];
    assert_rejects_with(&h, &p, &PolicyRuleId::ProtocolFnListInvalid);
}

#[test]
fn validate_policy_accepts_valid_config_and_ignores_installed_policy() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // No policy installed: the candidate is judged on its own merits.
    assert_eq!(
        client.validate_policy(&h.base_policy()),
        ValidationOutcome::Valid
    );

    // Install one, then dry-run the same candidate plus a broken one: the
    // verdict is about the *argument*, never the installed policy...
    h.install_policy(&h.base_policy());
    assert_eq!(
        client.validate_policy(&h.base_policy()),
        ValidationOutcome::Valid
    );
    let mut broken = h.base_policy();
    broken.window_cap = -1;
    assert_eq!(
        client.validate_policy(&broken),
        ValidationOutcome::Invalid(PolicyRuleId::AmountSign)
    );

    // ...and a rejected dry-run never disturbs the installed policy.
    assert_eq!(client.policy().unwrap().window_cap, 0);
}

// ── Issue #34: sane upper bounds on `window_secs` / `dms_grace_secs` ─────

/// SPEC §8 (issue #34): both duration fields are `u64`, so a seconds/millis
/// mix-up or `u64::MAX` would read as a valid config while silently disabling
/// pruning (or the dead-man switch) forever. Anything above
/// `MAX_WINDOW_SECS` / `MAX_DMS_GRACE_SECS` (`315_360_000` s ≈ 10 years) is
/// rejected as `InvalidConfig`, fail-closed: the previously installed policy
/// (if any) stays unchanged.
#[test]
fn window_and_dms_upper_bounds_rejected() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // `set_policy` returns `()` and signals rejection by panicking through
    // `panic_with_error!` (same pattern as `self_address_rejected_in_every_list`):
    // assert the panic *and* the fail-closed invariant.
    let expect_invalid = |cfg: &PolicyConfig, what: &str| {
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.set_policy(cfg);
        }));
        assert!(
            res.is_err(),
            "`{what}` must fail set_policy with InvalidConfig"
        );
        assert!(
            client.policy().is_none(),
            "`{what}` must leave the policy uninstalled (fail-closed)"
        );
    };

    // The motivating case: `u64::MAX` — "effectively forever".
    let mut p = h.base_policy();
    p.window_secs = u64::MAX;
    expect_invalid(&p, "window_secs = u64::MAX");

    // One second past the bound is already rejected (inclusive bound).
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS + 1;
    expect_invalid(&p, "window_secs = MAX + 1");

    // Same rule for the dead-man switch grace: `u64::MAX` silently turns §5 off.
    let mut p = h.base_policy();
    p.dms_grace_secs = u64::MAX;
    expect_invalid(&p, "dms_grace_secs = u64::MAX");

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS + 1;
    expect_invalid(&p, "dms_grace_secs = MAX + 1");

    // Sanity: the same env still installs an in-bounds policy cleanly, proving
    // the rejections above came from the bound and not from a broken harness.
    client.set_policy(&h.base_policy());
    assert!(client.policy().is_some());
}

/// SPEC §8 (issue #34): the bound is inclusive — exactly `MAX_WINDOW_SECS` /
/// `MAX_DMS_GRACE_SECS` installs cleanly — and `0` stays legal for both
/// fields (feature disabled), so no legitimate policy regresses.
#[test]
fn window_and_dms_upper_bounds_accept_boundary() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    // Exactly at the bound: accepted, stored verbatim.
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS;
    client.set_policy(&p);
    assert_eq!(
        client.policy().expect("policy installed").window_secs,
        crate::types::MAX_WINDOW_SECS
    );

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS;
    client.set_policy(&p);
    assert_eq!(
        client.policy().expect("policy installed").dms_grace_secs,
        crate::types::MAX_DMS_GRACE_SECS
    );

    // 0 remains legal for both fields.
    let mut p = h.base_policy();
    p.window_secs = 0;
    p.dms_grace_secs = 0;
    client.set_policy(&p);
    let stored = client.policy().expect("policy installed");
    assert_eq!((stored.window_secs, stored.dms_grace_secs), (0, 0));
}

/// The dry-run read reports the same duration rule: the #34 bound is
/// implemented as a `PolicyRuleId`, so `validate_policy` identifies it too —
/// `set_policy` and the dry run can never disagree about this rule.
#[test]
fn validate_policy_reports_duration_exceeds_bound() {
    let h = Harness::new();
    let client = PolicyEngineClient::new(&h.env, &h.guard);

    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS + 1;
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::DurationExceedsBound)
    );

    let mut p = h.base_policy();
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS + 1;
    assert_eq!(
        client.validate_policy(&p),
        ValidationOutcome::Invalid(PolicyRuleId::DurationExceedsBound)
    );

    // Exactly at the bound (both fields at once): the dry run is `Valid` and
    // the real `set_policy` accepts — inclusive bound, on both surfaces.
    let mut p = h.base_policy();
    p.window_secs = crate::types::MAX_WINDOW_SECS;
    p.dms_grace_secs = crate::types::MAX_DMS_GRACE_SECS;
    assert_eq!(client.validate_policy(&p), ValidationOutcome::Valid);
    client.set_policy(&p);
    assert!(client.policy().is_some());
}

// ── Auth verification ordering (Issue #27, SPEC §4 & §7) ───────────────────
//
// __check_auth executes in a strict 3-step authentication sequence before any
// policy decision table gate is reached:
//   1. Check `DataKey::AgentPubkey` in instance storage:
//      - If uninitialized: returns contract error `GuardError::NotInitialized` (code #3).
//      - Crucially: this check precedes crypto verification, so an uninitialized
//        account returns `NotInitialized` even if provided arbitrary/invalid signature bytes.
//   2. Verify Ed25519 signature via `env.crypto().ed25519_verify`:
//      - If invalid (wrong signer key or corrupted signature bytes): host crypto
//        verification fails and traps the execution frame (`InvokeError::Abort`).
//      - Crucially: this host abort precedes policy snapshot lookup, so a wrong-key
//        signature aborts the frame even if NO policy is installed on the contract
//        (it never proceeds to return `GuardError::NoPolicy`).
//   3. Load policy snapshot via `AuthSnapshot::load`:
//      - If no policy is installed (never set or revoked): returns contract error
//        `GuardError::NoPolicy` (code #12).
//   4. If policy snapshot is loaded:
//      - Evaluates the policy decision table (§4) over all auth contexts.
//
// Exact observable difference for triage:
//   - Uninitialized contract: returns contract error `GuardError::NotInitialized`.
//   - Bad signature / wrong key: host crypto trap (`InvokeError::Abort`), NOT a contract error.
//   - Good signature + no policy: returns contract error `GuardError::NoPolicy`.
//   - Good signature + valid policy: returns `Ok(())`.

#[test]
fn auth_verification_order_uninitialized_account_rejects_with_not_initialized() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let uninit_guard = h.env.register(PolicyEngine, ());

    // Case 1: uninitialized account with completely arbitrary / zeroed signature bytes.
    let arbitrary_sig = [0u8; 64];
    let arbitrary_payload = [1u8; 32];
    let contexts = soroban_sdk::Vec::new(&h.env);
    let res = h.invoke_check_auth_raw(&uninit_guard, &arbitrary_payload, &arbitrary_sig, &contexts);
    assert_eq!(
        res,
        Err(Ok(GuardError::NotInitialized)),
        "uninitialized account with arbitrary sig must return NotInitialized, not trap"
    );

    // Case 2: uninitialized account with transfer context and signature from an arbitrary key.
    let any_key = SigningKey::from_bytes(&[99u8; 32]);
    let res_transfer = h.invoke_check_auth_transfer(&uninit_guard, &any_key, &recv, 100);
    assert_eq!(
        res_transfer,
        Err(Ok(GuardError::NotInitialized)),
        "uninitialized account with validly-signed payload from any key must still return NotInitialized"
    );

    // Case 3: even with the harness agent key, an uninitialized contract returns NotInitialized.
    let res_agent = h.invoke_check_auth_transfer(&uninit_guard, &h.agent.clone(), &recv, 100);
    assert_eq!(
        res_agent,
        Err(Ok(GuardError::NotInitialized)),
        "uninitialized account must return NotInitialized before attempting crypto verification"
    );
}

#[test]
fn auth_verification_order_initialized_account_wrong_signature_traps_as_host_abort() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let wrong_key = SigningKey::from_bytes(&[42u8; 32]);

    // Subcase A: Account is initialized, but NO policy is installed.
    // Presenting a signature from a wrong key MUST trap the frame via host crypto
    // (`InvokeError::Abort`), and MUST NOT reach policy loading to return `NoPolicy`.
    let res_no_policy_wrong_sig =
        h.invoke_check_auth_transfer(&h.guard.clone(), &wrong_key, &recv, 50);
    assert_eq!(
        res_no_policy_wrong_sig,
        Err(Err(InvokeError::Abort)),
        "wrong-key signature on account with no policy must trap with host abort, not return NoPolicy"
    );

    // Corrupted signature bytes also trap the host crypto frame.
    let root = h.transfer_invocation(&h.guard, &recv, 50);
    let payload = h.payload(h.guard_nonce, &root);
    let corrupted_sig = [0xffu8; 64];
    let contexts = soroban_sdk::vec![
        &h.env,
        Context::Contract(ContractContext {
            contract: h.asset.clone(),
            fn_name: Symbol::new(&h.env, "transfer"),
            args: soroban_sdk::vec![
                &h.env,
                h.guard.clone().into_val(&h.env),
                recv.clone().into_val(&h.env),
                50i128.into_val(&h.env),
            ],
        }),
    ];
    let res_corrupted =
        h.invoke_check_auth_raw(&h.guard.clone(), &payload, &corrupted_sig, &contexts);
    assert_eq!(
        res_corrupted,
        Err(Err(InvokeError::Abort)),
        "corrupted signature on account with no policy must trap with host abort"
    );

    // Subcase B: Account is initialized, AND policy IS installed.
    // Wrong signature must still trap with host abort (`InvokeError::Abort`).
    h.install_policy(&h.base_policy());
    let res_with_policy_wrong_sig =
        h.invoke_check_auth_transfer(&h.guard.clone(), &wrong_key, &recv, 50);
    assert_eq!(
        res_with_policy_wrong_sig,
        Err(Err(InvokeError::Abort)),
        "wrong-key signature on account with policy installed must trap with host abort"
    );
}

#[test]
fn auth_verification_order_initialized_account_valid_signature_no_policy_yields_no_policy() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let agent_key = h.agent.clone();

    // Subcase A: Freshly initialized account (no policy ever set).
    // Valid signature by the registered agent key verifies crypto successfully,
    // then proceeds to policy loading, returning contract error `GuardError::NoPolicy`.
    let res_fresh = h.invoke_check_auth_transfer(&h.guard.clone(), &agent_key, &recv, 10);
    assert_eq!(
        res_fresh,
        Err(Ok(GuardError::NoPolicy)),
        "registered agent signature with no policy installed must return NoPolicy"
    );

    // Subcase B: Account has policy installed, then admin revokes the policy.
    // Valid signature by the registered agent key must again return `GuardError::NoPolicy`.
    h.install_policy(&h.base_policy());
    // Control: with policy installed, the exact same transfer succeeds.
    let res_allowed = h.invoke_check_auth_transfer(&h.guard.clone(), &agent_key, &recv, 10);
    assert_eq!(
        res_allowed,
        Ok(()),
        "registered agent signature with installed policy must succeed"
    );

    // Now revoke policy.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    client.revoke_policy();
    assert!(client.policy().is_none());

    // Subsequent authorization with registered agent signature now yields NoPolicy again.
    let res_revoked = h.invoke_check_auth_transfer(&h.guard.clone(), &agent_key, &recv, 10);
    assert_eq!(
        res_revoked,
        Err(Ok(GuardError::NoPolicy)),
        "registered agent signature after policy revocation must return NoPolicy"
    );
}

#[test]
fn auth_verification_ordering_matrix_pins_exact_observables() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let agent_key = h.agent.clone();
    let wrong_key = SigningKey::from_bytes(&[88u8; 32]);
    let uninit_guard = h.env.register(PolicyEngine, ());

    // Matrix Row 1: Uninitialized guard + any signature -> Contract Error #3 (NotInitialized).
    // Does not reach host crypto verification.
    let r1 = h.invoke_check_auth_transfer(&uninit_guard, &wrong_key, &recv, 25);
    assert_eq!(
        r1,
        Err(Ok(GuardError::NotInitialized)),
        "Row 1: uninitialized guard must return NotInitialized regardless of signature"
    );

    // Matrix Row 2: Initialized guard (no policy) + wrong signature -> Host Error (InvokeError::Abort).
    // Traps in host crypto; does not reach policy loading.
    let r2 = h.invoke_check_auth_transfer(&h.guard.clone(), &wrong_key, &recv, 25);
    assert_eq!(
        r2,
        Err(Err(InvokeError::Abort)),
        "Row 2: wrong-key signature must trap in host crypto with InvokeError::Abort"
    );

    // Matrix Row 3: Initialized guard (no policy) + valid signature -> Contract Error #12 (NoPolicy).
    // Passes crypto verification, fails policy load.
    let r3 = h.invoke_check_auth_transfer(&h.guard.clone(), &agent_key, &recv, 25);
    assert_eq!(
        r3,
        Err(Ok(GuardError::NoPolicy)),
        "Row 3: registered signature without policy must return NoPolicy"
    );

    // Matrix Row 4: Initialized guard (policy installed) + valid signature -> Success (Ok(())).
    // Passes crypto verification and passes policy evaluation.
    h.install_policy(&h.base_policy());
    let r4 = h.invoke_check_auth_transfer(&h.guard.clone(), &agent_key, &recv, 25);
    assert_eq!(
        r4,
        Ok(()),
        "Row 4: registered signature with policy installed must approve"
    );
}

/// Issue #358: Exercise contract creation denial through the real host path.
///
/// Verifies end-to-end that when contract creation is deployed on behalf of the guarded
/// custom account address, the real Soroban host surfaces the creation context to
/// `__check_auth` (both `Context::CreateContractHostFn` for zero constructor args and
/// `Context::CreateContractWithCtorHostFn` for non-zero constructor args).
///
/// In both cases, the policy engine denies the authorization fail-closed with
/// `Error::CreateContractNotAllowed` (code 28), emits the `auth_checked` event with
/// `blocked` and `create_contract_not_allowed`, and causes the host transaction to fail
/// with `Error(Contract, #28)`.
#[test]
fn contract_creation_denied_through_real_host_path() {
    let mut h = Harness::new();
    let p = h.base_policy();
    h.install_policy(&p);

    let wasm_hash = h
        .env
        .deployer()
        .upload_contract_wasm(soroban_sdk::Bytes::new(&h.env));
    let deployer_contract = h.env.register(MockDeployer, ());
    let client = MockDeployerClient::new(&h.env, &deployer_contract);

    // Case 1: Deploy with no constructor arguments.
    // The host surfaces Context::CreateContractHostFn to __check_auth.
    let salt1 = BytesN::from_array(&h.env, &[1u8; 32]);
    let root1 = h.create_contract_invocation(&salt1, &wasm_hash);
    let entry1 = h.guard_entry(&root1);
    h.enforce(entry1);

    let res1 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.deploy_v2(&h.guard, &salt1, &wasm_hash);
    }));
    assert!(
        res1.is_err(),
        "contract creation without constructor args must be blocked"
    );
    let panic_msg1 = res1
        .err()
        .and_then(|payload| payload.downcast_ref::<std::string::String>().cloned())
        .unwrap_or_default();
    assert!(
        panic_msg1.contains("Error(Contract, #28)"),
        "expected panic log to contain Error(Contract, #28), got: {panic_msg1}"
    );
    assert!(
        panic_msg1.contains("create_contract_not_allowed"),
        "expected panic log to contain create_contract_not_allowed, got: {panic_msg1}"
    );
    assert!(
        panic_msg1.contains("CreateContractHostFn"),
        "expected host diagnostic log to show Context::CreateContractHostFn, got: {panic_msg1}"
    );

    // Case 2: Deploy with constructor arguments.
    // The host surfaces Context::CreateContractWithCtorHostFn to __check_auth.
    let salt2 = BytesN::from_array(&h.env, &[2u8; 32]);
    let root2 = h.create_contract_with_ctor_invocation(&salt2, &wasm_hash, 99);
    let entry2 = h.guard_entry(&root2);
    h.enforce(entry2);

    let res2 = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.deploy_with_ctor(&h.guard, &salt2, &wasm_hash, &99);
    }));
    assert!(
        res2.is_err(),
        "contract creation with constructor args must be blocked"
    );
    let panic_msg2 = res2
        .err()
        .and_then(|payload| payload.downcast_ref::<std::string::String>().cloned())
        .unwrap_or_default();
    assert!(
        panic_msg2.contains("Error(Contract, #28)"),
        "expected panic log to contain Error(Contract, #28), got: {panic_msg2}"
    );
    assert!(
        panic_msg2.contains("create_contract_not_allowed"),
        "expected panic log to contain create_contract_not_allowed, got: {panic_msg2}"
    );
    assert!(
        panic_msg2.contains("CreateContractWithCtorHostFn"),
        "expected host diagnostic log to show Context::CreateContractWithCtorHostFn, got: {panic_msg2}"
    );
}

#[test]
fn unfreeze_does_not_clear_outside_active_window_until_set_policy() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    let mut p = h.base_policy();
    p.active_from = 100;
    p.active_until = 500;
    h.install_policy(&p);

    // Ledger time moves past active_until (600 > 500).
    h.set_time(600);

    // outside_active_window is active.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert!(h.status().outside_active_window);
    assert_eq!(
        client.check(&h.asset, &recv, &10),
        CheckResult::Blocked(Symbol::new(&h.env, "outside_active_window"))
    );

    // Both spend and heartbeat are blocked at gate #5 (account_error).
    h.transfer_expect_blocked(&recv, 10);
    h.heartbeat_expect_blocked();

    // Admin unfreezes the account. This clears AdminFrozen and sets LastHeartbeat = now,
    // but does NOT touch policy configuration (cannot advance active_until).
    h.unfreeze();

    // The account remains outside the active window: unfreeze alone cannot revive it.
    assert!(h.status().outside_active_window);
    assert_eq!(
        client.check(&h.asset, &recv, &10),
        CheckResult::Blocked(Symbol::new(&h.env, "outside_active_window"))
    );
    h.transfer_expect_blocked(&recv, 10);
    h.heartbeat_expect_blocked();

    // Only set_policy with a renewed active window restores the account.
    let mut renewed = p;
    renewed.active_until = 1_000;
    h.set_policy_enforcing(&renewed);

    // The account is revived: outside_active_window is cleared, heartbeat and transfer succeed.
    assert!(!h.status().outside_active_window);
    assert_eq!(client.check(&h.asset, &recv, &10), CheckResult::Allowed);
    h.heartbeat();
    h.transfer(&recv, 10);
}

// ── Admin-gated functions (issue #365, SPEC §1 & §7) ─────────────────────
//
// SPEC §1 and §7 state that only the admin can change policy and manage admin
// controls ('Admin never gains fund-moving authority' and 'only the admin can
// change policy'). Admin calls must be rejected if authorized by a non-admin
// principal (whether the agent key or an arbitrary external address).
//
// Contract methods returning `()` (`set_policy`, `revoke_policy`, `freeze`,
// `unfreeze`, `rotate_agent_key`, `propose_admin_rotation`,
// `cancel_admin_rotation`) panic on authorization failure via the host's
// `require_auth` check; the Soroban SDK generates no `try_*` client method
// for unit-returning contract functions that signals host-level auth rejection.
// `std::panic::catch_unwind` + `std::panic::AssertUnwindSafe` is therefore the
// standard mechanism to assert that unauthorized calls fail closed.

#[test]
fn admin_gating_set_policy_rejects_non_admin() {
    let mut h = Harness::new();
    let base = h.base_policy();
    h.install_policy(&base);

    let mut rogue_policy = base.clone();
    rogue_policy.allow_any_recipient = true;

    let root = h.set_policy_invocation(&rogue_policy);

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `set_policy` returns `()` and the host aborts with an auth error; `try_set_policy`
    // is not generated by the SDK for unit returns, so `catch_unwind` asserts rejection.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&rogue_policy);
    }));
    assert!(
        res.is_err(),
        "set_policy authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).set_policy(&rogue_policy);
    }));
    assert!(
        res_agent.is_err(),
        "set_policy authorized by the agent key must fail"
    );

    // Fail-closed: policy and revision remain untouched.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(client.policy(), Some(base));
    assert_eq!(h.status().policy_revision, 1);
}

#[test]
fn admin_gating_revoke_policy_rejects_non_admin() {
    let mut h = Harness::new();
    let base = h.base_policy();
    h.install_policy(&base);

    let root = h.revoke_policy_invocation();

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `revoke_policy` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).revoke_policy();
    }));
    assert!(
        res.is_err(),
        "revoke_policy authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).revoke_policy();
    }));
    assert!(
        res_agent.is_err(),
        "revoke_policy authorized by the agent key must fail"
    );

    // Fail-closed: policy is still active and revision unchanged.
    let client = PolicyEngineClient::new(&h.env, &h.guard);
    assert_eq!(client.policy(), Some(base));
    assert_eq!(h.status().policy_revision, 1);
}

#[test]
fn admin_gating_freeze_rejects_non_admin() {
    let mut h = Harness::new();
    assert!(!h.status().admin_frozen);

    let root = h.freeze_invocation();

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `freeze` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).freeze();
    }));
    assert!(
        res.is_err(),
        "freeze authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).freeze();
    }));
    assert!(
        res_agent.is_err(),
        "freeze authorized by the agent key must fail"
    );

    // Fail-closed: account is still not frozen.
    assert!(!h.status().admin_frozen);
}

#[test]
fn admin_gating_unfreeze_rejects_non_admin() {
    let mut h = Harness::new();

    // Legitimate admin freeze.
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).freeze();
    assert!(h.status().admin_frozen);

    let root = h.unfreeze_invocation();

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `unfreeze` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).unfreeze();
    }));
    assert!(
        res.is_err(),
        "unfreeze authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).unfreeze();
    }));
    assert!(
        res_agent.is_err(),
        "unfreeze authorized by the agent key must fail"
    );

    // Fail-closed: account remains frozen.
    assert!(h.status().admin_frozen);

    // Legitimate admin unfreeze succeeds.
    h.unfreeze();
    assert!(!h.status().admin_frozen);
}

#[test]
fn admin_gating_rotate_agent_key_rejects_non_admin() {
    let mut h = Harness::new();
    let recv = h.recv.clone();
    h.install_policy(&h.base_policy());
    h.set_time(1_000);

    let attacker_key = SigningKey::from_bytes(&[99u8; 32]);
    let attacker_pk = attacker_key.verifying_key().to_bytes();
    let attacker_pk_val = BytesN::from_array(&h.env, &attacker_pk);

    let root = h.rotate_agent_key_invocation(&attacker_pk_val);

    // Case 1: Non-admin principal cannot rotate the agent key to its own key.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `rotate_agent_key` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).rotate_agent_key(&attacker_pk_val);
    }));
    assert!(
        res.is_err(),
        "rotate_agent_key authorized by a non-admin account must fail"
    );

    // Case 2: Current agent key cannot rotate the agent key either.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).rotate_agent_key(&attacker_pk_val);
    }));
    assert!(
        res_agent.is_err(),
        "rotate_agent_key authorized by the agent key must fail"
    );

    // Assert that the attacker cannot authorize operations as the agent:
    // the rejected rotation leaves the bound agent key unchanged.
    let transfer_root = h.transfer_invocation(&h.guard, &recv, 10);
    let attacker_auth = h.guard_entry_with(&attacker_key, &transfer_root);
    h.enforce(attacker_auth);

    let res_transfer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        MockAssetClient::new(&h.env, &h.asset).transfer(&h.guard, &recv, &10);
    }));
    assert!(
        res_transfer.is_err(),
        "attacker who failed to bind key must not authorize as agent"
    );

    // Legitimate agent key still authorizes transfers successfully.
    h.transfer(&recv, 10);
}

#[test]
fn admin_gating_propose_admin_rotation_rejects_non_admin() {
    let mut h = Harness::new();
    let rogue_admin = Address::generate(&h.env);

    let root = h.propose_admin_invocation(&rogue_admin);

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `propose_admin_rotation` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).propose_admin_rotation(&rogue_admin);
    }));
    assert!(
        res.is_err(),
        "propose_admin_rotation authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).propose_admin_rotation(&rogue_admin);
    }));
    assert!(
        res_agent.is_err(),
        "propose_admin_rotation authorized by the agent key must fail"
    );

    // Fail-closed: pending admin slot remains empty.
    let (_, pending) = h.stored_admins();
    assert!(pending.is_none());
}

#[test]
fn admin_gating_cancel_admin_rotation_rejects_non_admin() {
    let mut h = Harness::new();
    let new_admin = Address::generate(&h.env);

    // Admin legitimately proposes rotation.
    h.env.mock_all_auths();
    PolicyEngineClient::new(&h.env, &h.guard).propose_admin_rotation(&new_admin);
    let (_, pending) = h.stored_admins();
    assert_eq!(pending, Some(new_admin.clone()));

    let root = h.cancel_admin_invocation();

    // Case 1: Unauthorized random principal.
    let non_admin = h.env.register(MockAdmin, ());
    let entry = h.non_admin_entry(&non_admin, &root);
    h.enforce(entry);

    // `cancel_admin_rotation` returns `()`; host auth failure traps without SDK `try_*` error,
    // so `catch_unwind` is used.
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).cancel_admin_rotation();
    }));
    assert!(
        res.is_err(),
        "cancel_admin_rotation authorized by a non-admin account must fail"
    );

    // Case 2: Agent key principal.
    let agent_entry = h.guard_entry(&root);
    h.enforce(agent_entry);

    let res_agent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        PolicyEngineClient::new(&h.env, &h.guard).cancel_admin_rotation();
    }));
    assert!(
        res_agent.is_err(),
        "cancel_admin_rotation authorized by the agent key must fail"
    );

    // Fail-closed: pending admin rotation is not cancelled.
    let (_, pending) = h.stored_admins();
    assert_eq!(pending, Some(new_admin));
}

// ── Admin functions before `initialize` (issue #364) ─────────────────────
//
// `admin_or_panic` (src/lib.rs) is the single gate in front of every admin
// write: with no admin stored it panics `NotInitialized`, so a guard that was
// registered but never initialized cannot accept a policy, rotate its key, or
// flip the freeze switch. Default-deny depends on every state path failing
// closed — the administrative ones included — but this `NotInitialized` arm
// had no coverage: `initialize`'s double-call rejection was tested, the
// pre-init rejection of every other admin function was not.
//
// These assertions use the generated `try_*` client methods rather than
// `catch_unwind`. `try_*` is generated for unit-returning contract functions
// too, and it distinguishes a contract error (`Err(Ok(..))`, the
// `panic_with_error!` path this test targets) from a host-level failure
// (`Err(Err(..))`), so the exact error code is asserted instead of just "it
// panicked".

/// The contract error carried by a generated `try_*` call, or a panic naming
/// how the call failed to be one.
fn try_contract_error<T, E>(
    res: Result<Result<T, E>, Result<soroban_sdk::Error, InvokeError>>,
) -> GuardError
where
    T: std::fmt::Debug,
    E: std::fmt::Debug,
{
    match res {
        Err(Ok(err)) => GuardError::try_from(err).expect("unknown contract error code"),
        Ok(ok) => panic!("expected a contract error, but the call succeeded: {ok:?}"),
        Err(Err(host)) => panic!("expected a contract error, but the host failed: {host:?}"),
    }
}

#[test]
fn admin_functions_reject_with_not_initialized_before_initialize() {
    let h = Harness::new();
    // A freshly registered guard: no `initialize` call was ever made, so no
    // admin address is stored and there is no key or policy state either.
    let guard = h.env.register(PolicyEngine, ());
    let client = PolicyEngineClient::new(&h.env, &guard);

    let status_before = client.status();
    assert!(!status_before.has_policy, "a fresh guard has no policy");
    assert_eq!(status_before.policy_revision, 0);
    assert!(!status_before.admin_frozen);
    assert_eq!(status_before.last_heartbeat, 0);

    // Raw state the `status` snapshot does not expose (the bound agent key and
    // the rolling ledger), read as the contract so it sees the stored bytes.
    let stored_agent_key = || {
        h.env.as_contract(&guard, || {
            h.env
                .storage()
                .instance()
                .get::<DataKey, BytesN<32>>(&DataKey::AgentPubkey)
        })
    };
    let stored_window = || {
        h.env.as_contract(&guard, || {
            h.env
                .storage()
                .persistent()
                .get::<DataKey, WindowState>(&DataKey::Window)
        })
    };
    assert!(stored_agent_key().is_none());
    assert!(stored_window().is_none());

    // After each rejection the whole observable state must be byte-identical
    // to the pre-call snapshot: no policy, no agent key, no window, no
    // revision/freeze/heartbeat movement, and no lifecycle event (a rejected
    // admin call emits nothing; the event log still holds its own invocation).
    let assert_unchanged = |label: &str| {
        assert!(
            h.env.events().all().events().is_empty(),
            "`{label}` before initialize must not emit an event"
        );
        assert_eq!(
            client.status(),
            status_before,
            "`{label}` before initialize must leave the status snapshot untouched"
        );
        assert!(
            client.policy().is_none(),
            "`{label}` before initialize must not install a policy"
        );
        assert!(
            stored_agent_key().is_none(),
            "`{label}` before initialize must not bind an agent key"
        );
        assert!(
            stored_window().is_none(),
            "`{label}` before initialize must not create a window"
        );
    };

    // Every admin entrypoint, driven against the uninitialized account. The
    // candidate policy and key are valid on their own, so the only thing that
    // can reject them here is the missing admin.
    assert_eq!(
        try_contract_error(client.try_set_policy(&h.base_policy())),
        GuardError::NotInitialized,
        "set_policy before initialize must fail closed with NotInitialized"
    );
    assert_unchanged("set_policy");

    assert_eq!(
        try_contract_error(client.try_revoke_policy()),
        GuardError::NotInitialized,
        "revoke_policy before initialize must fail closed with NotInitialized"
    );
    assert_unchanged("revoke_policy");

    let new_pubkey = BytesN::from_array(&h.env, &[9u8; 32]);
    assert_eq!(
        try_contract_error(client.try_rotate_agent_key(&new_pubkey)),
        GuardError::NotInitialized,
        "rotate_agent_key before initialize must fail closed with NotInitialized"
    );
    assert_unchanged("rotate_agent_key");

    assert_eq!(
        try_contract_error(client.try_freeze()),
        GuardError::NotInitialized,
        "freeze before initialize must fail closed with NotInitialized"
    );
    assert_unchanged("freeze");

    assert_eq!(
        try_contract_error(client.try_unfreeze()),
        GuardError::NotInitialized,
        "unfreeze before initialize must fail closed with NotInitialized"
    );
    assert_unchanged("unfreeze");

    // Sanity: once the same account is initialized the identical call is
    // accepted, so the rejections above came from the missing admin and not
    // from a broken harness or an invalid candidate policy.
    h.env.mock_all_auths();
    let pk = h.agent.verifying_key().to_bytes();
    client.initialize(&h.admin, &BytesN::from_array(&h.env, &pk));
    client.set_policy(&h.base_policy());
    assert!(client.policy().is_some());
    assert!(client.status().has_policy);
}
