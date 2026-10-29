//! Derive the raw Ed25519 public key (hex, 32 bytes) from a Stellar secret
//! key. The guard contract registers the agent as `BytesN<32>` — the raw
//! Ed25519 public key — not the `G...` address, so this is the bridge between
//! a standard `stellar keys` identity and `PolicyEngine::initialize`.
//!
//! Usage:
//! ```text
//! echo '<SECRET>' | cargo run --example agent_pubkey
//! ```
//!
//! A Stellar secret key is a strkey: version byte `0x90` + 32-byte Ed25519
//! seed + 2-byte CRC16-XModem checksum, base32-encoded (RFC 4648, no
//! padding). The seed *is* the Ed25519 signing seed, so the derived public
//! key matches the `G...` address the identity resolves to.
//!
//! # What this example guarantees
//!
//! The derivation is **deterministic and standard**, not a project-specific
//! convention:
//!
//! - base32 decoding follows RFC 4648 (no padding), and the trailing two
//!   bytes are the strkey CRC16-XModem checksum. The decode is the
//!   `agent-strkey` crate's: the same implementation `tools/agent-tx` parses
//!   its flags with, so there is one place a key-handling bug can live and
//!   one place it gets fixed (issue #379).
//! - The strkey layout (version byte `0x90` + 32-byte seed + CRC16-XModem
//!   checksum) is [SEP-0023][sep23]: `STRKEY_PRIVKEY` base value `18 << 3` with
//!   the `STRKEY_ALG_ED25519` selector `0` — the same layout `stellar keys` and
//!   every Stellar SDK use.
//! - seed → public key is plain [Ed25519][rfc8032] scalar multiplication,
//!   performed by `ed25519-dalek`'s `SigningKey::from_bytes(..).verifying_key()`.
//!   The seed *is* the Ed25519 signing seed, so the printed 32 bytes are the
//!   public key of the `G...` address that identity resolves to — `stellar keys
//!   show` and any SDK `Keypair.publicKey()` agree with this output byte for
//!   byte.
//!
//! Running the same secret through this example twice therefore always prints
//! the same hex, and any standard Stellar tooling derives the same value.
//!
//! [sep23]: https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0023.md
//! [rfc8032]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5
//!
//! # What this example does NOT guarantee (trust boundary)
//!
//! This tool is **off-chain convenience only**. It proves nothing about the
//! key the agent runtime will actually use, and printing a pubkey here is not
//! evidence that the runtime signs with it. Callers must still verify:
//!
//! 1. **Runtime key identity.** The agent runtime must hold the secret whose
//!    derivation produced the value passed to `initialize`. If it holds a
//!    different key, every later transaction fails authorization: the
//!    contract's own `__check_auth` verifies the signature against the
//!    registered `AgentPubkey` (SPEC §7, step 2) before any policy evaluation,
//!    so a bad signature **traps the frame and never reaches the decision
//!    table**. A wrong key therefore never surfaces as a policy `Blocked`
//!    reason — it fails earlier, as an auth error at broadcast time. A
//!    `Blocked` reason means the runtime *did* sign successfully, so the
//!    absence of a block is not evidence that the key is the one you derived.
//! 2. **Secret handling.** The secret is read from stdin so it stays out of
//!    shell history and process arguments, but this example does not zeroize
//!    memory and offers no HSM or hardware-backed protection. For anything
//!    beyond testnet keys, derive the pubkey in the same secure environment
//!    that holds the secret.
//! 3. **Checksum validation is format validation, nothing more.** The shared
//!    codec (`agent-strkey`) checks the version byte, the 56-character length
//!    and the CRC16-XModem checksum, so a *mistyped* secret is rejected here
//!    instead of silently deriving some other key. That is all it proves: a
//!    different but well-formed secret also derives a valid-looking 32-byte
//!    pubkey, and that mix-up only shows up later as the runtime auth failure
//!    described in (1).
//! 4. **Key custody and rotation.** Nothing here registers, stores, or rotates
//!    the key. Registration happens in `initialize`; rotation goes through
//!    `rotate_agent_key`, which emits the old/new fingerprints (SPEC §9) that
//!    let an auditor reconstruct when a key stopped being authoritative.
//!
//! # Runtime-side counterpart
//!
//! The end of this trust chain is covered by the contract's integration tests,
//! which exercise the real host crypto path with real Ed25519 signatures:
//!
//! - `src/integration_tests.rs::allowed_transaction_succeeds` — a signature by
//!   the registered agent key authorizes the transfer, proving the registered
//!   pubkey is the one the runtime signs with.
//! - `src/integration_tests.rs::wrong_signature_is_rejected_by_host_crypto` —
//!   a signature by an unregistered key is rejected (the exact failure mode a
//!   derivation mismatch produces), and the registered key still works after.
//! - `src/integration_tests.rs::rotated_agent_key_binds` — after
//!   `rotate_agent_key`, only the new key authorizes.
//!
//! If you are auditing the trust chain, read those three together with this
//! example: derivation here, key binding enforced there.

use agent_strkey::strkey::{decode_strkey, VER_SECRET};
use ed25519_dalek::SigningKey;
use std::io::Read;

fn main() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("reading the secret from stdin");
    let secret = input.trim();
    // Alphabet, length, version byte and CRC16-XModem checksum, all checked by
    // the codec the submission tool uses too.
    let (version, seed) = decode_strkey(secret).unwrap_or_else(|reason| {
        panic!("invalid secret seed: {reason}; expected a 56-character StrKey secret seed (S...)")
    });
    assert_eq!(
        version, VER_SECRET,
        "not a StrKey secret seed (expected leading character 'S', version byte 0x90)"
    );
    let signing = SigningKey::from_bytes(&seed);
    for b in signing.verifying_key().to_bytes() {
        print!("{b:02x}");
    }
    println!();
}
