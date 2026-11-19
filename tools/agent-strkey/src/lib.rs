//! StrKey (Stellar's base-32 address format) codec shared by
//! `tools/agent-tx` — the submission tool — and `examples/agent_pubkey.rs` —
//! the example that derives the agent's raw Ed25519 pubkey from its secret
//! seed (issue #379).
//!
//! # Why this is its own crate
//!
//! The tool and the example are separate cargo projects (the tool has its own
//! `Cargo.toml` and `Cargo.lock`, and the example is a target of the contract
//! crate), so neither can `mod` the other's files. The two realistic ways to
//! share one implementation are a path-dependency library or copying the code;
//! copying is what this crate removes. A third option — have the example
//! depend on the `agent-tx` binary crate — was rejected because it would pull
//! `ureq`, `dirs`, `getrandom`, `serde` and `stellar-xdr` into the contract
//! crate's dev dependency graph for a key codec, and would register all of
//! their licenses and advisories against `deny.toml`'s policy.
//!
//! So: a library crate with **no dependencies**, consumed by path from both
//! sides. The rule it enforces is stated once, in one place, and both readers
//! of an `S...`/`G...`/`C...` string get the same answer.
//!
//! # Trust boundary
//!
//! Everything here is format work — it tells you a StrKey is *well formed*
//! (alphabet, length, version byte, CRC16-XModem checksum). It says nothing
//! about whether a key is the right key for a given agent or network; that
//! binding is enforced on-chain by the guard contract's `__check_auth`.
//!
//! [`base32`] holds the bit accumulator, the CRC16 and the StrKey envelope;
//! [`strkey`] holds validation/decoding plus the account/contract encoders.

pub mod base32;
pub mod strkey;

#[cfg(test)]
mod tests {
    use crate::base32::{base32_decode, base32_encode, strkey_encode, B32};
    use crate::strkey::{
        account_strkey, contract_strkey, decode_strkey, VER_ACCOUNT, VER_CONTRACT, VER_SECRET,
    };

    /// Small reproducible PRNG so "random" byte strings are deterministic
    /// across runs without pulling in a `rand` dependency.
    struct CodecRng(u64);

    impl CodecRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn fill(&mut self, buf: &mut [u8]) {
            for chunk in buf.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    #[test]
    fn base32_decode_encodes_back_the_same_bytes() {
        // Round-trip property: decode(encode(x)) == x for byte strings of
        // many lengths, including lengths that straddle base-32's 5/8-bit
        // group boundary and the 33-byte strkey body length.
        let mut rng = CodecRng(0x1234_5678_9abc_def0);
        let mut lengths: Vec<usize> = (0usize..=40usize).collect();
        lengths.push(100usize);
        for len in lengths {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let encoded = base32_encode(&data);
            let decoded = base32_decode(&encoded).expect("round-trip decode must succeed");
            assert_eq!(decoded, data, "length {len} round-trip");
        }
    }

    #[test]
    fn base32_encode_output_has_no_padding_and_uses_rfc4648_alphabet() {
        let mut rng = CodecRng(0xdead_beef_cafe_1234);
        for len in 0usize..=40usize {
            let mut data = vec![0u8; len];
            rng.fill(&mut data);
            let encoded = base32_encode(&data);
            assert!(
                !encoded.contains('='),
                "base-32 output must not be padded: {encoded}"
            );
            assert!(
                encoded.bytes().all(|c| B32.contains(&c)),
                "base-32 output must use the RFC 4648 alphabet: {encoded}"
            );
        }
    }

    #[test]
    fn strkey_encode_decode_is_identity_for_random_payloads() {
        let mut rng = CodecRng(0xfeed_cafe_babe_cafe);
        let versions = [VER_ACCOUNT, VER_CONTRACT, VER_SECRET];
        for i in 0..100u32 {
            let version = versions[(i as usize) % versions.len()];
            let mut payload = [0u8; 32];
            rng.fill(&mut payload);
            let encoded = strkey_encode(version, &payload);
            let (found_version, found_payload) =
                decode_strkey(&encoded).expect("round-trip decode_strkey");
            assert_eq!(found_version, version, "iteration {i}");
            assert_eq!(found_payload, payload, "iteration {i}");
        }
    }

    #[test]
    fn base32_decode_rejects_invalid_character() {
        assert!(base32_decode("ABC!DEFG").is_none());
        assert!(base32_decode("abcdef").is_none());
        assert_eq!(base32_decode(""), Some(vec![]));
    }

    #[test]
    fn decode_strkey_rejects_character_outside_alphabet() {
        let mut corrupted = contract_strkey(&[0x01u8; 32]);
        corrupted.replace_range(10..11, "!");
        let err = decode_strkey(&corrupted).unwrap_err();
        assert!(err.contains("outside the StrKey base-32 alphabet"), "{err}");
    }

    #[test]
    fn decode_strkey_rejects_wrong_length() {
        let contract = contract_strkey(&[0x01u8; 32]);
        let err = decode_strkey(&contract[..48]).unwrap_err();
        assert!(err.contains("expected 56 characters, got 48"), "{err}");
    }

    #[test]
    fn decode_strkey_rejects_bad_crc16_checksum() {
        let mut mistyped = contract_strkey(&[0x01u8; 32]);
        let replacement = if &mistyped[40..41] == "A" { "B" } else { "A" };
        mistyped.replace_range(40..41, replacement);
        let err = decode_strkey(&mistyped).unwrap_err();
        assert!(
            err.contains("CRC16-XModem checksum does not match"),
            "{err}"
        );
    }

    #[test]
    fn decode_strkey_rejects_lowercase_input() {
        let err = decode_strkey(&contract_strkey(&[0x01u8; 32]).to_lowercase()).unwrap_err();
        assert!(
            err.contains("lowercase") && err.contains("case-sensitive"),
            "{err}"
        );
    }

    #[test]
    fn decode_strkey_rejects_trailing_whitespace() {
        let contract = contract_strkey(&[0x01u8; 32]);
        let err = decode_strkey(&format!("{contract} ")).unwrap_err();
        assert!(
            err.contains("expected 56 characters")
                || err.contains("outside the StrKey base-32 alphabet"),
            "{err}"
        );
    }

    #[test]
    fn contract_address_known_vector_round_trips() {
        // Known-good vector: a 32-byte contract id encodes to a C... strkey
        // that decodes back to the same id.
        let id = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&id);
        let encoded = contract_strkey(&arr);
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_CONTRACT);
        assert_eq!(decoded, arr);
        assert!(encoded.starts_with('C'));
        assert_eq!(encoded.len(), 56);
    }

    #[test]
    fn account_address_known_vector_round_trips() {
        // Known-good vector from the repo's own samples: pubkey
        // `1cb479ac…cc05` encodes to the GAOLI… account address.
        let pk = hex::decode("1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05")
            .unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk);
        let encoded = account_strkey(&arr);
        assert_eq!(
            encoded,
            "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP"
        );
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_ACCOUNT);
        assert_eq!(decoded, arr);
    }

    #[test]
    fn secret_seed_known_vector_round_trips() {
        // Known-good vector: the repo's agent secret decodes to its seed and
        // round-trips through the encoder.
        let secret = "SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4";
        let (version, seed) = decode_strkey(secret).unwrap();
        assert_eq!(version, VER_SECRET);
        assert_eq!(
            hex::encode(seed),
            "635711bd422c08b9354a34e3b748c0f47dcbfda399ba2b1f8c39a4c46f3f5513"
        );
        let encoded = strkey_encode(VER_SECRET, &seed);
        let (version, decoded) = decode_strkey(&encoded).unwrap();
        assert_eq!(version, VER_SECRET);
        assert_eq!(decoded, seed);
        assert!(encoded.starts_with('S'));
        assert_eq!(encoded.len(), 56);
    }
}
