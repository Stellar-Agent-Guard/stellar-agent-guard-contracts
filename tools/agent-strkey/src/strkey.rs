//! StrKey version bytes, validation, and the account/contract encoders.
//!
//! A StrKey is `base32(version || 32-byte payload || crc16)` with no `=`
//! padding — 56 characters for every key type this crate handles. The version
//! byte carries the *key type* (`G` account, `C` contract, `S` secret seed)
//! and never the network, so the same Ed25519 key has the same string form on
//! testnet, futurenet and mainnet. Nothing here tries to tell networks apart;
//! which network a call reaches is decided by the caller's endpoint and
//! network passphrase.
//!
//! Validation is deliberately strict: lowercase input, trailing whitespace, a
//! truncated string, and a mistyped-but-in-alphabet key are all rejected with
//! a reason an operator can act on. The checksum is what catches the last
//! case, which is the one that would otherwise send funds to an address that
//! merely looks right.

use crate::base32::{base32_decode, crc16_xmodem, strkey_encode, B32};

/// Version byte of an account ID (`G...`).
pub const VER_ACCOUNT: u8 = 6 << 3; // 0x30
/// Version byte of a contract ID (`C...`).
pub const VER_CONTRACT: u8 = 2 << 3; // 0x12
/// Version byte of an account secret seed (`S...`).
pub const VER_SECRET: u8 = 0x90;

/// A 32-byte payload with version byte and CRC16 checksum, base-32 encoded:
/// `ceil(35 * 8 / 5) == 56` characters, with no `=` padding.
const STRKEY_LEN: usize = 56;

fn in_alphabet(c: char) -> bool {
    c.is_ascii() && !c.is_ascii_lowercase() && B32.contains(&(c.to_ascii_uppercase() as u8))
}

/// Encode a 32-byte account public key as a `G...` address.
pub fn account_strkey(pubkey: &[u8; 32]) -> String {
    strkey_encode(VER_ACCOUNT, pubkey)
}

/// Encode a 32-byte contract id as a `C...` address.
pub fn contract_strkey(id: &[u8; 32]) -> String {
    strkey_encode(VER_CONTRACT, id)
}

/// Decode a StrKey into `(version byte, 32-byte payload)`, checking the
/// alphabet, the length, and the CRC16-XModem checksum. The error names the
/// broken rule in terms an operator can act on.
pub fn decode_strkey(value: &str) -> Result<(u8, [u8; 32]), String> {
    if value.is_empty() {
        return Err("the value is empty".to_string());
    }
    if let Some((index, c)) = value.char_indices().find(|(_, c)| !in_alphabet(*c)) {
        return Err(
            if c.is_ascii_lowercase() && in_alphabet(c.to_ascii_uppercase()) {
                format!(
                "character '{c}' at position {index} is lowercase; StrKey is case-sensitive and \
                 uses uppercase"
            )
            } else {
                format!(
                    "character '{c}' at position {index} is outside the StrKey base-32 alphabet \
                 (A-Z, 2-7)"
                )
            },
        );
    }
    if value.chars().count() != STRKEY_LEN {
        return Err(format!(
            "expected {STRKEY_LEN} characters, got {} (addresses copied from log lines are \
             often truncated)",
            value.chars().count()
        ));
    }
    let raw = base32_decode(value).ok_or_else(|| "value does not decode as base-32".to_string())?;
    let (body, checksum) = raw.split_at(raw.len().saturating_sub(2));
    if body.len() != 33 || checksum.len() != 2 {
        return Err(format!(
            "decodes to {} bytes, expected 35 (1 version byte + 32 key bytes + 2 checksum bytes)",
            raw.len()
        ));
    }
    let expected = crc16_xmodem(body);
    let found = u16::from(checksum[1]) << 8 | u16::from(checksum[0]);
    if expected != found {
        return Err(format!(
            "its CRC16-XModem checksum does not match (computed 0x{expected:04x}, found \
             0x{found:04x}) — the key is mistyped or truncated"
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[1..33]);
    Ok((body[0], key))
}
