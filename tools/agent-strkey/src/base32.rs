//! Base-32 (RFC 4648, no padding) and the StrKey envelope:
//! `version || payload || crc16`, checksum appended little-endian (matching
//! stellar-strkey).
//!
//! These are the primitives [`crate::strkey`] validates with, and the single
//! implementation used by both consumers of this crate (see the crate docs).
//! Key material for the guard's agent identity passes through here, so the
//! bit accumulator is covered by the property, negative and vector tests in
//! `crate::tests` rather than being reimplemented per caller.

/// RFC 4648 base-32 alphabet, which is what Stellar's StrKey uses.
pub const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// CRC16-XModem (polynomial 0x1021, init 0x0000, no reflection).
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Decode an RFC 4648 base-32 string (no `=` padding) into bytes.
/// Returns `None` if a character is outside the alphabet.
pub fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in input.bytes() {
        if c == b'=' {
            break;
        }
        let v = u32::try_from(B32.iter().position(|&a| a == c)?).ok()?;
        acc = (acc << 5) | v;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
        // Drop the bits already emitted as bytes so the stale high bits can
        // never re-enter the next byte on the following shift.
        acc &= (1u32 << bits) - 1;
    }
    Some(out)
}

/// Encode bytes as RFC 4648 base-32 (no `=` padding).
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((acc >> bits) & 0x1f) as usize]));
        }
        acc &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(B32[((acc << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// Encode a StrKey: `base32_encode(version || payload || crc16_xmodem(version || payload))`.
/// The checksum is appended little-endian (low byte first), matching
/// stellar-strkey.
pub fn strkey_encode(version: u8, payload: &[u8]) -> String {
    let mut raw = Vec::with_capacity(payload.len() + 3);
    raw.push(version);
    raw.extend_from_slice(payload);
    let crc = crc16_xmodem(&raw);
    // stellar-strkey appends the checksum in little-endian byte order.
    raw.push((crc & 0xff) as u8);
    raw.push((crc >> 8) as u8);
    base32_encode(&raw)
}
