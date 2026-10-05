//! StrKey input validation (issue #52).
//!
//! Nothing in this module performs I/O, which is what makes "malformed input
//! never reaches an RPC" testable: `agent-tx` validates every address-typed
//! flag here, before it constructs an RPC client. See [`crate::network`] for
//! the other pre-network concern, endpoint selection.
//!
//! # Network-vs-prefix policy
//!
//! A StrKey's leading character comes from its version byte, which encodes the
//! *key type* (`G` account, `C` contract, `S` secret seed) and never the
//! network. The same Ed25519 key has the same string form on testnet,
//! futurenet and mainnet, so no prefix check can tell a "testnet address" from
//! a "mainnet address" and validation deliberately does not try to: rejecting
//! on prefix would be a false guarantee. Which network a call reaches is
//! decided by `--network`/`--rpc-url` and the network passphrase; a
//! well-formed contract ID deployed on a different network fails at
//! simulation (`MISSING_CONTRACT`), not here. `mainnet` additionally prints
//! the unaudited-contract reminder, because that is where a wrong-network or
//! accidental call can move real funds.

use super::{base32_decode, crc16_xmodem, VER_ACCOUNT, VER_CONTRACT};

/// Version byte of an account secret seed (`S...`).
const VER_SECRET: u8 = 0x90;
/// A 32-byte payload with version byte and CRC16 checksum, base-32 encoded:
/// `ceil(35 * 8 / 5) == 56` characters, with no `=` padding.
const STRKEY_LEN: usize = 56;
/// RFC 4648 base-32 alphabet, which is what Stellar's StrKey uses.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn in_alphabet(c: char) -> bool {
    c.is_ascii() && !c.is_ascii_lowercase() && ALPHABET.contains(&(c.to_ascii_uppercase() as u8))
}

/// Which kind of key a flag expects.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// `C...` — a contract ID (the guard, a token contract).
    Contract,
    /// `G...` — an account ID (an admin).
    Account,
    /// `G...` or `C...` — a transfer recipient may be either.
    Recipient,
    /// `S...` — the registered agent's secret seed.
    Secret,
}

impl KeyKind {
    fn versions(self) -> &'static [u8] {
        match self {
            Self::Contract => &[VER_CONTRACT],
            Self::Account => &[VER_ACCOUNT],
            Self::Recipient => &[VER_ACCOUNT, VER_CONTRACT],
            Self::Secret => &[VER_SECRET],
        }
    }

    /// The rule quoted in every rejection, so the message fixes itself.
    fn rule(self) -> String {
        let prefixes = self
            .versions()
            .iter()
            .map(|v| format!("'{}'", prefix_for(*v)))
            .collect::<Vec<_>>()
            .join(" or ");
        format!(
            "{prefixes} followed by 55 uppercase characters from `A-Z2-7` whose CRC16-XModem \
             checksum matches"
        )
    }
}

/// The leading character a StrKey with this version byte renders as. StrKey is
/// base-32 over `version || payload || crc`, so it carries the top 5 bits of
/// the version byte.
fn prefix_for(version: u8) -> char {
    char::from(ALPHABET[usize::from(version >> 3)])
}

fn version_name(version: u8) -> String {
    match version {
        VER_ACCOUNT => "an account ID (leading character 'G')".to_string(),
        VER_CONTRACT => "a contract ID (leading character 'C')".to_string(),
        VER_SECRET => "a secret seed (leading character 'S')".to_string(),
        other => format!("an unrecognized StrKey version byte 0x{other:02x}"),
    }
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

/// Validate one address-typed CLI value against the rule for `kind`. Every
/// rejection names the field and the rule it broke.
pub fn validate_key(field: &str, kind: KeyKind, value: &str) -> Result<[u8; 32], String> {
    let (version, key) = decode_strkey(value).map_err(|reason| {
        format!(
            "invalid {field} '{value}': {reason}; expected {}",
            kind.rule()
        )
    })?;
    if !kind.versions().contains(&version) {
        return Err(format!(
            "invalid {field} '{value}': {} is not accepted here; expected {}",
            version_name(version),
            kind.rule()
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{account_strkey, contract_strkey};

    /// An account ID from the repository's own known vector (pubkey
    /// `1cb479ac…cc05`), so the positive cases are checked against something
    /// outside this module's encoder.
    const KNOWN_ACCOUNT: &str = "GAOLI6NMXG5X3GZ2ASTIMX24IQQW7CSGHVSOU7HOWFCH73RBZXGAKSPP";

    fn valid_contract() -> String {
        contract_strkey(&[0x01u8; 32])
    }

    #[test]
    fn known_account_strkey_validates_as_account_and_recipient() {
        let key = validate_key("--to", KeyKind::Account, KNOWN_ACCOUNT).unwrap();
        assert_eq!(
            hex::encode(key),
            "1cb479acb9bb7d9b3a04a6865f5c44216f8a463d64ea7ceeb1447fee21cdcc05"
        );
        assert!(validate_key("--to", KeyKind::Recipient, KNOWN_ACCOUNT).is_ok());
    }

    #[test]
    fn all_zero_key_is_a_valid_edge_case() {
        // A 32-byte all-zero public key is well formed, not a placeholder for
        // "missing": it must validate rather than trip the format checks.
        let account = account_strkey(&[0u8; 32]);
        let contract = contract_strkey(&[0u8; 32]);
        assert_eq!(
            validate_key("--to", KeyKind::Account, &account).unwrap(),
            [0u8; 32]
        );
        assert_eq!(
            validate_key("--guard", KeyKind::Contract, &contract).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn secret_seed_validates_and_rejects_other_key_types() {
        let secret = "SBRVOEN5IIWAROJVJI2OHN2IYD2H3S75UOM3UKY7RQ42JRDPH5KRHQC4";
        assert!(validate_key("--agent-secret", KeyKind::Secret, secret).is_ok());
        let err = validate_key("--agent-secret", KeyKind::Secret, KNOWN_ACCOUNT).unwrap_err();
        assert!(err.contains("--agent-secret"), "{err}");
        assert!(err.contains("'S' followed by"), "{err}");
    }

    fn rejection(kind: KeyKind, value: &str) -> String {
        validate_key("--guard", kind, value).unwrap_err()
    }

    #[test]
    fn rejections_name_the_field_and_the_rule_broken() {
        let contract = valid_contract();

        let err = rejection(KeyKind::Contract, "");
        assert!(err.starts_with("invalid --guard"), "{err}");
        assert!(err.contains("the value is empty"), "{err}");

        let err = rejection(KeyKind::Contract, &contract.to_lowercase());
        assert!(
            err.contains("lowercase") && err.contains("case-sensitive"),
            "{err}"
        );

        let err = rejection(KeyKind::Contract, "C0123!@#$%");
        assert!(err.contains("base-32 alphabet"), "{err}");

        // A truncated address: the last 8 characters dropped.
        let err = rejection(KeyKind::Contract, &contract[..48]);
        assert!(err.contains("expected 56 characters, got 48"), "{err}");

        // Same length, one character mistyped: the checksum catches it, which
        // is what stops a plausible-but-wrong address reaching the network.
        let mut mistyped = contract.clone();
        mistyped.replace_range(40..41, if &contract[40..41] == "A" { "B" } else { "A" });
        let err = rejection(KeyKind::Contract, &mistyped);
        assert!(
            err.contains("CRC16-XModem checksum does not match"),
            "{err}"
        );

        let err = rejection(KeyKind::Contract, KNOWN_ACCOUNT);
        assert!(err.contains("an account ID"), "{err}");
        assert!(err.contains("expected 'C' followed by"), "{err}");

        let err = rejection(KeyKind::Account, &contract);
        assert!(err.contains("a contract ID"), "{err}");
        assert!(err.contains("expected 'G' followed by"), "{err}");
    }

    #[test]
    fn recipient_accepts_both_key_types() {
        assert!(validate_key("--to", KeyKind::Recipient, KNOWN_ACCOUNT).is_ok());
        assert!(validate_key("--to", KeyKind::Recipient, &valid_contract()).is_ok());
    }

    #[test]
    fn validation_is_network_agnostic() {
        // Documented policy: the version byte carries the key type, not the
        // network, so the same string validates whatever network the endpoint
        // selects. Nothing here can (or claims to) catch a testnet contract ID
        // aimed at mainnet — see the module doc.
        let contract = valid_contract();
        for _ in 0..3 {
            assert!(validate_key("--guard", KeyKind::Contract, &contract).is_ok());
        }
    }
}
