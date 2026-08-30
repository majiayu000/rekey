use data_encoding::BASE32_NOPAD;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use super::KEY_LEN;
use crate::error::AuthorityError;

pub const RECOVERY_PREFIX: &str = "RKREC1-";
const CHECKSUM_LEN: usize = 4;
const GROUP: usize = 6;

fn checksum(key: &[u8; KEY_LEN]) -> [u8; CHECKSUM_LEN] {
    let digest = Sha256::digest(key);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// `RKREC1-` + grouped uppercase base32 of `key || sha256(key)[..4]`.
pub fn encode_recovery_key(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    let mut payload = [0u8; KEY_LEN + CHECKSUM_LEN];
    payload[..KEY_LEN].copy_from_slice(key);
    payload[KEY_LEN..].copy_from_slice(&checksum(key));
    let raw = BASE32_NOPAD.encode(&payload);
    payload.zeroize();

    let mut grouped = String::with_capacity(RECOVERY_PREFIX.len() + raw.len() + raw.len() / GROUP);
    grouped.push_str(RECOVERY_PREFIX);
    for (i, c) in raw.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            grouped.push('-');
        }
        grouped.push(c);
    }
    Zeroizing::new(grouped)
}

/// Ignores `-` and spaces; strictly checks prefix, length, and checksum.
pub fn parse_recovery_key(input: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, AuthorityError> {
    let trimmed = input.trim();
    let rest = trimmed
        .strip_prefix(RECOVERY_PREFIX)
        .ok_or(AuthorityError::InvalidUnlockCredential)?;
    let compact: String = rest
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let mut decoded = BASE32_NOPAD
        .decode(compact.as_bytes())
        .map_err(|_| AuthorityError::InvalidUnlockCredential)?;
    if decoded.len() != KEY_LEN + CHECKSUM_LEN {
        decoded.zeroize();
        return Err(AuthorityError::InvalidUnlockCredential);
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decoded[..KEY_LEN]);
    let expected = checksum(&key);
    let ok = decoded[KEY_LEN..] == expected;
    decoded.zeroize();
    if !ok {
        key.zeroize();
        return Err(AuthorityError::InvalidUnlockCredential);
    }
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0xabu8; KEY_LEN];
        let display = encode_recovery_key(&key);
        assert!(display.starts_with(RECOVERY_PREFIX));
        let parsed = parse_recovery_key(&display).unwrap();
        assert_eq!(*parsed, key);
        // whitespace and lowercase tolerated
        let sloppy = display.to_lowercase().replace('-', " ");
        let sloppy = sloppy.replacen("rkrec1 ", "RKREC1-", 1);
        assert_eq!(*parse_recovery_key(&sloppy).unwrap(), key);
    }

    #[test]
    fn rejects_bad_input() {
        let key = [0x01u8; KEY_LEN];
        let display = encode_recovery_key(&key);
        assert!(parse_recovery_key("RKREC2-AAAA").is_err());
        assert!(parse_recovery_key("no-prefix").is_err());
        assert!(parse_recovery_key(&display[..display.len() - 2]).is_err());
        let mut corrupted = display.to_string();
        let flip = corrupted.pop().unwrap();
        corrupted.push(if flip == 'A' { 'B' } else { 'A' });
        assert!(parse_recovery_key(&corrupted).is_err());
    }
}
