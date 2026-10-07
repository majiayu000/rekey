//! Development hygiene. Secret matching runs inside the Authority worker;
//! only source positions and signed connection names leave that boundary.

use std::collections::BTreeSet;
use std::fmt;

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use rekey_domain::ids::CredentialId;
use zeroize::Zeroizing;

use crate::AuthorityError;

pub mod env;
pub use env::{
    EnvImportEntry, EnvImportReport, EnvImportRequest, EnvImportSelection, EnvPreview,
    EnvReplacement, EnvUnsupported, preview_env, rewrite_env,
};

pub const SCAN_MAX_FINDINGS: usize = 4096;
pub const SCAN_FILE_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const SCAN_TOTAL_MAX_BYTES: usize = 100 * 1024 * 1024;

pub struct ScanInput {
    pub path: String,
    pub bytes: Zeroizing<Vec<u8>>,
}
impl ScanInput {
    pub fn new(path: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            bytes: Zeroizing::new(bytes),
        }
    }
}
impl fmt::Debug for ScanInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScanInput")
            .field("path", &self.path)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// Constructed from the daemon's verified connections, never agent metadata.
#[derive(Debug, Clone)]
pub struct ScanCredential {
    pub connection: String,
    pub credential_id: CredentialId,
}

pub use rekey_domain::ipc::ScanFinding;

pub(crate) fn validate_scan_inputs(inputs: &[ScanInput]) -> Result<(), AuthorityError> {
    let mut total = 0usize;
    for input in inputs {
        if input.bytes.len() > SCAN_FILE_MAX_BYTES {
            return Err(invalid("scan file exceeds 10 MiB"));
        }
        total = total
            .checked_add(input.bytes.len())
            .ok_or_else(|| invalid("scan exceeds 100 MiB"))?;
        if total > SCAN_TOTAL_MAX_BYTES {
            return Err(invalid("scan exceeds 100 MiB"));
        }
    }
    Ok(())
}

pub(crate) fn invalid(message: &'static str) -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition(message.to_owned()).into()
}

/// Complete direct representations only. No credential substrings or base64
/// alignment fragments become needles, even for long credentials.
pub fn matching_positions(bytes: &[u8], secret: &[u8]) -> Result<Vec<usize>, AuthorityError> {
    if secret.is_empty() {
        return Ok(Vec::new());
    }
    let needles = [
        Zeroizing::new(secret.to_vec()),
        Zeroizing::new(BASE64.encode(secret).into_bytes()),
        Zeroizing::new(BASE64_NOPAD.encode(secret).into_bytes()),
        Zeroizing::new(BASE64URL.encode(secret).into_bytes()),
        Zeroizing::new(BASE64URL_NOPAD.encode(secret).into_bytes()),
        Zeroizing::new(HEXLOWER.encode(secret).into_bytes()),
        Zeroizing::new(HEXUPPER.encode(secret).into_bytes()),
    ];
    let mut positions = BTreeSet::new();
    find_positions(bytes, None, &needles, &mut positions)?;
    if bytes.contains(&b'%') {
        let (decoded, offsets) = percent_projection(bytes);
        find_positions(&decoded, Some(&offsets), &needles, &mut positions)?;
    }
    if bytes.contains(&b'\\') {
        let (decoded, offsets) = json_projection(bytes);
        find_positions(&decoded, Some(&offsets), &needles, &mut positions)?;
    }
    Ok(positions.into_iter().collect())
}

fn find_positions(
    bytes: &[u8],
    offsets: Option<&[usize]>,
    needles: &[Zeroizing<Vec<u8>>],
    out: &mut BTreeSet<usize>,
) -> Result<(), AuthorityError> {
    for needle in needles {
        if needle.len() > bytes.len() {
            continue;
        }
        for (index, window) in bytes.windows(needle.len()).enumerate() {
            if window == needle.as_slice() {
                out.insert(offsets.map_or(index, |map| map[index]));
                if out.len() > SCAN_MAX_FINDINGS {
                    return Err(invalid("too many scan findings; scan a smaller input"));
                }
            }
        }
    }
    Ok(())
}

fn percent_projection(bytes: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<usize>) {
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        offsets.push(index);
        let escaped = bytes.get(index..index + 3).and_then(|triplet| {
            if triplet[0] != b'%' {
                return None;
            }
            Some(
                ((triplet[1] as char).to_digit(16)? << 4 | (triplet[2] as char).to_digit(16)?)
                    as u8,
            )
        });
        if let Some(byte) = escaped {
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    (decoded, offsets)
}

fn json_projection(bytes: &[u8]) -> (Zeroizing<Vec<u8>>, Vec<usize>) {
    fn unit(bytes: &[u8]) -> Option<u16> {
        if bytes.len() < 6 || &bytes[..2] != b"\\u" {
            return None;
        }
        bytes[2..6].iter().try_fold(0u16, |value, b| {
            Some((value << 4) | (*b as char).to_digit(16)? as u16)
        })
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut offsets = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if let Some(first) = unit(rest) {
            let codepoint = if (0xd800..=0xdbff).contains(&first) {
                unit(&rest[6..])
                    .filter(|second| (0xdc00..=0xdfff).contains(second))
                    .and_then(|second| {
                        char::from_u32(
                            0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second)
                                - 0xdc00,
                        )
                        .map(|ch| (ch, 12))
                    })
            } else {
                char::from_u32(u32::from(first)).map(|ch| (ch, 6))
            };
            if let Some((ch, length)) = codepoint {
                let mut utf8 = [0; 4];
                let encoded = ch.encode_utf8(&mut utf8).as_bytes();
                decoded.extend_from_slice(encoded);
                offsets.extend(std::iter::repeat_n(index, encoded.len()));
                index += length;
                continue;
            }
        }
        let escaped = if rest.len() >= 2 && rest[0] == b'\\' {
            match rest[1] {
                b'"' | b'\\' | b'/' => Some(rest[1]),
                b'b' => Some(8),
                b'f' => Some(12),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                _ => None,
            }
        } else {
            None
        };
        offsets.push(index);
        if let Some(byte) = escaped {
            decoded.push(byte);
            index += 2;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    (decoded, offsets)
}

pub(crate) fn finding(input: &ScanInput, offset: usize, connection: &str) -> ScanFinding {
    let prefix = &input.bytes[..offset];
    let line = 1 + prefix.iter().filter(|byte| **byte == b'\n').count() as u64;
    let column = offset
        - prefix
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |last| last + 1)
        + 1;
    ScanFinding {
        path: input.path.clone(),
        line: line as u32,
        column: column as u32,
        connection: connection.to_owned(),
    }
}
