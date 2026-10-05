use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
use zeroize::Zeroizing;

use crate::upstream::ResponseHeaders;

/// Direct encodings of the secret (and the full auth header value) that a
/// reflecting upstream could echo: raw, base64 standard/url with and without
/// padding, and full percent-encoding. Percent escape comparison normalizes
/// hex digit case because each escape is independently case-insensitive.
pub(crate) fn sealing_needles(secret: &[u8], auth_value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
    let mut needles = Vec::new();
    for source in [secret, auth_value] {
        if source.is_empty() {
            continue;
        }
        needles.push(Zeroizing::new(source.to_vec()));
        needles.push(Zeroizing::new(BASE64.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64_NOPAD.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64URL.encode(source).into_bytes()));
        needles.push(Zeroizing::new(BASE64URL_NOPAD.encode(source).into_bytes()));
        needles.push(Zeroizing::new(HEXLOWER.encode(source).into_bytes()));
        needles.push(Zeroizing::new(HEXUPPER.encode(source).into_bytes()));
        // A prefix/suffix changes the base64 edge sextets. Keep only sextets
        // wholly inside the secret, for each of the three byte alignments.
        for offset in (0..3).filter(|_| source.len() >= 16) {
            let mut aligned = Zeroizing::new(vec![0; offset]);
            aligned.extend_from_slice(source);
            let start = (offset * 8).div_ceil(6);
            let end = (aligned.len() * 8) / 6;
            if start < end {
                for encoding in [&BASE64_NOPAD, &BASE64URL_NOPAD] {
                    let encoded = Zeroizing::new(encoding.encode(&aligned).into_bytes());
                    needles.push(Zeroizing::new(encoded[start..end].to_vec()));
                }
            }
        }
        needles.push(Zeroizing::new(percent_encode(source, false).into_bytes()));
        needles.push(Zeroizing::new(percent_encode(source, true).into_bytes()));
        needles.push(Zeroizing::new(percent_encode_all(source)));
    }
    needles
}

/// Fixed HTTP representations only; the transmitted value remains untouched.
pub(super) fn fixed_header_sealing_needles(
    secret: &[u8],
    actual_auth: &[u8],
    registered_prefix: &[u8],
) -> Vec<Zeroizing<Vec<u8>>> {
    fn edge_ows(mut bytes: &[u8]) -> &[u8] {
        while bytes
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            bytes = &bytes[1..];
        }
        while bytes
            .last()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            bytes = &bytes[..bytes.len() - 1];
        }
        bytes
    }

    let mut needles = sealing_needles(secret, actual_auth);
    let value = edge_ows(secret);
    if !value.is_empty() && (value != secret || edge_ows(actual_auth) != actual_auth) {
        let mut normalized_auth = Zeroizing::new(registered_prefix.to_vec());
        normalized_auth.extend_from_slice(value);
        needles.extend(sealing_needles(value, edge_ows(&normalized_auth)));
        needles.extend(sealing_needles(value, edge_ows(actual_auth)));
    }
    needles
}

fn percent_encode_all(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        out.extend_from_slice(&[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
    }
    out
}

pub(super) fn percent_encode(bytes: &[u8], uppercase: bool) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(*b as char);
        } else if uppercase {
            out.push_str(&format!("%{b:02X}"));
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

pub(crate) fn contains_secret(haystack: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> bool {
    if needles.iter().any(|needle| find_subslice(haystack, needle)) {
        return true;
    }
    if haystack.contains(&b'\\') {
        let json_decoded = decode_json_escapes(haystack);
        if needles
            .iter()
            .any(|needle| find_subslice(&json_decoded, needle))
        {
            return true;
        }
    }
    // With no percent marker both projections equal the raw bytes already
    // checked above. Avoid rescanning each bytewise SSE window unchanged.
    if !haystack.contains(&b'%') {
        return false;
    }
    let decoded_haystack = percent_decode(haystack);
    if needles
        .iter()
        .any(|needle| find_subslice(&decoded_haystack, needle))
    {
        return true;
    }
    let normalized_haystack = normalize_percent_hex(haystack);
    needles.iter().any(|needle| {
        let normalized_needle = normalize_percent_hex(needle);
        find_subslice(&normalized_haystack, &normalized_needle)
    })
}

// Scan escape sequences without requiring a whole JSON document: the caller
// also scans bounded SSE windows. Invalid/incomplete escapes remain literal.
// This is a detection projection, never a parser used for authorization.
fn decode_json_escapes(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    fn code_unit(bytes: &[u8]) -> Option<u16> {
        if bytes.len() < 6 || &bytes[..2] != b"\\u" {
            return None;
        }
        bytes[2..6].iter().try_fold(0, |value, byte| {
            (*byte as char)
                .to_digit(16)
                .map(|digit| (value << 4) | digit as u16)
        })
    }
    let mut result = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if let Some(first) = code_unit(rest) {
            let decoded = if (0xd800..=0xdbff).contains(&first) {
                code_unit(&rest[6..])
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
            if let Some((ch, consumed)) = decoded {
                let mut utf8 = [0; 4];
                result.extend_from_slice(ch.encode_utf8(&mut utf8).as_bytes());
                index += consumed;
                continue;
            }
        }
        if rest.len() >= 2 && rest[0] == b'\\' {
            let escaped = match rest[1] {
                b'"' | b'\\' | b'/' => Some(rest[1]),
                b'b' => Some(8),
                b'f' => Some(12),
                b'n' => Some(b'\n'),
                b'r' => Some(b'\r'),
                b't' => Some(b'\t'),
                _ => None,
            };
            if let Some(byte) = escaped {
                result.push(byte);
                index += 2;
                continue;
            }
        }
        result.push(bytes[index]);
        index += 1;
    }
    result
}

fn percent_decode(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        if index + 2 < bytes.len()
            && bytes[index] == b'%'
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            let high = (bytes[index + 1] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (bytes[index + 2] as char).to_digit(16).unwrap_or(0) as u8;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    decoded
}

fn normalize_percent_hex(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut normalized = Zeroizing::new(bytes.to_vec());
    let mut index = 0;
    while index + 2 < normalized.len() {
        if normalized[index] == b'%'
            && normalized[index + 1].is_ascii_hexdigit()
            && normalized[index + 2].is_ascii_hexdigit()
        {
            normalized[index + 1].make_ascii_lowercase();
            normalized[index + 2].make_ascii_lowercase();
            index += 3;
        } else {
            index += 1;
        }
    }
    normalized
}

pub(super) fn headers_contain_secret(
    headers: &ResponseHeaders,
    needles: &[Zeroizing<Vec<u8>>],
) -> bool {
    headers
        .name_value_bytes()
        .any(|(name, value)| contains_secret(name, needles) || contains_secret(value, needles))
}

#[cfg(test)]
mod v3_tests {
    use super::*;

    #[test]
    fn detects_embedded_base64_for_all_alignments_and_tails() {
        for length in 16..20 {
            let secret = &b"v3-unique-secret-1234"[..length];
            let needles = sealing_needles(secret, secret);
            for prefix in 0..9 {
                for suffix in 0..5 {
                    let mut reflected = vec![0xfb; prefix];
                    reflected.extend_from_slice(secret);
                    reflected.extend(vec![0xff; suffix]);
                    for encoding in [&BASE64, &BASE64_NOPAD, &BASE64URL, &BASE64URL_NOPAD] {
                        assert!(
                            contains_secret(encoding.encode(&reflected).as_bytes(), &needles),
                            "missed length={length}, prefix={prefix}, suffix={suffix}"
                        );
                    }
                }
            }
            assert!(!contains_secret(
                b"ordinary safe response with no reflected credential",
                &needles
            ));
        }
    }

    #[test]
    fn detects_hex_and_mixed_json_unicode_escapes() {
        let secret = b"synthetic-secret-1234";
        let needles = sealing_needles(secret, secret);
        for encoding in [&HEXLOWER, &HEXUPPER] {
            assert!(contains_secret(
                encoding.encode(secret).as_bytes(),
                &needles
            ));
        }
        assert!(contains_secret(
            br#"{"data":"synthetic-\u0073ecret-1234"}"#,
            &needles
        ));
        let all_escaped = secret
            .iter()
            .map(|byte| format!("\\u{byte:04X}"))
            .collect::<String>();
        assert!(contains_secret(all_escaped.as_bytes(), &needles));
        assert!(!contains_secret(
            br#"{"data":"synthetic-\uZZZZecret-1234"}"#,
            &needles
        ));
    }

    #[test]
    fn short_secrets_do_not_create_single_character_alignment_needles() {
        let needles = sealing_needles(b"x", b"x");
        assert!(!contains_secret(b"hello", &needles));
        assert!(contains_secret(b"eA==", &needles));
        assert!(contains_secret(br"\u0078", &needles));
    }

    #[test]
    fn json_projection_handles_surrogates_and_incomplete_windows() {
        assert_eq!(&*decode_json_escapes(br"x\uD83D\uDE00y"), "x😀y".as_bytes());
        assert_eq!(&*decode_json_escapes(br"x\uD83D\u0041y"), br"x\uD83DAy");
        assert_eq!(&*decode_json_escapes(br"x\u12"), br"x\u12");
        assert_eq!(&*decode_json_escapes(br"a\n\t\"), b"a\n\t\\");
        assert_eq!(&*decode_json_escapes(br"\\u0073"), br"\u0073");
    }
}
