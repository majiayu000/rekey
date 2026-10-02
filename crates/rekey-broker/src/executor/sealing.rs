use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use zeroize::Zeroizing;

use crate::upstream::ResponseHeaders;

/// Direct encodings of the secret (and the full auth header value) that a
/// reflecting upstream could echo: raw, base64 standard/url with and without
/// padding, and full percent-encoding. Percent escape comparison normalizes
/// hex digit case because each escape is independently case-insensitive.
pub(super) fn sealing_needles(secret: &[u8], auth_value: &[u8]) -> Vec<Zeroizing<Vec<u8>>> {
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
