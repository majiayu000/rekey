use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD, HEXLOWER, HEXUPPER};
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
    // Several encodings coincide for ASCII credentials. Scan each exact byte
    // sequence once; the detection union and maximum held tail are unchanged.
    needles.sort_unstable_by(|a, b| a.as_slice().cmp(b.as_slice()));
    needles.dedup_by(|a, b| a.as_slice() == b.as_slice());
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
    needles.sort_unstable_by(|a, b| a.as_slice().cmp(b.as_slice()));
    needles.dedup_by(|a, b| a.as_slice() == b.as_slice());
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
    if memchr::memchr(needle[0], haystack).is_none() {
        return false;
    }
    memchr::memmem::find(haystack, needle).is_some()
}

pub(crate) fn contains_secret(haystack: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> bool {
    if needles.iter().any(|needle| find_subslice(haystack, needle)) {
        return true;
    }
    if memchr::memchr(b'\\', haystack).is_some() {
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
    if memchr::memchr(b'%', haystack).is_none() {
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

    // Keep all four projections unconditional to detect an invalid marker
    // guard. The bytewise literal search is independent of the fast matcher.
    fn ungated_contains_secret(haystack: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> bool {
        fn literal(haystack: &[u8], needle: &[u8]) -> bool {
            !needle.is_empty()
                && needle.len() <= haystack.len()
                && haystack.windows(needle.len()).any(|bytes| bytes == needle)
        }
        let json = decode_json_escapes(haystack);
        let percent = percent_decode(haystack);
        let folded = normalize_percent_hex(haystack);
        needles.iter().any(|needle| {
            literal(haystack, needle)
                || literal(&json, needle)
                || literal(&percent, needle)
                || literal(&folded, &normalize_percent_hex(needle))
        })
    }

    #[test]
    fn transform_guards_match_ungated_reference_for_short_binary_inputs() {
        fn inputs(max_len: u32) -> Vec<Vec<u8>> {
            let alphabet = [0, b'a', b'A', b'%', b'\\', b'0', 0xff];
            let mut values = Vec::new();
            for length in 0..=max_len {
                for mut value in 0..(alphabet.len() as u32).pow(length) {
                    let mut bytes = Vec::new();
                    for _ in 0..length {
                        bytes.push(alphabet[value as usize % alphabet.len()]);
                        value /= alphabet.len() as u32;
                    }
                    values.push(bytes);
                }
            }
            values
        }
        let haystacks = inputs(4);
        let candidates = inputs(2);
        for haystack in &haystacks {
            assert!(!contains_secret(haystack, &[]));
            assert!(!contains_secret(haystack, &[Zeroizing::new(Vec::new())]));
            for (index, needle) in candidates.iter().enumerate() {
                let needles = [
                    Zeroizing::new(Vec::new()),
                    Zeroizing::new(needle.clone()),
                    Zeroizing::new(needle.clone()),
                    Zeroizing::new(candidates[(index + 17) % candidates.len()].clone()),
                ];
                assert_eq!(
                    contains_secret(haystack, &needles),
                    ungated_contains_secret(haystack, &needles),
                    "haystack={haystack:?}, needle={needle:?}"
                );
            }
        }
    }

    #[test]
    fn transform_guards_preserve_partial_malformed_and_single_projection_contracts() {
        let cases: &[(&[u8], &[u8], bool)] = &[
            (b"ordinary", b"synthetic", false),
            (br"\u0073", b"s", true),
            (br"\u007", b"s", false),
            (br"\uZZ73", b"s", false),
            (br"\u007", br"\u007", true),
            (br"\/", b"/", true),
            (br"\n", b"\n", true),
            (br"\q", b"q", true),
            (br"\", b"s", false),
            (br"\uD83D\uDE00", "😀".as_bytes(), true),
            (br"\uD83D\u0041", b"A", true),
            (br"\uDE00", "😀".as_bytes(), false),
            (b"%72", b"r", true),
            (b"%7", b"r", false),
            (b"%", b"r", false),
            (b"%g2", b"r", false),
            (b"%7", b"%7", true),
            (b"%AB", b"%ab", true),
            (b"%aB%Cd%eF", b"%ab%cd%EF", true),
            (br"\u0025\u0037\u0033", b"s", false),
            (b"%5Cu0073", b"s", false),
            (b"%2573", b"s", false),
            (br"\\u0073", b"s", false),
        ];
        for (fragment, needle, expected) in cases {
            let needles = [Zeroizing::new(needle.to_vec())];
            for (prefix, suffix) in [(0, 9), (7, 9), (7, 0)] {
                let mut haystack = vec![0xfe; prefix];
                haystack.extend_from_slice(fragment);
                haystack.extend(vec![0xfe; suffix]);
                assert_eq!(
                    ungated_contains_secret(&haystack, &needles),
                    *expected,
                    "reference fragment={fragment:?}, needle={needle:?}"
                );
                assert_eq!(
                    contains_secret(&haystack, &needles),
                    *expected,
                    "fragment={fragment:?}, needle={needle:?}, prefix={prefix}"
                );
            }
        }
    }

    #[test]
    fn percent_fold_only_reflections_keep_independent_hex_case() {
        let needles = [Zeroizing::new(b"%ab%CD%ef".to_vec())];
        let haystack = b"%Ab%cd%eF";
        assert!(!find_subslice(haystack, &needles[0]));
        assert!(!find_subslice(&percent_decode(haystack), &needles[0]));
        assert!(!find_subslice(&decode_json_escapes(haystack), &needles[0]));
        assert!(contains_secret(haystack, &needles));
        assert_eq!(
            contains_secret(haystack, &needles),
            ungated_contains_secret(haystack, &needles)
        );
    }

    #[test]
    fn every_generated_needle_matches_each_single_projection_at_every_position() {
        fn mixed_percent_case(bytes: &[u8]) -> Vec<u8> {
            let mut result = bytes.to_vec();
            let mut index = 0;
            let mut escape = 0;
            while index + 2 < result.len() {
                if result[index] == b'%'
                    && result[index + 1].is_ascii_hexdigit()
                    && result[index + 2].is_ascii_hexdigit()
                {
                    if escape % 2 == 0 {
                        result[index + 1].make_ascii_uppercase();
                        result[index + 2].make_ascii_lowercase();
                    } else {
                        result[index + 1].make_ascii_lowercase();
                        result[index + 2].make_ascii_uppercase();
                    }
                    escape += 1;
                    index += 3;
                } else {
                    index += 1;
                }
            }
            result
        }
        let secret = b"SYNTHETIC-REFLECTION/?+~_=20261005";
        let auth = [b"Bearer ".as_slice(), secret].concat();
        let needles = sealing_needles(secret, &auth);
        for needle in &needles {
            let only = [Zeroizing::new(needle.to_vec())];
            let json = needle
                .iter()
                .map(|byte| format!("\\u{byte:04x}"))
                .collect::<String>()
                .into_bytes();
            for (projection, form) in [
                ("literal", needle.to_vec()),
                ("JSON", json),
                ("percent", percent_encode_all(needle)),
                ("fold", mixed_percent_case(needle)),
            ] {
                for (prefix, suffix) in [(0, 9), (7, 9), (7, 0)] {
                    let mut haystack = vec![0xfe; prefix];
                    haystack.extend_from_slice(&form);
                    haystack.extend(vec![0xfe; suffix]);
                    assert!(
                        ungated_contains_secret(&haystack, &only),
                        "reference projection={projection}, needle={needle:?}"
                    );
                    assert!(
                        contains_secret(&haystack, &only),
                        "projection={projection}, needle={needle:?}, prefix={prefix}"
                    );
                    assert!(contains_secret(&haystack, &needles));
                }
            }
        }
    }

    #[test]
    fn literal_search_matches_reference_for_short_binary_inputs() {
        fn inputs(max_len: u32) -> Vec<Vec<u8>> {
            let alphabet = [0, b'a', 0xff];
            let mut values = Vec::new();
            for length in 0..=max_len {
                for mut value in 0..3_u32.pow(length) {
                    let mut bytes = Vec::new();
                    for _ in 0..length {
                        bytes.push(alphabet[(value % 3) as usize]);
                        value /= 3;
                    }
                    values.push(bytes);
                }
            }
            values
        }
        let haystacks = inputs(6);
        let needles = inputs(5);
        for haystack in &haystacks {
            for needle in &needles {
                let expected = !needle.is_empty()
                    && needle.len() <= haystack.len()
                    && haystack.windows(needle.len()).any(|bytes| bytes == needle);
                assert_eq!(find_subslice(haystack, needle), expected);
            }
        }
        // Longer overlapping prefixes exercise the optimized algorithm beyond
        // the short-needle paths covered by exhaustive binary enumeration.
        let haystack = [vec![b'a'; 4096], b"b".to_vec()].concat();
        for length in [16, 32, 64, 255, 4096, 4097, 4098] {
            let needle = [vec![b'a'; length - 1], b"b".to_vec()].concat();
            let expected = needle.len() <= haystack.len()
                && haystack.windows(needle.len()).any(|bytes| bytes == needle);
            assert_eq!(find_subslice(&haystack, &needle), expected);
        }
    }

    #[test]
    fn literal_prefilter_preserves_all_first_bytes_and_match_positions() {
        assert!(!find_subslice(b"", b""));
        assert!(!find_subslice(b"ordinary", b""));
        assert!(!find_subslice(b"a", b"aa"));
        for first in 0..=u8::MAX {
            let needle = [first, first.wrapping_add(1), 0x80, 0, 0xff];
            let absent: Vec<u8> = (0..=u8::MAX).filter(|byte| *byte != first).collect();
            assert!(!find_subslice(&absent, &needle), "first={first}");
            assert!(!find_subslice(&[first; 64], &needle), "first={first}");
            for (prefix, suffix) in [(0, 9), (7, 9), (7, 0)] {
                let mut haystack = vec![first.wrapping_add(17); prefix];
                haystack.extend_from_slice(&needle);
                haystack.extend(vec![first.wrapping_add(17); suffix]);
                assert!(find_subslice(&haystack, &needle), "first={first}");
            }
        }
        assert!(find_subslice(b"ababababac", b"ababac"));
        assert!(!find_subslice(b"ababababab", b"ababac"));
        assert!(find_subslice(b"aaaaaab", b"aaaab"));
        assert!(!find_subslice(b"aaaaaaa", b"aaaab"));
    }

    #[test]
    fn literal_prefilter_keeps_marker_heavy_nonreflections_false() {
        let secret = b"SYNTHETIC-REKEY-BENCH-SECRET";
        let auth = [b"Bearer ".as_slice(), secret].concat();
        let needles = sealing_needles(secret, &auth);
        for body in [
            br"S!B!C!J!N!Q!T!U!4!5!%!\u0078%78\q%g2\\text\/raw\n".as_slice(),
            br"\u0025\u0035\u0033%5Cu0053%2553".as_slice(),
            br"\u0053YNTHETIC-REKEY-BENCH-SECREX%53YNTHETIC-REKEY-BENCH-SECREX".as_slice(),
        ] {
            assert!(!ungated_contains_secret(body, &needles));
            assert!(!contains_secret(body, &needles));
        }
    }

    #[test]
    fn large_body_reflections_at_start_middle_and_end_are_sealed() {
        const BODY_BYTES: usize = 4 * 1024 * 1024;
        let secret = b"SYNTHETIC-SCANNER-REFLECTION-ONLY";
        let auth = [b"Bearer ".as_slice(), secret].concat();
        let needles = sealing_needles(secret, &auth);
        let mut forms = vec![secret.to_vec(), auth];
        for encoding in [
            &BASE64,
            &BASE64_NOPAD,
            &BASE64URL,
            &BASE64URL_NOPAD,
            &HEXLOWER,
            &HEXUPPER,
        ] {
            forms.push(encoding.encode(secret).into_bytes());
        }
        forms.push(percent_encode_all(secret));
        forms.push(
            secret
                .iter()
                .map(|byte| format!("\\u{byte:04x}"))
                .collect::<String>()
                .into_bytes(),
        );
        let mut body = vec![b'x'; BODY_BYTES];
        assert!(!contains_secret(&body, &needles));
        for form in forms {
            for position in [0, BODY_BYTES / 2, BODY_BYTES - form.len()] {
                body[position..position + form.len()].copy_from_slice(&form);
                assert!(
                    contains_secret(&body, &needles),
                    "missed form length={} at position={position}",
                    form.len()
                );
                body[position..position + form.len()].fill(b'x');
            }
        }
        assert!(!contains_secret(&body, &needles));
    }

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
