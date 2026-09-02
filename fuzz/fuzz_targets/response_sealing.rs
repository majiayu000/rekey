#![no_main]

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use libfuzzer_sys::fuzz_target;
use rekey_broker::executor::{fuzz_response_header_name_sealing, fuzz_response_sealing};

fuzz_target!(|data: &[u8]| {
    let first = data.len() / 3;
    let second = first.saturating_mul(2);
    let _ = fuzz_response_sealing(
        &data[..first],
        &data[first..second],
        &data[second..],
        data.first().is_some_and(|byte| byte & 1 == 1),
    );

    let secret = if data.is_empty() {
        b"fuzz-secret".as_slice()
    } else {
        data
    };
    let mut auth_value = b"Bearer ".to_vec();
    auth_value.extend_from_slice(secret);
    for variant in sealing_variants(secret) {
        assert!(fuzz_response_sealing(secret, &auth_value, &variant, false));
        if std::str::from_utf8(&variant).is_ok() {
            assert!(fuzz_response_sealing(secret, &auth_value, &variant, true));
        }
    }
    for variant in sealing_variants(&auth_value) {
        assert!(fuzz_response_sealing(secret, &auth_value, &variant, false));
        if std::str::from_utf8(&variant).is_ok() {
            assert!(fuzz_response_sealing(secret, &auth_value, &variant, true));
        }
    }

    let negative_secret = b"negative-case-secret-0x8f7e6d5c";
    let negative_auth = b"Bearer negative-case-secret-0x8f7e6d5c";
    let unrelated = b"upstream response without credential material";
    assert!(!fuzz_response_sealing(
        negative_secret,
        negative_auth,
        unrelated,
        false,
    ));
    assert!(!fuzz_response_sealing(
        negative_secret,
        negative_auth,
        unrelated,
        true,
    ));

    let mut header_name = b"x-rekey-".to_vec();
    header_name.extend(
        data.iter()
            .take(32)
            .map(|byte| b'a'.saturating_add(byte % 26)),
    );
    let mut header_auth = b"Bearer ".to_vec();
    header_auth.extend_from_slice(&header_name);
    assert!(fuzz_response_header_name_sealing(
        &header_name,
        &header_auth,
        &header_name,
    ));
});

fn sealing_variants(value: &[u8]) -> [Vec<u8>; 8] {
    [
        value.to_vec(),
        BASE64.encode(value).into_bytes(),
        BASE64_NOPAD.encode(value).into_bytes(),
        BASE64URL.encode(value).into_bytes(),
        BASE64URL_NOPAD.encode(value).into_bytes(),
        percent_encode(value, false, false),
        percent_encode(value, true, false),
        percent_encode(value, false, true),
    ]
}

fn percent_encode(bytes: &[u8], uppercase: bool, encode_all: bool) -> Vec<u8> {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";
    let hex = if uppercase { UPPER_HEX } else { LOWER_HEX };
    let mut encoded = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        if !encode_all
            && (byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
        {
            encoded.push(*byte);
        } else {
            encoded.extend_from_slice(&[
                b'%',
                hex[(byte >> 4) as usize],
                hex[(byte & 0x0f) as usize],
            ]);
        }
    }
    encoded
}
