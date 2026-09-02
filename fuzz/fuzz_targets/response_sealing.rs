#![no_main]

use data_encoding::{BASE64, BASE64_NOPAD, BASE64URL, BASE64URL_NOPAD};
use libfuzzer_sys::fuzz_target;
use rekey_broker::executor::fuzz_response_sealing;

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
    let variants = [
        secret.to_vec(),
        BASE64.encode(secret).into_bytes(),
        BASE64_NOPAD.encode(secret).into_bytes(),
        BASE64URL.encode(secret).into_bytes(),
        BASE64URL_NOPAD.encode(secret).into_bytes(),
        percent_encode(secret, false, false),
        percent_encode(secret, true, false),
        percent_encode(secret, false, true),
    ];
    for variant in variants {
        assert!(fuzz_response_sealing(secret, secret, &variant, false));
        if std::str::from_utf8(&variant).is_ok() {
            assert!(fuzz_response_sealing(secret, secret, &variant, true));
        }
    }
});

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
