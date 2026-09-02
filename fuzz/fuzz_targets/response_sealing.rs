#![no_main]

use data_encoding::{BASE64, BASE64URL_NOPAD};
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
        BASE64URL_NOPAD.encode(secret).into_bytes(),
        percent_encode_all(secret),
    ];
    for variant in variants {
        assert!(fuzz_response_sealing(secret, secret, &variant, false));
        if std::str::from_utf8(&variant).is_ok() {
            assert!(fuzz_response_sealing(secret, secret, &variant, true));
        }
    }
});

fn percent_encode_all(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(bytes.len() * 3);
    for byte in bytes {
        encoded.extend_from_slice(&[b'%', HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
    }
    encoded
}
