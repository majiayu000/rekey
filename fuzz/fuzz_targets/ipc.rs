#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    Channel, FRAME_HEADER_LEN, FrameHeader, ProofKind, encode_proof_and_secret_body,
    encode_proof_body, parse_proof_and_secret_body, parse_proof_body,
};

fuzz_target!(|data: &[u8]| {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    let copied = data.len().min(FRAME_HEADER_LEN);
    header[..copied].copy_from_slice(&data[..copied]);
    let _ = FrameHeader::decode(&header);
    let _ = parse_proof_body(data);
    let _ = parse_proof_and_secret_body(data);

    let mut request_bytes = [0_u8; 16];
    let id_bytes = data.len().min(request_bytes.len());
    request_bytes[..id_bytes].copy_from_slice(&data[..id_bytes]);
    let valid = FrameHeader {
        channel: if data.first().is_some_and(|byte| byte & 1 == 1) {
            Channel::Agent
        } else {
            Channel::Admin
        },
        flags: 0,
        message_type: u16::from_be_bytes([
            data.first().copied().unwrap_or(0),
            data.get(1).copied().unwrap_or(0),
        ]),
        request_id: RequestId::from_random_bytes(request_bytes),
        metadata_len: data.len().min(64 * 1024) as u32,
        body_len: data.len().min(1024 * 1024) as u32,
    };
    assert_eq!(FrameHeader::decode(&valid.encode()), Ok(valid));

    let proof_kind = if data.first().is_some_and(|byte| byte & 2 == 2) {
        ProofKind::Recovery
    } else {
        ProofKind::Password
    };
    let mut body = Vec::new();
    encode_proof_body(proof_kind, data, &mut body);
    assert_eq!(parse_proof_body(&body), Ok((proof_kind, data)));

    let split = data.len() / 2;
    body.clear();
    encode_proof_and_secret_body(proof_kind, &data[..split], &data[split..], &mut body);
    assert_eq!(
        parse_proof_and_secret_body(&body),
        Ok((proof_kind, &data[..split], &data[split..]))
    );
});
