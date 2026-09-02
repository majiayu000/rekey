#![no_main]

use libfuzzer_sys::fuzz_target;
use rekey_domain::ipc::{
    FRAME_HEADER_LEN, FrameHeader, parse_proof_and_secret_body, parse_proof_body,
};

fuzz_target!(|data: &[u8]| {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    let copied = data.len().min(FRAME_HEADER_LEN);
    header[..copied].copy_from_slice(&data[..copied]);
    let _ = FrameHeader::decode(&header);
    let _ = parse_proof_body(data);
    let _ = parse_proof_and_secret_body(data);
});
