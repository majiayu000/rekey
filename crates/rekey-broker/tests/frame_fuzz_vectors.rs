//! Deterministic fuzz vectors for the frame codec: no panic on any input,
//! strict rejection of every malformed class.

use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{Channel, FRAME_HEADER_LEN, FrameError, FrameHeader, METADATA_MAX_BYTES};

fn valid_header() -> [u8; FRAME_HEADER_LEN] {
    FrameHeader {
        channel: Channel::Admin,
        flags: 0,
        message_type: 1,
        request_id: RequestId::new_random(),
        metadata_len: 128,
        body_len: 64,
    }
    .encode()
}

#[test]
fn single_byte_mutations_never_panic() {
    let base = valid_header();
    for index in 0..FRAME_HEADER_LEN {
        for delta in [0x01u8, 0x80, 0xff] {
            let mut mutated = base;
            mutated[index] ^= delta;
            // Must either decode to something structurally valid or return a
            // typed error; never panic.
            let _ = FrameHeader::decode(&mutated);
        }
    }
}

#[test]
fn malformed_classes_rejected() {
    let mut bad_magic = valid_header();
    bad_magic[0..4].copy_from_slice(b"HTTP");
    assert_eq!(FrameHeader::decode(&bad_magic), Err(FrameError::BadMagic));

    let mut bad_version = valid_header();
    bad_version[4..6].copy_from_slice(&0u16.to_be_bytes());
    assert_eq!(
        FrameHeader::decode(&bad_version),
        Err(FrameError::UnsupportedVersion)
    );

    let mut bad_channel = valid_header();
    bad_channel[6] = 0;
    assert_eq!(
        FrameHeader::decode(&bad_channel),
        Err(FrameError::UnknownChannel)
    );
    bad_channel[6] = 3;
    assert_eq!(
        FrameHeader::decode(&bad_channel),
        Err(FrameError::UnknownChannel)
    );

    let mut reserved = valid_header();
    reserved[11] = 0xff;
    assert_eq!(
        FrameHeader::decode(&reserved),
        Err(FrameError::NonZeroReserved)
    );

    let mut nil_request = valid_header();
    nil_request[12..28].copy_from_slice(&[0u8; 16]);
    assert_eq!(
        FrameHeader::decode(&nil_request),
        Err(FrameError::InvalidField)
    );

    let mut huge_meta = valid_header();
    huge_meta[28..32].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        FrameHeader::decode(&huge_meta),
        Err(FrameError::SectionTooLarge)
    );

    let mut boundary = valid_header();
    boundary[28..32].copy_from_slice(&METADATA_MAX_BYTES.to_be_bytes());
    assert!(FrameHeader::decode(&boundary).is_ok());
    boundary[28..32].copy_from_slice(&(METADATA_MAX_BYTES + 1).to_be_bytes());
    assert_eq!(
        FrameHeader::decode(&boundary),
        Err(FrameError::SectionTooLarge)
    );
}

#[test]
fn proof_body_fuzz_vectors() {
    use rekey_domain::ipc::{ProofKind, encode_proof_and_secret_body, parse_proof_and_secret_body};
    let mut valid = Vec::new();
    encode_proof_and_secret_body(ProofKind::Password, b"proof", b"secret", &mut valid);

    // Truncations at every length must error, never panic.
    for len in 0..valid.len() {
        assert!(
            parse_proof_and_secret_body(&valid[..len]).is_err(),
            "len {len}"
        );
    }
    // Trailing garbage rejected.
    let mut extended = valid.clone();
    extended.push(0);
    assert!(parse_proof_and_secret_body(&extended).is_err());
    // Length-field lies rejected.
    let mut lying = valid.clone();
    lying[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_proof_and_secret_body(&lying).is_err());
    // Unknown proof kind rejected.
    let mut unknown_kind = valid;
    unknown_kind[0] = 9;
    assert!(parse_proof_and_secret_body(&unknown_kind).is_err());
}
