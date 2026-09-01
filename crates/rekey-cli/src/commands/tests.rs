use super::*;

#[test]
fn ttl_parser_rejects_overflow() {
    assert_eq!(parse_ttl_ms("1h").unwrap(), 3_600_000);
    let error = parse_ttl_ms("2305843009213693953s").unwrap_err();
    assert_eq!(error.code, "USAGE");
}

#[test]
fn recovery_step_up_uses_the_recovery_proof_kind() {
    let body = proof_body(true, b"RKREC1-test");
    let (kind, proof) = ipc::parse_proof_body(&body).unwrap();
    assert_eq!(kind, ProofKind::Recovery);
    assert_eq!(proof, b"RKREC1-test");
}

#[test]
fn bounded_reader_rejects_before_growing_past_the_limit() {
    let input = std::io::Cursor::new(vec![b'x'; 18]);
    let error = read_bounded(input, 16, "test input").unwrap_err();
    assert_eq!(error.code, "INVALID_FRAME");
}

#[test]
fn secret_line_reader_applies_the_limit_to_each_line() {
    let limit = ipc::ADMIN_SECRET_FIELD_MAX_BYTES as usize;
    let mut input = vec![b'p'; limit];
    input.push(b'\n');
    input.extend_from_slice(&vec![b's'; limit]);
    input.push(b'\n');
    let lines = read_lines_bounded(input.as_slice(), 2, limit, "test input").unwrap();
    assert_eq!(lines[0].len(), limit);
    assert_eq!(lines[1].len(), limit);

    let error =
        read_lines_bounded(vec![b'x'; limit + 1].as_slice(), 1, limit, "test input").unwrap_err();
    assert_eq!(error.code, "INVALID_FRAME");
}

#[test]
fn secret_line_reader_stops_at_the_required_newline() {
    struct OneByteReader {
        bytes: &'static [u8],
        offset: usize,
    }

    impl Read for OneByteReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            assert!(self.offset < self.bytes.len(), "reader polled past newline");
            output[0] = self.bytes[self.offset];
            self.offset += 1;
            Ok(1)
        }
    }

    let mut reader = OneByteReader {
        bytes: b"secret\nproducer-stays-open",
        offset: 0,
    };
    let lines = read_lines_bounded(&mut reader, 1, 64, "test input").unwrap();
    assert_eq!(lines[0].as_slice(), b"secret");
    assert_eq!(reader.offset, b"secret\n".len());
}

#[cfg(unix)]
#[test]
fn backup_rejects_non_utf8_output_before_reading_proof() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let output = PathBuf::from(OsString::from_vec(b"backup-\xff.rkbackup".to_vec()));
    let error = backup(Path::new("missing-state"), &output, false, false).unwrap_err();
    assert_eq!(error.code, "USAGE");
    assert!(error.message.contains("valid UTF-8"));
}
