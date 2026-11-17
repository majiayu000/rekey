//! Request body coding on the loopback service. Git smart HTTP gzips larger
//! upload-pack requests, so a `github-git` Connection decodes exactly one
//! bounded gzip member before policy, approval and the upstream see the body.
//! Any other coding, and any coding on another Connection, is refused before
//! admission; the upstream always receives the uncoded body.
use std::io::Read;

use hyper::header::HeaderMap;

use crate::error::BrokerError;

const UNSUPPORTED: BrokerError = BrokerError::LocalCall(
    "INVALID_INPUT",
    "compressed request bodies are accepted only for Git smart HTTP",
    "Send the request body uncompressed; only a github-git Connection accepts Content-Encoding: gzip.",
);
const MALFORMED: BrokerError = BrokerError::LocalCall(
    "INVALID_INPUT",
    "the gzip request body is malformed",
    "Send exactly one complete gzip member, or send the body uncompressed.",
);

/// The body the Connection call uses, decoded at most once within `limit`.
pub(super) fn decoded_body(
    headers: &HeaderMap,
    preset: &str,
    body: Vec<u8>,
    limit: usize,
) -> Result<Vec<u8>, (u16, BrokerError)> {
    match super::single(headers, "content-encoding").map_err(|e| (400, e))? {
        None => Ok(body),
        Some(coding) if coding.eq_ignore_ascii_case("identity") => Ok(body),
        Some(coding) if coding.eq_ignore_ascii_case("gzip") && preset == "github-git" => {
            gunzip(&body, limit)
        }
        Some(_) => Err((400, UNSUPPORTED)),
    }
}

fn gunzip(compressed: &[u8], limit: usize) -> Result<Vec<u8>, (u16, BrokerError)> {
    let mut decoder = flate2::bufread::GzDecoder::new(compressed);
    let mut body = Vec::new();
    // One byte past the limit proves the decoded body is too large without
    // inflating the rest of a compression bomb.
    let read = (&mut decoder).take(limit as u64 + 1).read_to_end(&mut body);
    if body.len() > limit {
        return Err((400, rekey_domain::DomainError::RequestTooLarge.into()));
    }
    // A verified trailer ends the member; any further byte is refused.
    if read.is_err() || decoder.header().is_none() || !decoder.into_inner().is_empty() {
        return Err((400, MALFORMED));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append("content-encoding", value.parse().unwrap());
        }
        map
    }

    fn refused(result: Result<Vec<u8>, (u16, BrokerError)>) -> (u16, &'static str, String) {
        let (status, error) = result.unwrap_err();
        (status, error.code(), error.to_string())
    }

    #[test]
    fn git_gzip_is_decoded_once_and_identity_passes_through() {
        let pktlines = b"0014command=ls-refs\n0000".to_vec();
        for coding in ["gzip", "GZIP"] {
            assert_eq!(
                decoded_body(&headers(&[coding]), "github-git", gzip(&pktlines), 64).unwrap(),
                pktlines
            );
        }
        // A body exactly at the limit is accepted; the encoded form is not decoded twice.
        let nested = gzip(&pktlines);
        assert_eq!(
            decoded_body(
                &headers(&["gzip"]),
                "github-git",
                gzip(&nested),
                nested.len()
            )
            .unwrap(),
            nested
        );
        for (map, preset) in [
            (headers(&[]), "anthropic"),
            (headers(&["identity"]), "anthropic"),
            (headers(&["Identity"]), "github-git"),
        ] {
            assert_eq!(
                decoded_body(&map, preset, pktlines.clone(), 64).unwrap(),
                pktlines
            );
        }
    }

    #[test]
    fn other_codings_connections_and_duplicates_are_refused() {
        let body = gzip(b"{}");
        for (map, preset) in [
            (headers(&["gzip"]), "anthropic"),
            (headers(&["gzip"]), "github-pat"),
            (headers(&["deflate"]), "github-git"),
            (headers(&["br"]), "github-git"),
            (headers(&["gzip, gzip"]), "github-git"),
        ] {
            let (status, code, message) = refused(decoded_body(&map, preset, body.clone(), 64));
            assert_eq!((status, code), (400, "INVALID_INPUT"), "{preset}");
            assert!(message.contains("only for Git smart HTTP"), "{message}");
        }
        let (status, code, _) = refused(decoded_body(
            &headers(&["gzip", "gzip"]),
            "github-git",
            body,
            64,
        ));
        assert_eq!((status, code), (400, "INVALID_FRAME"));
    }

    #[test]
    fn bombs_truncation_corruption_and_trailing_bytes_fail_closed() {
        // 2 MiB of zeros is a few KiB compressed; decoding stops one byte past the limit.
        let bomb = gzip(&vec![0; 2 * 1024 * 1024]);
        assert!(bomb.len() < 16 * 1024);
        let (status, code, _) = refused(gunzip(&bomb, 1024 * 1024));
        assert_eq!((status, code), (400, "REQUEST_TOO_LARGE"));
        let valid = gzip(b"0009done\n0000");
        let mut corrupt_crc = valid.clone();
        let crc = corrupt_crc.len() - 8;
        corrupt_crc[crc] ^= 0xff;
        let mut corrupt_size = valid.clone();
        let size = corrupt_size.len() - 4;
        corrupt_size[size] ^= 0x01;
        for malformed in [
            Vec::new(),
            b"0009done\n0000".to_vec(),
            valid[..valid.len() - 1].to_vec(),
            valid[..10].to_vec(),
            corrupt_crc,
            corrupt_size,
            [valid.as_slice(), b"x"].concat(),
            [valid.as_slice(), valid.as_slice()].concat(),
        ] {
            let (status, code, message) = refused(gunzip(&malformed, 1024));
            assert_eq!((status, code), (400, "INVALID_INPUT"));
            assert!(message.contains("malformed"), "{message}");
        }
    }
}
