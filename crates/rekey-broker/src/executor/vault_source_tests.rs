use zeroize::Zeroizing;

use super::*;
use crate::upstream::UpstreamResponse;

const PROFILE: &[u8] = br#"{
  "credential_type":"vault-kv-v2-source-v1",
  "origin":"https://vault.example.com",
  "mount":"secret",
  "path":"agents/github",
  "key":"token",
  "version":7,
  "vault_token":"hvs.source-canary"
}"#;

fn response(value: serde_json::Value) -> UpstreamResponse {
    UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: Zeroizing::new(serde_json::to_vec(&value).unwrap()),
    }
}

#[test]
fn profile_builds_one_exact_versioned_read() {
    let profile = VaultKvProfile::parse_profile(PROFILE).unwrap();
    let request = profile.request(Duration::from_secs(2));
    assert_eq!(request.host, "vault.example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.method, FixedMethod::Get);
    assert_eq!(request.path, "/v1/secret/data/agents/github?version=7");
    assert_eq!(
        request.headers,
        [("accept".to_owned(), "application/json".to_owned())]
    );
    assert_eq!(request.auth_header.0, "x-vault-token");
    assert_eq!(&*request.auth_header.1, b"hvs.source-canary");
    assert!(request.body.is_empty());
    assert_eq!(request.response_max_bytes, 64 * 1024);
}

#[test]
fn response_is_exactly_version_and_single_field_bound() {
    let profile = VaultKvProfile::parse_profile(PROFILE).unwrap();
    let valid = response(serde_json::json!({
        "data": {
            "data": {"token":"resolved-canary"},
            "metadata": {"version":7,"deletion_time":"","destroyed":false},
            "provider_extra":"ignored"
        },
        "request_id":"ignored"
    }));
    assert_eq!(&*profile.resolve(&valid).unwrap(), b"resolved-canary");

    for invalid in [
        serde_json::json!({"data":{"data":{"other":"x"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x","other":"y"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":8,"deletion_time":"","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":7,"deletion_time":"2026-09-03T00:00:00Z","destroyed":false}}}),
        serde_json::json!({"data":{"data":{"token":"x"},"metadata":{"version":7,"deletion_time":"","destroyed":true}}}),
        serde_json::json!({"data":{"data":{"token":{"nested":true}},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}),
    ] {
        assert!(profile.resolve(&response(invalid)).is_err());
    }

    let duplicate = br#"{"data":{"data":{"token":"first","token":"second"},"metadata":{"version":7,"deletion_time":"","destroyed":false}}}"#;
    let duplicate = UpstreamResponse {
        status: 200,
        headers: Vec::new().into(),
        body: Zeroizing::new(duplicate.to_vec()),
    };
    assert_eq!(
        profile.resolve(&duplicate).map(|_| ()),
        Err(VaultKvError::SourceResponse)
    );

    let maximum = response(serde_json::json!({
        "data":{"data":{"token":"x".repeat(8 * 1024)},"metadata":{"version":7,"deletion_time":"","destroyed":false}}
    }));
    assert_eq!(profile.resolve(&maximum).unwrap().len(), 8 * 1024);
    for value in [
        String::new(),
        "contains space".to_owned(),
        "x".repeat(8 * 1024 + 1),
    ] {
        let invalid = response(serde_json::json!({
            "data":{"data":{"token":value},"metadata":{"version":7,"deletion_time":"","destroyed":false}}
        }));
        assert_eq!(
            profile.resolve(&invalid).map(|_| ()),
            Err(VaultKvError::SourceResponse)
        );
    }
}

#[test]
fn profile_rejects_open_or_unsafe_configuration() {
    for invalid in [
        br#"{"credential_type":"wrong","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"http://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"../secret","path":"a","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a/../b","key":"token","version":1,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":0,"vault_token":"hvs.x"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"bad token"}"#.as_slice(),
        br#"{"credential_type":"vault-kv-v2-source-v1","origin":"https://vault.example.com","mount":"secret","path":"a","key":"token","version":1,"vault_token":"hvs.x","extra":true}"#.as_slice(),
    ] {
        assert_eq!(
            VaultKvProfile::parse_profile(invalid).map(|_| ()),
            Err(VaultKvError::InvalidCredential)
        );
    }

    for (field, value) in [
        ("mount", "x".repeat(129)),
        (
            "path",
            std::iter::repeat_n("x", 17).collect::<Vec<_>>().join("/"),
        ),
        ("key", "x".repeat(129)),
        ("vault_token", "x".repeat(4_097)),
    ] {
        let mut raw: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        raw[field] = value.into();
        assert_eq!(
            VaultKvProfile::parse_profile(&serde_json::to_vec(&raw).unwrap()).map(|_| ()),
            Err(VaultKvError::InvalidCredential)
        );
    }
}
