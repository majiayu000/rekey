use serde::de::DeserializeSeed;

use super::*;

const PROFILE: &[u8] = br#"{
  "credential_type":"vault-dynamic-source-v1",
  "origin":"https://vault.example.com",
  "mount":"database",
  "role":"agent-api-token",
  "key":"token",
  "vault_token":"hvs.bootstrap"
}"#;

fn parse_issued(body: &[u8]) -> Result<ParsedIssued, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let parsed = (IssuedSeed { key: "token" }).deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(parsed)
}

#[test]
fn profile_accepts_only_the_closed_shape() {
    let profile = VaultDynamicProfile::parse_profile(PROFILE).unwrap();
    assert_eq!(profile.origin.host(), "vault.example.com");
    assert_eq!(profile.mount, "database");
    assert_eq!(profile.role, "agent-api-token");
    assert_eq!(profile.key, "token");
    assert_eq!(profile.token(), b"hvs.bootstrap");

    for invalid in [
        br#"{}"#.as_slice(),
        br#"{"credential_type":"vault-dynamic-source-v1","credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","vault_token":"hvs.x","extra":true}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"http://vault.example.com","mount":"database","role":"role","key":"token","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com/path","mount":"database","role":"role","key":"token","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"bad/path","role":"role","key":"token","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"database","role":"bad/path","key":"token","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"database","role":"role","key":"","vault_token":"hvs.x"}"#,
        br#"{"credential_type":"vault-dynamic-source-v1","origin":"https://vault.example.com","mount":"database","role":"role","key":"token","vault_token":""}"#,
    ] {
        assert_eq!(
            VaultDynamicProfile::parse_profile(invalid).map(|_| ()),
            Err(VaultDynamicError::InvalidCredential)
        );
    }

    for (field, invalid_value) in [
        ("mount", "m".repeat(129)),
        ("role", "r".repeat(129)),
        ("key", "k".repeat(129)),
        ("vault_token", "t".repeat(4_097)),
    ] {
        let mut value: serde_json::Value = serde_json::from_slice(PROFILE).unwrap();
        value[field] = invalid_value.into();
        assert_eq!(
            VaultDynamicProfile::parse_profile(&serde_json::to_vec(&value).unwrap()).map(|_| ()),
            Err(VaultDynamicError::InvalidCredential)
        );
    }
}

#[test]
fn issued_response_extracts_one_bounded_selected_value() {
    let parsed = parse_issued(
        br#"{"lease_id":"database/creds/role/abc","lease_duration":60,"renewable":true,"data":{"username":"ignored","token":"dynamic-secret"},"request_id":"ignored"}"#,
    )
    .unwrap();
    assert_eq!(parsed.lease_id.as_str(), "database/creds/role/abc");
    assert_eq!(parsed.lease_duration, 60);
    assert_eq!(&*parsed.value, b"dynamic-secret");

    for duration in [5, 300] {
        let body = format!(
            r#"{{"lease_id":"id","lease_duration":{duration},"renewable":false,"data":{{"token":"x"}}}}"#
        );
        assert!(parse_issued(body.as_bytes()).is_ok());
    }

    for invalid in [
        br#"{"lease_id":"id","lease_duration":4,"renewable":true,"data":{"token":"x"}}"#.as_slice(),
        br#"{"lease_id":"id","lease_duration":301,"renewable":true,"data":{"token":"x"}}"#,
        br#"{"lease_id":"id","lease_id":"other","lease_duration":60,"renewable":true,"data":{"token":"x"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":"x","token":"y"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":null}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"other":"x"}}"#,
        br#"{"lease_id":"id","lease_duration":60,"renewable":true,"data":{"token":"x"}} trailing"#,
    ] {
        assert!(parse_issued(invalid).is_err());
    }
}

#[test]
fn lease_probe_is_bounded_and_rejects_escaped_values() {
    let probe = probe_lease_ids(
        br#"{"lease_id":"one","nested":{"lease_id":"two"},"more":[{"lease_id":"three"},{"lease_id":"four"},{"lease_id":"five"}]}"#,
    );
    assert_eq!(probe.occurrences, 5);
    assert_eq!(probe.lease_ids.len(), LEASE_CAPTURE_LIMIT);
    assert!(probe.truncated);

    let escaped = probe_lease_ids(br#"{"lease_id":"escaped\\u002did"}"#);
    assert_eq!(escaped.occurrences, 0);
    assert!(escaped.lease_ids.is_empty());
}
