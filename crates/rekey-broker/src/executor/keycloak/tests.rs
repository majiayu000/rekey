use super::*;

#[test]
fn malformed_tokens_are_captured_before_response_validation() {
    let (tokens, count) = captured_tokens(
        br#"{"access_token":"FIRST-ISSUED-TOKEN", "access_token":"SECOND-ISSUED-TOKEN", broken"#,
    );
    assert_eq!(count, 2);
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[1].as_str(), "SECOND-ISSUED-TOKEN");
}

#[test]
fn json_string_content_needles_match_prefix_suffix_and_optional_slashes() {
    let secret = "synthetic-quote\"-slash/-backslash\\";
    let needles = json_string_needles(secret);
    let standard = serde_json::to_vec(&format!("prefix:{secret}:suffix")).unwrap();
    assert!(contains_secret(&standard, &needles));
    let optional = String::from_utf8(standard.clone())
        .unwrap()
        .replace('/', "\\/");
    assert!(contains_secret(optional.as_bytes(), &needles));
    let content = serde_json::to_string(secret).unwrap();
    let content = &content.as_bytes()[1..content.len() - 1];
    assert!(contains_secret(
        data_encoding::BASE64.encode(content).as_bytes(),
        &needles
    ));
    assert!(!contains_secret(b"clean-public-response", &needles));
}

#[tokio::test]
async fn escaped_bootstrap_issued_tokens_are_rejected_without_revoke_ownership() {
    let raw = serde_json::to_vec(&serde_json::json!({"credential_type":"keycloak-token-exchange-v1","origin":"https://issuer.example.com","realm":"realm","client_id":"client","client_secret":"synthetic-client-secret","subject_token":"synthetic-subject-token","audience":"audience","target_origin":"https://api.example.com","target_path":"/business"})).unwrap();
    let profile = KeycloakProfile::parse_profile(&raw).unwrap();
    for value in [
        profile.client_secret.as_str(),
        profile.subject_token.as_str(),
    ] {
        let escaped = value
            .bytes()
            .map(|b| format!("\\u{:04x}", b))
            .collect::<String>();
        let body = serde_json::to_string(&serde_json::json!({"access_token":value,"token_type":"Bearer","issued_token_type":TOKEN_TYPE,"expires_in":60})).unwrap().replace(value, &escaped).into_bytes();
        assert!(!contains_secret(&body, &profile.needles()));
        let decoded: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(decoded["access_token"], value);
        let fake = crate::testing::FakeUpstreamTransport::new();
        fake.push_response(Ok(crate::upstream::UpstreamResponse {
            status: 200,
            headers: vec![].into(),
            body: Zeroizing::new(body),
        }));
        let exchange = profile
            .exchange(&fake, Instant::now() + Duration::from_secs(10))
            .await;
        assert!(exchange.value.is_err());
        assert!(exchange.tokens.is_empty());
        assert_eq!(fake.take_requests().len(), 1);
    }
}
