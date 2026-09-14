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
