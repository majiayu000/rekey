//! Pure verification for the fixed administrator OIDC login boundary.
use std::collections::BTreeSet;

use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::Timestamp;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{PolicyError, parse_unique_json};

const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 512;
const MAX_KEYS: usize = 8;
const MAX_AGE_MS: i64 = 300_000;

/// Trusted values from the node profile and the same completed code response.
/// Profile configuration is validated by the caller at its trusted boundary.
pub struct OidcAdminContext<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub expected_nonce: &'a str,
    pub now: Timestamp,
    pub access_token: &'a str,
}

/// Verified identity facts only; this grants no administrator eligibility.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedOidcAdmin {
    pub issuer: String,
    pub subject: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Verify a compact RS256 ID token using only this supplied fixed-source JWKS.
/// No key fetch, refresh, permission inference, or session creation occurs here.
pub fn verify_id_token(
    token: &[u8],
    jwks: &[u8],
    context: &OidcAdminContext<'_>,
) -> Result<VerifiedOidcAdmin, PolicyError> {
    if token.len() > MAX_TOKEN_BYTES || jwks.len() > MAX_JWKS_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let mut segments = token.split(|byte| *byte == b'.');
    let header_segment = segments.next().ok_or(PolicyError::Malformed)?;
    let claims_segment = segments.next().ok_or(PolicyError::Malformed)?;
    let signature_segment = segments.next().ok_or(PolicyError::Malformed)?;
    if segments.next().is_some() {
        return Err(PolicyError::Malformed);
    }
    let header = parse_unique_json(&decode_segment(header_segment)?)?;
    if !header.is_object()
        || text(&header, "alg")? != "RS256"
        || header
            .get("typ")
            .is_some_and(|value| value.as_str() != Some("JWT"))
        || ["crit", "b64", "jku", "x5u"]
            .iter()
            .any(|name| header.get(*name).is_some())
    {
        return Err(PolicyError::Invalid);
    }
    let kid = text(&header, "kid")?;
    bounded_text(kid)?;
    let (n, e) = selected_key(jwks, kid)?;
    let signature = decode_segment(signature_segment)?;
    let signing_input_len = header_segment.len() + 1 + claims_segment.len();
    RsaPublicKeyComponents { n: &n, e: &e }
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            &token[..signing_input_len],
            &signature,
        )
        .map_err(|_| PolicyError::InvalidSignature)?;

    let claims = parse_unique_json(&decode_segment(claims_segment)?)?;
    let issuer = text(&claims, "iss")?;
    let subject = text(&claims, "sub")?;
    bounded_text(subject)?;
    if issuer != context.issuer
        || context.expected_nonce.is_empty()
        || text(&claims, "nonce")? != context.expected_nonce
    {
        return Err(PolicyError::Invalid);
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(audience)) => vec![audience.as_str()],
        Some(Value::Array(values)) if !values.is_empty() && values.len() <= MAX_KEYS => values
            .iter()
            .map(|value| value.as_str().ok_or(PolicyError::Malformed))
            .collect::<Result<_, _>>()?,
        _ => return Err(PolicyError::Malformed),
    };
    let mut unique = BTreeSet::new();
    for audience in &audiences {
        if !unique.insert(*audience) {
            return Err(PolicyError::Invalid);
        }
    }
    if !unique.contains(context.client_id)
        || (audiences.len() > 1 && claims.get("azp").is_none())
        || claims
            .get("azp")
            .is_some_and(|value| value.as_str() != Some(context.client_id))
    {
        return Err(PolicyError::Invalid);
    }
    let issued_at_ms = numeric_date_ms(&claims, "iat")?;
    let expires_at_ms = numeric_date_ms(&claims, "exp")?;
    let now_ms = context.now.as_unix_ms();
    if issued_at_ms > now_ms || expires_at_ms <= issued_at_ms {
        return Err(PolicyError::Invalid);
    }
    if now_ms >= expires_at_ms
        || now_ms
            .checked_sub(issued_at_ms)
            .is_none_or(|age| age > MAX_AGE_MS)
    {
        return Err(PolicyError::Expired);
    }
    if claims.get("nbf").is_some() {
        let not_before_ms = numeric_date_ms(&claims, "nbf")?;
        if not_before_ms > now_ms || not_before_ms >= expires_at_ms {
            return Err(PolicyError::Invalid);
        }
    }
    if claims.get("at_hash").is_some() {
        let digest = Sha256::digest(context.access_token.as_bytes());
        if text(&claims, "at_hash")? != BASE64URL_NOPAD.encode(&digest[..16]) {
            return Err(PolicyError::Invalid);
        }
    }
    Ok(VerifiedOidcAdmin {
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
        issued_at_ms,
        expires_at_ms,
    })
}

fn selected_key(bytes: &[u8], selected_kid: &str) -> Result<(Vec<u8>, Vec<u8>), PolicyError> {
    let document = parse_unique_json(bytes)?;
    let keys = document
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| !keys.is_empty() && keys.len() <= MAX_KEYS)
        .ok_or(PolicyError::Malformed)?;
    let mut kids = BTreeSet::new();
    let mut selected = None;
    for key in keys {
        let kid = text(key, "kid")?;
        bounded_text(kid)?;
        if !matches!(text(key, "kty")?, "RSA" | "EC" | "OKP") {
            return Err(PolicyError::Invalid);
        }
        if let Some(algorithm) = key.get("alg") {
            bounded_text(algorithm.as_str().ok_or(PolicyError::Malformed)?)?;
        }
        if !kids.insert(kid)
            || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
                .iter()
                .any(|name| key.get(*name).is_some())
            || key
                .get("use")
                .is_some_and(|value| value.as_str() != Some("sig"))
            || key.get("key_ops").is_some_and(|value| {
                value
                    .as_array()
                    .is_none_or(|ops| ops.len() != 1 || ops[0].as_str() != Some("verify"))
            })
        {
            return Err(PolicyError::Invalid);
        }
        if kid != selected_kid {
            continue;
        }
        if text(key, "kty")? != "RSA"
            || key
                .get("alg")
                .is_some_and(|value| value.as_str() != Some("RS256"))
        {
            return Err(PolicyError::Invalid);
        }
        let n = decode_segment(text(key, "n")?.as_bytes())?;
        let e = decode_segment(text(key, "e")?.as_bytes())?;
        if !(256..=1024).contains(&n.len()) || n[0] == 0 || e.len() > 8 || e[0] == 0 {
            return Err(PolicyError::Invalid);
        }
        let exponent = e
            .iter()
            .try_fold(0u64, |value, byte| {
                value.checked_mul(256)?.checked_add(u64::from(*byte))
            })
            .ok_or(PolicyError::Invalid)?;
        if exponent < 3 || exponent % 2 == 0 {
            return Err(PolicyError::Invalid);
        }
        RsaPublicKeyComponents { n: &n, e: &e }
            .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
            .map_err(|_| PolicyError::Invalid)?;
        selected = Some((n, e));
    }
    selected.ok_or(PolicyError::InvalidSignature)
}

fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, PolicyError> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .and_then(Value::as_str)
        .ok_or(PolicyError::Malformed)
}

fn bounded_text(value: &str) -> Result<(), PolicyError> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || value.chars().any(char::is_control) {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

fn numeric_date_ms(value: &Value, name: &str) -> Result<i64, PolicyError> {
    value
        .get(name)
        .and_then(Value::as_i64)
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or(PolicyError::Malformed)
}

fn decode_segment(segment: &[u8]) -> Result<Vec<u8>, PolicyError> {
    if segment.is_empty() {
        return Err(PolicyError::Malformed);
    }
    let bytes = BASE64URL_NOPAD
        .decode(segment)
        .map_err(|_| PolicyError::Malformed)?;
    if BASE64URL_NOPAD.encode(&bytes).as_bytes() != segment {
        return Err(PolicyError::Malformed);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};
    use data_encoding::BASE64URL_NOPAD;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    const NOW: i64 = 1_000_000;

    fn key() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate(KeySize::Rsa2048).unwrap())
    }

    fn context() -> OidcAdminContext<'static> {
        OidcAdminContext {
            issuer: "https://issuer.example",
            client_id: "rekey-admin",
            expected_nonce: "flow-nonce",
            now: Timestamp::from_unix_ms(NOW * 1_000),
            access_token: "synthetic-access-token",
        }
    }

    fn claims() -> Value {
        json!({"iss":"https://issuer.example", "sub":"stable-admin",
            "aud":"rekey-admin", "iat":NOW, "exp":NOW+600, "nonce":"flow-nonce"})
    }

    fn header() -> Value {
        json!({"alg":"RS256", "kid":"current", "typ":"JWT"})
    }

    fn jwk(key: &RsaKeyPair, kid: &str) -> Value {
        json!({"kty":"RSA", "kid":kid, "use":"sig", "alg":"RS256", "key_ops":["verify"],
            "n":BASE64URL_NOPAD.encode(key.public_key().modulus().big_endian_without_leading_zero()),
            "e":BASE64URL_NOPAD.encode(key.public_key().exponent().big_endian_without_leading_zero())})
    }

    fn jwks() -> Vec<u8> {
        serde_json::to_vec(&json!({"keys":[jwk(key(), "current")]})).unwrap()
    }

    fn sign_raw(key: &RsaKeyPair, header: &[u8], claims: &[u8]) -> Vec<u8> {
        let input = format!(
            "{}.{}",
            BASE64URL_NOPAD.encode(header),
            BASE64URL_NOPAD.encode(claims)
        );
        let mut signature = vec![0; key.public_modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{input}.{}", BASE64URL_NOPAD.encode(&signature)).into_bytes()
    }

    fn sign(header: &Value, claims: &Value) -> Vec<u8> {
        sign_raw(
            key(),
            &serde_json::to_vec(header).unwrap(),
            &serde_json::to_vec(claims).unwrap(),
        )
    }

    fn verify(claims: &Value) -> Result<VerifiedOidcAdmin, PolicyError> {
        verify_id_token(&sign(&header(), claims), &jwks(), &context())
    }

    #[test]
    fn signed_single_audience_returns_only_identity_times() {
        assert_eq!(
            verify(&claims()).unwrap(),
            VerifiedOidcAdmin {
                issuer: "https://issuer.example".into(),
                subject: "stable-admin".into(),
                issued_at_ms: NOW * 1_000,
                expires_at_ms: (NOW + 600) * 1_000,
            }
        );
        let mut h = header();
        h.as_object_mut().unwrap().remove("typ");
        assert!(verify_id_token(&sign(&h, &claims()), &jwks(), &context()).is_ok());
    }

    #[test]
    fn signed_multi_audience_requires_matching_authorized_party() {
        let mut c = claims();
        c["aud"] = json!(["second-client", "rekey-admin"]);
        assert!(verify(&c).is_err());
        c["azp"] = json!("rekey-admin");
        assert!(verify(&c).is_ok());
        for azp in [json!("other"), Value::Null, json!(1)] {
            c["azp"] = azp;
            assert!(verify(&c).is_err());
        }
        c = claims();
        c["azp"] = json!("other");
        assert!(verify(&c).is_err());
    }

    #[test]
    fn signed_access_hash_binds_same_code_response_token() {
        let mut c = claims();
        c["at_hash"] =
            json!(BASE64URL_NOPAD.encode(&Sha256::digest(context().access_token.as_bytes())[..16]));
        assert!(verify(&c).is_ok());
        let mut ctx = context();
        ctx.access_token = "another-synthetic-token";
        assert!(verify_id_token(&sign(&header(), &c), &jwks(), &ctx).is_err());
        for hash in [
            json!(""),
            json!("a="),
            Value::Null,
            json!(1),
            json!("AAAAAAAAAAAAAAAAAAAAAA"),
        ] {
            c["at_hash"] = hash;
            assert!(verify(&c).is_err());
        }
    }

    #[test]
    fn signed_rotation_requires_newly_supplied_jwks_and_allows_other_algorithm() {
        let new = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let h = json!({"alg":"RS256", "kid":"rotated"});
        let token = sign_raw(
            &new,
            &serde_json::to_vec(&h).unwrap(),
            &serde_json::to_vec(&claims()).unwrap(),
        );
        assert!(verify_id_token(&token, &jwks(), &context()).is_err());
        let keys = json!({"keys":[jwk(key(), "current"), jwk(&new, "rotated"),
            {"kid":"ed-rotation", "kty":"OKP", "alg":"EdDSA", "use":"sig", "crv":"Ed25519", "x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]});
        assert!(verify_id_token(&token, &serde_json::to_vec(&keys).unwrap(), &context()).is_ok());
        let mut keys = keys;
        keys["keys"][1] = jwk(key(), "rotated");
        assert!(verify_id_token(&token, &serde_json::to_vec(&keys).unwrap(), &context()).is_err());
    }

    #[test]
    fn signing_input_and_signature_tampering_fail() {
        let token = sign(&header(), &claims());
        let mut parts: Vec<Vec<u8>> = token.split(|b| *b == b'.').map(<[u8]>::to_vec).collect();
        let mut c = claims();
        c["sub"] = json!("different-admin");
        parts[1] = BASE64URL_NOPAD
            .encode(&serde_json::to_vec(&c).unwrap())
            .into_bytes();
        assert!(verify_id_token(&parts.join(&b'.'), &jwks(), &context()).is_err());
        let mut parts: Vec<Vec<u8>> = token.split(|b| *b == b'.').map(<[u8]>::to_vec).collect();
        let mut sig = BASE64URL_NOPAD.decode(&parts[2]).unwrap();
        sig[0] ^= 1;
        parts[2] = BASE64URL_NOPAD.encode(&sig).into_bytes();
        assert!(matches!(
            verify_id_token(&parts.join(&b'.'), &jwks(), &context()),
            Err(PolicyError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_header_algorithm_confusion_and_extensions_fail() {
        for alg in [
            json!("none"),
            json!("HS256"),
            json!("RS512"),
            json!("EdDSA"),
            Value::Null,
        ] {
            let mut h = header();
            h["alg"] = alg;
            assert!(verify_id_token(&sign(&h, &claims()), &jwks(), &context()).is_err());
        }
        for (name, value) in [
            ("crit", json!([])),
            ("b64", json!(true)),
            ("jku", json!("https://other.example")),
            ("x5u", Value::Null),
            ("typ", json!("at+jwt")),
            ("kid", json!("unknown")),
            ("kid", json!("")),
            ("kid", json!("k".repeat(513))),
            ("kid", json!("bad\n")),
        ] {
            let mut h = header();
            h[name] = value;
            assert!(
                verify_id_token(&sign(&h, &claims()), &jwks(), &context()).is_err(),
                "{name}"
            );
        }
        for name in ["alg", "kid"] {
            let mut h = header();
            h.as_object_mut().unwrap().remove(name);
            assert!(verify_id_token(&sign(&h, &claims()), &jwks(), &context()).is_err());
        }
    }

    #[test]
    fn signed_identity_audience_and_nonce_claims_fail_closed() {
        for (name, value) in [
            ("iss", json!("https://other.example")),
            ("sub", json!("")),
            ("sub", json!("s".repeat(513))),
            ("sub", json!("bad\n")),
            ("sub", Value::Null),
            ("aud", json!("other")),
            ("aud", json!([])),
            ("aud", json!(["rekey-admin", "rekey-admin"])),
            ("aud", json!(["rekey-admin", 1])),
            (
                "aud",
                json!(["a", "b", "c", "d", "e", "f", "g", "h", "rekey-admin"]),
            ),
            ("nonce", json!("wrong")),
            ("nonce", json!("")),
            ("nonce", Value::Null),
            ("nonce", json!(1)),
        ] {
            let mut c = claims();
            c[name] = value;
            assert!(verify(&c).is_err(), "{name}");
        }
        for name in ["iss", "sub", "aud", "nonce"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(name);
            assert!(verify(&c).is_err(), "{name}");
        }
        let mut ctx = context();
        ctx.expected_nonce = "";
        let mut c = claims();
        c["nonce"] = json!("");
        assert!(verify_id_token(&sign(&header(), &c), &jwks(), &ctx).is_err());
    }

    #[test]
    fn signed_time_types_and_checked_conversion_reject_invalid_dates() {
        for name in ["iat", "exp", "nbf"] {
            for value in [
                Value::Null,
                json!("1000000"),
                json!(true),
                json!(1000000.0),
                json!(i64::MAX),
                json!(i64::MIN),
                json!(u64::MAX),
            ] {
                let mut c = claims();
                c[name] = value;
                assert!(verify(&c).is_err(), "{name}");
            }
        }
        for name in ["iat", "exp"] {
            let mut c = claims();
            c.as_object_mut().unwrap().remove(name);
            assert!(verify(&c).is_err());
        }
    }

    #[test]
    fn signed_time_age_expiry_and_not_before_boundaries() {
        let mut c = claims();
        c["iat"] = json!(NOW - 300);
        c["nbf"] = json!(NOW);
        assert!(verify(&c).is_ok());
        c["iat"] = json!(NOW - 301);
        assert!(verify(&c).is_err());
        for (name, value) in [
            ("iat", NOW + 1),
            ("exp", NOW),
            ("exp", NOW - 1),
            ("nbf", NOW + 1),
        ] {
            let mut c = claims();
            c[name] = json!(value);
            assert!(verify(&c).is_err(), "{name}");
        }
        let mut c = claims();
        c["exp"] = json!(NOW);
        c["iat"] = json!(NOW);
        assert!(verify(&c).is_err());
        let mut ctx = context();
        ctx.now = Timestamp::from_unix_ms(i64::MAX - 1_000);
        let mut c = claims();
        c["iat"] = json!(i64::MIN / 1000);
        c["exp"] = json!(i64::MAX / 1000);
        assert!(verify_id_token(&sign(&header(), &c), &jwks(), &ctx).is_err());
        let mut ctx = context();
        ctx.now = Timestamp::from_unix_ms(NOW * 1000 + 999);
        assert!(verify_id_token(&sign(&header(), &claims()), &jwks(), &ctx).is_ok());
    }

    #[test]
    fn duplicate_header_claims_and_nested_unknown_json_rejected() {
        let c = serde_json::to_vec(&claims()).unwrap();
        for h in [
            br#"{"alg":"RS256","alg":"RS256","kid":"current"}"#.as_slice(),
            br#"{"alg":"RS256","kid":"current","unknown":{"a":1,"a":2}}"#.as_slice(),
        ] {
            assert!(verify_id_token(&sign_raw(key(), h, &c), &jwks(), &context()).is_err());
        }
        let h = serde_json::to_vec(&header()).unwrap();
        let c = serde_json::to_string(&claims()).unwrap();
        for extra in [
            ",\"sub\":\"other\"}",
            ",\"unknown\":1,\"unknown\":2}",
            ",\"unknown\":{\"a\":1,\"a\":2}}",
        ] {
            let raw = format!("{}{extra}", &c[..c.len() - 1]);
            assert!(
                verify_id_token(&sign_raw(key(), &h, raw.as_bytes()), &jwks(), &context()).is_err()
            );
        }
    }

    #[test]
    fn jwks_duplicate_kids_fields_and_ambiguous_rotations_rejected() {
        let token = sign(&header(), &claims());
        for keys in [
            json!([jwk(key(), "current"), jwk(key(), "current")]),
            json!([jwk(key(), "current"), {"kid":"current", "kty":"EC", "alg":"ES256"}]),
        ] {
            assert!(
                verify_id_token(
                    &token,
                    &serde_json::to_vec(&json!({"keys":keys})).unwrap(),
                    &context()
                )
                .is_err()
            );
        }
        let raw = String::from_utf8(jwks()).unwrap();
        let raw = raw.replace("\"kty\":\"RSA\"", "\"kty\":\"RSA\",\"kty\":\"RSA\"");
        assert!(verify_id_token(&token, raw.as_bytes(), &context()).is_err());
        let raw = format!(
            "{{\"keys\":{},\"unknown\":1,\"unknown\":2}}",
            json!([jwk(key(), "current")])
        );
        assert!(verify_id_token(&token, raw.as_bytes(), &context()).is_err());
    }

    #[test]
    fn jwks_selected_key_must_be_public_rs256_signing_key() {
        let token = sign(&header(), &claims());
        for (field, value) in [
            ("kty", json!("EC")),
            ("alg", json!("HS256")),
            ("use", json!("enc")),
            ("key_ops", json!(["verify", "sign"])),
            ("key_ops", json!([])),
            ("key_ops", json!(["verify", "verify"])),
            ("key_ops", Value::Null),
            ("n", json!("AA")),
            ("e", json!("Ag")),
            ("e", json!("AAEAAQ")),
            ("e", json!("AQAB=")),
            ("n", json!(BASE64URL_NOPAD.encode(&[255; 255]))),
        ] {
            let mut k = jwk(key(), "current");
            k[field] = value;
            assert!(
                verify_id_token(
                    &token,
                    &serde_json::to_vec(&json!({"keys":[k]})).unwrap(),
                    &context()
                )
                .is_err(),
                "{field}"
            );
        }
        for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
            let mut k = jwk(key(), "current");
            k[field] = Value::Null;
            assert!(
                verify_id_token(
                    &token,
                    &serde_json::to_vec(&json!({"keys":[k]})).unwrap(),
                    &context()
                )
                .is_err(),
                "{field}"
            );
        }
        let mut k = jwk(key(), "current");
        for field in ["alg", "use", "key_ops"] {
            k.as_object_mut().unwrap().remove(field);
        }
        assert!(
            verify_id_token(
                &token,
                &serde_json::to_vec(&json!({"keys":[k]})).unwrap(),
                &context()
            )
            .is_ok()
        );
    }

    #[test]
    fn jwks_byte_key_and_kid_caps() {
        let token = sign(&header(), &claims());
        let mut bytes = jwks();
        bytes.resize(64 * 1024, b' ');
        assert!(verify_id_token(&token, &bytes, &context()).is_ok());
        bytes.push(b' ');
        assert!(matches!(
            verify_id_token(&token, &bytes, &context()),
            Err(PolicyError::TooLarge)
        ));
        for keys in [
            json!([]),
            json!([
                jwk(key(), "a"),
                jwk(key(), "b"),
                jwk(key(), "c"),
                jwk(key(), "d"),
                jwk(key(), "e"),
                jwk(key(), "f"),
                jwk(key(), "g"),
                jwk(key(), "h"),
                jwk(key(), "current")
            ]),
        ] {
            assert!(
                verify_id_token(
                    &token,
                    &serde_json::to_vec(&json!({"keys":keys})).unwrap(),
                    &context()
                )
                .is_err()
            );
        }
        for kid in [
            json!(""),
            json!("x".repeat(513)),
            json!("bad\n"),
            Value::Null,
        ] {
            let mut k = jwk(key(), "unselected");
            k["kid"] = kid;
            assert!(
                verify_id_token(
                    &token,
                    &serde_json::to_vec(&json!({"keys":[jwk(key(),"current"),k]})).unwrap(),
                    &context()
                )
                .is_err()
            );
        }
    }

    #[test]
    fn compact_segment_structure_canonical_encoding_and_caps() {
        let token = sign(&header(), &claims());
        for malformed in [
            b"".to_vec(),
            b"a.b".to_vec(),
            b"a.b.c.d".to_vec(),
            b"a.b.c.d.e".to_vec(),
            b".a.b".to_vec(),
            b"a..b".to_vec(),
            b"a.b.".to_vec(),
        ] {
            assert!(verify_id_token(&malformed, &jwks(), &context()).is_err());
        }
        for idx in 0..3 {
            let mut parts: Vec<Vec<u8>> = token.split(|b| *b == b'.').map(<[u8]>::to_vec).collect();
            parts[idx].push(b'=');
            assert!(verify_id_token(&parts.join(&b'.'), &jwks(), &context()).is_err());
            parts[idx] = b"+w".to_vec();
            assert!(verify_id_token(&parts.join(&b'.'), &jwks(), &context()).is_err());
        }
        let mut c = claims();
        c["padding"] = json!("x".repeat(13_000));
        assert!(matches!(verify(&c), Err(PolicyError::TooLarge)));
        c["padding"] = json!("x".repeat(11_000));
        assert!(verify(&c).is_ok());
        let h = serde_json::to_vec(&header()).unwrap();
        assert!(verify_id_token(&sign_raw(key(), &h, b"[]"), &jwks(), &context()).is_err());
        assert!(
            verify_id_token(
                &sign_raw(key(), b"[]", &serde_json::to_vec(&claims()).unwrap()),
                &jwks(),
                &context()
            )
            .is_err()
        );
    }
    #[test]
    fn exact_key_audience_and_utf8_text_caps_accept_valid_signatures() {
        let mut keys = (0..7)
            .map(|i| jwk(key(), &format!("rotation-{i}")))
            .collect::<Vec<_>>();
        keys.push(jwk(key(), "current"));
        let bytes = serde_json::to_vec(&json!({"keys":keys})).unwrap();
        let mut c = claims();
        c["aud"] = json!(["a", "b", "c", "d", "e", "f", "g", "rekey-admin"]);
        c["azp"] = json!("rekey-admin");
        c["sub"] = json!("s".repeat(512));
        assert!(verify_id_token(&sign(&header(), &c), &bytes, &context()).is_ok());
        c["sub"] = json!("界".repeat(171));
        assert!(verify(&c).is_err());
        c = claims();
        c["aud"] = json!(["rekey-admin"]);
        assert!(verify(&c).is_ok());
        c["aud"] = json!(["rekey-admin", "a".repeat(513)]);
        c["azp"] = json!("rekey-admin");
        assert!(verify(&c).is_ok());
        let kid = "k".repeat(512);
        let h = json!({"alg":"RS256", "kid":kid});
        let bytes = serde_json::to_vec(&json!({"keys":[jwk(key(), &kid)]})).unwrap();
        assert!(verify_id_token(&sign(&h, &claims()), &bytes, &context()).is_ok());
    }

    #[test]
    fn millisecond_age_boundary_and_unselected_nonpublic_keys_fail() {
        let mut c = claims();
        c["iat"] = json!(NOW - 300);
        let mut ctx = context();
        ctx.now = Timestamp::from_unix_ms(NOW * 1_000 + 1);
        assert!(matches!(
            verify_id_token(&sign(&header(), &c), &jwks(), &ctx),
            Err(PolicyError::Expired)
        ));
        for extra in [
            json!({"kid":"other", "kty":"oct", "alg":"HS256"}),
            json!({"kid":"other"}),
            json!({"kid":"other", "kty":"EC", "alg":null}),
            json!({"kid":"other", "kty":"OKP", "d":null}),
        ] {
            let bytes =
                serde_json::to_vec(&json!({"keys":[jwk(key(), "current"), extra]})).unwrap();
            assert!(verify_id_token(&sign(&header(), &claims()), &bytes, &context()).is_err());
        }
        let mut k = jwk(key(), "current");
        k["n"] = json!(BASE64URL_NOPAD.encode(&[127; 256]));
        let bytes = serde_json::to_vec(&json!({"keys":[k]})).unwrap();
        assert!(verify_id_token(&sign(&header(), &claims()), &bytes, &context()).is_err());
    }
}
