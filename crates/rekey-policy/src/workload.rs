use std::collections::{BTreeMap, BTreeSet};

use aws_lc_rs::signature::{
    ED25519, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents, UnparsedPublicKey,
};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::Timestamp;
use rekey_domain::ids::PrincipalId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::{PolicyError, PolicyRule, RuleEffect, parse_unique_json};

const MAX_IDENTITIES: usize = 64;
const MAX_KEYS: usize = 8;
const MAX_AUDIENCES: usize = 8;
const MAX_TEXT_BYTES: usize = 512;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_TOKEN_AGE_MS: i64 = 60 * 60 * 1_000;
const REPLAY_DOMAIN: &[u8] = b"rekey-workload-replay-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub principal_id: PrincipalId,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub max_token_age_ms: i64,
    pub profile: WorkloadProfile,
    pub keys: Vec<WorkloadVerificationKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum WorkloadProfile {
    #[serde(rename = "oidc")]
    Oidc { subject: String },
    #[serde(rename = "spiffe-jwt-svid")]
    SpiffeJwtSvid { spiffe_id: String },
    #[serde(rename = "kubernetes-service-account")]
    KubernetesServiceAccount {
        namespace: String,
        service_account: String,
    },
    #[serde(rename = "ci-cloud")]
    CiCloud { subject: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "algorithm", deny_unknown_fields)]
pub enum WorkloadVerificationKey {
    #[serde(rename = "ed25519")]
    Ed25519 { kid: String, x: String },
    #[serde(rename = "rs256")]
    Rs256 { kid: String, n: String, e: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedWorkloadIdentity {
    pub principal_id: PrincipalId,
    pub replay_digest: [u8; 32],
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Algorithm {
    Ed25519,
    Rs256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerificationKey {
    Ed25519([u8; 32]),
    Rs256 { n: Vec<u8>, e: Vec<u8> },
}

#[derive(Debug)]
struct CompiledIdentity {
    principal_id: PrincipalId,
    issuer: String,
    subject: String,
    audiences: Vec<String>,
    max_token_age_ms: i64,
    key_selectors: Vec<(String, Algorithm)>,
}

#[derive(Debug, Default)]
pub(crate) struct WorkloadCatalog {
    identities: Vec<CompiledIdentity>,
    keys: BTreeMap<(String, String, Algorithm), VerificationKey>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JwtHeader {
    alg: String,
    kid: String,
    #[serde(default)]
    typ: Option<String>,
}

struct Claims {
    issuer: String,
    subject: String,
    audiences: Vec<String>,
    jti: String,
    issued_at_ms: i64,
    not_before_ms: Option<i64>,
    expires_at_ms: i64,
}

impl Drop for Claims {
    fn drop(&mut self) {
        self.issuer.zeroize();
        self.subject.zeroize();
        self.jti.zeroize();
        for audience in &mut self.audiences {
            audience.zeroize();
        }
    }
}

struct SensitiveJson(Value);

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

impl WorkloadCatalog {
    pub(crate) fn compile(
        identities: &[WorkloadIdentity],
        rules: &[PolicyRule],
    ) -> Result<Self, PolicyError> {
        if identities.len() > MAX_IDENTITIES {
            return Err(PolicyError::Invalid);
        }
        let mut catalog = Self::default();
        let mut principals = BTreeSet::new();
        let mut external_identities = BTreeSet::new();
        for identity in identities {
            if !principals.insert(identity.principal_id)
                || !rules.iter().any(|rule| {
                    rule.principal_id == identity.principal_id
                        && matches!(
                            rule.effect,
                            RuleEffect::Permit | RuleEffect::RequireApproval
                        )
                })
                || identity.max_token_age_ms <= 0
                || identity.max_token_age_ms > MAX_TOKEN_AGE_MS
            {
                return Err(PolicyError::Invalid);
            }
            validate_issuer(&identity.issuer)?;
            validate_sorted_audiences(&identity.audiences)?;
            let subject = subject_for_profile(&identity.issuer, &identity.profile)?;
            if !external_identities.insert((
                identity.issuer.clone(),
                subject.clone(),
                identity.audiences.clone(),
            )) {
                return Err(PolicyError::Invalid);
            }
            if identity.keys.is_empty() || identity.keys.len() > MAX_KEYS {
                return Err(PolicyError::Invalid);
            }
            let mut local_kids = BTreeSet::new();
            let mut local_material = BTreeSet::new();
            let mut key_selectors = Vec::with_capacity(identity.keys.len());
            for key in &identity.keys {
                let (kid, algorithm, material) = compile_key(key)?;
                if !local_kids.insert(kid.to_owned()) {
                    return Err(PolicyError::Invalid);
                }
                if !local_material.insert(key_material_bytes(&material)) {
                    return Err(PolicyError::Invalid);
                }
                let selector = (identity.issuer.clone(), kid.to_owned(), algorithm);
                match catalog.keys.get(&selector) {
                    Some(existing) if existing != &material => return Err(PolicyError::Invalid),
                    Some(_) => {}
                    None => {
                        catalog.keys.insert(selector, material);
                    }
                }
                key_selectors.push((kid.to_owned(), algorithm));
            }
            catalog.identities.push(CompiledIdentity {
                principal_id: identity.principal_id,
                issuer: identity.issuer.clone(),
                subject,
                audiences: identity.audiences.clone(),
                max_token_age_ms: identity.max_token_age_ms,
                key_selectors,
            });
        }
        Ok(catalog)
    }

    pub(crate) fn verify(
        &self,
        token: &[u8],
        now: Timestamp,
        policy_digest: [u8; 32],
    ) -> Result<VerifiedWorkloadIdentity, PolicyError> {
        if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
            return Err(PolicyError::Malformed);
        }
        let mut segments = token.split(|byte| *byte == b'.');
        let header_segment = segments
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(PolicyError::Malformed)?;
        let claims_segment = segments
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(PolicyError::Malformed)?;
        let signature_segment = segments
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(PolicyError::Malformed)?;
        if segments.next().is_some() {
            return Err(PolicyError::Malformed);
        }
        let header_bytes = Zeroizing::new(decode_segment(header_segment, 4 * 1024)?);
        let header_value = parse_unique_json(&header_bytes)?;
        match header_value.get("typ") {
            None => {}
            Some(Value::String(value)) if matches!(value.as_str(), "JWT" | "at+jwt") => {}
            _ => return Err(PolicyError::InvalidSignature),
        }
        let header: JwtHeader =
            serde_json::from_value(header_value).map_err(|_| PolicyError::Malformed)?;
        validate_text(&header.kid)?;
        let algorithm = match header.alg.as_str() {
            "EdDSA" => Algorithm::Ed25519,
            "RS256" => Algorithm::Rs256,
            _ => return Err(PolicyError::InvalidSignature),
        };
        if header
            .typ
            .as_deref()
            .is_some_and(|typ| !matches!(typ, "JWT" | "at+jwt"))
        {
            return Err(PolicyError::InvalidSignature);
        }

        let claims_bytes = Zeroizing::new(decode_segment(claims_segment, MAX_TOKEN_BYTES)?);
        let claims_value = SensitiveJson(parse_unique_json(&claims_bytes)?);
        let untrusted_issuer = string_claim(&claims_value.0, "iss")?;
        let key = self
            .keys
            .iter()
            .find_map(|((issuer, kid, candidate_algorithm), key)| {
                (issuer == untrusted_issuer
                    && kid == &header.kid
                    && *candidate_algorithm == algorithm)
                    .then_some(key)
            })
            .ok_or(PolicyError::InvalidSignature)?;
        let signing_input_len = header_segment
            .len()
            .checked_add(1)
            .and_then(|len| len.checked_add(claims_segment.len()))
            .ok_or(PolicyError::Malformed)?;
        let signing_input = token
            .get(..signing_input_len)
            .ok_or(PolicyError::Malformed)?;
        let signature = Zeroizing::new(decode_segment(signature_segment, 512)?);
        verify_signature(key, signing_input, &signature)?;

        let claims = parse_claims(&claims_value.0)?;
        let identity = self
            .identities
            .iter()
            .filter(|identity| {
                identity.issuer == claims.issuer
                    && identity.subject == claims.subject
                    && identity.audiences == claims.audiences
                    && identity
                        .key_selectors
                        .iter()
                        .any(|(kid, candidate_algorithm)| {
                            kid == &header.kid && *candidate_algorithm == algorithm
                        })
            })
            .exactly_one()?;
        let now_ms = now.as_unix_ms();
        if claims.issued_at_ms > now_ms
            || claims.not_before_ms.is_some_and(|nbf| nbf > now_ms)
            || now_ms >= claims.expires_at_ms
            || claims.expires_at_ms <= claims.issued_at_ms
            || claims
                .expires_at_ms
                .checked_sub(claims.issued_at_ms)
                .is_none_or(|age| age > identity.max_token_age_ms)
        {
            return Err(PolicyError::InvalidSignature);
        }
        let replay_digest =
            replay_digest(policy_digest, &claims.issuer, &claims.subject, &claims.jti)?;
        Ok(VerifiedWorkloadIdentity {
            principal_id: identity.principal_id,
            replay_digest,
            expires_at_ms: claims.expires_at_ms,
        })
    }
}

trait ExactlyOne<T> {
    fn exactly_one(self) -> Result<T, PolicyError>;
}

impl<I, T> ExactlyOne<T> for I
where
    I: Iterator<Item = T>,
{
    fn exactly_one(mut self) -> Result<T, PolicyError> {
        let first = self.next().ok_or(PolicyError::InvalidSignature)?;
        if self.next().is_some() {
            return Err(PolicyError::InvalidSignature);
        }
        Ok(first)
    }
}

fn compile_key(
    key: &WorkloadVerificationKey,
) -> Result<(&str, Algorithm, VerificationKey), PolicyError> {
    match key {
        WorkloadVerificationKey::Ed25519 { kid, x } => {
            validate_text(kid)?;
            let bytes = decode_canonical(x, 32)?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| PolicyError::Invalid)?;
            if curve25519_dalek::edwards::CompressedEdwardsY(key)
                .decompress()
                .is_none_or(|point| point.is_small_order())
            {
                return Err(PolicyError::Invalid);
            }
            Ok((kid, Algorithm::Ed25519, VerificationKey::Ed25519(key)))
        }
        WorkloadVerificationKey::Rs256 { kid, n, e } => {
            validate_text(kid)?;
            let n = decode_canonical(n, 512)?;
            let e = decode_canonical(e, 8)?;
            if !(256..=512).contains(&n.len())
                || n.first() == Some(&0)
                || n.first().is_none_or(|byte| byte & 0x80 == 0)
                || e.is_empty()
                || e.first() == Some(&0)
            {
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
            Ok((kid, Algorithm::Rs256, VerificationKey::Rs256 { n, e }))
        }
    }
}

fn key_material_bytes(key: &VerificationKey) -> Vec<u8> {
    match key {
        VerificationKey::Ed25519(key) => [b"ed25519\0".as_slice(), key].concat(),
        VerificationKey::Rs256 { n, e } => {
            let mut material = b"rs256\0".to_vec();
            material.extend_from_slice(&(n.len() as u32).to_be_bytes());
            material.extend_from_slice(n);
            material.extend_from_slice(&(e.len() as u32).to_be_bytes());
            material.extend_from_slice(e);
            material
        }
    }
}

fn verify_signature(
    key: &VerificationKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), PolicyError> {
    match key {
        VerificationKey::Ed25519(key) => UnparsedPublicKey::new(&ED25519, key)
            .verify(signing_input, signature)
            .map_err(|_| PolicyError::InvalidSignature),
        VerificationKey::Rs256 { n, e } => RsaPublicKeyComponents { n, e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, signing_input, signature)
            .map_err(|_| PolicyError::InvalidSignature),
    }
}

fn parse_claims(value: &Value) -> Result<Claims, PolicyError> {
    let mut claims = Claims {
        issuer: String::new(),
        subject: String::new(),
        audiences: Vec::new(),
        jti: String::new(),
        issued_at_ms: 0,
        not_before_ms: None,
        expires_at_ms: 0,
    };
    claims.issuer.push_str(string_claim(value, "iss")?);
    claims.subject.push_str(string_claim(value, "sub")?);
    claims.jti.push_str(string_claim(value, "jti")?);
    validate_text(&claims.issuer)?;
    validate_text(&claims.subject)?;
    validate_text(&claims.jti)?;
    match value.get("aud") {
        Some(Value::String(audience)) => {
            validate_text(audience)?;
            claims.audiences.push(audience.clone());
        }
        Some(Value::Array(values)) if !values.is_empty() => {
            for value in values {
                let audience = value.as_str().ok_or(PolicyError::Malformed)?;
                validate_text(audience)?;
                claims.audiences.push(audience.to_owned());
            }
        }
        _ => return Err(PolicyError::Malformed),
    }
    claims.audiences.sort();
    if claims.audiences.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyError::InvalidSignature);
    }
    claims.issued_at_ms = numeric_date_ms(value, "iat", false)?.ok_or(PolicyError::Malformed)?;
    claims.not_before_ms = numeric_date_ms(value, "nbf", true)?;
    claims.expires_at_ms = numeric_date_ms(value, "exp", false)?.ok_or(PolicyError::Malformed)?;
    if claims.issued_at_ms < 0
        || claims.expires_at_ms < 0
        || claims
            .not_before_ms
            .is_some_and(|not_before| not_before < 0)
    {
        return Err(PolicyError::InvalidSignature);
    }
    Ok(claims)
}

fn numeric_date_ms(value: &Value, name: &str, optional: bool) -> Result<Option<i64>, PolicyError> {
    match value.get(name) {
        None if optional => Ok(None),
        Some(Value::Number(number)) => number
            .as_i64()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .map(Some)
            .ok_or(PolicyError::Malformed),
        _ => Err(PolicyError::Malformed),
    }
}

fn string_claim<'a>(value: &'a Value, name: &str) -> Result<&'a str, PolicyError> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .and_then(Value::as_str)
        .ok_or(PolicyError::Malformed)
}

fn replay_digest(
    policy_digest: [u8; 32],
    issuer: &str,
    subject: &str,
    jti: &str,
) -> Result<[u8; 32], PolicyError> {
    let mut hasher = Sha256::new();
    hasher.update(REPLAY_DOMAIN);
    hasher.update(policy_digest);
    for value in [issuer, subject, jti] {
        let len = u32::try_from(value.len()).map_err(|_| PolicyError::InvalidSignature)?;
        hasher.update(len.to_be_bytes());
        hasher.update(value.as_bytes());
    }
    Ok(hasher.finalize().into())
}

fn subject_for_profile(issuer: &str, profile: &WorkloadProfile) -> Result<String, PolicyError> {
    match profile {
        WorkloadProfile::Oidc { subject } | WorkloadProfile::CiCloud { subject } => {
            validate_text(subject)?;
            Ok(subject.clone())
        }
        WorkloadProfile::SpiffeJwtSvid { spiffe_id } => {
            validate_text(spiffe_id)?;
            let spiffe = Url::parse(spiffe_id).map_err(|_| PolicyError::Invalid)?;
            let issuer = Url::parse(issuer).map_err(|_| PolicyError::Invalid)?;
            let spiffe_host = spiffe.host_str().ok_or(PolicyError::Invalid)?;
            if spiffe.scheme() != "spiffe"
                || Some(spiffe_host) != issuer.host_str()
                || spiffe.as_str() != spiffe_id
                || !spiffe.username().is_empty()
                || spiffe.password().is_some()
                || spiffe.port().is_some()
                || spiffe.query().is_some()
                || spiffe.fragment().is_some()
                || !valid_spiffe_trust_domain(spiffe_host)
                || !valid_spiffe_path(spiffe.path())
            {
                return Err(PolicyError::Invalid);
            }
            Ok(spiffe_id.clone())
        }
        WorkloadProfile::KubernetesServiceAccount {
            namespace,
            service_account,
        } => {
            validate_dns_label(namespace)?;
            validate_dns_label(service_account)?;
            Ok(format!(
                "system:serviceaccount:{namespace}:{service_account}"
            ))
        }
    }
}

fn valid_spiffe_trust_domain(value: &str) -> bool {
    value.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
    })
}

fn valid_spiffe_path(path: &str) -> bool {
    path.is_empty()
        || (path.starts_with('/')
            && !path.ends_with('/')
            && path[1..].split('/').all(|segment| {
                !segment.is_empty()
                    && !matches!(segment, "." | "..")
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                    })
            }))
}

fn validate_issuer(issuer: &str) -> Result<(), PolicyError> {
    validate_text(issuer)?;
    if issuer.chars().any(char::is_whitespace) {
        return Err(PolicyError::Invalid);
    }
    let url = Url::parse(issuer).map_err(|_| PolicyError::Invalid)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

fn validate_sorted_audiences(audiences: &[String]) -> Result<(), PolicyError> {
    if audiences.is_empty() || audiences.len() > MAX_AUDIENCES {
        return Err(PolicyError::Invalid);
    }
    for audience in audiences {
        validate_text(audience)?;
    }
    if audiences.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

fn validate_text(value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

fn validate_dns_label(value: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > 63
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || value.starts_with('-')
        || value.ends_with('-')
    {
        return Err(PolicyError::Invalid);
    }
    Ok(())
}

fn decode_canonical(value: &str, max_len: usize) -> Result<Vec<u8>, PolicyError> {
    let decoded = BASE64URL_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| PolicyError::Invalid)?;
    if decoded.len() > max_len || BASE64URL_NOPAD.encode(&decoded) != value {
        return Err(PolicyError::Invalid);
    }
    Ok(decoded)
}

fn decode_segment(value: &[u8], max_len: usize) -> Result<Vec<u8>, PolicyError> {
    let decoded = BASE64URL_NOPAD
        .decode(value)
        .map_err(|_| PolicyError::Malformed)?;
    if decoded.len() > max_len || BASE64URL_NOPAD.encode(&decoded).as_bytes() != value {
        return Err(PolicyError::Malformed);
    }
    Ok(decoded)
}

fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json_strings),
        Value::Object(fields) => fields.values_mut().for_each(zeroize_json_strings),
        _ => {}
    }
}
