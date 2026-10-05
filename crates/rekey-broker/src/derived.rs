//! Signed, fixed-target T1 issuance; only the resulting temporary credential is returned.
use crate::error::BrokerError;
use crate::upstream::{UpstreamRequest, UpstreamTransport};
use aws_lc_rs::{
    hmac,
    rand::SystemRandom,
    signature::{RSA_PKCS1_SHA256, RsaKeyPair},
};
use rekey_domain::action::FixedMethod;
use rekey_domain::connection::DerivedCredentialTarget;
use rekey_domain::credential::CredentialKind;
use rekey_domain::ids::CredentialId;
use rekey_vault::handle::AuthorityHandle;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;
use zeroize::Zeroizing;

fn invalid() -> BrokerError {
    BrokerError::LocalCall(
        "INVALID_INPUT",
        "invalid derivation source or target",
        "Review the signed temporary-credential settings in Rekey App.",
    )
}
fn response_error() -> BrokerError {
    BrokerError::Upstream("derived-response-invalid")
}
fn secret<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(d).map(Zeroizing::new)
}
fn optional_secret<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<String>>, D::Error> {
    Option::<String>::deserialize(d).map(|v| v.map(Zeroizing::new))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AwsRoot {
    credential_type: String,
    #[serde(deserialize_with = "secret")]
    access_key_id: Zeroizing<String>,
    #[serde(deserialize_with = "secret")]
    secret_access_key: Zeroizing<String>,
    #[serde(default, deserialize_with = "optional_secret")]
    session_token: Option<Zeroizing<String>>,
}
impl AwsRoot {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, BrokerError> {
        let root: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if root.credential_type != "aws-static-v1"
            || !(16..=128).contains(&root.access_key_id.len())
            || !root
                .access_key_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric())
            || root.secret_access_key.is_empty()
            || root.secret_access_key.len() > 16 * 1024
            || root.secret_access_key.chars().any(char::is_control)
            || root.session_token.as_ref().is_some_and(|s| {
                s.is_empty() || s.len() > 16 * 1024 || s.chars().any(char::is_control)
            })
        {
            return Err(invalid());
        }
        Ok(root)
    }
    fn needles(&self) -> Vec<Zeroizing<Vec<u8>>> {
        [&self.access_key_id, &self.secret_access_key]
            .into_iter()
            .chain(self.session_token.as_ref())
            .flat_map(|s| crate::executor::sealing_needles(s.as_bytes(), s.as_bytes()))
            .collect()
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GitHubRoot {
    credential_type: String,
    client_id: String,
    installation_id: u64,
    #[serde(deserialize_with = "secret")]
    private_key_pkcs1_der_base64: Zeroizing<String>,
}
impl GitHubRoot {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, BrokerError> {
        let root: Self = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if root.credential_type != "github-app-root-v1"
            || root.client_id.is_empty()
            || root.client_id.len() > 128
            || !root
                .client_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.'))
            || root.installation_id == 0
        {
            return Err(invalid());
        }
        let der = Zeroizing::new(
            data_encoding::BASE64
                .decode(root.private_key_pkcs1_der_base64.as_bytes())
                .map_err(|_| invalid())?,
        );
        RsaKeyPair::from_der(&der).map_err(|_| invalid())?;
        Ok(root)
    }
    fn jwt(&self, now_ms: i64) -> Result<Zeroizing<String>, BrokerError> {
        #[derive(Serialize)]
        struct Claims<'a> {
            iat: i64,
            exp: i64,
            iss: &'a str,
        }
        let claims = serde_json::to_vec(&Claims {
            iat: now_ms / 1000 - 60,
            exp: now_ms / 1000 + 540,
            iss: &self.client_id,
        })
        .map_err(|_| invalid())?;
        let data = Zeroizing::new(format!(
            "{}.{}",
            data_encoding::BASE64URL_NOPAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#),
            data_encoding::BASE64URL_NOPAD.encode(&claims)
        ));
        let der = Zeroizing::new(
            data_encoding::BASE64
                .decode(self.private_key_pkcs1_der_base64.as_bytes())
                .map_err(|_| invalid())?,
        );
        let key = RsaKeyPair::from_der(&der).map_err(|_| invalid())?;
        let mut signature = Zeroizing::new(vec![0; key.public_modulus_len()]);
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            data.as_bytes(),
            &mut signature,
        )
        .map_err(|_| invalid())?;
        Ok(Zeroizing::new(format!(
            "{}.{}",
            data.as_str(),
            data_encoding::BASE64URL_NOPAD.encode(&signature)
        )))
    }
}
fn hex(bytes: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(bytes)
}
fn dates(now_ms: i64) -> Result<(String, String), BrokerError> {
    let now = time::OffsetDateTime::from_unix_timestamp(now_ms / 1000).map_err(|_| invalid())?;
    let date = format!("{:04}{:02}{:02}", now.year(), now.month() as u8, now.day());
    Ok((
        date.clone(),
        format!(
            "{date}T{:02}{:02}{:02}Z",
            now.hour(),
            now.minute(),
            now.second()
        ),
    ))
}
fn mac(key: &[u8], value: &[u8]) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), value)
            .as_ref()
            .to_vec(),
    )
}
fn signature(
    secret: &str,
    date: &str,
    region: &str,
    stamp: &str,
    canonical: &str,
) -> Zeroizing<String> {
    let seed = Zeroizing::new(format!("AWS4{secret}"));
    let datekey = mac(seed.as_bytes(), date.as_bytes());
    let regionkey = mac(&datekey, region.as_bytes());
    let service = mac(&regionkey, b"sts");
    let key = mac(&service, b"aws4_request");
    let string = Zeroizing::new(format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{date}/{region}/sts/aws4_request\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    ));
    Zeroizing::new(hex(&mac(&key, string.as_bytes())))
}
fn escape(value: &str) -> String {
    let mut result = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            result.push(b as char);
        } else {
            result.push_str(&format!("%{b:02X}"));
        }
    }
    result
}
fn timestamp(ms: i64) -> Result<String, BrokerError> {
    time::OffsetDateTime::from_unix_timestamp(ms / 1000)
        .map_err(|_| response_error())?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| response_error())
}
fn expiry(value: &str, now: i64, max: u32) -> Result<i64, BrokerError> {
    let nanos = time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .map_err(|_| response_error())?
        .unix_timestamp_nanos();
    if nanos <= now as i128 * 1_000_000 || nanos > (now as i128 + max as i128 * 1000) * 1_000_000 {
        return Err(BrokerError::LocalCall(
            "UPSTREAM_ERROR",
            "upstream temporary credential expiry violates the signed limit",
            "Check the system clock and upstream expiry; the signed lifetime remains enforced.",
        ));
    }
    i64::try_from((nanos + 999_999).div_euclid(1_000_000)).map_err(|_| response_error())
}
pub(crate) struct Issued {
    pub body: Zeroizing<Vec<u8>>,
    pub expires_at_ms: i64,
    pub credential_version: u64,
    pub kind: &'static str,
}
#[derive(Deserialize)]
struct AssumeResponse {
    #[serde(rename = "AssumeRoleResult")]
    result: AssumeResult,
}
#[derive(Deserialize)]
struct AssumeResult {
    #[serde(rename = "Credentials")]
    credentials: TemporaryAws,
}
#[derive(Deserialize)]
struct TemporaryAws {
    #[serde(rename = "AccessKeyId", deserialize_with = "secret")]
    access_key: Zeroizing<String>,
    #[serde(rename = "SecretAccessKey", deserialize_with = "secret")]
    secret: Zeroizing<String>,
    #[serde(rename = "SessionToken", deserialize_with = "secret")]
    token: Zeroizing<String>,
    #[serde(rename = "Expiration")]
    expiration: String,
}
#[derive(Deserialize)]
struct InstallationResponse {
    #[serde(deserialize_with = "secret")]
    token: Zeroizing<String>,
    expires_at: String,
    repositories: Vec<Repository>,
    permissions: BTreeMap<String, String>,
}
#[derive(Deserialize)]
struct Repository {
    id: u64,
}

pub(crate) async fn issue(
    authority: &AuthorityHandle,
    transport: &dyn UpstreamTransport,
    lifecycle: &crate::lifecycle::Lifecycle,
    id: CredentialId,
    target: &DerivedCredentialTarget,
    ttl: u32,
    deadline: Instant,
) -> Result<Issued, BrokerError> {
    let now = crate::now_ts()?.as_unix_ms();
    match target {
        DerivedCredentialTarget::AwsAssumeRole {
            role_arn,
            region,
            session_policy,
        } => {
            let prepared = authority.prepare_aws_static(id).await?;
            let version = prepared.version();
            let root = prepared.consume(AwsRoot::parse)?;
            let host = format!("sts.{region}.amazonaws.com");
            let (date, stamp) = dates(now)?;
            let policy = serde_jcs::to_vec(session_policy).map_err(|_| invalid())?;
            let policy = std::str::from_utf8(&policy).map_err(|_| invalid())?;
            let duration = ttl.to_string();
            let body = Zeroizing::new(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs([
                        ("Action", "AssumeRole"),
                        ("Version", "2011-06-15"),
                        ("RoleArn", role_arn.as_str()),
                        ("RoleSessionName", "rekey"),
                        ("DurationSeconds", &duration),
                        ("Policy", policy),
                    ])
                    .finish()
                    .into_bytes(),
            );
            let mut headers: Vec<(String, String)> = vec![
                (
                    "content-type".into(),
                    "application/x-www-form-urlencoded".into(),
                ),
                ("host".into(), host.clone()),
                ("x-amz-date".into(), stamp.clone()),
            ];
            if let Some(token) = &root.session_token {
                headers.push(("x-amz-security-token".into(), token.to_string()));
            }
            let signed = headers
                .iter()
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(";");
            let canonical_headers = Zeroizing::new(
                headers
                    .iter()
                    .map(|(k, v)| {
                        format!(
                            "{k}:{}\n",
                            v.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
                        )
                    })
                    .collect::<String>(),
            );
            let canonical = Zeroizing::new(format!(
                "POST\n/\n\n{}\n{signed}\n{}",
                canonical_headers.as_str(),
                hex(&Sha256::digest(&body))
            ));
            let sig = signature(&root.secret_access_key, &date, region, &stamp, &canonical);
            let auth=Zeroizing::new(format!("AWS4-HMAC-SHA256 Credential={}/{date}/{region}/sts/aws4_request, SignedHeaders={signed}, Signature={}",root.access_key_id.as_str(),sig.as_str()).into_bytes());
            lifecycle.reject_if_not_running()?;
            let response = transport
                .send(UpstreamRequest {
                    host,
                    port: 443,
                    method: FixedMethod::Post,
                    path: "/".into(),
                    headers,
                    auth_header: ("authorization".into(), auth),
                    body,
                    timeout: deadline.saturating_duration_since(Instant::now()),
                    response_max_bytes: 64 * 1024,
                })
                .await
                .map_err(|_| BrokerError::Upstream("sts-transport"))?;
            if response.status != 200 {
                return Err(response_error());
            }
            let raw: AssumeResponse = quick_xml::de::from_str(
                std::str::from_utf8(&response.body).map_err(|_| response_error())?,
            )
            .map_err(|_| response_error())?;
            let value = raw.result.credentials;
            let expires_at_ms = expiry(&value.expiration, crate::now_ts()?.as_unix_ms(), ttl)?;
            for value in [&value.access_key, &value.secret, &value.token] {
                if value.is_empty()
                    || value.len() > 16 * 1024
                    || value.chars().any(char::is_control)
                    || crate::executor::contains_secret(value.as_bytes(), &root.needles())
                {
                    return Err(BrokerError::ResponseSecurityViolation);
                }
            }
            #[derive(Serialize)]
            #[serde(rename_all = "PascalCase")]
            struct Output<'a> {
                version: u8,
                access_key_id: &'a str,
                secret_access_key: &'a str,
                session_token: &'a str,
                expiration: &'a str,
            }
            let body = Zeroizing::new(
                serde_json::to_vec(&Output {
                    version: 1,
                    access_key_id: &value.access_key,
                    secret_access_key: &value.secret,
                    session_token: &value.token,
                    expiration: &value.expiration,
                })
                .map_err(|_| response_error())?,
            );
            Ok(Issued {
                body,
                expires_at_ms,
                credential_version: version,
                kind: "aws-assume-role",
            })
        }
        DerivedCredentialTarget::KubernetesEks { cluster_id, region } => {
            let prepared = authority.prepare_aws_static(id).await?;
            let version = prepared.version();
            let root = prepared.consume(AwsRoot::parse)?;
            lifecycle.reject_if_not_running()?;
            // Embedding a bootstrap session token in the presigned URL would return root material.
            if root.session_token.is_some() {
                return Err(invalid());
            }
            let host = format!("sts.{region}.amazonaws.com");
            let (date, stamp) = dates(now)?;
            let credential = Zeroizing::new(format!(
                "{}/{date}/{region}/sts/aws4_request",
                root.access_key_id.as_str()
            ));
            let query = [
                ("Action", "GetCallerIdentity"),
                ("Version", "2011-06-15"),
                ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
                ("X-Amz-Credential", credential.as_str()),
                ("X-Amz-Date", stamp.as_str()),
                ("X-Amz-Expires", "60"),
                ("X-Amz-SignedHeaders", "host;x-k8s-aws-id"),
            ]
            .into_iter()
            .map(|(k, v)| (escape(k), escape(v)))
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
            let canonical = Zeroizing::new(format!(
                "GET\n/\n{query}\nhost:{host}\nx-k8s-aws-id:{cluster_id}\n\nhost;x-k8s-aws-id\n{}",
                hex(&Sha256::digest(b""))
            ));
            let sig = signature(&root.secret_access_key, &date, region, &stamp, &canonical);
            let url = Zeroizing::new(format!(
                "https://{host}/?{query}&X-Amz-Signature={}",
                sig.as_str()
            ));
            let token = Zeroizing::new(format!(
                "k8s-aws-v1.{}",
                data_encoding::BASE64URL_NOPAD.encode(url.as_bytes())
            ));
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Output<'a> {
                api_version: &'static str,
                kind: &'static str,
                spec: BTreeMap<String, String>,
                status: Status<'a>,
            }
            #[derive(Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Status<'a> {
                token: &'a str,
                expiration_timestamp: String,
            }
            let body = Zeroizing::new(
                serde_json::to_vec(&Output {
                    api_version: "client.authentication.k8s.io/v1",
                    kind: "ExecCredential",
                    spec: BTreeMap::new(),
                    status: Status {
                        token: &token,
                        expiration_timestamp: timestamp(now.div_euclid(1000) * 1000 + 840_000)?,
                    },
                })
                .map_err(|_| response_error())?,
            );
            Ok(Issued {
                body,
                expires_at_ms: now.div_euclid(1000) * 1000 + 900_000,
                credential_version: version,
                kind: "kubernetes-eks",
            })
        }
        DerivedCredentialTarget::GitHubApp {
            installation_id,
            repository_ids,
            permissions,
        } => {
            let prepared = authority.prepare_credential(id).await?;
            if prepared.kind() != CredentialKind::GitHubAppInstallation {
                return Err(invalid());
            }
            let version = prepared.version();
            let root = prepared.consume(GitHubRoot::parse)?;
            if root.installation_id != *installation_id {
                return Err(invalid());
            }
            let jwt = root.jwt(now)?;
            #[derive(Serialize)]
            struct Request<'a> {
                repository_ids: &'a [u64],
                permissions: &'a BTreeMap<String, String>,
            }
            let body = Zeroizing::new(
                serde_json::to_vec(&Request {
                    repository_ids,
                    permissions,
                })
                .map_err(|_| invalid())?,
            );
            lifecycle.reject_if_not_running()?;
            let response = transport
                .send(UpstreamRequest {
                    host: "api.github.com".into(),
                    port: 443,
                    method: FixedMethod::Post,
                    path: format!("/app/installations/{installation_id}/access_tokens"),
                    headers: vec![
                        ("content-type".into(), "application/json".into()),
                        ("accept".into(), "application/vnd.github+json".into()),
                        ("x-github-api-version".into(), "2022-11-28".into()),
                    ],
                    auth_header: (
                        "authorization".into(),
                        Zeroizing::new(format!("Bearer {}", jwt.as_str()).into_bytes()),
                    ),
                    body,
                    timeout: deadline.saturating_duration_since(Instant::now()),
                    response_max_bytes: 256 * 1024,
                })
                .await
                .map_err(|_| BrokerError::Upstream("github-installation-transport"))?;
            if response.status != 201 {
                return Err(response_error());
            }
            let raw: InstallationResponse =
                serde_json::from_slice(&response.body).map_err(|_| response_error())?;
            let mut actual = raw
                .repositories
                .into_iter()
                .map(|r| r.id)
                .collect::<Vec<_>>();
            actual.sort_unstable();
            let mut expected = repository_ids.clone();
            expected.sort_unstable();
            let expires_at_ms = expiry(&raw.expires_at, crate::now_ts()?.as_unix_ms(), ttl)?;
            let der = Zeroizing::new(
                data_encoding::BASE64
                    .decode(root.private_key_pkcs1_der_base64.as_bytes())
                    .map_err(|_| invalid())?,
            );
            if actual != expected
                || &raw.permissions != permissions
                || raw.token.is_empty()
                || raw.token.len() > 16 * 1024
                || raw.token.chars().any(char::is_control)
                || crate::executor::contains_secret(
                    raw.token.as_bytes(),
                    &[
                        crate::executor::sealing_needles(&der, &der),
                        crate::executor::sealing_needles(jwt.as_bytes(), jwt.as_bytes()),
                        crate::executor::sealing_needles(
                            root.private_key_pkcs1_der_base64.as_bytes(),
                            root.private_key_pkcs1_der_base64.as_bytes(),
                        ),
                    ]
                    .concat(),
                )
            {
                return Err(BrokerError::ResponseSecurityViolation);
            }
            Ok(Issued {
                body: Zeroizing::new(raw.token.as_bytes().to_vec()),
                expires_at_ms,
                credential_version: version,
                kind: "github-app",
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fractional_actual_expiry_cannot_exceed_signed_limit_or_be_misreported() {
        let now = 1_700_000_000_000;
        assert_eq!(
            expiry("2023-11-14T22:28:20Z", now, 900).unwrap(),
            now + 900_000
        );
        assert!(expiry("2023-11-14T22:28:20.9Z", now, 900).is_err());
        assert_eq!(
            expiry("2023-11-14T22:28:19.125Z", now, 900).unwrap(),
            now + 899_125
        );
        assert!(expiry("2023-11-14T22:13:20Z", now, 900).is_err());
    }
    #[test]
    fn aws_xml_and_encoding_follow_provider_wire_contract() {
        let raw:AssumeResponse=quick_xml::de::from_str("<AssumeRoleResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><AssumeRoleResult><Credentials><AccessKeyId>synthetic-temporary-access</AccessKeyId><SecretAccessKey>synthetic-temporary-secret</SecretAccessKey><SessionToken>synthetic-temporary-token</SessionToken><Expiration>2023-11-14T22:28:20Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>").unwrap();
        assert_eq!(
            raw.result.credentials.access_key.as_str(),
            "synthetic-temporary-access"
        );
        assert_eq!(escape("a /+~"), "a%20%2F%2B~");
        assert_eq!(
            dates(1_700_000_000_000).unwrap(),
            ("20231114".into(), "20231114T221320Z".into())
        );
    }
    #[test]
    fn decoded_der_reflections_are_blocked_in_hex_and_url_base64_forms() {
        // Bytes model the already decoded private DER, not a real credential.
        let der = b"synthetic-private-der-component+/=";
        let needles = crate::executor::sealing_needles(der, der);
        for encoded in [
            data_encoding::HEXLOWER.encode(der),
            data_encoding::BASE64URL_NOPAD.encode(der),
        ] {
            assert!(crate::executor::contains_secret(
                encoded.as_bytes(),
                &needles
            ));
        }
    }
}
