use crate::{Config, Failure, now_ms, private_file, stable};
use serde::{
    Deserialize,
    de::{self, IgnoredAny, MapAccess, Visitor},
};
use std::{collections::BTreeSet, fmt, time::Duration};
use tokio::time::Instant;
use zeroize::Zeroizing;

pub struct Authenticator {
    client: reqwest::Client,
    url: String,
    client_id: String,
    secret: Zeroizing<String>,
}
#[derive(Clone)]
pub struct Identity {
    pub subject: String,
    expires_ms: i64,
}
impl Identity {
    pub fn recheck(&self, deadline: Instant) -> Result<(), u16> {
        if Instant::now() >= deadline {
            Err(503)
        } else if now_ms() >= self.expires_ms {
            Err(401)
        } else {
            Ok(())
        }
    }
}
#[derive(Default)]
struct Claims {
    active: Option<bool>,
    issuer: Option<String>,
    audience: Option<Vec<String>>,
    client: Option<String>,
    token_type: Option<String>,
    subject: Option<String>,
    issued: Option<i64>,
    expires: Option<i64>,
    not_before: Option<i64>,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
impl<'de> Deserialize<'de> for Claims {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ClaimsVisitor;
        impl<'de> Visitor<'de> for ClaimsVisitor {
            type Value = Claims;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("introspection object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Claims, A::Error> {
                let mut seen = BTreeSet::new();
                let mut c = Claims::default();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(de::Error::custom("duplicate claim"));
                    }
                    match key.as_str() {
                        "active" => c.active = Some(map.next_value()?),
                        "iss" => c.issuer = Some(map.next_value()?),
                        "aud" => {
                            c.audience = Some(match map.next_value()? {
                                Audience::One(s) => vec![s],
                                Audience::Many(v) => v,
                            })
                        }
                        "client_id" => c.client = Some(map.next_value()?),
                        "token_type" => c.token_type = Some(map.next_value()?),
                        "sub" => c.subject = Some(map.next_value()?),
                        "iat" => c.issued = Some(map.next_value()?),
                        "exp" => c.expires = Some(map.next_value()?),
                        "nbf" => c.not_before = Some(map.next_value()?),
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(c)
            }
        }
        d.deserialize_map(ClaimsVisitor)
    }
}
impl Authenticator {
    pub fn new(c: &Config) -> Result<Self, Failure> {
        let ca = private_file(&c.idp_ca_certificate_file, 64 * 1024)?;
        let secret = private_file(&c.introspection_client_secret_file, 4096)?;
        let secret = Zeroizing::new(
            std::str::from_utf8(&secret)
                .map_err(|_| "private-file")?
                .to_owned(),
        );
        if secret.is_empty() || secret.chars().any(char::is_control) {
            return Err("private-file");
        }
        let cert = reqwest::Certificate::from_pem(&ca).map_err(|_| "invalid-idp-ca")?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| "invalid-idp-client")?;
        Ok(Self {
            client,
            url: c.introspection_url.clone(),
            client_id: c.introspection_client_id.clone(),
            secret,
        })
    }
    pub async fn authenticate(
        &self,
        token: &str,
        c: &Config,
        deadline: Instant,
    ) -> Result<Identity, u16> {
        let mut response = self
            .client
            .post(&self.url)
            .basic_auth(&self.client_id, Some(self.secret.as_str()))
            .form(&[("token", token), ("token_type_hint", "access_token")])
            .send()
            .await
            .map_err(|_| 503u16)?;
        if response.status() != reqwest::StatusCode::OK
            || response.content_length().is_some_and(|n| n > 64 * 1024)
            || response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .is_none_or(|v| {
                    v.split(';')
                        .next()
                        .is_none_or(|s| s.trim() != "application/json")
                })
        {
            return Err(503);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await.map_err(|_| 503u16)? {
            if bytes.len() + chunk.len() > 64 * 1024 {
                return Err(503);
            }
            bytes.extend_from_slice(&chunk);
        }
        let claims: Claims = serde_json::from_slice(&bytes).map_err(|_| 503u16)?;
        match claims.active {
            Some(false) => return Err(401),
            Some(true) => {}
            None => return Err(503),
        }
        let (Some(iss), Some(aud), Some(client), Some(kind), Some(sub), Some(iat), Some(exp)) = (
            claims.issuer,
            claims.audience,
            claims.client,
            claims.token_type,
            claims.subject,
            claims.issued,
            claims.expires,
        ) else {
            return Err(503);
        };
        let now = now_ms() / 1000;
        if iss != c.idp_issuer
            || !aud.iter().any(|a| a == &c.audience)
            || client != c.personnel_client_id
            || !kind.eq_ignore_ascii_case("Bearer")
            || !stable(&sub)
            || iat < 0
            || iat > now
            || exp <= now
            || exp.checked_sub(iat).is_none_or(|d| !(1..=300).contains(&d))
            || claims.not_before.is_some_and(|nbf| nbf > now)
        {
            return Err(401);
        }
        let expires_ms = exp.checked_mul(1000).ok_or(503u16)?;
        // Persist only the explicitly configured subject, never arbitrary IdP data.
        let subject = if sub == c.uploader_subject {
            c.uploader_subject.clone()
        } else if let Some(a) = c.approvers.iter().find(|a| a.subject == sub) {
            a.subject.clone()
        } else if let Some(l) = c
            .directory
            .links
            .iter()
            .find(|l| l.subject == sub && l.admin_allowed)
        {
            l.subject.clone()
        } else {
            return Err(404);
        };
        let identity = Identity {
            subject,
            expires_ms,
        };
        identity.recheck(deadline)?;
        Ok(identity)
    }
}

#[cfg(test)]
impl Identity {
    pub(crate) fn test(subject: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            expires_ms: now_ms() + 120_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_expiry_and_original_deadline_are_rechecked() {
        let mut who = Identity::test("administrator");
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(who.recheck(deadline).is_ok());
        who.expires_ms = now_ms() - 1;
        assert_eq!(who.recheck(deadline), Err(401));
        assert_eq!(who.recheck(Instant::now()), Err(503));
    }
}
