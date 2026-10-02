use crate::{Config, Failure, canonical_uuid, https_url, now_ms, private_file, sha, stable};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use std::{collections::BTreeSet, fmt, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    task::JoinSet,
    time::{Instant, timeout_at},
};
use zeroize::Zeroizing;

pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const ABSENT: &[u8] = b"rekey.directory.authenticated-source-404.v1";
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Directory {
    pub base_url: String,
    pub ca_certificate_file: PathBuf,
    pub access_token_file: PathBuf,
    pub mapping_version: u64,
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Node {
    pub node_id: String,
    pub vault_id: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Link {
    pub source_user_id: String,
    pub external_id: String,
    pub issuer: String,
    pub subject: String,
    pub principal_id: String,
    pub admin_allowed: bool,
    pub approver_id: Option<String>,
    pub public_key_sha256: Option<String>,
    pub confirmed_by: String,
    pub confirmed_at_ms: i64,
}
impl Directory {
    pub fn validate(&self, c: &Config) -> Result<(), Failure> {
        let base = https_url(&self.base_url)?;
        if base.path().contains("//")
            || self.mapping_version == 0
            || self.mapping_version > i64::MAX as u64
            || self.nodes.len() != 2
            || self.links.is_empty()
            || self.links.len() > 32
            || !self.links.iter().any(|l| l.admin_allowed)
            || !self.ca_certificate_file.is_absolute()
            || !self.access_token_file.is_absolute()
        {
            return Err("invalid-config");
        }
        let mut nodes = BTreeSet::new();
        let mut vaults = BTreeSet::new();
        for n in &self.nodes {
            if !canonical_uuid(&n.node_id)
                || !canonical_uuid(&n.vault_id)
                || !nodes.insert(&n.node_id)
                || !vaults.insert(&n.vault_id)
            {
                return Err("invalid-config");
            }
        }
        let mut sources = BTreeSet::new();
        let mut external = BTreeSet::new();
        let mut subjects = BTreeSet::new();
        let mut principals = BTreeSet::new();
        let mut approvers = BTreeSet::new();
        for l in &self.links {
            if l.source_user_id.is_empty()
                || l.source_user_id.len() > 256
                || matches!(l.source_user_id.as_str(), "." | "..")
                || !l
                    .source_user_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b))
                || !stable(&l.external_id)
                || l.issuer != c.idp_issuer
                || !stable(&l.subject)
                || !canonical_uuid(&l.principal_id)
                || !stable(&l.confirmed_by)
                || l.confirmed_at_ms <= 0
                || l.confirmed_at_ms > now_ms()
                || !sources.insert(&l.source_user_id)
                || !external.insert(&l.external_id)
                || !subjects.insert(&l.subject)
                || !principals.insert(&l.principal_id)
            {
                return Err("invalid-config");
            }
            match (&l.approver_id, &l.public_key_sha256) {
                (None, None) => {
                    if c.approvers.iter().any(|a| a.subject == l.subject) {
                        return Err("invalid-config");
                    }
                }
                (Some(id), Some(key))
                    if canonical_uuid(id)
                        && approvers.insert(id)
                        && key.len() == 64
                        && key
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        && c.approvers
                            .iter()
                            .any(|a| a.subject == l.subject && a.approver_id == *id) => {}
                _ => return Err("invalid-config"),
            }
            if !l.admin_allowed
                && l.subject != c.uploader_subject
                && !c.approvers.iter().any(|a| a.subject == l.subject)
            {
                return Err("invalid-config");
            }
        }
        if !subjects.contains(&c.uploader_subject)
            || c.approvers.iter().any(|a| !subjects.contains(&a.subject))
        {
            return Err("invalid-config");
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, Failure> {
        serde_json::to_vec(self)
            .map(|v| sha(&v))
            .map_err(|_| "invalid-config")
    }
    pub fn registration(&self) -> Result<Value, Failure> {
        Ok(
            serde_json::json!({"formatVersion":1,"mappingVersion":self.mapping_version,
            "mappingSha256":self.digest()?,"nodes":self.nodes}),
        )
    }
    pub fn resource(&self, l: &Link) -> String {
        format!(
            "{}/Users/{}",
            self.base_url.trim_end_matches('/'),
            l.source_user_id
        )
    }
}
// Reject duplicate keys recursively, even in fields this fixed consumer ignores.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unique JSON")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut obj = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if obj.contains_key(&k) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    obj.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(obj)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(Value::String(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(Value::String(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(JsonVisitor)
    }
}
fn active(bytes: &[u8], id: &str, external: &str) -> Option<bool> {
    let v = serde_json::from_slice::<Unique>(bytes).ok()?.0;
    let schemas = v.get("schemas")?.as_array()?;
    if !schemas.iter().all(Value::is_string)
        || v.get("id")?.as_str()? != id
        || v.get("externalId")?.as_str()? != external
        || !schemas.iter().any(|s| s.as_str() == Some(USER_SCHEMA))
    {
        return None;
    }
    v.get("active")?.as_bool()
}
pub enum State {
    Active,
    Unknown,
    Removed(String),
}
pub struct Observation {
    pub state: State,
    pub received_ms: i64,
    pub completed: Instant,
    pub token_expires_ms: i64,
}
impl Observation {
    pub fn unknown() -> Self {
        Self {
            state: State::Unknown,
            received_ms: now_ms(),
            completed: Instant::now(),
            token_expires_ms: 0,
        }
    }
}
pub struct Consumer {
    client: reqwest::Client,
}
impl Consumer {
    pub fn new(c: &Directory) -> Result<Self, Failure> {
        let bytes = private_file(&c.ca_certificate_file, 64 * 1024)?;
        let ca = reqwest::Certificate::from_pem(&bytes).map_err(|_| "invalid-directory-ca")?;
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .tls_built_in_root_certs(false)
            .add_root_certificate(ca)
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| "invalid-directory-client")?;
        Ok(Self { client })
    }
    fn token(c: &Directory) -> Result<(Zeroizing<String>, i64), Failure> {
        let bytes = private_file(&c.access_token_file, 8192)?;
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Token {
            access_token: String,
            expires_at_ms: i64,
        }
        let mut t: Token = serde_json::from_slice(&bytes).map_err(|_| "invalid-directory-token")?;
        let secret = Zeroizing::new(std::mem::take(&mut t.access_token));
        if secret.is_empty()
            || secret.len() > 4096
            || secret
                .chars()
                .any(|ch| ch.is_whitespace() || ch.is_control())
            || t.expires_at_ms <= now_ms()
        {
            return Err("invalid-directory-token");
        }
        Ok((secret, t.expires_at_ms))
    }
    async fn get(
        client: reqwest::Client,
        url: String,
        link: Link,
        token: Arc<Zeroizing<String>>,
        expires: i64,
    ) -> (Link, Observation) {
        let state = async {
            if now_ms() >= expires {
                return None;
            }
            let mut r = client
                .get(url)
                .bearer_auth(token.as_str())
                .send()
                .await
                .ok()?;
            if now_ms() >= expires {
                return None;
            }
            if r.status() == reqwest::StatusCode::NOT_FOUND {
                return Some(State::Removed(sha(ABSENT)));
            }
            if r.status() != reqwest::StatusCode::OK
                || r.content_length().is_some_and(|n| n > 64 * 1024)
            {
                return None;
            }
            let mut body = Zeroizing::new(Vec::new());
            while let Some(chunk) = r.chunk().await.ok()? {
                if body.len() + chunk.len() > 64 * 1024 {
                    return None;
                }
                body.extend_from_slice(&chunk);
            }
            if now_ms() >= expires {
                return None;
            }
            match active(&body, &link.source_user_id, &link.external_id)? {
                true => Some(State::Active),
                false => Some(State::Removed(sha(&body))),
            }
        }
        .await
        .unwrap_or(State::Unknown);
        (
            link,
            Observation {
                state,
                received_ms: now_ms(),
                completed: Instant::now(),
                token_expires_ms: expires,
            },
        )
    }
    pub async fn poll<F>(&self, c: &Directory, mut apply: F) -> Result<(), Failure>
    where
        F: FnMut(&Link, Observation) -> Result<(), Failure>,
    {
        let deadline = Instant::now() + Duration::from_secs(10);
        let Ok((token, expires)) = Self::token(c) else {
            for l in &c.links {
                apply(l, Observation::unknown())?;
            }
            return Ok(());
        };
        let token = Arc::new(token);
        let mut pending = c.links.iter();
        let mut tasks = JoinSet::new();
        let mut unfinished = BTreeSet::new();
        loop {
            while tasks.len() < 4 {
                let Some(l) = pending.next() else {
                    break;
                };
                unfinished.insert(l.subject.clone());
                tasks.spawn(Self::get(
                    self.client.clone(),
                    c.resource(l),
                    l.clone(),
                    token.clone(),
                    expires,
                ));
            }
            if tasks.is_empty() {
                break;
            }
            match timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(Ok((l, result)))) => {
                    unfinished.remove(&l.subject);
                    apply(&l, result)?;
                }
                _ => {
                    tasks.abort_all();
                    break;
                }
            }
        }
        for l in pending {
            unfinished.insert(l.subject.clone());
        }
        for l in &c.links {
            if unfinished.contains(&l.subject) {
                apply(l, Observation::unknown())?;
            }
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_identity_requires_explicit_active_and_schema() {
        let valid=br#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"user-1","externalId":"person-1","active":true}"#;
        assert_eq!(active(valid, "user-1", "person-1"), Some(true));
        assert_eq!(active(valid, "user-2", "person-1"), None);
        assert_eq!(active(valid, "user-1", "person-2"), None);
        assert_eq!(
            active(
                br#"{"id":"user-1","externalId":"person-1","schemas":[],"active":true}"#,
                "user-1",
                "person-1"
            ),
            None
        );
        assert_eq!(active(br#"{"id":"user-1","externalId":"person-1","schemas":["urn:ietf:params:scim:schemas:core:2.0:User"]}"#,"user-1","person-1"),None);
    }
    #[test]
    fn duplicate_keys_including_unrelated_nested_fields_reject() {
        assert_eq!(active(br#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"user-1","externalId":"person-1","active":true,"active":false}"#,"user-1","person-1"),None);
        assert_eq!(active(br#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"user-1","externalId":"person-1","active":true,"name":{"x":1,"x":2}}"#,"user-1","person-1"),None);
        assert_eq!(active(br#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"id":"user-1","externalId":"person-1","active":false,"name":{"x":1}}"#,"user-1","person-1"),Some(false));
    }
}

#[cfg(test)]
mod config_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn confirmed_exact_mapping_rejects_duplicates_inference_and_unbound_keys() {
        let base = crate::test_config(std::path::Path::new("/fixture/state"));
        assert!(base.directory.validate(&base).is_ok());
        for field in [
            "sourceUserId",
            "externalId",
            "subject",
            "principalId",
            "issuer",
            "approverId",
            "publicKeySha256",
            "confirmedBy",
            "confirmedAtMs",
        ] {
            let mut v = serde_json::to_value(&base.directory).unwrap();
            v["links"][1][field] = match field {
                "sourceUserId" | "externalId" | "subject" | "principalId" => {
                    v["links"][0][field].clone()
                }
                "issuer" => serde_json::json!("https://other.test"),
                "approverId" => serde_json::json!("11111111-1111-4111-8111-111111111111"),
                "publicKeySha256" => serde_json::json!("AA".repeat(32)),
                "confirmedBy" => serde_json::json!(""),
                _ => serde_json::json!(0),
            };
            let d: Directory = serde_json::from_value(v).unwrap();
            assert!(d.validate(&base).is_err(), "{field}");
        }
        for source in [
            "../member",
            ".",
            "..",
            "%2F",
            "member?filter=one",
            "member#fragment",
            "",
        ] {
            let mut d = base.directory.clone();
            d.links[0].source_user_id = source.to_owned();
            assert!(d.validate(&base).is_err());
        }
        let mut d = base.directory.clone();
        d.links[1].public_key_sha256 = None;
        assert!(d.validate(&base).is_err());
        let mut d = base.directory.clone();
        d.links.pop();
        assert!(d.validate(&base).is_err());
        let mut d = base.directory.clone();
        d.nodes[1] = d.nodes[0].clone();
        assert!(d.validate(&base).is_err());
        for url in [
            "http://directory.test",
            "https://user:password@directory.test",
            "https://directory.test/?filter=one",
            "https://directory.test/#x",
        ] {
            let mut d = base.directory.clone();
            d.base_url = url.into();
            assert!(d.validate(&base).is_err());
        }
        let mut d = base.directory.clone();
        d.mapping_version = 0;
        assert!(d.validate(&base).is_err());
        let mut d = base.directory.clone();
        d.links[0].subject = "same-email-unconfirmed-subject".into();
        assert!(d.validate(&base).is_err());
    }
    #[test]
    fn admin_flag_is_required_and_distinct_admin_is_not_a_transport_role() {
        let mut c = crate::test_config(std::path::Path::new("/fixture/state"));
        let mut value = serde_json::to_value(&c.directory).unwrap();
        value["links"][0]
            .as_object_mut()
            .unwrap()
            .remove("adminAllowed");
        assert!(serde_json::from_value::<Directory>(value).is_err());
        for wrong in [
            serde_json::json!(null),
            serde_json::json!("true"),
            serde_json::json!(1),
        ] {
            let mut value = serde_json::to_value(&c.directory).unwrap();
            value["links"][0]["adminAllowed"] = wrong;
            assert!(serde_json::from_value::<Directory>(value).is_err());
        }
        let mut admin = serde_json::to_value(&c.directory.links[0]).unwrap();
        admin["sourceUserId"] = serde_json::json!("admin-user");
        admin["externalId"] = serde_json::json!("admin-person");
        admin["subject"] = serde_json::json!("administrator");
        admin["principalId"] = serde_json::json!("55555555-5555-4555-8555-555555555555");
        admin["adminAllowed"] = serde_json::json!(true);
        c.directory
            .links
            .push(serde_json::from_value(admin).unwrap());
        assert!(c.directory.validate(&c).is_ok());
        let pinned = c.directory.digest().unwrap();
        for link in &mut c.directory.links {
            link.admin_allowed = false;
        }
        assert!(c.directory.validate(&c).is_err());
        assert_ne!(pinned, c.directory.digest().unwrap());
        assert_ne!(c.uploader_subject, "administrator");
        assert!(!c.approvers.iter().any(|a| a.subject == "administrator"));
    }
    #[test]
    fn source_token_is_explicit_private_expiring_and_duplicate_fields_reject() {
        let root = tempfile::tempdir().unwrap();
        let mut d = crate::test_config(root.path()).directory;
        d.access_token_file = root.path().join("token");
        for (expected, bytes) in [
            (
                true,
                serde_json::json!({"accessToken":"synthetic-token","expiresAtMs":now_ms()+60000})
                    .to_string(),
            ),
            (
                false,
                serde_json::json!({"accessToken":"synthetic-token","expiresAtMs":now_ms()-1})
                    .to_string(),
            ),
            (
                false,
                "{\"accessToken\":\"a\",\"accessToken\":\"b\",\"expiresAtMs\":9223372036854775807}"
                    .into(),
            ),
        ] {
            std::fs::write(&d.access_token_file, &bytes).unwrap();
            std::fs::set_permissions(&d.access_token_file, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            assert_eq!(Consumer::token(&d).is_ok(), expected);
        }
        std::fs::write(
            &d.access_token_file,
            serde_json::json!({"accessToken":"synthetic-token","expiresAtMs":now_ms()+60000})
                .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&d.access_token_file, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(Consumer::token(&d).is_err());
    }
}
