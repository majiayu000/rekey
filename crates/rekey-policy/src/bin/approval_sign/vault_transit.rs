//! One fixed Transit Ed25519 signing endpoint; private to the operator binary.
use super::Result;
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use data_encoding::BASE64;
use rekey_domain::action::ip_is_public;
use reqwest::header::HeaderValue;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Read,
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    time::Duration,
};
use zeroize::Zeroizing;

const PROFILE_LIMIT: usize = 65536;
const RESPONSE_LIMIT: usize = 65536;
const DEADLINE: Duration = Duration::from_secs(10);
const REMOTE_ERROR: &str =
    "Transit signing failed; remote result may be unknown; no automatic retry";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    credential_type: String,
    origin: String,
    mount: String,
    key: String,
    key_version: u32,
    public_key: String,
    vault_token: Zeroizing<String>,
    token_expires_at_ms: i64,
}

fn segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

impl Profile {
    pub(super) fn load(path: &str) -> Result<Self> {
        let load = || -> Result<Self> {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
                || meta.len() > PROFILE_LIMIT as u64
            {
                return Err("invalid profile permissions or size".into());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            file.take((PROFILE_LIMIT + 1) as u64)
                .read_to_end(&mut bytes)?;
            if bytes.len() > PROFILE_LIMIT {
                return Err("profile size limit".into());
            }
            let profile: Self = serde_json::from_slice(&bytes)?;
            let origin = url::Url::parse(&profile.origin)?;
            if profile.credential_type != "vault-transit-approval-v1"
                || origin.scheme() != "https"
                || origin.host_str().is_none()
                || !origin.username().is_empty()
                || origin.password().is_some()
                || origin.query().is_some()
                || origin.fragment().is_some()
                || profile.origin != origin.origin().ascii_serialization()
                || !segment(&profile.mount)
                || !segment(&profile.key)
                || profile.key_version == 0
                || profile.token_expires_at_ms <= 0
                || profile.vault_token.is_empty()
                || profile.vault_token.len() > 8192
                || !profile
                    .vault_token
                    .bytes()
                    .all(|byte| (33..=126).contains(&byte))
            {
                return Err("invalid profile".into());
            }
            rekey_policy::validate_ed25519_public_key(&profile.public_key)?;
            Ok(profile)
        };
        load().map_err(|_| "invalid private Transit profile".into())
    }

    pub(super) fn public_review(&self) -> Value {
        json!({"credential_type":self.credential_type,"origin":self.origin,"mount":self.mount,
               "key":self.key,"key_version":self.key_version,"public_key":self.public_key})
    }

    pub(super) fn check(&self, approver_key: &[u8], time_ms: i64) -> Result<()> {
        if self.token_expires_at_ms <= time_ms {
            return Err("Transit token expired".into());
        }
        if rekey_policy::validate_ed25519_public_key(&self.public_key)?.as_slice() != approver_key {
            return Err("Transit public key does not match policy approver".into());
        }
        Ok(())
    }

    pub(super) fn sign(
        &self,
        message: &[u8],
        approver_key: &[u8],
        grant_expires_at_ms: i64,
    ) -> Result<Vec<u8>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| REMOTE_ERROR)?;
        let result = runtime.block_on(async {
            tokio::time::timeout(
                request_deadline(),
                self.request(message, grant_expires_at_ms),
            )
            .await
            .map_err(|_| REMOTE_ERROR)?
        });
        // lookup_host may use an OS resolver blocking task. Cancellation prevents
        // continuation to POST; do not wait indefinitely for that resolver on drop.
        runtime.shutdown_timeout(Duration::ZERO);
        let bytes = result.map_err(|_| REMOTE_ERROR)?;
        let signature = parse_signature(&bytes, self.key_version).map_err(|_| REMOTE_ERROR)?;
        UnparsedPublicKey::new(&ED25519, approver_key)
            .verify(message, &signature)
            .map_err(|_| REMOTE_ERROR)?;
        Ok(signature)
    }

    async fn request(
        &self,
        message: &[u8],
        grant_expires_at_ms: i64,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let origin = url::Url::parse(&self.origin)?;
        let host = origin.host_str().ok_or(REMOTE_ERROR)?;
        let port = origin.port_or_known_default().ok_or(REMOTE_ERROR)?;
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .timeout(request_deadline())
            .connect_timeout(request_deadline());
        #[cfg(test)]
        let fixture = TEST_TRANSPORT.with(|value| value.borrow().clone());
        #[cfg(test)]
        let addresses = if let Some(fixture) = fixture {
            tokio::time::sleep(fixture.dns_delay).await;
            builder = builder.add_root_certificate(fixture.certificate);
            fixture.addresses
        } else {
            resolve(host, port).await?
        };
        #[cfg(not(test))]
        let addresses = resolve(host, port).await?;
        builder = builder.resolve_to_addrs(host, &addresses);
        let client = builder.build()?;
        let admission = super::now()?.as_unix_ms();
        if admission >= self.token_expires_at_ms || admission >= grant_expires_at_ms {
            return Err("Transit token or grant expired before remote admission".into());
        }
        let mut token = HeaderValue::from_str(self.vault_token.as_str())?;
        token.set_sensitive(true);
        let payload = json!({"input":BASE64.encode(message),"key_version":self.key_version,"prehashed":false});
        let mut response = client
            .post(format!(
                "{}/v1/{}/sign/{}",
                self.origin, self.mount, self.key
            ))
            .header("X-Vault-Token", token)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(&payload)?)
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::OK
            || response
                .content_length()
                .is_some_and(|n| n > RESPONSE_LIMIT as u64)
        {
            return Err(REMOTE_ERROR.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > RESPONSE_LIMIT - bytes.len() {
                return Err(REMOTE_ERROR.into());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

fn screen(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
    if addresses.is_empty() || addresses.iter().any(|address| !ip_is_public(address.ip())) {
        return Err(REMOTE_ERROR.into());
    }
    Ok(addresses)
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    screen(
        tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
            .await?
            .collect(),
    )
}

fn parse_signature(bytes: &[u8], version: u32) -> Result<Vec<u8>> {
    #[derive(Deserialize)]
    struct Envelope {
        data: Signature,
    }
    #[derive(Deserialize)]
    struct Signature {
        signature: String,
    }
    let response: Envelope = serde_json::from_slice(bytes)?;
    let prefix = format!("vault:v{version}:");
    let encoded = response
        .data
        .signature
        .strip_prefix(&prefix)
        .ok_or(REMOTE_ERROR)?;
    let signature = BASE64.decode(encoded.as_bytes())?;
    if signature.len() != 64 || BASE64.encode(&signature) != encoded {
        return Err(REMOTE_ERROR.into());
    }
    Ok(signature)
}

fn request_deadline() -> Duration {
    #[cfg(test)]
    if let Some(fixture) = TEST_TRANSPORT.with(|value| value.borrow().clone()) {
        return fixture.deadline;
    }
    DEADLINE
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct TestTransport {
    pub addresses: Vec<SocketAddr>,
    pub certificate: reqwest::Certificate,
    pub deadline: Duration,
    pub dns_delay: Duration,
}

#[cfg(test)]
thread_local! {
    pub(super) static TEST_TRANSPORT: std::cell::RefCell<Option<TestTransport>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(super) fn screen_for_test(addresses: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
    screen(addresses)
}
