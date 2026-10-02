mod auth;
mod directory;
mod relay;

use http_body_util::Full;
use hyper::{body::Bytes, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::Read,
    net::SocketAddr,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use tokio_rustls::TlsAcceptor;
use zeroize::Zeroizing;

type Failure = &'static str;
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Approver {
    subject: String,
    approver_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    format_version: u32,
    instance_id: String,
    endpoint: String,
    listen_address: SocketAddr,
    state_dir: PathBuf,
    tls_certificate_file: PathBuf,
    tls_key_file: PathBuf,
    idp_issuer: String,
    introspection_url: String,
    idp_ca_certificate_file: PathBuf,
    introspection_client_id: String,
    introspection_client_secret_file: PathBuf,
    personnel_client_id: String,
    audience: String,
    tenant_id: String,
    origin_public_key: String,
    uploader_subject: String,
    approvers: Vec<Approver>,
    directory: directory::Directory,
}
fn canonical_uuid(s: &str) -> bool {
    uuid::Uuid::parse_str(s).is_ok_and(|id| id.to_string() == s)
}
fn https_url(s: &str) -> Result<url::Url, Failure> {
    let u = url::Url::parse(s).map_err(|_| "invalid-config")?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
    {
        return Err("invalid-config");
    }
    Ok(u)
}
impl Config {
    fn validate(&self) -> Result<(), Failure> {
        if self.format_version != 2
            || !canonical_uuid(&self.instance_id)
            || !canonical_uuid(&self.tenant_id)
            || https_url(&self.endpoint)?.path() != "/v1"
            || self.approvers.is_empty()
            || self.approvers.len() > 32
            || !self.state_dir.is_absolute()
        {
            return Err("invalid-config");
        }
        https_url(&self.introspection_url)?;
        https_url(&self.idp_issuer)?;
        if self.idp_issuer.len() > 256 {
            return Err("invalid-config");
        }
        rekey_policy::validate_ed25519_public_key(&self.origin_public_key)
            .map_err(|_| "invalid-config")?;
        let mut subjects = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for a in &self.approvers {
            if !stable(&a.subject)
                || !canonical_uuid(&a.approver_id)
                || !subjects.insert(&a.subject)
                || !ids.insert(&a.approver_id)
            {
                return Err("invalid-config");
            }
        }
        if [
            &self.uploader_subject,
            &self.introspection_client_id,
            &self.personnel_client_id,
            &self.audience,
        ]
        .iter()
        .any(|s| !stable(s))
        {
            return Err("invalid-config");
        }
        self.directory.validate(self)?;
        Ok(())
    }
}
fn stable(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control)
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(i64::MAX)
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private_file(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "private-file")?;
    let m = file.metadata().map_err(|_| "private-file")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > limit
    {
        return Err("private-file");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "private-file")?;
    if bytes.len() as u64 > limit {
        return Err("private-file");
    }
    Ok(bytes)
}
fn state_directory(path: &Path) -> Result<File, Failure> {
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)
        .map_err(|_| "private-state")?;
    let m = dir.metadata().map_err(|_| "private-state")?;
    if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o777 != 0o700 {
        return Err("private-state");
    }
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("state-in-use");
    }
    Ok(dir)
}
fn tls_config(c: &Config) -> Result<rustls::ServerConfig, Failure> {
    let cert = private_file(&c.tls_certificate_file, 64 * 1024)?;
    let key = private_file(&c.tls_key_file, 16 * 1024)?;
    let certificates = CertificateDer::pem_slice_iter(&cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid-tls")?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|_| "invalid-tls")?;
    rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|_| "invalid-tls")?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| "invalid-tls")
}
fn directory_registration(config_path: &Path) -> Result<(), Failure> {
    let bytes = private_file(config_path, 64 * 1024)?;
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| "invalid-config")?;
    config.validate()?;
    println!("{}", config.directory.registration()?);
    Ok(())
}
async fn serve(config_path: &Path) -> Result<(), Failure> {
    unsafe {
        libc::umask(0o077);
    }
    let bytes = private_file(config_path, 64 * 1024)?;
    let config: Config = serde_json::from_slice(&bytes).map_err(|_| "invalid-config")?;
    config.validate()?;
    let config_digest = sha(&bytes);
    let directory = state_directory(&config.state_dir)?;
    let tls = TlsAcceptor::from(Arc::new(tls_config(&config)?));
    let auth = auth::Authenticator::new(&config)?;
    let consumer = directory::Consumer::new(&config.directory)?;
    let store = relay::Store::open(&config, directory)?;
    let service = Arc::new(relay::Service::new(config, auth, store));
    service.cleanup()?;
    service.poll_directory(&consumer).await?;
    let listener = TcpListener::bind(service.config.listen_address)
        .await
        .map_err(|_| "listen-failed")?;
    println!(
        "rekey.approval.relay.v2 instance={} config_sha256={}",
        service.config.instance_id, config_digest
    );
    let slots = Arc::new(Semaphore::new(16));
    let mut tasks = JoinSet::new();
    let polling_service = service.clone();
    let polling = tasks.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            if polling_service.is_faulted()
                || polling_service.poll_directory(&consumer).await.is_err()
            {
                break;
            }
        }
    });
    let mut cleanup = tokio::time::interval(Duration::from_secs(60));
    cleanup.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = service.faulted.notified() => break,
            _ = tokio::signal::ctrl_c() => break,
            _ = terminate() => break,
            _ = cleanup.tick() => { if service.cleanup().is_err() { break; } },
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if result.is_err() { service.fault(); break; }
            },
            accepted = listener.accept() => {
                let (socket, _) = accepted.map_err(|_| "accept-failed")?;
                if service.is_faulted() { break; }
                let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                let deadline = Instant::now() + Duration::from_secs(10);
                let tls = tls.clone(); let service = service.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(stream)) = timeout(Duration::from_secs(3), tls.accept(socket)).await else { return; };
                    let handler = service_fn(move |request| {
                        let service = service.clone();
                        async move { Ok::<_, std::convert::Infallible>(service.handle(request, deadline).await) }
                    });
                    let _ = timeout_at(deadline, http1::Builder::new().timer(TokioTimer::new())
                        .keep_alive(false).max_headers(32).max_buf_size(16 * 1024)
                        .header_read_timeout(Duration::from_secs(3))
                        .serve_connection(TokioIo::new(stream), handler)).await;
                });
            }
        }
    }
    drop(listener);
    polling.abort();
    if timeout(Duration::from_secs(10), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    if service.is_faulted() {
        Err("storage-fault")
    } else {
        Ok(())
    }
}
async fn terminate() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut signal) => {
            signal.recv().await;
        }
        Err(_) => std::future::pending::<()>().await,
    }
}
fn response(status: hyper::StatusCode, bytes: Vec<u8>) -> hyper::Response<Full<Bytes>> {
    let mut r = hyper::Response::new(Full::new(Bytes::from(bytes)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    r.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    r
}
#[tokio::main]
async fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("rekey-approval-relay: internal-failure")
    }));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!(
            "rekey-approval-relay serve --config PRIVATE.json\nrekey-approval-relay directory-registration --config PRIVATE.json\nHTTPS approval file transport and authenticated GET /v1/inbox; Broker revalidates at execute"
        );
        return;
    }
    let result = if args.len() == 3 && args[0] == "serve" && args[1] == "--config" {
        serve(Path::new(&args[2])).await
    } else if args.len() == 3 && args[0] == "directory-registration" && args[1] == "--config" {
        directory_registration(Path::new(&args[2]))
    } else {
        Err("invalid-arguments")
    };
    if let Err(error) = result {
        eprintln!("rekey-approval-relay: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
fn test_config(state: &Path) -> Config {
    serde_json::from_value(serde_json::json!({"formatVersion":2,
      "instanceId":"11111111-1111-4111-8111-111111111111","tenantId":"22222222-2222-4222-8222-222222222222",
      "endpoint":"https://localhost:443/v1","listenAddress":"127.0.0.1:443","stateDir":state,
      "tlsCertificateFile":"/fixture/ca","tlsKeyFile":"/fixture/key","idpIssuer":"https://issuer.test",
      "introspectionUrl":"https://issuer.test/introspect","idpCaCertificateFile":"/fixture/ca",
      "introspectionClientId":"relay","introspectionClientSecretFile":"/fixture/secret",
      "personnelClientId":"personnel","audience":"relay","originPublicKey":"11".repeat(32),
      "uploaderSubject":"operator","approvers":[{"subject":"reviewer","approverId":"33333333-3333-4333-8333-333333333333"}],
      "directory":{"baseUrl":"https://directory.test/scim/v2","caCertificateFile":"/fixture/ca","accessTokenFile":"/fixture/token",
      "mappingVersion":1,"nodes":[{"nodeId":"11111111-1111-4111-8111-111111111111","vaultId":"22222222-2222-4222-8222-222222222222"},
      {"nodeId":"33333333-3333-4333-8333-333333333333","vaultId":"44444444-4444-4444-8444-444444444444"}],
      "links":[{"sourceUserId":"user-1","externalId":"person-1","issuer":"https://issuer.test","subject":"operator",
      "principalId":"11111111-1111-4111-8111-111111111111","adminAllowed":true,"confirmedBy":"operator-registrar","confirmedAtMs":1},
      {"sourceUserId":"user-2","externalId":"person-2","issuer":"https://issuer.test","subject":"reviewer",
      "principalId":"22222222-2222-4222-8222-222222222222","approverId":"33333333-3333-4333-8333-333333333333",
      "publicKeySha256":"22".repeat(32),"adminAllowed":true,"confirmedBy":"operator-registrar","confirmedAtMs":1}]}})).unwrap()
}
