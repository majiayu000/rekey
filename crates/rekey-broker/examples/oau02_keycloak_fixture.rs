//! Test-only BrokerRuntime transport for the real Keycloak acceptance harness.
//! Injects one loopback TLS endpoint and its CA; production screening is unchanged.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rekey_broker::runtime::{BrokerConfig, serve};
use rekey_broker::upstream::{
    ScreenedEndpoint, UpstreamError, UpstreamFuture, UpstreamRequest, UpstreamTransport,
    send_screened,
};

struct LocalTlsTransport {
    address: SocketAddr,
    ca_der: Arc<Vec<u8>>,
}

impl UpstreamTransport for LocalTlsTransport {
    fn send(&self, request: UpstreamRequest) -> UpstreamFuture<'_> {
        Box::pin(async move {
            if request.host != "oau02.test" || request.port != self.address.port() {
                return Err(UpstreamError::Blocked("fixture-target-mismatch"));
            }
            let endpoint = ScreenedEndpoint {
                host: request.host.clone(),
                addr: self.address,
            };
            send_screened(request, endpoint, Some(&self.ca_der)).await
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("expected STATE CA_DER TLS_PORT".into());
    }
    let port: u16 = args[2].to_str().ok_or("invalid port")?.parse()?;
    let mut config = BrokerConfig::new(PathBuf::from(&args[0]));
    config.idle_lock = Duration::from_secs(15 * 60);
    config.transport = Some(Arc::new(LocalTlsTransport {
        address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        ca_der: Arc::new(std::fs::read(&args[1])?),
    }));
    serve(config).await?;
    Ok(())
}
