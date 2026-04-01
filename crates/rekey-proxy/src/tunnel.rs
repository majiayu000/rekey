use anyhow::Result;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

pub async fn tunnel_passthrough(
    mut client: tokio::io::DuplexStream,
    host: &str,
    port: u16,
) -> Result<()> {
    let addr = format!("{host}:{port}");
    let mut upstream = TcpStream::connect(&addr).await?;
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
