use anyhow::{Context, Result};

pub fn run(daemon: bool, port: u16) -> Result<()> {
    let dir = super::cmd_init::rekey_dir();
    let ca = rekey_ca::authority::CertificateAuthority::load(&dir)?;
    let password = super::cmd_init::prompt_password("Master password: ")?;

    let conn = rusqlite::Connection::open(super::cmd_init::db_path())?;
    let salt: Vec<u8> = conn.query_row("SELECT value FROM config WHERE key = 'salt'", [], |r| {
        r.get(0)
    })?;
    let master_key = rekey_vault::crypto::derive_master_key(&password, &salt)?;
    drop(conn);

    if daemon {
        println!("Daemon mode not yet implemented — running in foreground");
    }

    println!("rekey proxy starting on 127.0.0.1:{port}");
    let rt = tokio::runtime::Runtime::new().context("failed to create proxy runtime")?;
    rt.block_on(async {
        let server = rekey_proxy::server::ProxyServer::new(
            ca,
            master_key,
            super::cmd_init::db_path().to_string_lossy().to_string(),
            port,
        );
        server.run().await
    })
}
