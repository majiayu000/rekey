use anyhow::{Result, bail};

pub fn run(name: &str, value: &str, host: Option<&str>, header: Option<&str>) -> Result<()> {
    let (conn, master_key) = super::cmd_init::open_vault()?;
    let provider = rekey_vault::providers::get_provider(name);
    let host_pattern = match (host, &provider) {
        (Some(h), _) => h.to_string(),
        (None, Some(p)) => p.host_pattern.to_string(),
        (None, None) => bail!("--host required for generic provider"),
    };
    let provider_name = if provider.is_some() { name } else { "generic" };
    rekey_vault::secrets::add_secret(
        &conn,
        &master_key,
        name,
        provider_name,
        value,
        &host_pattern,
    )?;

    if provider.is_none() {
        let header = header.unwrap_or("authorization");
        let secret_id = conn.query_row("SELECT id FROM secrets WHERE name = ?1", [name], |r| {
            r.get::<_, String>(0)
        })?;
        rekey_vault::rules::add_injection_rule(&conn, &secret_id, header, "{value}", "*", "*")?;
    }

    println!("Added secret: {name} -> {host_pattern}");
    Ok(())
}
