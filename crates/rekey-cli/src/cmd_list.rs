use anyhow::Result;

pub fn run() -> Result<()> {
    let path = super::cmd_init::db_path();
    let conn = rusqlite::Connection::open(path)?;
    rekey_vault::db::init_db(&conn)?;
    let secrets = rekey_vault::secrets::list_secrets(&conn)?;
    if secrets.is_empty() {
        println!("No credentials stored. Run: rekey store <name> or rekey add <provider> <key>");
        return Ok(());
    }
    println!(
        "{:<20} {:<10} {:<12} {:<30}",
        "NAME", "TYPE", "PROVIDER", "HOST"
    );
    println!("{}", "-".repeat(72));
    for s in &secrets {
        let provider = if s.provider.is_empty() {
            "-"
        } else {
            &s.provider
        };
        let host = if s.host_pattern.is_empty() {
            "-"
        } else {
            &s.host_pattern
        };
        println!(
            "{:<20} {:<10} {:<12} {:<30}",
            s.name, s.credential_type, provider, host
        );
    }
    Ok(())
}
