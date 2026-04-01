use anyhow::Result;

pub fn run() -> Result<()> {
    let path = super::cmd_init::db_path();
    let conn = rusqlite::Connection::open(path)?;
    rekey_vault::db::init_db(&conn)?;
    let secrets = rekey_vault::secrets::list_secrets(&conn)?;
    if secrets.is_empty() {
        println!("No secrets configured. Run: rekey add <provider> <key>");
        return Ok(());
    }
    println!("{:<15} {:<12} {:<30}", "NAME", "PROVIDER", "HOST");
    println!("{}", "-".repeat(57));
    for s in &secrets {
        println!("{:<15} {:<12} {:<30}", s.name, s.provider, s.host_pattern);
    }
    Ok(())
}
