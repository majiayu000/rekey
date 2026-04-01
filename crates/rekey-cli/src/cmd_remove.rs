use anyhow::Result;

pub fn run(name: &str) -> Result<()> {
    let (conn, _) = super::cmd_init::open_vault()?;
    rekey_vault::secrets::remove_secret(&conn, name)?;
    println!("Removed secret: {name}");
    Ok(())
}
