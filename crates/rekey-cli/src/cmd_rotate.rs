use anyhow::Result;

pub fn run(name: &str, new_value: &str) -> Result<()> {
    let (conn, master_key) = super::cmd_init::open_vault()?;
    rekey_vault::secrets::rotate_secret(&conn, &master_key, name, new_value)?;
    println!("Rotated secret: {name}");
    Ok(())
}
