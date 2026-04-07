use anyhow::Result;

pub fn run() -> Result<()> {
    let conn = rekey_vault::db::open_connection(super::cmd_init::db_path())?;
    rekey_vault::db::init_db(&conn)?;
    let secrets = rekey_vault::secrets::list_secrets(&conn)?;
    let port = super::cmd_runtime::resolve_port();

    println!("export HTTPS_PROXY=http://localhost:{port}");
    println!("export HTTP_PROXY=http://localhost:{port}");
    for s in &secrets {
        let env_name = match s.provider.as_str() {
            "anthropic" => "ANTHROPIC_API_KEY",
            "openai" => "OPENAI_API_KEY",
            "github" => "GITHUB_TOKEN",
            _ => continue,
        };
        println!("export {env_name}=REKEY_PLACEHOLDER");
    }
    Ok(())
}
