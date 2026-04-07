use anyhow::Result;

pub fn run() -> Result<()> {
    let port = super::cmd_runtime::resolve_port();
    let url = format!("http://localhost:{port}/dashboard");
    println!("Opening {url}");
    open::that(url)?;
    Ok(())
}
