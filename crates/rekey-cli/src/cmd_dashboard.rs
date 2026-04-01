use anyhow::Result;

pub fn run() -> Result<()> {
    let url = "http://localhost:10800/dashboard";
    println!("Opening {url}");
    open::that(url)?;
    Ok(())
}
