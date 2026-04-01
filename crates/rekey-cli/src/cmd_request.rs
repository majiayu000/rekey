use anyhow::{Context, Result};
use base64::Engine;
use rekey_vault::secrets::{CredentialType, get_credential_fields};

pub fn run(
    name: &str,
    url: &str,
    method: &str,
    body: Option<&str>,
    extra_headers: &[String],
) -> Result<()> {
    let (conn, master_key) = super::cmd_init::open_vault()?;
    let (cred_type, fields) = get_credential_fields(&conn, &master_key, name)
        .with_context(|| format!("failed to load credential '{name}'"))?;

    let client = reqwest::blocking::Client::builder()
        .build()
        .context("failed to create HTTP client")?;

    let http_method: reqwest::Method =
        method.parse().with_context(|| format!("invalid HTTP method: {method}"))?;

    let mut req = client.request(http_method, url);

    match cred_type {
        CredentialType::Basic => {
            let username = fields.get("username").context("missing 'username' field")?;
            let password = fields.get("password").context("missing 'password' field")?;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
            req = req.header("authorization", format!("Basic {encoded}"));
        }
        CredentialType::Bearer => {
            let token = fields.get("token").context("missing 'token' field")?;
            req = req.header("authorization", format!("Bearer {token}"));
        }
        CredentialType::ApiKey => {
            let value = fields.get("value").context("missing 'value' field")?;
            let header = fields
                .get("header")
                .map(|s| s.as_str())
                .unwrap_or("authorization");
            let format_tmpl = fields
                .get("format")
                .map(|s| s.as_str())
                .unwrap_or("Bearer {value}");
            let header_value = format_tmpl.replace("{value}", value);
            req = req.header(header, header_value);
        }
        CredentialType::Custom => {
            for (key, value) in &fields {
                req = req.header(key.as_str(), value.as_str());
            }
        }
    }

    for h in extra_headers {
        if let Some((k, v)) = h.split_once(':') {
            req = req.header(k.trim(), v.trim());
        }
    }

    if let Some(b) = body {
        req = req.body(b.to_string());
    }

    let parsed_url = reqwest::Url::parse(url).ok();
    let target_host = parsed_url
        .as_ref()
        .and_then(|u| u.host_str())
        .unwrap_or("")
        .to_string();
    let target_path = parsed_url
        .as_ref()
        .map(|u| u.path().to_string())
        .unwrap_or_default();

    let start = std::time::Instant::now();
    let resp = req.send().context("request failed")?;
    let elapsed = start.elapsed().as_millis() as i64;
    let status = resp.status().as_u16() as i32;

    if let Err(e) = rekey_vault::audit::log_access(
        &conn,
        name,
        &target_host,
        &target_path,
        Some(status),
        Some(elapsed),
        "cli",
    ) {
        eprintln!("warning: failed to log audit: {e}");
    }

    let body_text = resp.text().context("failed to read response body")?;
    print!("{body_text}");

    if status >= 400 {
        std::process::exit(1);
    }

    Ok(())
}
