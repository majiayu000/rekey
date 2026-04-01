use anyhow::{Result, bail};
use rekey_vault::secrets::{CredentialType, store_credential};
use std::collections::HashMap;
use std::io::{self, Write};

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn prompt_secret(label: &str) -> Result<String> {
    rpassword::prompt_password(label).map_err(|e| anyhow::anyhow!("failed to read input: {e}"))
}

fn prompt_fields(cred_type: CredentialType) -> Result<HashMap<String, String>> {
    let mut fields = HashMap::new();
    match cred_type {
        CredentialType::Basic => {
            let username = prompt("Username: ")?;
            if username.is_empty() {
                bail!("username cannot be empty");
            }
            fields.insert("username".to_string(), username);
            fields.insert("password".to_string(), prompt_secret("Password: ")?);
        }
        CredentialType::Bearer => {
            let token = prompt_secret("Token: ")?;
            if token.is_empty() {
                bail!("token cannot be empty");
            }
            fields.insert("token".to_string(), token);
        }
        CredentialType::ApiKey => {
            let value = prompt_secret("API Key: ")?;
            if value.is_empty() {
                bail!("API key cannot be empty");
            }
            fields.insert("value".to_string(), value);
            let header = prompt("Header name [authorization]: ")?;
            fields.insert(
                "header".to_string(),
                if header.is_empty() {
                    "authorization".to_string()
                } else {
                    header
                },
            );
            let format = prompt("Value format [Bearer {value}]: ")?;
            fields.insert(
                "format".to_string(),
                if format.is_empty() {
                    "Bearer {value}".to_string()
                } else {
                    format
                },
            );
        }
        CredentialType::Custom => {
            loop {
                let name = prompt("Field name (empty to finish): ")?;
                if name.is_empty() {
                    break;
                }
                let value = prompt_secret(&format!("{name}: "))?;
                fields.insert(name, value);
            }
            if fields.is_empty() {
                bail!("at least one field is required");
            }
        }
    }
    Ok(fields)
}

pub fn run(name: &str, cred_type: Option<&str>) -> Result<()> {
    let (conn, master_key) = super::cmd_init::open_vault()?;

    let cred_type: CredentialType = match cred_type {
        Some(t) => t.parse()?,
        None => {
            let input = prompt("Credential type (api-key/basic/bearer/custom) [api-key]: ")?;
            if input.is_empty() {
                CredentialType::ApiKey
            } else {
                input.parse()?
            }
        }
    };

    let fields = prompt_fields(cred_type)?;
    store_credential(&conn, &master_key, name, cred_type, &fields)?;

    println!("Stored credential '{name}' ({cred_type})");
    Ok(())
}
