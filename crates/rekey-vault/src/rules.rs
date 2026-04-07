use anyhow::{Context, Result};
use rusqlite::Connection;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InjectionRule {
    pub id: String,
    pub secret_id: String,
    pub header_name: String,
    pub value_format: String,
    pub path_pattern: String,
    pub method: String,
}

pub fn add_injection_rule(
    conn: &Connection,
    secret_id: &str,
    header_name: &str,
    value_format: &str,
    path_pattern: &str,
    method: &str,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    conn.execute(
        "INSERT INTO injection_rules (id, secret_id, header_name, value_format, path_pattern, method)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, secret_id, header_name, value_format, path_pattern, method],
    )
    .context("failed to insert injection rule")?;
    Ok(id)
}

pub fn find_rules_for_host(conn: &Connection, host: &str) -> Result<Vec<(InjectionRule, String)>> {
    let host = host.trim().to_ascii_lowercase();
    let mut stmt = conn.prepare(
        "SELECT r.id, r.secret_id, r.header_name, r.value_format, r.path_pattern, r.method, s.name, s.host_pattern
         FROM injection_rules r
         JOIN secrets s ON s.id = r.secret_id
         WHERE s.host_pattern <> ''",
    )?;
    let mut rows = stmt.query([])?;
    let mut matched = Vec::new();
    while let Some(row) = rows.next()? {
        let pattern: String = row.get(7)?;
        if host_matches_pattern(&pattern, &host) {
            matched.push((
                InjectionRule {
                    id: row.get(0)?,
                    secret_id: row.get(1)?,
                    header_name: row.get(2)?,
                    value_format: row.get(3)?,
                    path_pattern: row.get(4)?,
                    method: row.get(5)?,
                },
                row.get(6)?,
            ));
        }
    }
    Ok(matched)
}

pub fn host_matches_pattern(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().to_ascii_lowercase();
    let host = host.trim().to_ascii_lowercase();
    if pattern.is_empty() || host.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() || host.len() <= suffix.len() {
            return false;
        }
        return host.ends_with(suffix) && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    host == pattern
}

#[cfg(test)]
mod tests {
    use super::host_matches_pattern;

    #[test]
    fn host_pattern_exact_match() {
        assert!(host_matches_pattern("api.openai.com", "api.openai.com"));
        assert!(!host_matches_pattern("api.openai.com", "openai.com"));
    }

    #[test]
    fn host_pattern_wildcard_match() {
        assert!(host_matches_pattern("*", "api.openai.com"));
        assert!(host_matches_pattern("*.openai.com", "api.openai.com"));
        assert!(host_matches_pattern("*.openai.com", "a.b.openai.com"));
        assert!(!host_matches_pattern("*.openai.com", "openai.com"));
        assert!(!host_matches_pattern("*.openai.com", "api.openai.org"));
    }
}
