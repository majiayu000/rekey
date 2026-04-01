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
    let mut stmt = conn.prepare(
        "SELECT r.id, r.secret_id, r.header_name, r.value_format, r.path_pattern, r.method, s.name
         FROM injection_rules r
         JOIN secrets s ON s.id = r.secret_id
         WHERE s.host_pattern = ?1 OR s.host_pattern = '*'",
    )?;
    let rows = stmt.query_map([host], |row| {
        Ok((
            InjectionRule {
                id: row.get(0)?,
                secret_id: row.get(1)?,
                header_name: row.get(2)?,
                value_format: row.get(3)?,
                path_pattern: row.get(4)?,
                method: row.get(5)?,
            },
            row.get::<_, String>(6)?,
        ))
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}
