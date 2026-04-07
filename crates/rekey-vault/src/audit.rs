use anyhow::Result;
use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: i64,
    pub secret_name: String,
    pub target_host: String,
    pub target_path: String,
    pub status_code: Option<i32>,
    pub latency_ms: Option<i64>,
    pub source: String,
}

pub fn log_access(
    conn: &Connection,
    secret_name: &str,
    target_host: &str,
    target_path: &str,
    status_code: Option<i32>,
    latency_ms: Option<i64>,
    source: &str,
) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    conn.execute(
        "INSERT INTO audit_log (timestamp, secret_name, target_host, target_path, status_code, latency_ms, source)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![now, secret_name, target_host, target_path, status_code, latency_ms, source],
    )?;
    Ok(())
}

pub fn query_audit(
    conn: &Connection,
    secret_name_filter: Option<&str>,
    provider_filter: Option<&str>,
    since: Option<i64>,
    limit: u32,
) -> Result<Vec<AuditEntry>> {
    let mut sql = String::from(
        "SELECT id, timestamp, secret_name, target_host, target_path, status_code, latency_ms, source
         FROM audit_log WHERE 1=1",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(name) = secret_name_filter {
        sql.push_str(" AND secret_name = ?");
        params.push(Box::new(name.to_string()));
    }
    if let Some(provider) = provider_filter {
        sql.push_str(
            " AND EXISTS (SELECT 1 FROM secrets s WHERE s.name = audit_log.secret_name AND s.provider = ?)",
        );
        params.push(Box::new(provider.to_string()));
    }
    if let Some(ts) = since {
        sql.push_str(" AND timestamp >= ?");
        params.push(Box::new(ts));
    }
    sql.push_str(" ORDER BY timestamp DESC, id DESC LIMIT ?");
    params.push(Box::new(limit));

    let mut stmt = conn.prepare(&sql)?;
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(param_refs.as_slice(), |row| {
        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            secret_name: row.get(2)?,
            target_host: row.get(3)?,
            target_path: row.get(4)?,
            status_code: row.get(5)?,
            latency_ms: row.get(6)?,
            source: row.get(7)?,
        })
    })?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_query_audit() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_db(&conn).unwrap();

        log_access(
            &conn,
            "openai-key",
            "api.openai.com",
            "/v1/chat",
            Some(200),
            Some(150),
            "agent-1",
        )
        .unwrap();
        log_access(
            &conn,
            "anthropic-key",
            "api.anthropic.com",
            "/v1/messages",
            Some(200),
            Some(90),
            "agent-2",
        )
        .unwrap();

        let entries = query_audit(&conn, None, None, None, 100).unwrap();
        assert_eq!(entries.len(), 2);
        // Most recent first (both have same second-resolution timestamp, but rowid order is DESC)
        assert_eq!(entries[0].secret_name, "anthropic-key");
        assert_eq!(entries[1].secret_name, "openai-key");
    }

    #[test]
    fn query_audit_filter_by_provider() {
        let conn = Connection::open_in_memory().unwrap();
        crate::db::init_db(&conn).unwrap();

        log_access(
            &conn,
            "openai-key",
            "api.openai.com",
            "/v1/chat",
            Some(200),
            Some(150),
            "agent-1",
        )
        .unwrap();
        log_access(
            &conn,
            "anthropic-key",
            "api.anthropic.com",
            "/v1/messages",
            Some(200),
            Some(90),
            "agent-2",
        )
        .unwrap();

        let entries = query_audit(&conn, Some("openai-key"), None, None, 100).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].secret_name, "openai-key");
        assert_eq!(entries[0].target_host, "api.openai.com");
    }
}
