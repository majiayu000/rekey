use anyhow::Result;

fn request_count_since(started_at: i64) -> i64 {
    let conn = match rekey_vault::db::open_connection(super::cmd_init::db_path()) {
        Ok(conn) => conn,
        Err(_) => return 0,
    };
    conn.query_row(
        "SELECT COUNT(*) FROM audit_log WHERE timestamp >= ?1",
        [started_at],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

pub fn run() -> Result<()> {
    super::cmd_runtime::cleanup_stale_runtime();
    if let Some(state) = super::cmd_runtime::current_runtime_if_running()? {
        let now = super::cmd_runtime::now_unix();
        let uptime = (now - state.started_at).max(0);
        let request_count = request_count_since(state.started_at);
        println!("state: running");
        println!("pid: {}", state.pid);
        println!("port: {}", state.port);
        println!("uptime_seconds: {uptime}");
        println!("request_count: {request_count}");
        return Ok(());
    }

    println!("state: stopped");
    println!("port: {}", super::cmd_runtime::default_port());
    println!("request_count: 0");
    Ok(())
}
