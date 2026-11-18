//! Hard-kill recovery with a real child process. The child publishes its
//! marker by rename, so the parent never parses a partial file, and the parent
//! waits for that event or the child's exit. The wall clock only bounds a hang.
use std::time::{Duration, Instant};

use rekey_domain::ids::PrincipalId;
use rekey_vault::{model::UsageTotals, paths};
use rusqlite::Connection;

use super::{begin, common, draft, finish, limits, sum};

/// Full libtest name of the child entry inside the `usage` test binary.
const CHILD: &str = "hard_kill::hard_kill_child";
/// Process start, unlock and one durable admission; a passing run never waits it out.
const CHILD_LIVENESS: Duration = Duration::from_secs(60);

#[test]
fn hard_kill_child() {
    let Some(state) = std::env::var_os("REKEY_USAGE_SYNTHETIC_CHILD") else {
        return;
    };
    let state = std::path::PathBuf::from(state);
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (h, _join) = common::spawn(&state);
        h.unlock(common::password_proof()).await.unwrap();
        let p = PrincipalId::new_random();
        begin(&h, limits(Some(37)), draft(p)).await.unwrap();
        let dir = state.parent().unwrap();
        let staged = dir.join("usage-ready.partial");
        std::fs::write(&staged, serde_json::to_vec(&p).unwrap()).unwrap();
        std::fs::rename(&staged, dir.join("usage-ready")).unwrap();
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

#[tokio::test]
async fn hard_kill_pending_is_recovered_once_before_unlock_admission() {
    let v = common::init_test_vault();
    let log = v.dir.path().join("child-stderr");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD, "--nocapture"])
        .env("REKEY_USAGE_SYNTHETIC_CHILD", &v.state_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let marker = v.dir.path().join("usage-ready");
    let started = Instant::now();
    let limit = common::test_timeout(CHILD_LIVENESS);
    while !marker.exists() {
        let exited = child.try_wait().unwrap();
        if exited.is_some() || started.elapsed() >= limit {
            let _ = child.kill();
            let status = child.wait().unwrap();
            panic!(
                "synthetic child did not durably start after {:?} ({status}): {}",
                started.elapsed(),
                std::fs::read_to_string(&log).unwrap_or_default()
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let p: PrincipalId = serde_json::from_slice(&std::fs::read(marker).unwrap()).unwrap();
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    for _ in 0..2 {
        let (h, j) = common::spawn(&v.state_dir);
        let db = Connection::open(paths::vault_db(&v.state_dir)).unwrap();
        h.unlock(common::password_proof()).await.unwrap();
        assert_eq!(
            sum(&h, p).await,
            UsageTotals {
                requests: 1,
                output_tokens: 37
            }
        );
        let n: i64 = db
            .query_row(
                "SELECT count(*) FROM audit_events WHERE event_type='execution.indeterminate'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
        finish(h, j).await;
    }
}
