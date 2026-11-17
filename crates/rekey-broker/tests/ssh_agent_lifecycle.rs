//! Native SSH challenge cancellation, owner drain on shutdown and per-socket
//! budgets, plus the public facts recorded on `ssh.sign`. Synthetic keys,
//! sockets and vaults only; no user SSH files or hardware keys.
mod common;
mod ssh_support;

use std::time::Duration;

use data_encoding::{BASE64, BASE64_NOPAD};
use rekey_domain::connection::RuleEffect;
use rekey_domain::ipc::{Channel, admin_msg};
use serde_json::json;
use sha2::{Digest, Sha256};
use ssh_support::*;

async fn shutdown(f: &Fixture) {
    let stopped = common::call(
        &f.broker.admin_sock(),
        Channel::Admin,
        admin_msg::SHUTDOWN,
        b"{}",
        &common::proof_body(common::PASSWORD),
    )
    .await;
    assert_eq!(stopped.ok()["shutdown"], true);
}

#[tokio::test]
async fn shutdown_cancels_a_pending_challenge_without_execution() {
    let f = Fixture::new(RuleEffect::Approve).await;
    let mut stream = f.socket().await;
    send(
        &mut stream,
        &request(&f.public, &userauth(&f.public, &[31; 32])),
    )
    .await;
    f.pending().await;
    shutdown(&f).await;
    // The waiting owner is cancelled; no signature ever reaches the client.
    let reply = response(&mut stream, Duration::from_secs(10)).await;
    assert!(reply.is_none() || reply == Some(vec![FAILURE]), "{reply:?}");
    assert_eq!(f.count("approval.requested"), 1);
    assert_eq!(f.count("approval.accepted"), 0);
    assert_eq!(f.count("execution.started"), 0);
    let Fixture { broker, .. } = f;
    let runtime = tokio::time::timeout(Duration::from_secs(10), broker.serve_task)
        .await
        .expect("runtime did not stop")
        .expect("runtime task panicked");
    assert!(runtime.is_ok(), "runtime returned {runtime:?}");
}

#[tokio::test]
async fn expired_challenge_is_cancelled_without_execution() {
    // The signed per-socket window is the challenge deadline.
    let f = Fixture::configured(
        RuleEffect::Approve,
        json!({"max_signatures":5,"max_seconds":1}),
        Duration::from_secs(2),
    )
    .await;
    let mut stream = f.socket().await;
    send(
        &mut stream,
        &request(&f.public, &userauth(&f.public, &[31; 32])),
    )
    .await;
    let id = f.pending().await;
    let (state, hash) = f.review(&id).await;
    assert_eq!(state, "pending");
    assert_eq!(
        response(&mut stream, Duration::from_secs(10)).await,
        Some(vec![FAILURE])
    );
    assert_eq!(f.review(&id).await.0, "cancelled");
    // A late decision cannot revive it.
    assert_eq!(f.approve(&id, &hash).await.ok()["state"], "cancelled");
    assert_eq!(f.count("approval.accepted"), 0);
    assert_eq!(f.count("execution.started"), 0);
    drop(stream);
    f.broker.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_waits_for_the_ssh_sign_terminal_audit() {
    // The drain window outlasts the blocked terminal, so stop must wait for it.
    let f = Fixture::configured(
        RuleEffect::Allow,
        json!({"max_signatures":5,"max_seconds":600}),
        Duration::from_secs(60),
    )
    .await;
    let db = f.db();
    db.busy_timeout(Duration::ZERO).unwrap();
    // Hold the Worker inside the SSH terminal insert, which keeps the writer.
    db.execute_batch("CREATE TRIGGER slow_ssh_terminal BEFORE INSERT ON audit_events WHEN NEW.event_type='execution.finished' AND NEW.reason_code='ssh-sign' BEGIN SELECT sum(n) FROM (WITH RECURSIVE delay(n) AS (VALUES(0) UNION ALL SELECT n+1 FROM delay WHERE n<8000000) SELECT n FROM delay); END;").unwrap();
    let mut stream = f.socket().await;
    let (host, host_public) = host();
    let sid = [31; 32];
    assert_eq!(
        exchange(&mut stream, &bind(&host, &host_public, &sid)).await,
        vec![6]
    );
    send(&mut stream, &request(&f.public, &userauth(&f.public, &sid))).await;
    let writer_busy = || match db.execute_batch("BEGIN IMMEDIATE;") {
        Ok(()) => {
            db.execute_batch("ROLLBACK;").unwrap();
            false
        }
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::DatabaseBusy =>
        {
            true
        }
        Err(e) => panic!("unexpected writer probe {e}"),
    };
    tokio::time::timeout(Duration::from_secs(60), async {
        while !(writer_busy() && f.count("ssh.sign") == 1) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the SSH terminal audit never started");
    assert_eq!(f.count("execution.started"), 1);
    assert_eq!(f.count("execution.finished"), 0);
    let socket = f.broker.admin_sock();
    let stop = tokio::spawn(async move {
        common::call(
            &socket,
            Channel::Admin,
            admin_msg::SHUTDOWN,
            b"{}",
            &common::proof_body(common::PASSWORD),
        )
        .await
    });
    let mut observed_waiting = false;
    while writer_busy() {
        assert!(
            !stop.is_finished() && !f.broker.serve_task.is_finished(),
            "shutdown completed while the SSH terminal audit was uncommitted"
        );
        observed_waiting = true;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        observed_waiting,
        "the terminal finished before shutdown was observed"
    );
    let stopped = tokio::time::timeout(Duration::from_secs(60), stop)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stopped.ok()["shutdown"], true);
    // The owner kept its lifecycle permit through the durable terminal.
    assert_eq!(f.count("execution.finished"), 1);
    assert_eq!(f.reasons("execution.finished"), ["ssh-sign"]);
    let Fixture { broker, .. } = f;
    let runtime = tokio::time::timeout(Duration::from_secs(10), broker.serve_task)
        .await
        .expect("runtime did not stop")
        .expect("runtime task panicked");
    assert!(runtime.is_ok(), "runtime returned {runtime:?}");
}

#[tokio::test]
async fn each_socket_starts_its_own_signature_budget() {
    for ttl in [false, true] {
        let budget = if ttl {
            json!({"max_signatures":5,"max_seconds":1})
        } else {
            json!({"max_signatures":1,"max_seconds":600})
        };
        let f = Fixture::configured(RuleEffect::Allow, budget, Duration::from_secs(2)).await;
        let (host, host_public) = host();
        let sid = [31; 32];
        let packet = request(&f.public, &userauth(&f.public, &sid));
        for socket in 1..=2 {
            let mut stream = f.socket().await;
            assert_eq!(
                exchange(&mut stream, &bind(&host, &host_public, &sid)).await,
                vec![6]
            );
            assert_eq!(
                exchange(&mut stream, &packet).await[0],
                SIGNATURE,
                "socket {socket}"
            );
            if ttl {
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
            assert_eq!(
                exchange(&mut stream, &packet).await,
                vec![FAILURE],
                "socket {socket}"
            );
        }
        // One signature per socket: a new socket never inherits a spent budget.
        assert_eq!(f.count("execution.started"), 2, "ttl={ttl}");
        f.broker.shutdown().await;
    }
}

#[tokio::test]
async fn ssh_sign_audit_names_the_verified_host_fingerprint_and_use() {
    let f = Fixture::new(RuleEffect::Allow).await;
    let (host, host_public) = host();
    let sid = [31; 32];
    // Registered, signature-verified host: authentication is allowed.
    let mut bound = f.socket().await;
    assert_eq!(
        exchange(&mut bound, &bind(&host, &host_public, &sid)).await,
        vec![6]
    );
    let signed = exchange(&mut bound, &request(&f.public, &userauth(&f.public, &sid))).await;
    assert_eq!(signed[0], SIGNATURE);
    // Unbound git signing is allowed by the signed git rule.
    let mut git = f.socket().await;
    assert_eq!(
        exchange(&mut git, &request(&f.public, &sshsig(b"git"))).await[0],
        SIGNATURE
    );
    // Other namespaces and unbound authentication need an approval.
    for data in [sshsig(b"file"), userauth(&f.public, &[32; 32])] {
        let mut stream = f.socket().await;
        let packet = request(&f.public, &data);
        let task = tokio::spawn(async move { exchange(&mut stream, &packet).await });
        let id = f.pending().await;
        let (_, hash) = f.review(&id).await;
        f.approve(&id, &hash).await.ok();
        assert_eq!(task.await.unwrap()[0], SIGNATURE);
    }
    let fingerprint = format!(
        "SHA256:{}",
        BASE64_NOPAD.encode(&Sha256::digest(&host_public))
    );
    assert_eq!(
        f.reasons("ssh.sign"),
        [
            format!("ssh-sign;use=auth;host_key={fingerprint}"),
            "ssh-sign;use=git;host_key=none".into(),
            "ssh-sign;use=unknown;host_key=none".into(),
            "ssh-sign;use=auth;host_key=none".into(),
        ]
    );
    for event in ["execution.started", "execution.finished"] {
        assert!(f.reasons(event).iter().all(|reason| reason == "ssh-sign"));
    }
    // The fingerprint is the one OpenSSH prints for the same host key.
    let public_path = f.broker.dir.path().join("synthetic-host.pub");
    std::fs::write(
        &public_path,
        format!(
            "ssh-ed25519 {} synthetic-host\n",
            BASE64.encode(&host_public)
        ),
    )
    .unwrap();
    let listed = tokio::process::Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(&public_path)
        .output()
        .await
        .unwrap();
    assert!(listed.status.success());
    let listed = String::from_utf8(listed.stdout).unwrap();
    assert_eq!(listed.split_whitespace().nth(1), Some(fingerprint.as_str()));
    drop((bound, git));
    f.broker.shutdown().await;
}
