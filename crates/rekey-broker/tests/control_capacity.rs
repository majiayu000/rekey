//! Shared live-owner capacity on the default build: 16 native SSH owners, a
//! bounded close for the 17th, and seven short admin requests that stay
//! independently admitted while the eighth gets immediate retryable
//! AUTHORITY_BUSY. Synthetic vault and keys only.
mod common;
mod ssh_support;

use std::time::Duration;

use rekey_domain::connection::RuleEffect;
use rekey_domain::ipc::{Channel, admin_msg};
use serde_json::json;
use ssh_support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIVE_OWNERS: usize = 16;
const SHORT_ADMIN_REQUESTS: usize = 7;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_live_ssh_owners_keep_seven_short_admin_requests_available() {
    let f = Fixture::new(RuleEffect::Allow).await;
    let mut owners = Vec::new();
    for _ in 0..LIVE_OWNERS {
        let mut stream = f.socket().await;
        // A reply proves the agent accepted the socket and holds its owner.
        assert_eq!(exchange(&mut stream, &[11]).await[0], 12);
        owners.push(stream);
    }

    // OpenSSH has no busy reply: the 17th socket is closed without a frame.
    let mut refused = f.socket().await;
    let _ = refused.write_u32(1).await;
    let _ = refused.write_all(&[11]).await;
    let mut byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(5), refused.read(&mut byte))
        .await
        .expect("the 17th SSH connection must be closed boundedly")
    {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
            ) => {}
        other => panic!("the 17th SSH connection was served: {other:?}"),
    }

    // Short admin requests do not compete with live owners. Hold the SQLite
    // writer so every admitted request stays in flight behind the Worker.
    let db = f.db();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut requests = Vec::new();
    for n in 0..=SHORT_ADMIN_REQUESTS {
        let socket = f.broker.admin_sock();
        requests.push(tokio::spawn(async move {
            common::call(
                &socket,
                Channel::Admin,
                admin_msg::CREDENTIAL_ADD,
                json!({"label":format!("capacity-{n}"),"kind":"opaque-token"})
                    .to_string()
                    .as_bytes(),
                &common::proof_and_secret_body(common::PASSWORD, b"SYNTHETIC-CAPACITY"),
            )
            .await
        }));
    }
    let refused = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(index) = requests.iter().position(|r| r.is_finished()) {
                return index;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the eighth short admin request must be refused immediately");
    let busy = requests.remove(refused).await.unwrap();
    assert_eq!(busy.err_code(), "AUTHORITY_BUSY");
    assert_eq!(busy.metadata["retryable"], true);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let blocked = requests.iter().filter(|r| !r.is_finished()).count();
    db.execute_batch("COMMIT").unwrap();
    assert_eq!(
        blocked, SHORT_ADMIN_REQUESTS,
        "admitted requests stay in flight"
    );
    for request in requests {
        request.await.unwrap().ok();
    }
    assert_eq!(
        db.query_row("SELECT count(*) FROM credentials", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        SHORT_ADMIN_REQUESTS as i64 + 1,
        "seven admitted adds plus the SSH identity"
    );

    // The owners stayed live throughout; releasing one admits a new socket.
    assert_eq!(exchange(&mut owners[0], &[11]).await[0], 12);
    drop(owners.pop());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // The released owner drops asynchronously; until then a new socket is refused.
            let mut stream = f.socket().await;
            let _ = stream.write_u32(1).await;
            let _ = stream.write_all(&[11]).await;
            if let Ok(len) = stream.read_u32().await {
                let mut reply = vec![0; len as usize];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply[0], 12);
                owners.push(stream);
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a released owner slot is reusable");
    drop(owners);
    f.broker.shutdown().await;
}
