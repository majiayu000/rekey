use crate::{
    Config, Failure,
    auth::{Authenticator, Identity},
    canonical_uuid,
    directory::{self, Link, Observation, State},
    now_ms, response, sha,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::{AUTHORIZATION, HeaderValue},
};
use rekey_domain::authorization::ApprovalMode;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{sync::Notify, time::Instant};
use zeroize::Zeroizing;

const RETENTION: i64 = 24 * 60 * 60 * 1000;
const MAX_BLOBS: i64 = 64 * 1024 * 1024;
const MAX_REQUESTS: i64 = 4096;
const MAX_EVENTS: i64 = 32768;
#[derive(Debug)]
enum Error {
    Http(u16),
    Storage,
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}
type Result<T> = std::result::Result<T, Error>;

pub struct Store {
    db: Connection,
    directory: File,
    db_file: File,
    directory_path: PathBuf,
    fresh: BTreeMap<String, (Instant, i64, i64)>,
}
struct Row {
    uploader: String,
    recipient: String,
    approver: String,
    challenge: Vec<u8>,
    challenge_sha: String,
    challenge_expires: i64,
    challenge_receipt: Vec<u8>,
    grant: Option<Vec<u8>>,
    grant_sha: Option<String>,
    grant_expires: Option<i64>,
    grant_receipt: Option<Vec<u8>>,
}
struct Output {
    status: u16,
    bytes: Vec<u8>,
    digest: Option<String>,
    expires: Option<i64>,
}
impl Output {
    fn receipt(status: u16, bytes: Vec<u8>) -> Self {
        Self {
            status,
            bytes,
            digest: None,
            expires: None,
        }
    }
}
struct InboxQuery {
    after: Option<(i64, String)>,
    include_expired: bool,
}
impl InboxQuery {
    fn parse(query: Option<&str>) -> Result<Self> {
        let query = query.unwrap_or_default();
        if query.len() > 256 {
            return Err(Error::Http(400));
        }
        let mut after = None;
        let mut include_expired = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "cursor" if after.is_none() => {
                    if value.len() > 64 {
                        return Err(Error::Http(400));
                    }
                    let (stamp, id) = value.split_once(':').ok_or(Error::Http(400))?;
                    let created = stamp.parse::<i64>().map_err(|_| Error::Http(400))?;
                    if created < 0 || created.to_string() != stamp || !canonical_uuid(id) {
                        return Err(Error::Http(400));
                    }
                    after = Some((created, id.to_owned()));
                }
                "includeExpired" if include_expired.is_none() => {
                    include_expired = Some(match value.as_ref() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(Error::Http(400)),
                    });
                }
                _ => return Err(Error::Http(400)),
            }
        }
        Ok(Self {
            after,
            include_expired: include_expired.unwrap_or(false),
        })
    }
}
struct InboxRow {
    id: String,
    created: i64,
    challenge_expires: i64,
    has_grant: bool,
    grant_expires: Option<i64>,
    last_transport_result: Option<String>,
}
impl Store {
    pub fn open(c: &Config, directory: File) -> std::result::Result<Self, Failure> {
        let path = c.state_dir.join("relay.sqlite");
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .map_err(|_| "private-state")?,
            Err(_) => return Err("private-state"),
        };
        let m = file.metadata().map_err(|_| "private-state")?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o777 != 0o600
            || m.nlink() != 1
        {
            return Err("private-state");
        }
        for suffix in ["-wal", "-shm"] {
            match std::fs::symlink_metadata(c.state_dir.join(format!("relay.sqlite{suffix}"))) {
                Ok(m)
                    if !m.is_file()
                        || m.uid() != unsafe { libc::geteuid() }
                        || m.mode() & 0o777 != 0o600
                        || m.nlink() != 1 =>
                {
                    return Err("private-state");
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("private-state"),
            }
        }
        let db_path = std::fs::canonicalize(&c.state_dir)
            .map_err(|_| "private-state")?
            .join("relay.sqlite");
        let db = Connection::open_with_flags(
            &db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| "storage-fault")?;
        let mut store = Self {
            db,
            directory,
            db_file: file,
            directory_path: c.state_dir.clone(),
            fresh: BTreeMap::new(),
        };
        store.check_files().map_err(|_| "private-state")?;
        store
            .db
            .busy_timeout(std::time::Duration::ZERO)
            .map_err(|_| "storage-fault")?;
        let version: i64 = store
            .db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(|_| "storage-fault")?;
        let count: i64 = store
            .db
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .map_err(|_| "storage-fault")?;
        if version != 2 && !(version == 0 && count == 0) {
            return Err("unsupported-store");
        }
        store
            .db
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
            .map_err(|_| "storage-fault")?;
        let binding = json!({"instance":c.instance_id,"endpoint":c.endpoint,"tenant":c.tenant_id,
            "origin":c.origin_public_key,"issuer":c.idp_issuer,
            "uploader":c.uploader_subject,"approvers":c.approvers,"directory":c.directory})
        .to_string();
        let tx = store.db.transaction().map_err(|_| "storage-fault")?;
        if version == 0 {
            tx.execute_batch("CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL) STRICT;
                CREATE TABLE requests (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, issuer TEXT NOT NULL,
                  uploader TEXT NOT NULL, recipient TEXT NOT NULL, approver TEXT NOT NULL,
                  challenge BLOB NOT NULL, challenge_sha TEXT NOT NULL, challenge_accepted INTEGER NOT NULL,
                  challenge_expires INTEGER NOT NULL, challenge_receipt BLOB NOT NULL,
                  grant BLOB, grant_sha TEXT, grant_accepted INTEGER, grant_expires INTEGER, grant_receipt BLOB) STRICT;
                CREATE TABLE transport_events (seq INTEGER PRIMARY KEY AUTOINCREMENT, issuer TEXT NOT NULL,
                  subject TEXT NOT NULL, request_id TEXT NOT NULL, kind TEXT NOT NULL, sha256 TEXT NOT NULL,
                  created INTEGER NOT NULL, result TEXT NOT NULL) STRICT;
                CREATE INDEX events_created ON transport_events(created);
                CREATE TABLE directory_subjects (subject TEXT PRIMARY KEY, source_id TEXT NOT NULL UNIQUE,
                  mapping_digest TEXT NOT NULL, tombstone INTEGER NOT NULL CHECK(tombstone IN (0,1))) STRICT;
                CREATE TABLE directory_revocations (subject TEXT PRIMARY KEY REFERENCES directory_subjects(subject),
                  receipt TEXT NOT NULL, affected_ids TEXT NOT NULL) STRICT;
                CREATE TABLE directory_nodes (subject TEXT NOT NULL, node_id TEXT NOT NULL, vault_id TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status='pending'), PRIMARY KEY(subject,node_id)) STRICT;
                CREATE TABLE directory_audit (subject TEXT PRIMARY KEY, mapping_digest TEXT NOT NULL,
                  body_sha256 TEXT NOT NULL, created INTEGER NOT NULL, result TEXT NOT NULL) STRICT;
                PRAGMA user_version=2;").map_err(|_| "storage-fault")?;
            tx.execute("INSERT INTO metadata VALUES(1,?1)", [&binding])
                .map_err(|_| "storage-fault")?;
            let digest = c.directory.digest()?;
            for l in &c.directory.links {
                tx.execute(
                    "INSERT INTO directory_subjects VALUES(?1,?2,?3,0)",
                    params![l.subject, l.source_user_id, digest],
                )
                .map_err(|_| "storage-fault")?;
            }
        } else {
            let saved: String = tx
                .query_row("SELECT binding FROM metadata WHERE id=1", [], |r| r.get(0))
                .map_err(|_| "storage-fault")?;
            if saved != binding {
                return Err("store-identity-mismatch");
            }
        }
        tx.commit().map_err(|_| "storage-fault")?;
        store.check_files().map_err(|_| "private-state")?;
        Ok(store)
    }
    fn gate(
        tx: &Transaction<'_>,
        fresh: &BTreeMap<String, (Instant, i64, i64)>,
        c: &Config,
        subject: &str,
        offboard_status: u16,
    ) -> Result<()> {
        let Some(link) = c.directory.links.iter().find(|l| l.subject == subject) else {
            return Err(Error::Http(503));
        };
        let saved:Option<(String,String,bool)>=tx.query_row("SELECT source_id,mapping_digest,tombstone FROM directory_subjects WHERE subject=?1",[subject],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((source, digest, tombstone)) = saved else {
            return Err(Error::Storage);
        };
        if source != link.source_user_id
            || digest != c.directory.digest().map_err(|_| Error::Storage)?
        {
            return Err(Error::Storage);
        }
        if tombstone {
            return Err(Error::Http(offboard_status));
        }
        if fresh.get(subject).is_none_or(|(observed, expires, _)| {
            Instant::now().saturating_duration_since(*observed) > std::time::Duration::from_secs(60)
                || now_ms() >= *expires
        }) {
            return Err(Error::Http(503));
        }
        Ok(())
    }
    fn apply_directory(&mut self, c: &Config, l: &Link, result: Observation) -> Result<()> {
        self.check_files()?;
        let digest = c.directory.digest().map_err(|_| Error::Storage)?;
        let tx = self.db.transaction()?;
        let saved: (String, String, bool) = tx.query_row(
            "SELECT source_id,mapping_digest,tombstone FROM directory_subjects WHERE subject=?1",
            [&l.subject],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if saved.0 != l.source_user_id
            || saved.1 != digest
            || !c.directory.links.iter().any(|registered| {
                registered.subject == l.subject && registered.source_user_id == l.source_user_id
            })
        {
            return Err(Error::Storage);
        }
        let valid_active =
            matches!(result.state, State::Active) && now_ms() < result.token_expires_ms && !saved.2;
        if let State::Removed(body_sha) = &result.state
            && !saved.2
        {
            let affected = {
                let mut stmt = tx.prepare(
                    "SELECT id FROM requests WHERE uploader=?1 OR recipient=?1 ORDER BY id",
                )?;
                stmt.query_map([&l.subject], |r| r.get::<_, String>(0))?
                    .collect::<std::result::Result<Vec<_>, _>>()?
            };
            if affected.len() > MAX_REQUESTS as usize {
                return Err(Error::Storage);
            }
            let applied = now_ms();
            let receipt = json!({"recordType":"rekey.directory.revocation.v1","issuer":l.issuer,"subject":l.subject,
                "sourceUserId":l.source_user_id,"externalId":l.external_id,"principalId":l.principal_id,
                "approverId":l.approver_id,"publicKeySha256":l.public_key_sha256,"confirmedBy":l.confirmed_by,
                "confirmedAtMs":l.confirmed_at_ms,"mappingVersion":c.directory.mapping_version,"mappingSha256":digest,
                "sourceResourceSha256":sha(c.directory.resource(l).as_bytes()),"sourceBodySha256":body_sha,
                "receivedAtMs":result.received_ms,"appliedAtMs":applied});
            tx.execute(
                "UPDATE directory_subjects SET tombstone=1 WHERE subject=?1",
                [&l.subject],
            )?;
            tx.execute(
                "INSERT INTO directory_revocations VALUES(?1,?2,?3)",
                params![
                    l.subject,
                    receipt.to_string(),
                    serde_json::to_string(&affected).map_err(|_| Error::Storage)?
                ],
            )?;
            for node in &c.directory.nodes {
                tx.execute(
                    "INSERT INTO directory_nodes VALUES(?1,?2,?3,'pending')",
                    params![l.subject, node.node_id, node.vault_id],
                )?;
            }
            tx.execute(
                "INSERT INTO directory_audit VALUES(?1,?2,?3,?4,'tombstoned')",
                params![l.subject, digest, body_sha, applied],
            )?;
        }
        tx.commit()?;
        if valid_active {
            self.fresh.insert(
                l.subject.clone(),
                (
                    result.completed,
                    result.token_expires_ms,
                    result.received_ms,
                ),
            );
        } else {
            self.fresh.remove(&l.subject);
        }
        self.check_files()?;
        Ok(())
    }
    fn admin_identity(&mut self, c: &Config, who: &Identity, deadline: Instant) -> Result<Output> {
        let link = c
            .directory
            .links
            .iter()
            .find(|l| l.subject == who.subject)
            .ok_or(Error::Http(503))?;
        self.check_files()?;
        let tx = self.db.transaction()?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 403)?;
        who.recheck(deadline).map_err(Error::Http)?;
        if !link.admin_allowed {
            return Err(Error::Http(403));
        }
        let observed = self.fresh.get(&who.subject).ok_or(Error::Http(503))?.2;
        let bytes = json!({"formatVersion":1,"issuer":link.issuer,"subject":link.subject,
            "principalId":link.principal_id,"mappingVersion":c.directory.mapping_version,
            "mappingSha256":c.directory.digest().map_err(|_| Error::Storage)?,
            "nodes":c.directory.nodes,"observedAtMs":observed})
        .to_string()
        .into_bytes();
        if bytes.len() > 4096 {
            return Err(Error::Http(503));
        }
        Self::event(
            &tx,
            &c.idp_issuer,
            &who.subject,
            "",
            "directory-admin-identity",
            "",
            "observed",
        )?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 403)?;
        who.recheck(deadline).map_err(Error::Http)?;
        tx.commit()?;
        self.check_files()?;
        Ok(Output::receipt(200, bytes))
    }
    fn revocations(&mut self, c: &Config, who: &Identity, deadline: Instant) -> Result<Output> {
        if who.subject != c.uploader_subject {
            return Err(Error::Http(403));
        }
        self.check_files()?;
        let tx = self.db.transaction()?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        who.recheck(deadline).map_err(Error::Http)?;
        let mut items = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT subject,receipt,affected_ids FROM directory_revocations ORDER BY subject",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            for row in rows {
                let (subject, receipt, ids) = row?;
                let mut v: serde_json::Value =
                    serde_json::from_str(&receipt).map_err(|_| Error::Storage)?;
                let ids: Vec<String> = serde_json::from_str(&ids).map_err(|_| Error::Storage)?;
                // Confirmations remain in the durable event. Shared mapping metadata is in the envelope.
                for field in [
                    "confirmedBy",
                    "confirmedAtMs",
                    "publicKeySha256",
                    "issuer",
                    "mappingVersion",
                    "mappingSha256",
                ] {
                    v.as_object_mut().ok_or(Error::Storage)?.remove(field);
                }
                let nodes = {
                    let mut q=tx.prepare("SELECT node_id,vault_id,status FROM directory_nodes WHERE subject=?1 ORDER BY node_id")?;
                    q.query_map([subject],|r|Ok(json!({"nodeId":r.get::<_,String>(0)?,"vaultId":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?})))?.collect::<std::result::Result<Vec<_>,_>>()?
                };
                if nodes.len() != 2 || items.len() >= 32 {
                    return Err(Error::Storage);
                }
                v["nodes"] = json!(nodes);
                v["affectedRequestIds"] = json!(ids.iter().take(8).collect::<Vec<_>>());
                v["truncatedRequestCount"] = json!(ids.len().saturating_sub(8));
                items.push(v);
            }
        }
        let bytes = loop {
            let bytes=json!({"recordType":"rekey.directory.revocations.v1","issuer":c.idp_issuer,"mappingVersion":c.directory.mapping_version,"mappingSha256":c.directory.digest().map_err(|_|Error::Storage)?,"items":items,"snapshot":"transport-only; node policy application pending"}).to_string().into_bytes();
            if bytes.len() <= 64 * 1024 {
                break bytes;
            }
            let Some(item) = items.iter_mut().rev().find(|v| {
                v["affectedRequestIds"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
            }) else {
                return Err(Error::Storage);
            };
            item["affectedRequestIds"]
                .as_array_mut()
                .ok_or(Error::Storage)?
                .pop();
            let count = item["truncatedRequestCount"]
                .as_u64()
                .ok_or(Error::Storage)?;
            item["truncatedRequestCount"] = json!(count + 1);
        };
        Self::event(
            &tx,
            &c.idp_issuer,
            &who.subject,
            "",
            "directory-revocations",
            "",
            "downloaded",
        )?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        who.recheck(deadline).map_err(Error::Http)?;
        tx.commit()?;
        self.check_files()?;
        Ok(Output::receipt(200, bytes))
    }
    fn check_files(&self) -> Result<()> {
        let original = self.directory.metadata().map_err(|_| Error::Storage)?;
        let current =
            std::fs::symlink_metadata(&self.directory_path).map_err(|_| Error::Storage)?;
        if !current.is_dir()
            || current.dev() != original.dev()
            || current.ino() != original.ino()
            || current.uid() != unsafe { libc::geteuid() }
            || current.mode() & 0o777 != 0o700
        {
            return Err(Error::Storage);
        }
        let original_db = self.db_file.metadata().map_err(|_| Error::Storage)?;
        for suffix in ["", "-wal", "-shm"] {
            match std::fs::symlink_metadata(
                self.directory_path.join(format!("relay.sqlite{suffix}")),
            ) {
                Ok(m) => {
                    if !m.is_file()
                        || m.uid() != unsafe { libc::geteuid() }
                        || m.mode() & 0o777 != 0o600
                        || m.nlink() != 1
                        || (suffix.is_empty()
                            && (m.dev() != original_db.dev() || m.ino() != original_db.ino()))
                    {
                        return Err(Error::Storage);
                    }
                }
                Err(e) if !suffix.is_empty() && e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Storage),
            }
        }
        Ok(())
    }
    fn event(
        tx: &Transaction<'_>,
        issuer: &str,
        subject: &str,
        id: &str,
        kind: &str,
        digest: &str,
        result: &str,
    ) -> Result<()> {
        let n: i64 = tx.query_row("SELECT count(*) FROM transport_events", [], |r| r.get(0))?;
        if n >= MAX_EVENTS {
            return Err(Error::Http(503));
        }
        tx.execute("INSERT INTO transport_events(issuer,subject,request_id,kind,sha256,created,result) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![issuer, subject, id, kind, digest, now_ms(), result])?;
        Ok(())
    }
    fn audit(
        &mut self,
        c: &Config,
        subject: Option<&str>,
        id: &str,
        kind: &str,
        status: u16,
    ) -> Result<()> {
        self.check_files()?;
        let tx = self.db.transaction()?;
        Self::event(
            &tx,
            if subject.is_some() {
                &c.idp_issuer
            } else {
                "unknown"
            },
            subject.unwrap_or("unknown"),
            id,
            kind,
            "",
            &format!("http-{status}"),
        )?;
        tx.commit()?;
        Ok(())
    }
    fn cleanup(&mut self, c: &Config) -> Result<()> {
        self.check_files()?;
        let tx = self.db.transaction()?;
        let before = now_ms().saturating_sub(RETENTION);
        let deleted = tx.execute("DELETE FROM requests WHERE challenge_accepted < ?1 AND (grant_accepted IS NULL OR grant_accepted < ?1)", [before])?;
        let events = tx.execute("DELETE FROM transport_events WHERE created < ?1", [before])?;
        if deleted > 0 || events > 0 {
            Self::event(
                &tx,
                &c.idp_issuer,
                "unknown",
                "",
                "retention",
                "",
                "retained-expired",
            )?;
        }
        tx.commit()?;
        Ok(())
    }
    fn row(tx: &Transaction<'_>, id: &str) -> Result<Option<Row>> {
        Ok(tx.query_row("SELECT uploader,recipient,approver,challenge,challenge_sha,challenge_expires,challenge_receipt,grant,grant_sha,grant_expires,grant_receipt FROM requests WHERE id=?1", [id], |r|
            Ok(Row { uploader:r.get(0)?,recipient:r.get(1)?,approver:r.get(2)?,challenge:r.get(3)?,challenge_sha:r.get(4)?,
                challenge_expires:r.get(5)?,challenge_receipt:r.get(6)?,grant:r.get(7)?,grant_sha:r.get(8)?,
                grant_expires:r.get(9)?,grant_receipt:r.get(10)? })).optional()?)
    }
    #[allow(clippy::too_many_arguments)] // The immutable wire receipt fields are explicit.
    fn receipt(
        c: &Config,
        who: &Identity,
        id: &str,
        kind: &str,
        digest: &str,
        length: usize,
        approver: &str,
        expiry: i64,
        accepted: i64,
    ) -> Vec<u8> {
        json!({"recordType":"rekey.approval.transport.receipt.v1","instanceId":c.instance_id,"requestId":id,
            "fileKind":kind,"sha256":digest,"byteLength":length,"actor":{"issuer":c.idp_issuer,"sub":who.subject},
            "recipientApproverId":approver,"acceptedAtMs":accepted,"fileExpiresAtMs":expiry,"status":"stored",
            "meaning":"transport-only; Broker revalidates at execute"}).to_string().into_bytes()
    }
    fn inbox(
        &mut self,
        c: &Config,
        who: &Identity,
        deadline: Instant,
        query: &InboxQuery,
    ) -> Result<Output> {
        if who.subject != c.uploader_subject
            && !c.approvers.iter().any(|a| a.subject == who.subject)
        {
            return Err(Error::Http(404));
        }
        self.check_files()?;
        who.recheck(deadline).map_err(Error::Http)?;
        let tx = self.db.transaction()?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        let snapshot = now_ms();
        let approver = c
            .approvers
            .iter()
            .find(|a| a.subject == who.subject)
            .map_or("", |a| a.approver_id.as_str());
        let (after_time, after_id) = query
            .after
            .as_ref()
            .map_or((-1, ""), |(time, id)| (*time, id.as_str()));
        let mut rows = {
            let mut statement = tx.prepare("SELECT id,challenge_accepted,challenge_expires,grant IS NOT NULL,grant_expires,
                (SELECT result FROM transport_events e WHERE e.request_id=requests.id AND e.issuer=?7
                 AND e.subject IN (requests.uploader,requests.recipient) AND e.kind IN ('challenge','grant')
                 AND e.result!='downloaded' ORDER BY e.seq DESC LIMIT 1)
                FROM requests WHERE ((uploader=?1 AND uploader=?2) OR (recipient=?1 AND approver=?3))
                AND (?4 OR (challenge_expires>?8 AND (grant IS NULL OR grant_expires>?8)))
                AND (challenge_accepted>?5 OR (challenge_accepted=?5 AND id>?6))
                ORDER BY challenge_accepted ASC,id ASC LIMIT 26")?;
            let found = statement.query_map(
                params![
                    who.subject,
                    c.uploader_subject,
                    approver,
                    query.include_expired,
                    after_time,
                    after_id,
                    c.idp_issuer,
                    snapshot
                ],
                |r| {
                    Ok(InboxRow {
                        id: r.get(0)?,
                        created: r.get(1)?,
                        challenge_expires: r.get(2)?,
                        has_grant: r.get(3)?,
                        grant_expires: r.get(4)?,
                        last_transport_result: r.get(5)?,
                    })
                },
            )?;
            found.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let more = rows.len() > 25;
        rows.truncate(25);
        let next = if more {
            rows.last().map(|r| format!("{}:{}", r.created, r.id))
        } else {
            None
        };
        let mut participants = BTreeSet::new();
        let mut cutoff = None;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let parties: (String, String) = tx.query_row(
                "SELECT uploader,recipient FROM requests WHERE id=?1",
                [&row.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Self::gate(&tx, &self.fresh, c, &parties.0, 503)?;
            Self::gate(&tx, &self.fresh, c, &parties.1, 503)?;
            let (uploader, recipient) = parties;
            participants.insert(uploader);
            participants.insert(recipient);
            let expires = if row.has_grant {
                row.grant_expires
                    .ok_or(Error::Storage)?
                    .min(row.challenge_expires)
            } else {
                row.challenge_expires
            };
            let status = if row.has_grant {
                if expires <= snapshot {
                    "grant-expired"
                } else {
                    "grant-stored"
                }
            } else if expires <= snapshot {
                "expired"
            } else if row
                .last_transport_result
                .as_deref()
                .is_some_and(|s| s.starts_with("http-"))
            {
                "transport-failed"
            } else {
                "awaiting-review"
            };
            if !query.include_expired {
                cutoff = Some(cutoff.map_or(expires, |previous: i64| previous.min(expires)));
            }
            items.push(json!({"requestId":row.id,"sourceLabel":format!("ed25519:{}",c.origin_public_key),
                "createdAtMs":row.created,"expiresAtMs":expires,"transportStatus":status,
                "detailPath":format!("/v1/requests/{}/challenge",row.id),"receiptPath":format!("/v1/requests/{}/receipt",row.id)}));
        }
        let bytes=json!({"recordType":"rekey.approval.inbox.v1","items":items,"nextCursor":next,"snapshotAtMs":snapshot,
            "snapshot":"transport-only; Broker revalidates at execute; lock/restart/revoke may invalidate these files"}).to_string().into_bytes();
        if bytes.len() > 16 * 1024 {
            return Err(Error::Storage);
        }
        Self::event(
            &tx,
            &c.idp_issuer,
            &who.subject,
            "",
            "inbox",
            "",
            "downloaded",
        )?;
        for subject in &participants {
            Self::gate(&tx, &self.fresh, c, subject, 503)?;
        }
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        who.recheck(deadline).map_err(Error::Http)?;
        tx.commit()?;
        self.check_files()?;
        who.recheck(deadline).map_err(Error::Http)?;
        if cutoff.is_some_and(|expires| now_ms() >= expires) {
            return Err(Error::Http(503));
        }
        Ok(Output {
            status: 200,
            bytes,
            digest: None,
            expires: None,
        })
    }
    #[allow(clippy::too_many_arguments)] // One fixed file operation, without a second request model.
    fn operate(
        &mut self,
        c: &Config,
        who: &Identity,
        deadline: Instant,
        id: &str,
        kind: &str,
        put: bool,
        approver: Option<&str>,
        bytes: &[u8],
    ) -> Result<Output> {
        self.check_files()?;
        who.recheck(deadline).map_err(Error::Http)?;
        let tx = self.db.transaction()?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        let row = Self::row(&tx, id)?;
        let mut participants = BTreeSet::new();
        if let Some(row) = &row {
            let uploader = who.subject == row.uploader && who.subject == c.uploader_subject;
            let recipient = who.subject == row.recipient
                && c.approvers
                    .iter()
                    .any(|a| a.subject == row.recipient && a.approver_id == row.approver);
            if !uploader && !recipient {
                return Err(Error::Http(404));
            }
            Self::gate(&tx, &self.fresh, c, &row.uploader, 503)?;
            Self::gate(&tx, &self.fresh, c, &row.recipient, 503)?;
            participants.insert(row.uploader.clone());
            participants.insert(row.recipient.clone());
        }
        // Revocation of a configured subject also removes access to previously assigned rows.
        let current_approver = |row: &Row| {
            c.approvers
                .iter()
                .any(|a| a.subject == row.recipient && a.approver_id == row.approver)
        };
        let output = if put && kind == "challenge" {
            if who.subject != c.uploader_subject {
                return Err(Error::Http(404));
            }
            let target = approver.ok_or(Error::Http(400))?;
            if let Some(row) = row {
                if row.uploader != who.subject {
                    return Err(Error::Http(404));
                }
                if row.approver != target || row.challenge != bytes {
                    return Err(Error::Http(409));
                }
                Self::event(
                    &tx,
                    &c.idp_issuer,
                    &who.subject,
                    id,
                    kind,
                    &row.challenge_sha,
                    "same-file-retry",
                )?;
                Output::receipt(200, row.challenge_receipt)
            } else {
                let a = c
                    .approvers
                    .iter()
                    .find(|a| a.approver_id == target)
                    .ok_or(Error::Http(400))?;
                Self::gate(&tx, &self.fresh, c, &a.subject, 503)?;
                participants.insert(a.subject.clone());
                let key = rekey_policy::validate_ed25519_public_key(&c.origin_public_key)
                    .map_err(|_| Error::Storage)?;
                let challenge =
                    rekey_policy::parse_and_verify_approval_challenge_envelope(bytes, &key)
                        .map_err(|_| Error::Http(400))?;
                if challenge.approval_request_id.to_string() != id
                    || challenge.tenant_id.to_string() != c.tenant_id
                    || challenge.mode != ApprovalMode::OneTime
                    || challenge.quorum != 1
                    || challenge.max_uses != 1
                    || !challenge
                        .approver_ids
                        .iter()
                        .any(|v| v.to_string() == target)
                {
                    return Err(Error::Http(400));
                }
                let now = now_ms();
                if challenge.created_at_ms > now {
                    return Err(Error::Http(400));
                }
                if challenge.max_expires_at_ms <= now {
                    return Err(Error::Http(410));
                }
                let (n,total): (i64,i64) = tx.query_row("SELECT count(*),coalesce(sum(length(challenge)+coalesce(length(grant),0)),0) FROM requests",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
                if n >= MAX_REQUESTS || total + bytes.len() as i64 > MAX_BLOBS {
                    return Err(Error::Http(503));
                }
                let digest = sha(bytes);
                let receipt = Self::receipt(
                    c,
                    who,
                    id,
                    kind,
                    &digest,
                    bytes.len(),
                    target,
                    challenge.max_expires_at_ms,
                    now,
                );
                tx.execute("INSERT INTO requests(id,tenant,issuer,uploader,recipient,approver,challenge,challenge_sha,challenge_accepted,challenge_expires,challenge_receipt) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![id,c.tenant_id,c.idp_issuer,who.subject,a.subject,target,bytes,digest,now,challenge.max_expires_at_ms,receipt])?;
                Self::event(
                    &tx,
                    &c.idp_issuer,
                    &who.subject,
                    id,
                    kind,
                    &digest,
                    "stored",
                )?;
                Output::receipt(201, receipt)
            }
        } else {
            let row = row.ok_or(Error::Http(404))?;
            let uploader = who.subject == row.uploader && who.subject == c.uploader_subject;
            let recipient = who.subject == row.recipient && current_approver(&row);
            if !uploader && !recipient {
                return Err(Error::Http(404));
            }
            if put {
                if !recipient {
                    return Err(Error::Http(404));
                }
                if let Some(saved) = row.grant {
                    if saved != bytes {
                        return Err(Error::Http(409));
                    }
                    Self::event(
                        &tx,
                        &c.idp_issuer,
                        &who.subject,
                        id,
                        kind,
                        row.grant_sha.as_deref().ok_or(Error::Storage)?,
                        "same-file-retry",
                    )?;
                    Output::receipt(200, row.grant_receipt.ok_or(Error::Storage)?)
                } else {
                    let grant: rekey_policy::SignedApprovalGrant =
                        serde_json::from_slice(bytes).map_err(|_| Error::Http(400))?;
                    if grant.format_version != 1
                        || grant.approval_request_id.to_string() != id
                        || grant.approver_id.to_string() != row.approver
                        || grant.tenant_id.to_string() != c.tenant_id
                        || grant.mode != ApprovalMode::OneTime
                        || grant.max_uses != 1
                        || grant.not_before_ms < 0
                        || grant.expires_at_ms <= grant.not_before_ms
                        || grant.expires_at_ms > row.challenge_expires
                    {
                        return Err(Error::Http(400));
                    }
                    let now = now_ms();
                    if grant.not_before_ms > now {
                        return Err(Error::Http(400));
                    }
                    if grant.expires_at_ms <= now || row.challenge_expires <= now {
                        return Err(Error::Http(410));
                    }
                    let total: i64=tx.query_row("SELECT coalesce(sum(length(challenge)+coalesce(length(grant),0)),0) FROM requests",[],|r|r.get(0))?;
                    if total + bytes.len() as i64 > MAX_BLOBS {
                        return Err(Error::Http(503));
                    }
                    let digest = sha(bytes);
                    let receipt = Self::receipt(
                        c,
                        who,
                        id,
                        kind,
                        &digest,
                        bytes.len(),
                        &row.approver,
                        grant.expires_at_ms,
                        now,
                    );
                    tx.execute("UPDATE requests SET grant=?1,grant_sha=?2,grant_accepted=?3,grant_expires=?4,grant_receipt=?5 WHERE id=?6",params![bytes,digest,now,grant.expires_at_ms,receipt,id])?;
                    Self::event(
                        &tx,
                        &c.idp_issuer,
                        &who.subject,
                        id,
                        kind,
                        &digest,
                        "stored",
                    )?;
                    Output::receipt(201, receipt)
                }
            } else if kind == "receipt" {
                let challenge: serde_json::Value =
                    serde_json::from_slice(&row.challenge_receipt).map_err(|_| Error::Storage)?;
                let grant = row
                    .grant_receipt
                    .map(|v| serde_json::from_slice::<serde_json::Value>(&v))
                    .transpose()
                    .map_err(|_| Error::Storage)?;
                let bytes=json!({"challenge":challenge,"grant":grant,"challengeExpired":now_ms()>=row.challenge_expires,
                    "grantExpired":row.grant_expires.map(|e|now_ms()>=e),"snapshot":"Broker lock/restart/revoke may invalidate these files"}).to_string().into_bytes();
                if bytes.len() > 4096 {
                    return Err(Error::Storage);
                }
                Self::event(&tx, &c.idp_issuer, &who.subject, id, kind, "", "downloaded")?;
                Output::receipt(200, bytes)
            } else {
                let (bytes, digest, expires) = if kind == "challenge" {
                    (row.challenge, row.challenge_sha, row.challenge_expires)
                } else {
                    (
                        row.grant.ok_or(Error::Http(404))?,
                        row.grant_sha.ok_or(Error::Storage)?,
                        row.grant_expires.ok_or(Error::Storage)?,
                    )
                };
                if now_ms() >= expires {
                    return Err(Error::Http(410));
                }
                Self::event(
                    &tx,
                    &c.idp_issuer,
                    &who.subject,
                    id,
                    kind,
                    &digest,
                    "downloaded",
                )?;
                Output {
                    status: 200,
                    bytes,
                    digest: Some(digest),
                    expires: Some(expires),
                }
            }
        };
        who.recheck(deadline).map_err(Error::Http)?;
        Self::gate(&tx, &self.fresh, c, &who.subject, 503)?;
        for subject in &participants {
            Self::gate(&tx, &self.fresh, c, subject, 503)?;
        }
        // No caller bytes leave before this FULL/WAL transaction has committed.
        tx.commit()?;
        self.check_files()?;
        who.recheck(deadline).map_err(Error::Http)?;
        if output.expires.is_some_and(|e| now_ms() >= e) {
            return Err(Error::Http(410));
        }
        Ok(output)
    }
}

pub struct Service {
    pub config: Config,
    auth: Authenticator,
    store: Mutex<Store>,
    fault: AtomicBool,
    pub faulted: Notify,
}
impl Service {
    pub fn new(config: Config, auth: Authenticator, store: Store) -> Self {
        Self {
            config,
            auth,
            store: Mutex::new(store),
            fault: AtomicBool::new(false),
            faulted: Notify::new(),
        }
    }
    pub async fn poll_directory(
        &self,
        consumer: &directory::Consumer,
    ) -> std::result::Result<(), Failure> {
        let result = consumer
            .poll(&self.config.directory, |link, result| {
                self.apply_directory_member(link, result)
            })
            .await;
        if result.is_err() {
            self.fault();
        }
        result
    }
    fn apply_directory_member(
        &self,
        link: &Link,
        result: Observation,
    ) -> std::result::Result<(), Failure> {
        let mut store = self.store.lock().map_err(|_| {
            self.fault();
            "storage-fault"
        })?;
        let applied = store.apply_directory(&self.config, link, result);
        if applied.is_err() {
            // Latch fail-closed before the next admission can acquire the same store.
            self.fault();
        }
        applied.map_err(|_| "storage-fault")
    }
    pub fn is_faulted(&self) -> bool {
        self.fault.load(Ordering::Acquire)
    }
    pub fn fault(&self) {
        self.fault.store(true, Ordering::Release);
        self.faulted.notify_one();
    }
    pub fn cleanup(&self) -> std::result::Result<(), Failure> {
        let result = self
            .store
            .lock()
            .map_err(|_| Error::Storage)
            .and_then(|mut s| s.cleanup(&self.config));
        if result.is_err() {
            self.fault();
            return Err("storage-fault");
        }
        Ok(())
    }
    fn denied(
        &self,
        status: u16,
        who: Option<&Identity>,
        id: &str,
        kind: &str,
    ) -> Response<Full<Bytes>> {
        let mut status = status;
        if self.is_faulted() {
            status = 503;
        } else {
            match self
                .store
                .lock()
                .map_err(|_| Error::Storage)
                .and_then(|mut s| {
                    s.audit(
                        &self.config,
                        who.map(|w| w.subject.as_str()),
                        id,
                        kind,
                        status,
                    )
                }) {
                Ok(()) => {}
                Err(Error::Http(_)) => status = 503,
                Err(Error::Storage) => {
                    self.fault();
                    status = 503;
                }
            }
        }
        response(
            StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            format!("{{\"error\":\"http-{status}\"}}").into_bytes(),
        )
    }
    pub async fn handle(
        &self,
        request: Request<Incoming>,
        deadline: Instant,
    ) -> Response<Full<Bytes>> {
        if self.is_faulted() {
            return response(
                StatusCode::SERVICE_UNAVAILABLE,
                b"{\"error\":\"storage-fault\"}".to_vec(),
            );
        }
        let path = request.uri().path();
        let route = path
            .strip_prefix("/v1/requests/")
            .and_then(|v| v.split_once('/'));
        let is_inbox = path == "/v1/inbox";
        let is_revocations = path == "/v1/directory/revocations";
        let is_admin_identity = path == "/v1/directory/admin-identity";
        let route = if is_inbox {
            Some(("", "inbox"))
        } else if is_admin_identity {
            Some(("", "directory-admin-identity"))
        } else if is_revocations {
            Some(("", "directory-revocations"))
        } else {
            route.filter(|(id, kind)| {
                canonical_uuid(id) && matches!(*kind, "challenge" | "grant" | "receipt")
            })
        };
        let Some((id, kind)) = route else {
            return self.denied(404, None, "", "");
        };
        let id = id.to_owned();
        let kind = kind.to_owned();
        if (!is_inbox && request.uri().query().is_some())
            || request.headers().contains_key("cookie")
            || request.headers().contains_key("upgrade")
        {
            return self.denied(400, None, &id, &kind);
        }
        let put = request.method() == Method::PUT;
        if request.method() != Method::GET
            && (!put || kind == "receipt" || is_inbox || is_revocations || is_admin_identity)
        {
            return self.denied(405, None, &id, &kind);
        }
        let values = request.headers().get_all(AUTHORIZATION);
        let mut values = values.iter();
        let bearer = values
            .next()
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if values.next().is_some()
            || bearer.is_none_or(|v| {
                v.is_empty()
                    || v.len() > 4096
                    || v.chars().any(|ch| ch.is_whitespace() || ch.is_control())
            })
        {
            return self.denied(401, None, &id, &kind);
        }
        let token = Zeroizing::new(bearer.unwrap_or_default().to_owned());
        let who = match self.auth.authenticate(&token, &self.config, deadline).await {
            Ok(w) => w,
            Err(404) if is_admin_identity => return self.denied(503, None, &id, &kind),
            Err(404) if is_revocations => return self.denied(403, None, &id, &kind),
            Err(code) => return self.denied(code, None, &id, &kind),
        };
        drop(token);
        let inbox_query = if is_inbox {
            match InboxQuery::parse(request.uri().query()) {
                Ok(query) => Some(query),
                Err(Error::Http(code)) => return self.denied(code, Some(&who), &id, &kind),
                Err(Error::Storage) => {
                    self.fault();
                    return self.denied(503, Some(&who), &id, &kind);
                }
            }
        } else {
            None
        };
        let mut targets = request.headers().get_all("x-rekey-approver-id").iter();
        let target = targets
            .next()
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if targets.next().is_some()
            || (put && kind == "challenge" && target.as_deref().is_none_or(|t| !canonical_uuid(t)))
            || (!(put && kind == "challenge") && target.is_some())
        {
            return self.denied(400, Some(&who), &id, &kind);
        }
        let limit = if !put {
            0
        } else if kind == "challenge" {
            64 * 1024
        } else {
            4096
        };
        let bytes = match Limited::new(request.into_body(), limit).collect().await {
            Ok(b) => b.to_bytes(),
            Err(_) => return self.denied(413, Some(&who), &id, &kind),
        };
        let result = self
            .store
            .lock()
            .map_err(|_| Error::Storage)
            .and_then(|mut s| {
                if self.is_faulted() {
                    return Err(Error::Storage);
                }
                let result = if is_admin_identity {
                    s.admin_identity(&self.config, &who, deadline)
                } else if is_revocations {
                    s.revocations(&self.config, &who, deadline)
                } else if let Some(query) = &inbox_query {
                    s.inbox(&self.config, &who, deadline, query)
                } else {
                    s.operate(
                        &self.config,
                        &who,
                        deadline,
                        &id,
                        &kind,
                        put,
                        target.as_deref(),
                        &bytes,
                    )
                };
                if matches!(result, Err(Error::Storage)) {
                    self.fault();
                }
                result
            });
        match result {
            Ok(output) => {
                if let Err(code) = who.recheck(deadline) {
                    return self.denied(code, Some(&who), &id, &kind);
                }
                let mut result = response(
                    StatusCode::from_u16(output.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                    output.bytes,
                );
                if let Some(digest) = output.digest
                    && let Ok(v) = HeaderValue::from_str(&digest)
                {
                    result.headers_mut().insert("x-rekey-sha256", v);
                }
                if let Some(expires) = output.expires
                    && let Ok(v) = HeaderValue::from_str(&expires.to_string())
                {
                    result.headers_mut().insert("x-rekey-file-expires-at-ms", v);
                }
                result
            }
            Err(Error::Http(code)) => self.denied(code, Some(&who), &id, &kind),
            Err(Error::Storage) => {
                self.fault();
                self.denied(503, Some(&who), &id, &kind)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, time::Duration};
    fn fixture() -> (tempfile::TempDir, Config, Store) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let c = crate::test_config(root.path());
        let s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        (root, c, s)
    }
    fn observation(state: State) -> Observation {
        Observation {
            state,
            received_ms: now_ms(),
            completed: Instant::now(),
            token_expires_ms: now_ms() + 120_000,
        }
    }
    fn both_active(s: &mut Store, c: &Config) {
        for l in &c.directory.links {
            s.apply_directory(c, l, observation(State::Active)).unwrap();
        }
    }
    fn gate(s: &mut Store, c: &Config, subject: &str) -> Result<()> {
        let tx = s.db.transaction()?;
        Store::gate(&tx, &s.fresh, c, subject, 503)
    }
    fn row(s: &Store, c: &Config) {
        s.db.execute("INSERT INTO requests VALUES(?1,?2,?3,'operator','reviewer',?4,?5,?6,?7,?8,?9,NULL,NULL,NULL,NULL,NULL)",
          params![c.instance_id,c.tenant_id,c.idp_issuer,c.approvers[0].approver_id,b"PRIVATE-CHALLENGE-BYTES".as_slice(),"11".repeat(32),now_ms(),now_ms()+120_000,b"{}".as_slice()]).unwrap();
    }
    fn admin_fixture() -> (tempfile::TempDir, Config, Store) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = crate::test_config(root.path());
        c.directory.links[1].admin_allowed = false;
        let mut admin = c.directory.links[0].clone();
        admin.source_user_id = "admin-user".into();
        admin.external_id = "admin-person".into();
        admin.subject = "administrator".into();
        admin.principal_id = "55555555-5555-4555-8555-555555555555".into();
        c.directory.links.push(admin);
        c.validate().unwrap();
        let s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        (root, c, s)
    }
    #[test]
    fn admin_self_proof_has_closed_bounded_shape_source_time_and_no_transport_role() {
        let (_root, c, mut s) = admin_fixture();
        both_active(&mut s, &c);
        row(&s, &c);
        let source_time = now_ms() - 12_345;
        let mut observed = observation(State::Active);
        observed.received_ms = source_time;
        s.apply_directory(&c, &c.directory.links[2], observed)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let who = Identity::test("administrator");
        let output = s.admin_identity(&c, &who, deadline).unwrap();
        assert_eq!(output.status, 200);
        assert!(output.bytes.len() <= 4096);
        let proof: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        let keys: BTreeSet<_> = proof
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "formatVersion",
                "issuer",
                "subject",
                "principalId",
                "mappingVersion",
                "mappingSha256",
                "nodes",
                "observedAtMs"
            ])
        );
        assert_eq!(proof["formatVersion"], 1);
        assert_eq!(proof["subject"], "administrator");
        assert_eq!(proof["principalId"], c.directory.links[2].principal_id);
        assert_eq!(proof["issuer"], c.idp_issuer);
        assert_eq!(proof["mappingVersion"], c.directory.mapping_version);
        assert_eq!(proof["mappingSha256"], c.directory.digest().unwrap());
        assert_eq!(proof["observedAtMs"], source_time);
        assert_eq!(proof["nodes"].as_array().unwrap().len(), 2);
        for node in proof["nodes"].as_array().unwrap() {
            assert_eq!(node.as_object().unwrap().len(), 2);
        }
        assert!(!String::from_utf8_lossy(&output.bytes).contains("PRIVATE-CHALLENGE"));
        assert_eq!(s.db.query_row::<i64, _, _>("SELECT count(*) FROM transport_events WHERE kind='directory-admin-identity' AND subject='administrator' AND sha256='' AND result='observed'", [], |r| r.get(0)).unwrap(), 1);
        assert!(matches!(
            s.inbox(&c, &who, deadline, &InboxQuery::parse(None).unwrap()),
            Err(Error::Http(404))
        ));
        assert!(matches!(
            s.revocations(&c, &who, deadline),
            Err(Error::Http(403))
        ));
        for kind in ["challenge", "grant", "receipt"] {
            assert!(matches!(
                s.operate(&c, &who, deadline, &c.instance_id, kind, false, None, b""),
                Err(Error::Http(404))
            ));
        }
        assert!(matches!(
            s.operate(
                &c,
                &who,
                deadline,
                &c.instance_id,
                "challenge",
                true,
                Some(&c.approvers[0].approver_id),
                b""
            ),
            Err(Error::Http(404))
        ));
        assert!(matches!(
            s.admin_identity(&c, &Identity::test("reviewer"), deadline),
            Err(Error::Http(403))
        ));
        assert!(matches!(
            s.admin_identity(&c, &Identity::test("unlisted"), deadline),
            Err(Error::Http(503))
        ));
        let own = s
            .admin_identity(&c, &Identity::test("operator"), deadline)
            .unwrap();
        let own: serde_json::Value = serde_json::from_slice(&own.bytes).unwrap();
        assert_eq!(own["subject"], "operator");
    }
    #[test]
    fn admin_source_unknown_stale_token_offboard_restart_and_identity_deadline_close() {
        let (root, c, mut s) = admin_fixture();
        let who = Identity::test("administrator");
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(503))
        ));
        assert!(matches!(
            s.admin_identity(&c, &Identity::test("reviewer"), deadline),
            Err(Error::Http(503))
        ));
        both_active(&mut s, &c);
        assert!(matches!(
            s.admin_identity(&c, &Identity::test("reviewer"), deadline),
            Err(Error::Http(403))
        ));
        s.apply_directory(&c, &c.directory.links[1], Observation::unknown())
            .unwrap();
        assert!(matches!(
            s.admin_identity(&c, &Identity::test("reviewer"), deadline),
            Err(Error::Http(503))
        ));
        s.fresh.get_mut("administrator").unwrap().0 = Instant::now() - Duration::from_secs(61);
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(503))
        ));
        both_active(&mut s, &c);
        s.fresh.get_mut("administrator").unwrap().1 = now_ms() - 1;
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(503))
        ));
        both_active(&mut s, &c);
        assert!(matches!(
            s.admin_identity(&c, &who, Instant::now()),
            Err(Error::Http(503))
        ));
        s.apply_directory(&c, &c.directory.links[2], Observation::unknown())
            .unwrap();
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(503))
        ));
        s.apply_directory(
            &c,
            &c.directory.links[2],
            observation(State::Removed("11".repeat(32))),
        )
        .unwrap();
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(403))
        ));
        s.apply_directory(&c, &c.directory.links[2], observation(State::Active))
            .unwrap();
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(403))
        ));
        drop(s);
        let mut s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        assert!(matches!(
            s.admin_identity(&c, &who, deadline),
            Err(Error::Http(403))
        ));
    }
    #[test]
    fn admin_proof_remains_bounded_at_maximum_escaped_identity_metadata() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = crate::test_config(root.path());
        c.idp_issuer = format!("https://issuer.test/{}", "x".repeat(236));
        for link in &mut c.directory.links {
            link.issuer = c.idp_issuer.clone();
        }
        c.uploader_subject = "\"".repeat(256);
        c.directory.links[0].subject = c.uploader_subject.clone();
        c.validate().unwrap();
        let mut s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        both_active(&mut s, &c);
        let proof = s
            .admin_identity(
                &c,
                &Identity::test(&c.uploader_subject),
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
        assert!(proof.bytes.len() <= 4096);
        let proof: serde_json::Value = serde_json::from_slice(&proof.bytes).unwrap();
        assert_eq!(proof["subject"], c.uploader_subject);
        assert_eq!(proof["issuer"], c.idp_issuer);
    }
    #[test]
    fn admin_flag_digest_change_rejects_existing_store_without_schema_change() {
        let (root, mut c, s) = admin_fixture();
        let digest = c.directory.digest().unwrap();
        assert_eq!(
            s.db.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0))
                .unwrap(),
            2
        );
        drop(s);
        c.directory.links[2].admin_allowed = false;
        assert_ne!(digest, c.directory.digest().unwrap());
        assert!(matches!(
            Store::open(&c, crate::state_directory(root.path()).unwrap()),
            Err("store-identity-mismatch")
        ));
    }
    #[test]
    fn admin_proof_audit_and_commit_failure_never_return_body() {
        for commit in [false, true] {
            let (_root, c, mut s) = admin_fixture();
            both_active(&mut s, &c);
            if commit {
                s.db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE admin_parent(id INTEGER PRIMARY KEY); CREATE TABLE admin_child(id INTEGER REFERENCES admin_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_admin_commit AFTER INSERT ON transport_events WHEN NEW.kind='directory-admin-identity' BEGIN INSERT INTO admin_child VALUES(1); END;").unwrap();
            } else {
                s.db.execute_batch("CREATE TRIGGER fail_admin_audit BEFORE INSERT ON transport_events WHEN NEW.kind='directory-admin-identity' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
            }
            assert!(matches!(
                s.admin_identity(
                    &c,
                    &Identity::test("administrator"),
                    Instant::now() + Duration::from_secs(10)
                ),
                Err(Error::Storage)
            ));
            assert_eq!(
                s.db.query_row::<i64, _, _>("SELECT count(*) FROM transport_events", [], |r| r
                    .get(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn startup_and_restart_freshness_are_closed() {
        let (root, c, mut s) = fixture();
        assert!(matches!(
            gate(&mut s, &c, "operator"),
            Err(Error::Http(503))
        ));
        both_active(&mut s, &c);
        assert!(gate(&mut s, &c, "operator").is_ok());
        drop(s);
        let mut s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        assert!(matches!(
            gate(&mut s, &c, "operator"),
            Err(Error::Http(503))
        ));
    }
    #[test]
    fn per_member_unknown_and_monotonic_expiry_do_not_refresh_others() {
        let (_root, c, mut s) = fixture();
        both_active(&mut s, &c);
        s.apply_directory(&c, &c.directory.links[1], Observation::unknown())
            .unwrap();
        assert!(gate(&mut s, &c, "operator").is_ok());
        assert!(matches!(
            gate(&mut s, &c, "reviewer"),
            Err(Error::Http(503))
        ));
        s.fresh.insert(
            "operator".into(),
            (
                Instant::now() - Duration::from_secs(61),
                now_ms() + 120_000,
                now_ms(),
            ),
        );
        s.apply_directory(&c, &c.directory.links[1], observation(State::Active))
            .unwrap();
        assert!(matches!(
            gate(&mut s, &c, "operator"),
            Err(Error::Http(503))
        ));
        s.fresh
            .insert("reviewer".into(), (Instant::now(), now_ms() - 1, now_ms()));
        assert!(matches!(
            gate(&mut s, &c, "reviewer"),
            Err(Error::Http(503))
        ));
    }
    #[test]
    fn tombstone_is_one_way_idempotent_durable_and_retention_independent() {
        let (root, c, mut s) = fixture();
        both_active(&mut s, &c);
        row(&s, &c);
        let l = &c.directory.links[1];
        s.apply_directory(&c, l, observation(State::Removed("33".repeat(32))))
            .unwrap();
        let before: String =
            s.db.query_row("SELECT receipt FROM directory_revocations", [], |r| {
                r.get(0)
            })
            .unwrap();
        s.apply_directory(&c, l, observation(State::Removed("44".repeat(32))))
            .unwrap();
        s.apply_directory(&c, l, observation(State::Active))
            .unwrap();
        assert!(matches!(
            gate(&mut s, &c, "reviewer"),
            Err(Error::Http(503))
        ));
        assert_eq!(
            before,
            s.db.query_row::<String, _, _>("SELECT receipt FROM directory_revocations", [], |r| r
                .get(0))
                .unwrap()
        );
        assert_eq!(
            s.db.query_row::<i64, _, _>(
                "SELECT count(*) FROM directory_nodes WHERE status='pending'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            2
        );
        s.db.execute("UPDATE requests SET challenge_accepted=0", [])
            .unwrap();
        s.cleanup(&c).unwrap();
        assert_eq!(
            s.db.query_row::<i64, _, _>("SELECT count(*) FROM directory_revocations", [], |r| r
                .get(0))
                .unwrap(),
            1
        );
        drop(s);
        let mut s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        both_active(&mut s, &c);
        assert!(matches!(
            gate(&mut s, &c, "reviewer"),
            Err(Error::Http(503))
        ));
    }
    #[test]
    fn admissions_recheck_after_identity_and_body_and_gate_both_file_parties() {
        let (_root, c, mut s) = fixture();
        both_active(&mut s, &c);
        row(&s, &c);
        let who = Identity::test("operator");
        let deadline = Instant::now() + Duration::from_secs(10);
        who.recheck(deadline).unwrap();
        s.apply_directory(
            &c,
            &c.directory.links[1],
            observation(State::Removed("33".repeat(32))),
        )
        .unwrap();
        for kind in ["challenge", "grant", "receipt"] {
            assert!(matches!(
                s.operate(&c, &who, deadline, &c.instance_id, kind, false, None, &[]),
                Err(Error::Http(503))
            ));
        }
        assert!(matches!(
            s.operate(
                &c,
                &who,
                deadline,
                &c.instance_id,
                "challenge",
                true,
                Some(&c.approvers[0].approver_id),
                b"PRIVATE-CHALLENGE-BYTES"
            ),
            Err(Error::Http(503))
        ));
        assert!(matches!(
            s.inbox(
                &c,
                &who,
                deadline,
                &InboxQuery {
                    after: None,
                    include_expired: false
                }
            ),
            Err(Error::Http(503))
        ));
        let output = s.revocations(&c, &who, deadline).unwrap();
        assert_eq!(output.status, 200);
        assert!(
            !String::from_utf8(output.bytes)
                .unwrap()
                .contains("PRIVATE-CHALLENGE-BYTES")
        );
        assert!(matches!(
            s.revocations(&c, &Identity::test("reviewer"), deadline),
            Err(Error::Http(403))
        ));
    }
    #[test]
    fn audit_and_commit_failures_roll_back_every_directory_record() {
        for commit in [false, true] {
            let (_root, c, mut s) = fixture();
            both_active(&mut s, &c);
            if commit {
                s.db.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON directory_audit BEGIN INSERT INTO child VALUES(1); END;").unwrap();
            } else {
                s.db.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON directory_audit BEGIN SELECT RAISE(ABORT,'synthetic failure'); END;").unwrap();
            }
            assert!(matches!(
                s.apply_directory(
                    &c,
                    &c.directory.links[1],
                    observation(State::Removed("33".repeat(32)))
                ),
                Err(Error::Storage)
            ));
            assert_eq!(
                s.db.query_row::<i64, _, _>(
                    "SELECT count(*) FROM directory_subjects WHERE tombstone=1",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
                0
            );
            for table in [
                "directory_revocations",
                "directory_nodes",
                "directory_audit",
            ] {
                assert_eq!(
                    s.db.query_row::<i64, _, _>(
                        &format!("SELECT count(*) FROM {table}"),
                        [],
                        |r| r.get(0)
                    )
                    .unwrap(),
                    0
                );
            }
        }
    }
    #[test]
    fn fixed_mapping_and_v1_store_reject_without_reset() {
        let (root, mut c, s) = fixture();
        drop(s);
        c.directory.mapping_version += 1;
        assert!(matches!(
            Store::open(&c, crate::state_directory(root.path()).unwrap()),
            Err("store-identity-mismatch")
        ));
        let db = Connection::open(root.path().join("relay.sqlite")).unwrap();
        db.pragma_update(None, "user_version", 1).unwrap();
        drop(db);
        assert!(matches!(
            Store::open(&c, crate::state_directory(root.path()).unwrap()),
            Err("unsupported-store")
        ));
    }
    #[test]
    fn receipts_remain_bounded_with_maximum_registered_metadata_and_full_affected_ids() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut c = crate::test_config(root.path());
        c.idp_issuer = format!("https://issuer.test/{}", "x".repeat(236));
        c.directory.links.truncate(1);
        c.directory.links[0].issuer = c.idp_issuer.clone();
        c.approvers.clear();
        for n in 1..32 {
            let id = uuid::Uuid::from_u128(n).to_string();
            let subject = format!("{n:02}{}", "\"".repeat(254));
            c.approvers.push(crate::Approver {
                subject: subject.clone(),
                approver_id: id.clone(),
            });
            c.directory.links.push(Link {
                subject,
                issuer: c.idp_issuer.clone(),
                source_user_id: format!("{n:02}{}", "r".repeat(254)),
                external_id: format!("{n:02}{}", "\\".repeat(254)),
                principal_id: id.clone(),
                approver_id: Some(id),
                public_key_sha256: Some("11".repeat(32)),
                confirmed_by: "c".repeat(256),
                confirmed_at_ms: 1,
                admin_allowed: false,
            });
        }
        assert!(c.directory.validate(&c).is_ok());
        let mut s = Store::open(&c, crate::state_directory(root.path()).unwrap()).unwrap();
        both_active(&mut s, &c);
        {
            let tx = s.db.transaction().unwrap();
            for n in 0..4096 {
                tx.execute("INSERT INTO requests VALUES(?1,?2,?3,'operator',?4,?5,?6,?7,?8,?9,?10,NULL,NULL,NULL,NULL,NULL)",
                    params![uuid::Uuid::from_u128(n+10000).to_string(),c.tenant_id,c.idp_issuer,c.approvers[0].subject,c.approvers[0].approver_id,b"BODY-CANARY".as_slice(),"11".repeat(32),now_ms(),now_ms()+120000,b"{}".as_slice()]).unwrap();
            }
            tx.commit().unwrap();
        }
        for l in c.directory.links.iter().skip(1) {
            s.apply_directory(&c, l, observation(State::Removed("22".repeat(32))))
                .unwrap();
        }
        let result = s
            .revocations(
                &c,
                &Identity::test("operator"),
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
        assert!(result.bytes.len() <= 64 * 1024);
        assert!(!String::from_utf8_lossy(&result.bytes).contains("BODY-CANARY"));
        let v: serde_json::Value = serde_json::from_slice(&result.bytes).unwrap();
        assert_eq!(v["items"].as_array().unwrap().len(), 31);
        let event = v["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["subject"] == c.approvers[0].subject)
            .unwrap();
        assert_eq!(
            event["affectedRequestIds"].as_array().unwrap().len() as u64
                + event["truncatedRequestCount"].as_u64().unwrap(),
            4096
        );
        let saved: String =
            s.db.query_row(
                "SELECT affected_ids FROM directory_revocations WHERE subject=?1",
                [&c.approvers[0].subject],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&saved).unwrap().len(),
            4096
        );
    }

    #[tokio::test]
    async fn directory_storage_failure_faults_service_before_any_admission() {
        let (root, mut c, s) = fixture();
        let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = root.path().join("ca.pem");
        let secret = root.path().join("secret");
        std::fs::write(&pem, ca.cert.pem()).unwrap();
        std::fs::write(&secret, b"synthetic-introspection-secret").unwrap();
        for path in [&pem, &secret] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        c.idp_ca_certificate_file = pem.clone();
        c.introspection_client_secret_file = secret;
        c.directory.ca_certificate_file = pem;
        // A missing explicit source token yields unknown without network; the real store mutation then fails.
        s.db.execute_batch("DROP TABLE directory_subjects").unwrap();
        let consumer = directory::Consumer::new(&c.directory).unwrap();
        let auth = Authenticator::new(&c).unwrap();
        let service = Service::new(c, auth, s);
        assert!(matches!(
            service.poll_directory(&consumer).await,
            Err("storage-fault")
        ));
        assert!(service.is_faulted());
        assert_eq!(service.denied(403, None, "", "").status(), 503);
    }
    #[test]
    fn audit_failure_faults_before_store_unlock_blocks_concurrent_admission() {
        let (root, mut c, mut s) = fixture();
        both_active(&mut s, &c);
        row(&s, &c);
        s.db.execute_batch("CREATE TRIGGER fail_directory_audit BEFORE INSERT ON directory_audit BEGIN SELECT RAISE(ABORT,'synthetic audit failure'); END;").unwrap();
        let ca = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let pem = root.path().join("ca.pem");
        let secret = root.path().join("secret");
        std::fs::write(&pem, ca.cert.pem()).unwrap();
        std::fs::write(&secret, b"synthetic-introspection-secret").unwrap();
        for path in [&pem, &secret] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        c.idp_ca_certificate_file = pem;
        c.introspection_client_secret_file = secret;
        let auth = Authenticator::new(&c).unwrap();
        let service = Service::new(c, auth, s);
        let (failed, failed_rx) = std::sync::mpsc::sync_channel(0);
        let (admitted, admitted_rx) = std::sync::mpsc::sync_channel(0);
        let result = std::thread::scope(|scope| {
            let service = &service;
            scope.spawn(move || {
                assert!(matches!(
                    service.apply_directory_member(
                        &service.config.directory.links[1],
                        observation(State::Removed("33".repeat(32)))
                    ),
                    Err("storage-fault")
                ));
                // Pause at the existing callback-return boundary, before the outer poll error latch.
                failed.send(()).unwrap();
                admitted_rx.recv().unwrap();
                service.fault();
            });
            failed_rx.recv().unwrap();
            let result = service
                .store
                .lock()
                .map_err(|_| Error::Storage)
                .and_then(|mut store| {
                    // Same admission boundary as handle(), after introspection/body collection.
                    if service.is_faulted() {
                        return Err(Error::Storage);
                    }
                    store.operate(
                        &service.config,
                        &Identity::test("operator"),
                        Instant::now() + Duration::from_secs(10),
                        &service.config.instance_id,
                        "challenge",
                        false,
                        None,
                        &[],
                    )
                });
            admitted.send(()).unwrap();
            result
        });
        assert!(
            matches!(result, Err(Error::Storage)),
            "concurrent admission escaped the directory failure latch"
        );
        let store = service.store.lock().unwrap();
        assert_eq!(
            store
                .db
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM directory_subjects WHERE tombstone=1",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .db
                .query_row::<i64, _, _>(
                    "SELECT count(*) FROM transport_events WHERE result='downloaded'",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            0
        );
    }
}
