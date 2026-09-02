use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rekey_domain::audit::{AUDIT_SCHEMA_V1, AuditPage, AuditQuery};
use rekey_domain::ipc::admin_msg;
use serde::Serialize;

use super::admin;
use crate::client::CliError;

pub fn audit_list(state_dir: &Path, query: AuditQuery) -> Result<(), CliError> {
    query
        .validate()
        .map_err(|error| CliError::local("USAGE", error.to_string()))?;
    let page = fetch_page(state_dir, &query)?;
    let mut output = serde_json::to_vec_pretty(&page)
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode audit page"))?;
    output.push(b'\n');
    io::stdout()
        .write_all(&output)
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write output: {error}")))
}

pub fn audit_export(
    state_dir: &Path,
    output: &Path,
    mut query: AuditQuery,
) -> Result<(), CliError> {
    query
        .validate()
        .map_err(|error| CliError::local("USAGE", error.to_string()))?;
    let first = fetch_page(state_dir, &query)?;
    let snapshot_max_sequence = first.snapshot_max_sequence;
    let created_at_ms = now_ms()?;
    let output_text = output
        .to_str()
        .ok_or_else(|| CliError::local("USAGE", "audit output path must be valid UTF-8"))?;
    let (mut file, resolved) = create_export_file(output)?;

    let header = ExportHeader {
        record_type: "rekey.audit.export.v1",
        schema: AUDIT_SCHEMA_V1,
        created_at_ms,
        snapshot_max_sequence,
        request_id: query.request_id.map(|value| value.to_string()),
        session_id: query.session_id.map(|value| value.to_string()),
        action_id: query.action_id.map(|value| value.to_string()),
        credential_id: query.credential_id.map(|value| value.to_string()),
        outcome: query.outcome.clone(),
        since_ms: query.since_ms,
        until_ms: query.until_ms,
    };
    write_json_line(&mut file, &header)?;

    let mut page = first;
    let mut row_count = 0u64;
    loop {
        for event in &page.events {
            write_json_line(&mut file, event)?;
            row_count = row_count.checked_add(1).ok_or_else(|| {
                CliError::local("OUTPUT_FAILED", "audit export row count overflow")
            })?;
        }
        let Some(before) = page.next_before_sequence else {
            break;
        };
        query.snapshot_max_sequence = Some(snapshot_max_sequence);
        query.before_sequence = Some(before);
        page = fetch_page(state_dir, &query)?;
    }

    write_json_line(
        &mut file,
        &ExportTrailer {
            record_type: "rekey.audit.export.complete.v1",
            row_count,
        },
    )?;
    file.flush()
        .and_then(|_| file.sync_all())
        .map_err(output_error)?;
    fsync_parent(&resolved).map_err(output_error)?;

    let receipt = serde_json::json!({
        "exported": true,
        "output_path": output_text,
        "snapshot_max_sequence": snapshot_max_sequence,
        "row_count": row_count,
    });
    let mut stdout = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| CliError::local("OUTPUT_FAILED", "cannot encode export receipt"))?;
    stdout.push(b'\n');
    io::stdout()
        .write_all(&stdout)
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write output: {error}")))
}

fn fetch_page(state_dir: &Path, query: &AuditQuery) -> Result<AuditPage, CliError> {
    let metadata = serde_json::to_vec(query)
        .map_err(|_| CliError::local("USAGE", "cannot encode audit query"))?;
    let (response_metadata, body) =
        admin(state_dir)?.call(admin_msg::AUDIT_QUERY, &metadata, &[])?;
    let response_metadata: serde_json::Value = serde_json::from_slice(&response_metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    if !matches!(response_metadata, serde_json::Value::Object(ref fields) if fields.is_empty()) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "audit response metadata must be empty",
        ));
    }
    let page: AuditPage = serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid audit page"))?;
    page.validate_for(query)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid audit page"))?;
    Ok(page)
}

fn create_export_file(path: &Path) -> Result<(File, PathBuf), CliError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(output_error)?.join(path)
    };
    let name = absolute
        .file_name()
        .ok_or_else(|| CliError::local("USAGE", "audit output path has no file name"))?;
    let parent = absolute
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .map_err(output_error)?;
    let resolved = parent.join(name);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&resolved)
        .map_err(output_error)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(output_error(io::Error::last_os_error()));
    }
    let metadata = file.metadata().map_err(output_error)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(CliError::local(
            "OUTPUT_FAILED",
            "audit export file failed ownership or mode verification",
        ));
    }
    Ok((file, resolved))
}

fn fsync_parent(path: &Path) -> io::Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

fn write_json_line(file: &mut File, value: &impl Serialize) -> Result<(), CliError> {
    serde_json::to_writer(&mut *file, value).map_err(|error| {
        CliError::local("OUTPUT_FAILED", format!("cannot write export: {error}"))
    })?;
    file.write_all(b"\n").map_err(output_error)
}

fn now_ms() -> Result<i64, CliError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::local("OUTPUT_FAILED", "system clock is before Unix epoch"))?;
    i64::try_from(elapsed.as_millis())
        .map_err(|_| CliError::local("OUTPUT_FAILED", "system clock exceeds audit range"))
}

fn output_error(error: io::Error) -> CliError {
    CliError::local("OUTPUT_FAILED", format!("audit export failed: {error}"))
}

#[derive(Serialize)]
struct ExportHeader {
    record_type: &'static str,
    schema: &'static str,
    created_at_ms: i64,
    snapshot_max_sequence: u64,
    request_id: Option<String>,
    session_id: Option<String>,
    action_id: Option<String>,
    credential_id: Option<String>,
    outcome: Option<String>,
    since_ms: Option<i64>,
    until_ms: Option<i64>,
}

#[derive(Serialize)]
struct ExportTrailer {
    record_type: &'static str,
    row_count: u64,
}

#[cfg(test)]
mod tests {
    use serde::ser::Error as _;

    use super::*;

    struct FailingRecord;

    impl Serialize for FailingRecord {
        fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("injected serialization failure"))
        }
    }

    #[test]
    fn failed_write_keeps_the_create_new_partial_file() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("partial.jsonl");
        let (mut file, resolved) = create_export_file(&output).unwrap();
        write_json_line(&mut file, &serde_json::json!({"header": true})).unwrap();
        assert!(write_json_line(&mut file, &FailingRecord).is_err());
        drop(file);
        assert!(resolved.exists());
        assert!(output.exists());
        assert_eq!(fs::read_to_string(output).unwrap(), "{\"header\":true}\n");
    }

    #[test]
    fn vanished_parent_makes_the_final_directory_sync_fail() {
        let root = tempfile::tempdir().unwrap();
        let parent = root.path().join("parent");
        fs::create_dir(&parent).unwrap();
        let output = parent.join("audit.jsonl");
        let (mut file, resolved) = create_export_file(&output).unwrap();
        file.write_all(b"partial\n").unwrap();
        fs::remove_file(&resolved).unwrap();
        fs::remove_dir(&parent).unwrap();
        file.sync_all().unwrap();
        assert!(fsync_parent(&resolved).is_err());
    }
}
