use rekey_domain::ipc::ProofKind;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rekey_domain::audit::{
    AUDIT_SCHEMA_V2, AuditPage, AuditPruneReceipt, AuditPruneRequest, AuditQuery,
};
use rekey_domain::ipc::admin_msg;
use serde::Serialize;

use super::{
    LIFECYCLE_RESPONSE_TIMEOUT, admin, admin_with_response_timeout, proof_body, read_step_up,
};
use crate::client::CliError;

pub fn audit_prune(
    state_dir: &Path,
    before_ms: Option<i64>,
    older_than_days: Option<u64>,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    if before_ms.is_some() == older_than_days.is_some() {
        return Err(CliError::local(
            "USAGE",
            "select exactly one audit prune cutoff",
        ));
    }
    let age_ms = older_than_days.map(retention_age_ms).transpose()?;
    let proof = read_step_up(kind, password_stdin)?;
    let before_ms = match (before_ms, age_ms) {
        (Some(before_ms), None) => before_ms,
        (None, Some(age_ms)) => retention_cutoff_ms(age_ms, now_ms()?)?,
        _ => unreachable!("validated selector"),
    };
    let request = AuditPruneRequest { before_ms };
    let metadata = serde_json::to_vec(&request)
        .map_err(|_| CliError::local("USAGE", "cannot encode audit prune request"))?;
    let body = proof_body(kind, &proof);
    let (metadata, response_body) = admin_with_response_timeout(
        state_dir,
        LIFECYCLE_RESPONSE_TIMEOUT,
    )?
    .call(admin_msg::AUDIT_PRUNE, &metadata, &body)?;
    if !response_body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected audit prune response body",
        ));
    }
    let receipt: AuditPruneReceipt = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid audit prune receipt"))?;
    receipt
        .validate_for(&request)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid audit prune receipt"))?;
    let mut output = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode audit prune receipt"))?;
    output.push(b'\n');
    io::stdout()
        .write_all(&output)
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write output: {error}")))
}

fn retention_age_ms(days: u64) -> Result<i64, CliError> {
    i64::try_from(days)
        .ok()
        .filter(|days| *days > 0)
        .and_then(|days| days.checked_mul(86_400_000))
        .ok_or_else(|| CliError::local("USAGE", "audit retention age is out of range"))
}

fn retention_cutoff_ms(age_ms: i64, now_ms: i64) -> Result<i64, CliError> {
    now_ms
        .checked_sub(age_ms)
        .filter(|cutoff| *cutoff >= 0)
        .ok_or_else(|| CliError::local("USAGE", "audit retention age precedes Unix epoch"))
}

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
        record_type: "rekey.audit.export.v2",
        schema: AUDIT_SCHEMA_V2,
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
            record_type: "rekey.audit.export.complete.v2",
            row_count,
        },
    )?;
    file.flush()
        .and_then(|_| file.sync_all())
        .map_err(output_error)?;
    verify_export_path(&file, &resolved).map_err(output_error)?;
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

fn verify_export_path(file: &File, path: &Path) -> io::Result<()> {
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if opened.dev() != named.dev() || opened.ino() != named.ino() {
        return Err(io::Error::other(
            "audit export path no longer names the created file",
        ));
    }
    Ok(())
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

pub fn audit_retention_set(
    state_dir: &Path,
    days: Option<u64>,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    if let Some(days) = days {
        retention_age_ms(days)?;
    }
    let proof = read_step_up(kind, password_stdin)?;
    let request = rekey_domain::audit::AuditRetentionSet { days };
    let metadata = serde_json::to_vec(&request)
        .map_err(|_| CliError::local("USAGE", "cannot encode retention request"))?;
    let body = proof_body(kind, &proof);
    let (metadata, body) = admin_with_response_timeout(state_dir, LIFECYCLE_RESPONSE_TIMEOUT)?
        .call(admin_msg::AUDIT_RETENTION_SET, &metadata, &body)?;
    let receipt = retention_receipt(&metadata, &body)?;
    if receipt.days != days {
        return Err(CliError::local(
            "INVALID_FRAME",
            "retention receipt does not match request",
        ));
    }
    print_retention(&receipt)
}
pub fn audit_retention_status(state_dir: &Path) -> Result<(), CliError> {
    let (metadata, body) = admin(state_dir)?.call(admin_msg::AUDIT_RETENTION_STATUS, b"{}", &[])?;
    print_retention(&retention_receipt(&metadata, &body)?)
}
fn retention_receipt(
    metadata: &[u8],
    body: &[u8],
) -> Result<rekey_domain::audit::AuditRetentionStatus, CliError> {
    if !body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "unexpected retention body",
        ));
    }
    let receipt: rekey_domain::audit::AuditRetentionStatus = serde_json::from_slice(metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid retention receipt"))?;
    receipt
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid retention receipt"))?;
    Ok(receipt)
}
fn print_retention(receipt: &rekey_domain::audit::AuditRetentionStatus) -> Result<(), CliError> {
    let mut output = serde_json::to_vec_pretty(receipt)
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode retention receipt"))?;
    output.push(b'\n');
    io::stdout()
        .write_all(&output)
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write output: {error}")))
}

#[cfg(test)]
mod tests {
    use serde::ser::Error as _;

    use super::*;

    #[test]
    fn audit_retention_age_checks_overflow_and_epoch_without_clamping() {
        assert_eq!(retention_age_ms(30).unwrap(), 2_592_000_000);
        for days in [0, u64::MAX, (i64::MAX / 86_400_000) as u64 + 1] {
            assert_eq!(retention_age_ms(days).unwrap_err().code, "USAGE");
        }
        let maximum_days = (i64::MAX / 86_400_000) as u64;
        assert_eq!(
            retention_age_ms(maximum_days).unwrap(),
            maximum_days as i64 * 86_400_000
        );
        let day = retention_age_ms(1).unwrap();
        assert_eq!(retention_cutoff_ms(day, day).unwrap(), 0);
        assert_eq!(retention_cutoff_ms(day, day + 1).unwrap(), 1);
        assert_eq!(retention_cutoff_ms(day, day - 1).unwrap_err().code, "USAGE");
        assert_eq!(
            retention_cutoff_ms(day, i64::MIN).unwrap_err().code,
            "USAGE"
        );
        let request = AuditPruneRequest {
            before_ms: retention_cutoff_ms(day, day + 1).unwrap(),
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            serde_json::json!({"before_ms":1})
        );
    }

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

    #[test]
    fn replaced_export_path_is_rejected_before_success() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("audit.jsonl");
        let (mut file, resolved) = create_export_file(&output).unwrap();
        file.write_all(b"complete export\n").unwrap();
        fs::remove_file(&resolved).unwrap();
        fs::write(&resolved, b"replacement\n").unwrap();
        file.sync_all().unwrap();

        let error = verify_export_path(&file, &resolved).unwrap_err();
        assert!(error.to_string().contains("no longer names"));
        assert_eq!(fs::read(&resolved).unwrap(), b"replacement\n");
    }
}

#[cfg(test)]
mod retention_receipt_tests {
    use super::*;
    #[test]
    fn retention_receipt_rejects_missing_fields_ranges_unknown_fields_and_body() {
        for input in [
            b"{}".as_slice(),
            b"{\"updated_at_ms\":1}",
            b"{\"days\":null}",
            b"{\"days\":0,\"updated_at_ms\":1}",
            b"{\"days\":1,\"updated_at_ms\":-1}",
            b"{\"days\":1,\"updated_at_ms\":1,\"extra\":true}",
        ] {
            assert_eq!(
                retention_receipt(input, &[]).unwrap_err().code,
                "INVALID_FRAME"
            );
        }
        let valid = b"{\"days\":null,\"updated_at_ms\":1}";
        assert_eq!(retention_receipt(valid, &[]).unwrap().days, None);
        assert_eq!(
            retention_receipt(valid, b"x").unwrap_err().code,
            "INVALID_FRAME"
        );
    }
}
