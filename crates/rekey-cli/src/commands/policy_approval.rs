use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rekey_domain::action::HeaderName;
use rekey_domain::ipc::{self, Channel, admin_msg, agent_msg};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

use super::{
    ACTION_RESPONSE_TIMEOUT, admin, parse_action_ref, print_json, proof_body, read_bounded,
    read_step_up, stdin_lines,
};

type FileIdentity = (u64, u64);

fn read_regular_nosymlink(
    path: &Path,
    limit: usize,
    label: &'static str,
) -> Result<(Zeroizing<Vec<u8>>, FileIdentity), CliError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| CliError::local("USAGE", format!("cannot open {label}: {err}")))?;
    let metadata = file
        .metadata()
        .map_err(|err| CliError::local("USAGE", format!("cannot inspect {label}: {err}")))?;
    if !metadata.is_file() {
        return Err(CliError::local(
            "USAGE",
            format!("{label} must be a regular non-symlink file"),
        ));
    }
    let identity = (metadata.dev(), metadata.ino());
    read_bounded(file, limit, label).map(|bytes| (bytes, identity))
}

pub fn policy_trust_install(
    state_dir: &Path,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let (trust, _) = read_regular_nosymlink(file, 4 * 1024, "policy trust file")?;
    let proof = read_step_up(recovery, password_stdin)?;
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_TRUST_INSTALL, &trust, &body)?;
    print_policy_status(&meta)
}

pub fn policy_activate(
    state_dir: &Path,
    file: &Path,
    recovery: bool,
    password_stdin: bool,
) -> Result<(), CliError> {
    let (bundle, _) = read_regular_nosymlink(file, 64 * 1024, "policy bundle")?;
    let proof = read_step_up(recovery, password_stdin)?;
    let body = proof_body(recovery, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_ACTIVATE, &bundle, &body)?;
    print_policy_status(&meta)
}

pub fn policy_status(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_STATUS, b"{}", &[])?;
    print_policy_status(&meta)
}

fn print_policy_status(metadata: &[u8]) -> Result<(), CliError> {
    let status = serde_json::from_slice::<ipc::PolicyStatusResponse>(metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    status
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::PolicyStatusResponse>(metadata)
}

pub(super) fn read_approval_files(paths: &[PathBuf]) -> Result<Vec<String>, CliError> {
    if paths.len() > 2 {
        return Err(CliError::local(
            "USAGE",
            "execute accepts at most two approval files",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut grants = Vec::with_capacity(paths.len());
    for path in paths {
        let (bytes, identity) = read_regular_nosymlink(path, 4 * 1024, "approval file")?;
        if !seen.insert(identity) {
            return Err(CliError::local("USAGE", "duplicate approval file"));
        }
        grants.push(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| CliError::local("USAGE", "approval file must be utf-8 JSON"))?,
        );
    }
    Ok(grants)
}

pub fn approval_prepare(
    agent_socket: &Path,
    action: &str,
    capability: &str,
    body_file: Option<&Path>,
    content_type: Option<String>,
    headers: &[String],
) -> Result<(), CliError> {
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = capability_value(capability)?;
    let body = request_body(body_file)?;
    let extra_headers = request_headers(headers)?;
    let metadata = serde_json::to_vec(&ipc::PrepareApprovalMeta {
        capability_token,
        action_id,
        action_version: version,
        content_type,
        extra_headers,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode approval request"))?;
    let (meta, _) = Client::connect_with_response_timeout(
        agent_socket,
        Channel::Agent,
        ACTION_RESPONSE_TIMEOUT,
    )?
    .call(agent_msg::PREPARE_APPROVAL, &metadata, &body)?;
    let challenge = serde_json::from_slice::<ipc::ApprovalChallenge>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    challenge
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::ApprovalChallenge>(&meta)
}

pub(super) fn capability_value(capability: &str) -> Result<String, CliError> {
    if capability == "-" {
        String::from_utf8(stdin_lines(1)?.remove(0).to_vec())
            .map_err(|_| CliError::local("USAGE", "capability token must be utf-8"))
    } else {
        Ok(capability.to_owned())
    }
}

pub(super) fn request_body(body_file: Option<&Path>) -> Result<Zeroizing<Vec<u8>>, CliError> {
    match body_file {
        Some(path) => {
            super::read_regular_file_bounded(path, ipc::AGENT_BODY_MAX_BYTES as usize, "body file")
        }
        None => Ok(Zeroizing::new(Vec::new())),
    }
}

pub(super) fn request_headers(headers: &[String]) -> Result<Vec<(String, String)>, CliError> {
    headers
        .iter()
        .map(|header| {
            let (raw_name, value) = header
                .split_once(':')
                .ok_or_else(|| CliError::local("USAGE", "header must be NAME:VALUE"))?;
            let name = HeaderName::new(raw_name)
                .map_err(|err| CliError::local("USAGE", err.to_string()))?;
            Ok((name.as_str().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn policy_artifact_reader_rejects_fifo_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("policy.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = read_regular_nosymlink(&fifo, 4 * 1024, "policy file");
            tx.send(result.is_err()).expect("receiver remains alive");
        });
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
    }

    #[test]
    fn approval_reader_rejects_hard_link_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let grant = dir.path().join("grant.json");
        let alias = dir.path().join("alias.json");
        std::fs::write(&grant, b"{}").unwrap();
        std::fs::hard_link(&grant, &alias).unwrap();
        assert!(read_approval_files(&[grant, alias]).is_err());
    }
}
