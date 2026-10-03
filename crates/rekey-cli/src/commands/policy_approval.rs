use rekey_domain::ipc::ProofKind;
use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rekey_domain::action::HeaderName;
use rekey_domain::ids::ApprovalRequestId;
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
    file: Option<&Path>,
    stdin_request: bool,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let (trust, proof) = match (file, stdin_request) {
        (Some(file), false) => {
            let (trust, _) = read_regular_nosymlink(file, 4 * 1024, "policy trust file")?;
            (trust, read_step_up(kind, password_stdin)?)
        }
        (None, true) if password_stdin => {
            let mut lines = stdin_lines(2)?.into_iter();
            let proof = lines.next().expect("exact line count validated");
            let trust = lines.next().expect("exact line count validated");
            if trust.len() > 4 * 1024 {
                return Err(CliError::local("USAGE", "policy trust exceeds 4 KiB"));
            }
            (trust, proof)
        }
        _ => {
            return Err(CliError::local(
                "USAGE",
                "choose a trust file or --stdin-request --step-up-stdin",
            ));
        }
    };
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_TRUST_INSTALL, &trust, &body)?;
    print_policy_status(&meta)
}

pub fn policy_activate(
    state_dir: &Path,
    file: Option<&Path>,
    stdin_request: bool,
    expected_vault_id: &str,
    expected_trust_sha256: &str,
    kind: ProofKind,
    password_stdin: bool,
) -> Result<(), CliError> {
    let (metadata, proof) = match (file, stdin_request) {
        (Some(file), false) => {
            let (bundle, _) = read_regular_nosymlink(file, 64 * 1024, "policy bundle")?;
            // Keep the file path's error order: reject public input before asking for proof.
            let metadata =
                policy_activate_metadata(expected_vault_id, expected_trust_sha256, &bundle)?;
            (metadata, read_step_up(kind, password_stdin)?)
        }
        (None, true) if password_stdin => {
            let mut lines = stdin_lines(2)?.into_iter();
            let proof = lines.next().expect("exact line count validated");
            let bundle = lines.next().expect("exact line count validated");
            let metadata =
                policy_activate_metadata(expected_vault_id, expected_trust_sha256, &bundle)?;
            (metadata, proof)
        }
        _ => {
            return Err(CliError::local(
                "USAGE",
                "choose a bundle file or --stdin-request --step-up-stdin",
            ));
        }
    };
    let body = proof_body(kind, &proof);
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_ACTIVATE, &metadata, &body)?;
    print_policy_status(&meta)
}

fn policy_activate_metadata(
    expected_vault_id: &str,
    expected_trust_sha256: &str,
    bundle: &[u8],
) -> Result<Vec<u8>, CliError> {
    let expected_vault_id = expected_vault_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid expected vault id"))?;
    if expected_trust_sha256.len() != 64
        || !expected_trust_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CliError::local(
            "USAGE",
            "expected trust digest must be 64 lowercase hex characters",
        ));
    }
    let bundle_json = serde_json::from_slice::<Box<serde_json::value::RawValue>>(bundle)
        .map_err(|_| CliError::local("USAGE", "invalid policy bundle JSON"))?;
    let metadata = serde_json::to_vec(&ipc::PolicyActivateMeta {
        expected_vault_id,
        expected_trust_sha256: expected_trust_sha256.to_owned(),
        bundle_json,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode policy activation"))?;
    if metadata.len() > ipc::METADATA_MAX_BYTES as usize {
        return Err(CliError::local(
            "USAGE",
            "policy activation metadata exceeds 64 KiB",
        ));
    }
    Ok(metadata)
}

pub fn policy_draft(
    state_dir: &Path,
    principal: &str,
    expires_at_ms: i64,
    actions: &[String],
) -> Result<(), CliError> {
    let principal_id = principal
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid principal id"))?;
    let actions = actions
        .iter()
        .map(|value| {
            let (action_id, version) = parse_action_ref(value)?;
            Ok(rekey_domain::capability::ActionVersionRef { action_id, version })
        })
        .collect::<Result<Vec<_>, CliError>>()?;
    let request = serde_json::to_vec(&ipc::PersonalPolicyDraftMeta {
        principal_id,
        actions,
        expires_at_ms,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode personal policy draft request"))?;
    let (metadata, body) =
        admin(state_dir)?.call(admin_msg::PERSONAL_POLICY_DRAFT, &request, &[])?;
    let metadata: ipc::PersonalPolicyDraftResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid draft metadata"))?;
    metadata
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid draft metadata"))?;
    let sign_bytes = personal_draft_sign_bytes(&body)?;
    let response =
        serde_json::to_vec(&serde_json::json!({"metadata": metadata, "sign_bytes": sign_bytes}))
            .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode personal policy draft"))?;
    print_json::<serde_json::Value>(&response)
}

fn personal_draft_sign_bytes(body: &[u8]) -> Result<&str, CliError> {
    const PREFIX: &[u8] = b"RKPOLICY\0\x01";
    if body.len() > 64 * 1024 || body.len() <= PREFIX.len() || !body.starts_with(PREFIX) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "broker returned invalid signing bytes",
        ));
    }
    std::str::from_utf8(body)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid signing bytes"))
}

pub fn policy_status(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::POLICY_STATUS, b"{}", &[])?;
    print_policy_status(&meta)
}

pub fn approval_origin(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::APPROVAL_ORIGIN, b"{}", &[])?;
    let origin = serde_json::from_slice::<ipc::ApprovalOriginResponse>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    origin
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::ApprovalOriginResponse>(&meta)
}

pub fn approval_pending(state_dir: &Path) -> Result<(), CliError> {
    let (meta, _) = admin(state_dir)?.call(admin_msg::APPROVAL_PENDING, b"{}", &[])?;
    let pending = serde_json::from_slice::<ipc::ApprovalPendingResponse>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    pending
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::ApprovalPendingResponse>(&meta)
}

pub fn approval_get(state_dir: &Path, approval_request_id: &str) -> Result<(), CliError> {
    let approval_request_id: ApprovalRequestId = approval_request_id
        .parse()
        .map_err(|_| CliError::local("USAGE", "invalid approval request id"))?;
    let metadata = serde_json::to_vec(&ipc::ApprovalGetMeta {
        approval_request_id,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode approval get request"))?;
    let (meta, _) = admin(state_dir)?.call(admin_msg::APPROVAL_GET, &metadata, &[])?;
    let envelope = serde_json::from_slice::<ipc::SignedApprovalChallenge>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    envelope
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::SignedApprovalChallenge>(&meta)
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
    request: &crate::RequestArgs,
) -> Result<(), CliError> {
    let (action_id, version) = parse_action_ref(action)?;
    let capability_token = capability_value(capability)?;
    let body = request_body(request.body_file.as_deref())?;
    let extra_headers = request_headers(&request.headers)?;
    let metadata = serde_json::to_vec(&ipc::PrepareApprovalMeta {
        capability_token,
        action_id,
        action_version: version,
        content_type: request.content_type.clone(),
        extra_headers,
        params: request_values(&request.params)?,
        query: request_values(&request.query)?,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode approval request"))?;
    let (meta, _) = Client::connect_with_response_timeout(
        agent_socket,
        Channel::Agent,
        ACTION_RESPONSE_TIMEOUT,
    )?
    .call(agent_msg::PREPARE_APPROVAL, &metadata, &body)?;
    let envelope = serde_json::from_slice::<ipc::SignedApprovalChallenge>(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    envelope
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    print_json::<ipc::SignedApprovalChallenge>(&meta)
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

pub(super) fn request_values(
    values: &[String],
) -> Result<rekey_domain::template::TemplateValues, CliError> {
    let mut result = rekey_domain::template::TemplateValues::new();
    for value in values {
        let (name, value) = value
            .split_once('=')
            .ok_or_else(|| CliError::local("USAGE", "parameters require NAME=VALUE"))?;
        if name.is_empty() || result.insert(name.to_owned(), value.to_owned()).is_some() {
            return Err(CliError::local(
                "USAGE",
                "parameter names must be nonempty and unique",
            ));
        }
    }
    Ok(result)
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
    fn personal_draft_body_preserves_utf8_bytes_and_rejects_wrong_domain_or_bound() {
        let exact = b"RKPOLICY\0\x01{\"value\":\"\\u4e2d\"}";
        assert_eq!(personal_draft_sign_bytes(exact).unwrap().as_bytes(), exact);
        for invalid in [
            Vec::new(),
            b"RKPOLICY\0\x01".to_vec(),
            b"OTHER{ }".to_vec(),
            [b"RKPOLICY\0\x01".as_slice(), &[0xff]].concat(),
            [b"RKPOLICY\0\x01".as_slice(), &vec![b'a'; 65527]].concat(),
        ] {
            assert_eq!(
                personal_draft_sign_bytes(&invalid).unwrap_err().code,
                "INVALID_FRAME"
            );
        }
    }

    #[test]
    fn invalid_policy_file_fails_before_reading_stdin_proof() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("invalid.json");
        std::fs::write(&file, b"{").unwrap();
        let error = policy_activate(
            dir.path(),
            Some(&file),
            false,
            "00112233-4455-4677-8899-aabbccddeeff",
            &"a".repeat(64),
            ProofKind::Password,
            true,
        )
        .unwrap_err();
        assert_eq!(error.message, "invalid policy bundle JSON");
    }

    #[test]
    fn policy_activation_preserves_duplicate_keys_and_bounds_encoded_metadata() {
        let vault = "00112233-4455-4677-8899-aabbccddeeff";
        let digest = "a".repeat(64);
        let raw = br#"{"snapshot":{"version":1,"version":2}}"#;
        let encoded = policy_activate_metadata(vault, &digest, raw).unwrap();
        let metadata: ipc::PolicyActivateMeta = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(metadata.bundle_json.get().as_bytes(), raw);
        assert!(policy_activate_metadata("bad-id", &digest, b"{}").is_err());
        assert!(policy_activate_metadata(vault, &"A".repeat(64), b"{}").is_err());
        assert!(policy_activate_metadata(vault, "ab", b"{}").is_err());
        assert!(policy_activate_metadata(vault, &digest, b"{").is_err());
        // Bundle alone fits, but its activation envelope exceeds the frame bound.
        let bundle = format!(
            r#"{{"padding":"{}"}}"#,
            "x".repeat(ipc::METADATA_MAX_BYTES as usize - 20)
        );
        assert!(bundle.len() < ipc::METADATA_MAX_BYTES as usize);
        assert!(policy_activate_metadata(vault, &digest, bundle.as_bytes()).is_err());
    }

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
