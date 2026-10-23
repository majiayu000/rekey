//! One-step `rekey add`: save an API key, build the preset Connection, sign it
//! with the basic-mode software policy key and activate it, using one password.
//!
//! Signing is delegated to the bundled `rekey-policy-sign` so this CLI still
//! links no cryptography. The software key is a mode-0600 file in the state
//! directory, not Secure Enclave; every output says so.
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use rekey_domain::connection::{Connection, OAUTH_PRESETS, Preset, is_llm_preset};
use rekey_domain::credential::CredentialMetadata;
use rekey_domain::ids::{CredentialId, PolicySignerId};
use rekey_domain::ipc::{self, ConnectionListResponse, ProofKind, admin_msg};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

/// Basic-mode software policy key, beside the vault it signs for.
pub const SOFTWARE_SIGNER_FILE: &str = "policy-signer-p256.p8";
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

pub struct AddRequest {
    pub provider: String,
    pub name: Option<String>,
    pub label: Option<String>,
    pub credential_id: Option<String>,
    pub origin: Option<String>,
    pub header: Option<String>,
    pub prefix: Option<String>,
    pub valid_days: u32,
    pub models: Vec<String>,
    pub stdin_secrets: bool,
}

/// Interactive default-workspace users share the App's review/presence flow.
/// Explicit stdin and other workspaces retain the headless basic-mode command.
pub fn dispatch(
    state_dir: &Path,
    request: AddRequest,
    app: bool,
    inapplicable: bool,
) -> Result<(), CliError> {
    let automatic = cfg!(target_os = "macos")
        && !request.stdin_secrets
        && !inapplicable
        && state_dir == super::resolve_state_dir(None)?
        && Path::new("/Applications/Rekey.app").is_dir();
    if app || automatic {
        let url = app_url(state_dir, &request, inapplicable)?;
        super::launch_onboarding(&url)
    } else {
        add(state_dir, request)
    }
}

fn app_url(state_dir: &Path, request: &AddRequest, inapplicable: bool) -> Result<String, CliError> {
    let mut url = super::onboarding_url(state_dir, Some(&request.provider), inapplicable)?;
    if request.stdin_secrets || !(1..=365).contains(&request.valid_days) {
        return Err(CliError::local(
            "USAGE",
            "App onboarding does not accept stdin secrets; --valid-days must be 1..=365",
        ));
    }
    if request
        .credential_id
        .as_deref()
        .is_some_and(|id| id.parse::<CredentialId>().is_err())
    {
        return Err(CliError::local("USAGE", "invalid --credential-id"));
    }
    let encode = |value: &str| -> String {
        value
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    let mut query = vec![format!("valid_days={}", request.valid_days)];
    for (key, value) in [
        ("name", &request.name),
        ("label", &request.label),
        ("credential_id", &request.credential_id),
        ("origin", &request.origin),
        ("header", &request.header),
        ("prefix", &request.prefix),
    ] {
        if let Some(value) = value {
            query.push(format!("{key}={}", encode(value)));
        }
    }
    for model in &request.models {
        query.push(format!("model={}", encode(model)));
    }
    // OAuth has its own client-registration form; do not silently discard flags.
    if OAUTH_PRESETS.contains(&request.provider.as_str()) && query.len() != 1 {
        return Err(CliError::local(
            "USAGE",
            "OAuth connection options must be entered in the App",
        ));
    }
    url.push('?');
    url.push_str(&query.join("&"));
    if url.len() > 8192 {
        return Err(CliError::local("USAGE", "App onboarding URL is too large"));
    }
    Ok(url)
}

pub fn add(state_dir: &Path, request: AddRequest) -> Result<(), CliError> {
    if OAUTH_PRESETS.contains(&request.provider.as_str()) {
        return Err(CliError::local(
            "USAGE",
            format!(
                "{} uses browser OAuth; run `rekey add {} --app` to finish it in the App",
                request.provider, request.provider
            ),
        ));
    }
    if request.valid_days == 0 || request.valid_days > 365 {
        return Err(CliError::local("USAGE", "--valid-days must be 1..=365"));
    }
    let reuse: Option<CredentialId> = request
        .credential_id
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(|_| CliError::local("USAGE", "invalid --credential-id"))?;
    let name = request
        .name
        .clone()
        .unwrap_or_else(|| request.provider.clone());
    // Fail on public inputs before asking for any secret.
    let status = policy_status(state_dir)?;
    match status.mode {
        Some(rekey_domain::authorization::PolicyMode::Personal) => {}
        Some(_) => {
            return Err(CliError::local(
                "USAGE",
                "team vaults are signed by the external team signer; `rekey add` only supports personal vaults",
            ));
        }
        None => {
            return Err(CliError::local(
                "LOCKED",
                "vault is locked; run `rekey unlock` first",
            ));
        }
    }
    let signer = signer_binary();
    // Check the signer before asking for any secret, so a missing tool never
    // wastes a typed password or key.
    let probe = Command::new(&signer)
        .arg("--help")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| {
            CliError::local(
                "SIGNER_UNAVAILABLE",
                format!("cannot run {}: {err}", signer.display()),
            )
        })?;
    if !probe.success() {
        return Err(CliError::local(
            "SIGNER_UNAVAILABLE",
            format!("{} is not a working policy signer", signer.display()),
        ));
    }
    let key_file = state_dir.join(SOFTWARE_SIGNER_FILE);
    let mut install_trust = None;
    if status.trust_installed {
        let signer_id = status
            .signer_id
            .ok_or_else(|| CliError::local("INVALID_FRAME", "trust has no signer id"))?;
        let matches = key_file.exists()
            && software_trust(&signer, &key_file, signer_id)?.1
                == status.trust_sha256.clone().unwrap_or_default();
        if !matches {
            return Err(CliError::local(
                "TRUST_MISMATCH",
                "this vault trusts a signer this CLI does not hold (for example the App's Secure Enclave key); finish with `rekey add <provider> --app`, or create a new vault for basic mode",
            ));
        }
    } else if key_file.exists() {
        // A key without installed trust: reuse it rather than orphaning it.
        install_trust = Some(software_trust(&signer, &key_file, new_signer_id())?.0);
    }
    let models = llm_models(&request)?;
    let preset = load_preset(state_dir, &request)?;
    let baseline: ConnectionListResponse = public(state_dir, admin_msg::PROFILE_LIST, json!({}))?;
    if baseline.connections.iter().any(|item| item.name == name) {
        return Err(CliError::local(
            "USAGE",
            format!("a Connection named {name} already exists; choose another with --name"),
        ));
    }

    let (proof, secret) = collect_add_inputs(&request)?;
    if !status.trust_installed {
        let trust = match install_trust {
            Some(trust) => trust,
            None => {
                generate_key(&signer, &key_file)?;
                software_trust(&signer, &key_file, new_signer_id())?.0
            }
        };
        let body = proof_body(&proof);
        admin(state_dir)?.call(admin_msg::POLICY_TRUST_INSTALL, &trust, &body)?;
        eprintln!(
            "Installed basic-mode policy trust: software P-256 key {} (mode 0600, not Secure Enclave).",
            key_file.display()
        );
    }
    let credential_id = match (reuse, secret) {
        (Some(id), _) => id,
        (None, Some(secret)) => save_credential(state_dir, &proof, &secret, &request, &name)?,
        (None, None) => {
            unreachable!("collect_add_inputs returns a value unless reusing a credential")
        }
    };
    let connection = build_connection(preset, &name, credential_id, &models)?;

    let mut connections = baseline.connections;
    connections.push(connection);
    // Drafts carry Connections in canonical name order.
    connections.sort_by(|left, right| left.name.cmp(&right.name));
    let draft_request = serde_json::to_vec(&ipc::PersonalPolicyDraftMeta {
        connections,
        ssh_keys: Some(baseline.ssh_keys),
        derived_credentials: Some(baseline.derived_credentials),
        expected_policy_sha256: baseline.policy_sha256,
        expires_at_ms: now_ms()? + i64::from(request.valid_days) * DAY_MS,
    })
    .map_err(|_| CliError::local("USAGE", "cannot encode policy draft"))?;
    let (metadata, sign_bytes) =
        admin(state_dir)?.call(admin_msg::PERSONAL_POLICY_DRAFT, &draft_request, &[])?;
    let draft: ipc::PersonalPolicyDraftResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid draft"))?;
    draft
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid draft"))?;
    let signature = run_signer(&signer, &["sign", "--key-file"], &key_file, &sign_bytes)?;
    let bundle = signed_bundle(&sign_bytes, signature.trim())?;
    let activation = super::policy_approval::policy_activate_metadata(
        &draft.vault_id.to_string(),
        &draft.trust_sha256,
        &bundle,
    )?;
    let body = proof_body(&proof);
    admin(state_dir)?.call(admin_msg::POLICY_ACTIVATE, &activation, &body)?;

    let operations: Vec<_> = preset_operations(&draft, &name);
    println!(
        "Connection {name} is active (policy v{}, valid {} days). Signed with the basic-mode software key, not Secure Enclave.",
        draft.next_version, request.valid_days
    );
    if !operations.is_empty() {
        println!("Agents can call: {}", operations.join(", "));
    }
    if !models.is_empty() {
        println!(
            "Allowed models: {}; daily budget 100 requests / 100k output tokens.",
            models.join(", ")
        );
    }
    Ok(())
}

fn admin(state_dir: &Path) -> Result<Client, CliError> {
    super::admin(state_dir)
}

fn proof_body(proof: &[u8]) -> Zeroizing<Vec<u8>> {
    super::proof_body(ProofKind::Password, proof)
}

fn policy_status(state_dir: &Path) -> Result<ipc::PolicyStatusResponse, CliError> {
    let (metadata, _) = admin(state_dir)?.call(admin_msg::POLICY_STATUS, b"{}", &[])?;
    let status: ipc::PolicyStatusResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid policy status"))?;
    status
        .validate()
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid policy status"))?;
    Ok(status)
}

fn public<T: serde::de::DeserializeOwned>(
    state_dir: &Path,
    opcode: u16,
    request: Value,
) -> Result<T, CliError> {
    let metadata = serde_json::to_vec(&request)
        .map_err(|_| CliError::local("USAGE", "cannot encode request"))?;
    let (_, body) = admin(state_dir)?.call(opcode, &metadata, &[])?;
    serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public admin response fields"))
}

fn load_preset(state_dir: &Path, request: &AddRequest) -> Result<Preset, CliError> {
    let generic = request.provider.starts_with("generic-");
    if generic && request.origin.is_none() {
        return Err(CliError::local(
            "USAGE",
            "generic presets need --origin https://api.example.com",
        ));
    }
    public(
        state_dir,
        admin_msg::TEMPLATE_CATALOG,
        json!({"preset": request.provider, "origin": request.origin,
               "header": request.header, "prefix": request.prefix}),
    )
}

/// Same defaults as the App's onboarding Connection. LLM Connections must
/// carry a non-empty signed model allow-list and daily budget.
fn build_connection(
    preset: Preset,
    name: &str,
    credential_id: CredentialId,
    models: &[String],
) -> Result<Connection, CliError> {
    let preset_name = preset.name.clone();
    let mut value = serde_json::to_value(preset)
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode preset"))?;
    let fields = value
        .as_object_mut()
        .ok_or_else(|| CliError::local("INVALID_FRAME", "preset is not an object"))?;
    let bindings = if preset_name == "github-git" {
        json!({"owner": [], "repo": []})
    } else {
        json!({})
    };
    let llm = is_llm_preset(&preset_name).then(|| {
        json!({"models": models, "max_tokens": 4096, "max_requests_per_day": 100,
               "max_output_tokens_per_day": 100_000})
    });
    for (key, field) in [
        ("preset", json!(preset_name)),
        ("name", json!(name)),
        ("credential_id", json!(credential_id)),
        ("enabled", json!(true)),
        ("grade", json!("T0")),
        ("bindings", bindings),
        ("caller_overrides", json!({})),
        ("llm", json!(llm)),
        ("oauth", Value::Null),
        (
            "limits",
            json!({"requests_per_hour": 600, "max_request_bytes": 1_048_576,
                   "max_response_bytes": 4_194_304}),
        ),
    ] {
        fields.insert(key.to_owned(), field);
    }
    serde_json::from_value(value)
        .map_err(|_| CliError::local("INVALID_FRAME", "preset does not form a valid Connection"))
}

/// LLM presets need exact model names; ask once interactively, never guess.
fn llm_models(request: &AddRequest) -> Result<Vec<String>, CliError> {
    if !is_llm_preset(&request.provider) {
        return Ok(Vec::new());
    }
    let mut models = request.models.clone();
    if models.is_empty() {
        if request.stdin_secrets {
            return Err(CliError::local(
                "USAGE",
                format!(
                    "{} needs --model NAME (repeatable), the exact model names Agents may use",
                    request.provider
                ),
            ));
        }
        eprint!(
            "Allowed {} models, comma separated (exact names, e.g. the model your Agent requests): ",
            request.provider
        );
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|err| CliError::local("USAGE", format!("cannot read models: {err}")))?;
        models = line
            .split(',')
            .map(|model| model.trim().to_owned())
            .collect();
    }
    models.retain(|model| !model.is_empty());
    models.sort();
    models.dedup();
    if models.is_empty()
        || models
            .iter()
            .any(|model| model.len() > 256 || model.chars().any(char::is_control))
    {
        return Err(CliError::local(
            "USAGE",
            "enter at least one valid model name",
        ));
    }
    Ok(models)
}

type Secrets = (Zeroizing<Vec<u8>>, Option<Zeroizing<Vec<u8>>>);

fn collect_add_inputs(request: &AddRequest) -> Result<Secrets, CliError> {
    let need_key = request.credential_id.is_none();
    if request.stdin_secrets {
        let mut lines = super::stdin_lines(if need_key { 2 } else { 1 })?;
        let secret = need_key.then(|| lines.remove(1));
        return Ok((lines.remove(0), secret));
    }
    let proof = super::prompt_secret("Vault password: ")?;
    let secret = if need_key {
        Some(super::prompt_secret(&format!(
            "{} API key (hidden): ",
            request.provider
        ))?)
    } else {
        None
    };
    Ok((proof, secret))
}

fn save_credential(
    state_dir: &Path,
    proof: &[u8],
    secret: &[u8],
    request: &AddRequest,
    name: &str,
) -> Result<CredentialId, CliError> {
    let label = request.label.clone().unwrap_or_else(|| name.to_owned());
    let metadata = json!({"label": label, "kind": "opaque-token"});
    let mut body = Zeroizing::new(Vec::with_capacity(9 + proof.len() + secret.len()));
    ipc::encode_proof_and_secret_body(ProofKind::Password, proof, secret, &mut body);
    let (meta, _) = admin(state_dir)?.call(
        admin_msg::CREDENTIAL_ADD,
        metadata.to_string().as_bytes(),
        &body,
    )?;
    let saved: CredentialMetadata = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid credential"))?;
    eprintln!(
        "Saved credential {label} ({}). If a later step fails, retry with --credential-id {} instead of entering the key again.",
        saved.id, saved.id
    );
    Ok(saved.id)
}

fn signed_bundle(sign_bytes: &[u8], signature: &str) -> Result<Vec<u8>, CliError> {
    const PREFIX: &[u8] = b"RKPOLICY\0\x01";
    let envelope = sign_bytes
        .strip_prefix(PREFIX)
        .ok_or_else(|| CliError::local("INVALID_FRAME", "broker returned invalid signing bytes"))?;
    let mut bundle: Value = serde_json::from_slice(envelope)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid signing bytes"))?;
    bundle
        .as_object_mut()
        .ok_or_else(|| CliError::local("INVALID_FRAME", "signing envelope is not an object"))?
        .insert("signature".to_owned(), json!(signature));
    serde_json::to_vec(&bundle)
        .map_err(|_| CliError::local("INVALID_FRAME", "cannot encode bundle"))
}

fn preset_operations(draft: &ipc::PersonalPolicyDraftResponse, name: &str) -> Vec<String> {
    draft
        .connections
        .iter()
        .filter(|connection| connection.name == name)
        .flat_map(|connection| connection.operations.iter().map(|op| op.name.clone()))
        .collect()
}

/// The signer ships beside the real `rekey` binary inside the App bundle;
/// resolve the /usr/local/bin symlink so it is found from the installed CLI.
fn signer_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize)
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("rekey-policy-sign");
        if sibling.exists() {
            return sibling;
        }
    }
    PathBuf::from("rekey-policy-sign")
}

fn run_signer(
    signer: &Path,
    args: &[&str],
    key_file: &Path,
    input: &[u8],
) -> Result<String, CliError> {
    let mut child = Command::new(signer)
        .arg("software-key")
        .args(args)
        .arg(key_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            CliError::local(
                "SIGNER_UNAVAILABLE",
                format!("cannot run {}: {err}", signer.display()),
            )
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|err| CliError::local("SIGNER_FAILED", format!("signer input: {err}")))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| CliError::local("SIGNER_FAILED", format!("signer: {err}")))?;
    if !output.status.success() {
        return Err(CliError::local(
            "SIGNER_FAILED",
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| CliError::local("SIGNER_FAILED", "signer output is not UTF-8"))
}

fn generate_key(signer: &Path, key_file: &Path) -> Result<(), CliError> {
    run_signer(signer, &["generate", "--key-file"], key_file, &[]).map(|_| ())
}

/// Returns the canonical trust document bytes and its installed digest.
fn software_trust(
    signer: &Path,
    key_file: &Path,
    signer_id: PolicySignerId,
) -> Result<(Vec<u8>, String), CliError> {
    let mut child = Command::new(signer);
    child
        .args(["software-key", "trust", "--key-file"])
        .arg(key_file)
        .args(["--signer-id", &signer_id.to_string()]);
    let output = child.output().map_err(|err| {
        CliError::local("SIGNER_UNAVAILABLE", format!("cannot run signer: {err}"))
    })?;
    if !output.status.success() {
        return Err(CliError::local(
            "SIGNER_FAILED",
            String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| CliError::local("SIGNER_FAILED", "invalid signer trust output"))?;
    let trust = serde_json::to_vec(&value["trust"])
        .map_err(|_| CliError::local("SIGNER_FAILED", "invalid signer trust output"))?;
    let digest = value["trust_sha256"]
        .as_str()
        .ok_or_else(|| CliError::local("SIGNER_FAILED", "invalid signer trust output"))?
        .to_owned();
    Ok((trust, digest))
}

fn new_signer_id() -> PolicySignerId {
    PolicySignerId::from_random_bytes(rand::random())
}

fn now_ms() -> Result<i64, CliError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::local("CLOCK", "system clock is before 1970"))?;
    i64::try_from(elapsed.as_millis()).map_err(|_| CliError::local("CLOCK", "clock overflow"))
}

#[cfg(test)]
mod app_handoff_tests {
    use super::*;

    #[test]
    fn public_options_are_encoded_and_secrets_or_overrides_rejected() {
        let state = super::super::resolve_state_dir(None).unwrap();
        let mut request = AddRequest {
            provider: "generic-header".into(),
            name: Some("team key&other".into()),
            label: Some("测试 $()".into()),
            credential_id: Some("00000000-0000-4000-8000-000000000001".into()),
            origin: Some("https://example.com".into()),
            header: Some("x-api-key".into()),
            prefix: Some("Bearer ".into()),
            valid_days: 30,
            models: vec!["m/a".into(), "m+b".into()],
            stdin_secrets: false,
        };
        assert_eq!(
            app_url(&state, &request, false).unwrap(),
            "rekey://add/generic-header?valid_days=30&name=team%20key%26other&label=%E6%B5%8B%E8%AF%95%20%24%28%29&credential_id=00000000-0000-4000-8000-000000000001&origin=https%3A%2F%2Fexample.com&header=x-api-key&prefix=Bearer%20&model=m%2Fa&model=m%2Bb"
        );
        assert!(app_url(&state, &request, true).is_err());
        assert!(app_url(&state.join("custom"), &request, false).is_err());
        request.stdin_secrets = true;
        assert!(app_url(&state, &request, false).is_err());
        request.stdin_secrets = false;
        request.valid_days = 0;
        assert!(app_url(&state, &request, false).is_err());
        request.valid_days = 30;
        request.credential_id = Some("not-a-uuid".into());
        assert!(app_url(&state, &request, false).is_err());
    }
}
