//! Operator-only local approval signer. See the local approval endpoint spec.
use aws_lc_rs::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::{
    Timestamp,
    action::FixedHttpAction,
    authorization::{ApprovalMode, AuthorizationRequest, Decision, Principal},
    capability::ActionVersionRef,
    ids::{ApprovalId, ApproverId},
    ipc::SignedApprovalChallenge,
};
use rekey_policy::{
    evaluate, parse_and_verify_approval_challenge_envelope, parse_and_verify_approval_grant,
    parse_and_verify_policy_bundle, parse_policy_trust, validate_ed25519_public_key,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const USAGE: &str = "rekey-approval-sign review REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX\nrekey-approval-sign sign REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX --reviewed-sha256 HEX --key-file KEY.der --output NEW_GRANT.json";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    challenge: SignedApprovalChallenge,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}
fn now() -> Result<Timestamp> {
    Ok(Timestamp::from_unix_ms(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?))
}
fn read(path: &str, limit: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err("input must be a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds size limit".into());
    }
    Ok(bytes)
}
fn key(path: &str) -> Result<Ed25519KeyPair> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(
            "key must be a current-user-owned regular file with no group/other permissions".into(),
        );
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("key file exceeds size limit".into());
    }
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| "invalid Ed25519 DER PKCS8 key".into())
}
// JSON escapes ASCII controls; also escape Unicode controls/direction markers for terminal review.
fn terminal_json(value: &serde_json::Value) -> Result<String> {
    let text = serde_json::to_string_pretty(value)?;
    let mut safe = String::new();
    for ch in text.chars() {
        if (ch.is_control() && ch != '\n')
            || matches!(ch, '\u{061c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{2028}'..='\u{2029}')
        {
            use std::fmt::Write;
            write!(safe, "\\u{:04x}", ch as u32)?;
        } else {
            safe.push(ch);
        }
    }
    Ok(safe)
}
fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() < 2
        || !matches!(args[0].as_str(), "review" | "sign")
        || !args.len().is_multiple_of(2)
    {
        return Err(USAGE.into());
    }
    let sign = args[0] == "sign";
    let mut options = BTreeMap::new();
    for pair in args[2..].chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--policy"
                | "--trust"
                | "--action"
                | "--approver-id"
                | "--origin-key"
                | "--reviewed-sha256"
                | "--key-file"
                | "--output"
        ) || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(USAGE.into());
        }
    }
    if options.len() != if sign { 8 } else { 5 } {
        return Err(USAGE.into());
    }
    let get = |name| options.get(name).copied().ok_or(USAGE);
    let trust = parse_policy_trust(&read(get("--trust")?, rekey_policy::TRUST_MAX_BYTES)?)?;
    let time = now()?;
    let policy = parse_and_verify_policy_bundle(
        &read(get("--policy")?, rekey_policy::SNAPSHOT_MAX_BYTES)?,
        &trust,
        time,
    )?;
    let snapshot = policy.snapshot();
    let action: FixedHttpAction = serde_json::from_slice(&read(get("--action")?, 65536)?)?;
    action.validate()?;
    let origin = validate_ed25519_public_key(get("--origin-key")?)?;
    let request: Request = serde_json::from_slice(&read(&args[1], 2 * 1024 * 1024)?)?;
    let c = parse_and_verify_approval_challenge_envelope(
        &serde_json::to_vec(&request.challenge)?,
        &origin,
    )?;
    let approver: ApproverId = get("--approver-id")?.parse()?;
    if !action.enabled
        || action.id != c.action_id
        || action.version != c.action_version
        || c.mode != ApprovalMode::OneTime
        || c.quorum != 1
        || c.max_uses != 1
        || !c.approver_ids.contains(&approver)
    {
        return Err("action or single-use approval context mismatch".into());
    }
    if c.created_at_ms > time.as_unix_ms() || c.max_expires_at_ms <= time.as_unix_ms() {
        return Err("challenge is not currently valid".into());
    }
    let action_ref = ActionVersionRef {
        action_id: action.id,
        version: action.version,
    };
    let (resource, parameters) = snapshot.canonicalize(
        action_ref,
        request.content_type.as_deref(),
        &request.headers,
        request.body.as_bytes(),
    )?;
    if resource != c.resource
        || parameters.schema_id != c.schema_id
        || HEXLOWER.encode(&parameters.canonical_hash) != c.parameter_sha256
    {
        return Err("request does not match challenge".into());
    }
    let authorization = AuthorizationRequest {
        principal: Principal {
            tenant_id: c.tenant_id,
            principal_id: c.principal_id,
            session_id: c.session_id,
        },
        action: action_ref,
        resource,
        parameters,
    };
    let Decision::RequireApproval {
        policy_version,
        snapshot_digest,
        determining_rule,
        requirement,
    } = evaluate(snapshot, &authorization, time, false)
    else {
        return Err("policy does not require approval for this request".into());
    };
    let mut approvers = requirement.approver_ids.clone();
    approvers.sort();
    if policy_version.get() != c.policy_version
        || HEXLOWER.encode(&snapshot_digest) != c.policy_sha256
        || determining_rule != c.policy_rule_id
        || requirement.mode != c.mode
        || requirement.quorum != c.quorum
        || requirement.max_uses != c.max_uses
        || approvers != c.approver_ids
    {
        return Err("policy and challenge mismatch".into());
    }
    let review = json!({"record_type":"rekey.approval.review.v1", "source_assumption":"Operator pinned origin public key from rekey approval origin; envelope authenticates Broker challenge bytes, not Action/policy/trust files or the human's intent", "action":action, "request":request, "approver_id":approver, "policy_signer_id":policy.signer_id(), "policy_sha256":HEXLOWER.encode(&snapshot.digest()), "grant_lifetime_max_ms":60000});
    let digest = HEXLOWER.encode(&Sha256::digest(serde_jcs::to_vec(&review)?));
    if !sign {
        println!(
            "{}",
            terminal_json(&json!({"review":review,"reviewed_sha256":digest}))?
        );
        return Ok(());
    }
    if get("--reviewed-sha256")? != digest {
        return Err("reviewed digest mismatch; review again".into());
    }
    let signer = key(get("--key-file")?)?;
    if snapshot.approver_key(approver).map(|k| k.as_slice()) != Some(signer.public_key().as_ref()) {
        return Err("key does not match policy approver".into());
    }
    let issued = now()?.as_unix_ms();
    let expires = issued
        .checked_add(60000)
        .ok_or("clock overflow")?
        .min(c.max_expires_at_ms)
        .min(snapshot.expires_at_ms());
    if issued < c.created_at_ms || expires <= issued {
        return Err("approval expired before signing".into());
    }
    let mut random = [0u8; 16];
    SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| "random generation failed")?;
    let mut grant = json!({"format_version":1,"approval_id":ApprovalId::from_random_bytes(random),"approval_request_id":c.approval_request_id,"approver_id":approver,"tenant_id":c.tenant_id,"principal_id":c.principal_id,"session_id":c.session_id,"action_id":c.action_id,"action_version":c.action_version,"resource":c.resource,"schema_id":c.schema_id,"parameter_sha256":c.parameter_sha256,"policy_version":c.policy_version,"policy_sha256":c.policy_sha256,"policy_rule_id":c.policy_rule_id,"mode":c.mode,"not_before_ms":issued,"expires_at_ms":expires,"max_uses":1});
    let mut message = b"RKAPPROVAL\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&grant)?);
    grant["signature"] = BASE64URL_NOPAD
        .encode(signer.sign(&message).as_ref())
        .into();
    let bytes = serde_jcs::to_vec(&grant)?;
    parse_and_verify_approval_grant(&bytes, snapshot)?;
    let output = Path::new(get("--output")?);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(
        output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    println!(
        "Signed reviewed approval {digest}; submit the grant through the existing Broker execute command."
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("rekey-approval-sign: {error}");
        std::process::exit(1);
    }
}
