//! Operator-only local approval signer. See the local approval endpoint spec.
use aws_lc_rs::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::{
    Timestamp,
    action::FixedHttpAction,
    authorization::{ApprovalMode, ApproverSpec, AuthorizationRequest, Decision, Principal},
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

#[path = "approval_sign/pkcs11.rs"]
#[cfg(feature = "lab")]
mod pkcs11;
#[path = "approval_sign/vault_transit.rs"]
#[cfg(feature = "lab")]
mod vault_transit;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[cfg(feature = "lab")]
const USAGE: &str = "rekey-approval-sign review REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX\nrekey-approval-sign sign REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX --reviewed-sha256 HEX (--key-file KEY.der | --vault-transit-profile PRIVATE.json | --pkcs11-profile PRIVATE.json) --output NEW_GRANT.json\nHardware review requires --pkcs11-profile PRIVATE.json; Transit review requires --vault-transit-profile PRIVATE.json";
#[cfg(not(feature = "lab"))]
const USAGE: &str = "rekey-approval-sign review REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX\nrekey-approval-sign sign REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX --reviewed-sha256 HEX --key-file KEY.der --output NEW_GRANT.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    challenge: SignedApprovalChallenge,
    content_type: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
    #[serde(default)]
    params: rekey_domain::template::TemplateValues,
    #[serde(default)]
    query: rekey_domain::template::TemplateValues,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SshRequest {
    challenge: SignedApprovalChallenge,
    ssh: serde_json::Value,
}

fn verify_ssh_review(
    snapshot: &rekey_policy::ValidatedSnapshot,
    c: &rekey_domain::ipc::ApprovalChallenge,
    key: &rekey_domain::connection::SshKeyConnection,
    ssh: &serde_json::Value,
) -> Result<()> {
    use rekey_domain::connection::RuleEffect;
    if snapshot.ssh_key(&key.name) != Some(key)
        || ssh["key"] != key.name
        || ssh["public_key"] != key.user_public_key
        || c.resource.resource_type != "connection"
        || c.resource.id != key.name
        || c.schema_id.as_str() != "rekey.ssh-sign.v1"
        || c.approver != key.approver
        || c.policy_version != snapshot.version().get()
        || c.policy_sha256 != HEXLOWER.encode(&snapshot.digest())
        || HEXLOWER.encode(&Sha256::digest(serde_jcs::to_vec(ssh)?)) != c.parameter_sha256
    {
        return Err("SSH review does not match signed policy and challenge".into());
    }
    let (effect, rule, host) = match ssh["use"]["purpose"].as_str() {
        Some("git") => (key.git_signing, None, "git"),
        Some("authentication") => match ssh["bound_host_key"].as_str().and_then(|blob| {
            key.hosts
                .iter()
                .filter(|h| h.host_key == blob)
                .max_by_key(|h| h.effect)
        }) {
            Some(h) => (h.effect, Some(h.rule_id), h.host.as_str()),
            None => (RuleEffect::Approve, None, "unknown-host"),
        },
        _ => (RuleEffect::Approve, None, "unknown-purpose"),
    };
    let expected_rule = rule.unwrap_or_else(|| {
        let digest = Sha256::digest(format!("{}:ssh-default:{host}", key.name).as_bytes());
        rekey_domain::ids::PolicyRuleId::from_random_bytes(
            digest[..16].try_into().expect("fixed digest"),
        )
    });
    let action_digest = Sha256::digest(format!("ssh:{}", key.name).as_bytes());
    if effect != RuleEffect::Approve
        || ssh["host"] != host
        || c.policy_rule_id != expected_rule
        || c.action_id
            != rekey_domain::ids::ActionId::from_random_bytes(
                action_digest[..16].try_into().expect("fixed digest"),
            )
        || c.action_version != 1
    {
        return Err("SSH signed rule does not require this approval".into());
    }
    Ok(())
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
fn run_args(args: Vec<String>, output_text: &mut dyn Write) -> Result<()> {
    if args == ["--help"] {
        writeln!(output_text, "{USAGE}")?;
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
                | "--vault-transit-profile"
                | "--pkcs11-profile"
                | "--output"
        ) || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err(USAGE.into());
        }
    }
    let transit = options.contains_key("--vault-transit-profile");
    let hardware = options.contains_key("--pkcs11-profile");
    #[cfg(not(feature = "lab"))]
    if transit || hardware {
        return Err(USAGE.into());
    }
    let signing_sources = ["--key-file", "--vault-transit-profile", "--pkcs11-profile"]
        .iter()
        .filter(|name| options.contains_key(**name))
        .count();
    if signing_sources > 1
        || options.len()
            != if sign {
                8
            } else if transit || hardware {
                6
            } else {
                5
            }
        || !sign
            && ["--key-file", "--output", "--reviewed-sha256"]
                .iter()
                .any(|name| options.contains_key(name))
        || sign && signing_sources != 1
    {
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
    let origin = validate_ed25519_public_key(get("--origin-key")?)?;
    let approver: ApproverId = get("--approver-id")?.parse()?;
    let request_bytes = read(&args[1], 2 * 1024 * 1024)?;
    let protocol: serde_json::Value = serde_json::from_slice(&request_bytes)?;
    let (c, action, target, request, request_target) = if protocol.get("ssh").is_some() {
        let request: SshRequest = serde_json::from_slice(&request_bytes)?;
        let key: rekey_domain::connection::SshKeyConnection =
            serde_json::from_slice(&read(get("--action")?, 65536)?)?;
        let c = parse_and_verify_approval_challenge_envelope(
            &serde_json::to_vec(&request.challenge)?,
            &origin,
        )?;
        verify_ssh_review(snapshot, &c, &key, &request.ssh)?;
        let ApproverSpec::Ed25519 { keys, threshold } = &c.approver else {
            return Err("SSH challenge requires external Ed25519 authority".into());
        };
        if !(1..=2).contains(threshold)
            || !snapshot
                .ed25519_approver_ids(keys)
                .is_some_and(|ids| ids.contains(&approver))
            || c.mode != ApprovalMode::OneTime
            || c.max_uses != 1
            || c.created_at_ms > time.as_unix_ms()
            || c.max_expires_at_ms <= time.as_unix_ms()
        {
            return Err("SSH approval context mismatch or expired".into());
        }
        let target = request.ssh.clone();
        (
            c,
            serde_json::to_value(key)?,
            target,
            serde_json::to_value(request)?,
            None,
        )
    } else {
        let action: FixedHttpAction = serde_json::from_slice(&read(get("--action")?, 65536)?)?;
        action.validate()?;
        let request: Request = serde_json::from_slice(&request_bytes)?;
        let c = parse_and_verify_approval_challenge_envelope(
            &serde_json::to_vec(&request.challenge)?,
            &origin,
        )?;
        let ApproverSpec::Ed25519 { keys, threshold: 1 } = &c.approver else {
            return Err("signer requires a single Ed25519 approver".into());
        };
        let approvers = snapshot
            .ed25519_approver_ids(keys)
            .ok_or("challenge approver is not registered in policy")?;
        if !action.enabled
            || action.id != c.action_id
            || action.version != c.action_version
            || c.mode != ApprovalMode::OneTime
            || c.max_uses != 1
            || !approvers.contains(&approver)
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
        let (resource, parameters, target) = snapshot.canonicalize(
            &action,
            rekey_policy::ActionRequest {
                params: &request.params,
                query: &request.query,
                content_type: request.content_type.as_deref(),
                headers: &request.headers,
                body: request.body.as_bytes(),
            },
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
            approver: policy_approver,
            requirement,
        } = evaluate(snapshot, &authorization, time, false)
        else {
            return Err("policy does not require approval for this request".into());
        };
        if policy_version.get() != c.policy_version
            || HEXLOWER.encode(&snapshot_digest) != c.policy_sha256
            || determining_rule != c.policy_rule_id
            || requirement.mode != c.mode
            || requirement.max_uses != c.max_uses
            || policy_approver != c.approver
        {
            return Err("policy and challenge mismatch".into());
        }
        let request_target = target.request_target();
        (
            c,
            serde_json::to_value(action)?,
            serde_json::to_value(target)?,
            serde_json::to_value(request)?,
            Some(request_target),
        )
    };
    #[cfg(feature = "lab")]
    let profile = if transit {
        Some(vault_transit::Profile::load(get(
            "--vault-transit-profile",
        )?)?)
    } else {
        None
    };
    #[cfg(feature = "lab")]
    if let Some(profile) = &profile {
        profile.check(
            snapshot
                .approver_key(approver)
                .ok_or("unknown policy approver")?
                .as_slice(),
            now()?.as_unix_ms(),
        )?;
    }
    #[cfg(feature = "lab")]
    let hardware_profile = if hardware {
        let profile = pkcs11::Profile::load(get("--pkcs11-profile")?)?;
        profile.check(
            snapshot
                .approver_key(approver)
                .ok_or("unknown policy approver")?
                .as_slice(),
        )?;
        Some(profile)
    } else {
        None
    };
    #[allow(unused_mut)]
    let mut review = json!({"record_type":"rekey.approval.review.v1", "source_assumption":"Operator pinned origin public key from rekey approval origin; envelope authenticates Broker challenge bytes. Native SSH host proof is verified by the Broker; offline review verifies the signed policy and bound transcript digest.", "action":action, "target":target, "request_target":request_target, "request":request, "approver_id":approver, "policy_signer_id":policy.signer_id(), "policy_sha256":HEXLOWER.encode(&snapshot.digest()), "grant_lifetime_max_ms":60000});
    #[cfg(feature = "lab")]
    if let Some(profile) = &profile {
        review["vault_transit"] = profile.public_review();
    }
    #[cfg(feature = "lab")]
    if let Some(profile) = &hardware_profile {
        review["pkcs11"] = profile.public_review();
    }
    let digest = HEXLOWER.encode(&Sha256::digest(serde_jcs::to_vec(&review)?));
    if !sign {
        writeln!(
            output_text,
            "{}",
            terminal_json(&json!({"review":review,"reviewed_sha256":digest}))?
        )?;
        return Ok(());
    }
    if get("--reviewed-sha256")? != digest {
        return Err("reviewed digest mismatch; review again".into());
    }
    let approver_key = snapshot
        .approver_key(approver)
        .ok_or("unknown policy approver")?;
    let signer = if !transit && !hardware {
        let signer = key(get("--key-file")?)?;
        if approver_key.as_slice() != signer.public_key().as_ref() {
            return Err("key does not match policy approver".into());
        }
        Some(signer)
    } else {
        None
    };
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
    #[cfg(feature = "lab")]
    let signature = if let Some(profile) = &hardware_profile {
        profile.sign(&message, approver_key.as_slice(), expires)?
    } else if let Some(profile) = &profile {
        profile.check(approver_key.as_slice(), now()?.as_unix_ms())?;
        profile.sign(&message, approver_key.as_slice(), expires)?
    } else {
        signer
            .as_ref()
            .ok_or("missing explicit signing key")?
            .sign(&message)
            .as_ref()
            .to_vec()
    };
    #[cfg(not(feature = "lab"))]
    let signature = signer
        .as_ref()
        .ok_or("missing explicit signing key")?
        .sign(&message)
        .as_ref()
        .to_vec();
    let finished = now()?.as_unix_ms();
    if finished < issued
        || finished >= expires
        || finished >= snapshot.expires_at_ms()
        || finished >= c.max_expires_at_ms
    {
        return Err("approval expired while signing".into());
    }
    #[cfg(feature = "lab")]
    if let Some(profile) = &profile {
        profile.check(approver_key.as_slice(), finished)?;
    }
    grant["signature"] = BASE64URL_NOPAD.encode(&signature).into();
    let bytes = serde_jcs::to_vec(&grant)?;
    parse_and_verify_approval_grant(&bytes, snapshot)?;
    let requested = Path::new(get("--output")?);
    let parent = requested
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .canonicalize()?;
    let output = parent.join(requested.file_name().ok_or("output has no file name")?);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&output)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err("unsafe output permissions".into());
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    let named = std::fs::symlink_metadata(&output)?;
    if (named.dev(), named.ino()) != (meta.dev(), meta.ino()) {
        return Err("output path replaced".into());
    }
    File::open(&parent)?.sync_all()?;
    writeln!(
        output_text,
        "Signed reviewed approval {digest}; submit the grant through Broker execute, or use approval submit for SSH."
    )?;
    Ok(())
}
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "lab")]
    if pkcs11::internal_child(&args) {
        return;
    }
    if let Err(error) = run_args(args, &mut std::io::stdout().lock()) {
        eprintln!("rekey-approval-sign: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[path = "approval_sign/vault_transit_tests.rs"]
#[cfg(feature = "lab")]
mod vault_transit_tests;
