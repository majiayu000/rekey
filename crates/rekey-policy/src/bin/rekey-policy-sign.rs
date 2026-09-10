//! Offline operator executable. No Broker connection or agent-facing key access.
use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::{Timestamp, ids::PolicySignerId};
use rekey_policy::{
    SNAPSHOT_MAX_BYTES, parse_and_validate_snapshot, parse_and_verify_policy_bundle,
    parse_policy_trust,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const USAGE: &str = "usage: rekey-policy-sign review DRAFT.json\n       rekey-policy-sign sign DRAFT.json --reviewed-sha256 DIGEST --signer-id UUID --key-file KEY.der --output NEW_DIRECTORY";
type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn now() -> Result<Timestamp> {
    Ok(Timestamp::from_unix_ms(i64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?))
}

fn read_bounded(file: File, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input exceeds size limit".into());
    }
    Ok(bytes)
}

fn draft(path: &Path) -> Result<(Value, String)> {
    let bytes = read_bounded(File::open(path)?, SNAPSHOT_MAX_BYTES)?;
    let validated = parse_and_validate_snapshot(&bytes, now()?)?;
    // Validation uses duplicate-key rejection and computes this RFC 8785 digest.
    let value = serde_json::from_slice(&bytes)?;
    Ok((value, HEXLOWER.encode(&validated.digest())))
}

fn key(path: &Path) -> Result<Ed25519KeyPair> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(
            "key must be a current-user-owned regular file with no group/other permissions".into(),
        );
    }
    // Allocate once inside Zeroizing so failed or oversized reads also erase bytes.
    let mut bytes = Zeroizing::new(Vec::with_capacity(4097));
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err("key file exceeds size limit".into());
    }
    Ed25519KeyPair::from_pkcs8(bytes.as_slice()).map_err(|_| "invalid Ed25519 DER PKCS8 key".into())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--help" {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() == 2 && args[0] == "review" {
        let (snapshot, digest) = draft(Path::new(&args[1]))?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"snapshot": snapshot, "reviewed_sha256": digest})
            )?
        );
        return Ok(());
    }
    if args.len() != 10
        || args[0] != "sign"
        || args[2] != "--reviewed-sha256"
        || args[4] != "--signer-id"
        || args[6] != "--key-file"
        || args[8] != "--output"
    {
        return Err(USAGE.into());
    }
    let (snapshot, digest) = draft(Path::new(&args[1]))?;
    if args[3].to_str() != Some(&digest) {
        return Err("reviewed digest does not match validated draft; review again".into());
    }
    let signer_id: PolicySignerId = args[5].to_str().ok_or("invalid signer UUID")?.parse()?;
    let signer = key(Path::new(&args[7]))?;
    let trust = serde_jcs::to_vec(&json!({
        "format_version": 1, "signer_id": signer_id, "algorithm": "ed25519",
        "public_key": HEXLOWER.encode(signer.public_key().as_ref()),
    }))?;
    let mut bundle = json!({"format_version": 1, "signer_id": signer_id, "snapshot": snapshot});
    let mut message = b"RKPOLICY\0\x01".to_vec();
    message.extend_from_slice(&serde_jcs::to_vec(&bundle)?);
    bundle["signature"] = BASE64URL_NOPAD
        .encode(signer.sign(&message).as_ref())
        .into();
    let bundle = serde_jcs::to_vec(&bundle)?;
    parse_and_verify_policy_bundle(&bundle, &parse_policy_trust(&trust)?, now()?)?;
    let output = Path::new(&args[9]);
    fs::DirBuilder::new().mode(0o700).create(output)?;
    write_new(&output.join("trust.json"), &trust)?;
    write_new(&output.join("policy.json"), &bundle)?;
    File::open(output)?.sync_all()?;
    println!(
        "Signed reviewed policy {digest}; trust.json and policy.json created. Activation is a separate operator action."
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rekey-policy-sign: {error}");
        std::process::exit(1);
    }
}
