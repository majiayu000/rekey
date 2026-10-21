//! Basic-mode personal policy signer. The P-256 private key is a current-user
//! mode-0600 PKCS#8 file, so any process of that user can read it: this is a
//! software key, not Secure Enclave protection. Activation still requires the
//! vault password, and the daemon verifies every bundle against the trust root.
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use rekey_domain::ids::PolicySignerId;
use rekey_policy::{parse_policy_trust, policy_trust_sha256};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::{Result, read_key_bytes};

pub const USAGE: &str = "       rekey-policy-sign software-key generate --key-file KEY.p8\n       rekey-policy-sign software-key trust --key-file KEY.p8 --signer-id UUID\n       rekey-policy-sign software-key sign --key-file KEY.p8 < SIGN_BYTES";

const SIGN_PREFIX: &[u8] = b"RKPOLICY\0\x01";
const SIGN_BYTES_MAX: usize = 64 * 1024;

pub fn run(args: &[OsString]) -> Result<()> {
    let flag = |index: usize, name: &str| args.get(index).is_some_and(|arg| arg == name);
    match args.first().and_then(|arg| arg.to_str()) {
        Some("generate") if args.len() == 3 && flag(1, "--key-file") => {
            generate(Path::new(&args[2]))
        }
        Some("trust") if args.len() == 5 && flag(1, "--key-file") && flag(3, "--signer-id") => {
            let signer_id: PolicySignerId =
                args[4].to_str().ok_or("invalid signer UUID")?.parse()?;
            trust(Path::new(&args[2]), signer_id)
        }
        Some("sign") if args.len() == 3 && flag(1, "--key-file") => sign(Path::new(&args[2])),
        _ => Err(USAGE.into()),
    }
}

fn load(path: &Path) -> Result<EcdsaKeyPair> {
    let bytes = read_key_bytes(path)?;
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &bytes)
        .map_err(|_| "invalid P-256 PKCS#8 key".into())
}

fn generate(path: &Path) -> Result<()> {
    let document =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())
            .map_err(|_| "cannot generate P-256 key")?;
    let document = Zeroizing::new(document.as_ref().to_vec());
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &document)
        .map_err(|_| "generated key is invalid")?;
    // create_new: never replace a key that an installed trust root may depend on.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&document)?;
    file.sync_all()?;
    println!(
        "{}",
        json!({"public_key": HEXLOWER.encode(pair.public_key().as_ref())})
    );
    Ok(())
}

fn trust(path: &Path, signer_id: PolicySignerId) -> Result<()> {
    let pair = load(path)?;
    // The installed algorithm label is the existing personal P-256 label; it
    // describes the curve and signature encoding, not where the key lives.
    let document = json!({
        "format_version": 1, "signer_id": signer_id, "algorithm": "secure-enclave-p256",
        "public_key": HEXLOWER.encode(pair.public_key().as_ref()),
    });
    let canonical = serde_jcs::to_vec(&document)?;
    let validated = parse_policy_trust(&canonical)?;
    let digest = policy_trust_sha256(validated.signer_id(), validated.key())?;
    println!(
        "{}",
        json!({"trust": document, "trust_sha256": HEXLOWER.encode(&digest)})
    );
    Ok(())
}

fn sign(path: &Path) -> Result<()> {
    let mut message = Vec::new();
    std::io::stdin()
        .lock()
        .take(SIGN_BYTES_MAX as u64 + 1)
        .read_to_end(&mut message)?;
    // Only daemon-issued personal policy envelopes are signed, never arbitrary bytes.
    if message.len() > SIGN_BYTES_MAX
        || !message.starts_with(SIGN_PREFIX)
        || !serde_json::from_slice::<Value>(&message[SIGN_PREFIX.len()..])
            .is_ok_and(|value| value.is_object())
    {
        return Err("input is not a personal policy signing envelope".into());
    }
    let pair = load(path)?;
    let signature = pair
        .sign(&SystemRandom::new(), &message)
        .map_err(|_| "signing failed")?;
    println!("{}", BASE64URL_NOPAD.encode(signature.as_ref()));
    Ok(())
}
