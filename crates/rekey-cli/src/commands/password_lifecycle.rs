use std::io::Write;
use std::path::Path;

use rekey_domain::ipc::{self, admin_msg};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{
    LIFECYCLE_RESPONSE_TIMEOUT, admin_with_response_timeout, print_json, prompt_secret, proof_body,
    proof_kind, stdin_lines, step_up_prompt,
};
use crate::client::CliError;

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct PasswordChangedResponse {
    changed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRotatedResponse {
    rotated: bool,
}

pub fn password_change(
    state_dir: &Path,
    recovery: bool,
    stdin_secrets: bool,
) -> Result<(), CliError> {
    let (proof, new_password) = if stdin_secrets {
        let mut lines = stdin_lines(2)?;
        let new_password = lines.remove(1);
        let proof = lines.remove(0);
        (proof, new_password)
    } else {
        let proof = prompt_secret(step_up_prompt(recovery))?;
        let first = prompt_secret("New vault password: ")?;
        let second = prompt_secret("Confirm new password: ")?;
        if first.as_slice() != second.as_slice() {
            return Err(CliError::local("USAGE", "passwords do not match"));
        }
        (proof, first)
    };
    let body_len = 1 + 4 + proof.len() + 4 + new_password.len();
    let mut body = Zeroizing::new(Vec::with_capacity(body_len));
    ipc::encode_proof_and_secret_body(proof_kind(recovery), &proof, &new_password, &mut body);
    // The Broker bounds queue admission at 25 seconds, then deliberately
    // waits for an admitted transaction's definitive result. Keep the client
    // alive for that post-admission completion instead of reverting to the
    // ordinary 30-second Admin response timeout.
    let (metadata, response_body) = admin_with_response_timeout(
        state_dir,
        LIFECYCLE_RESPONSE_TIMEOUT,
    )?
    .call(admin_msg::PASSWORD_CHANGE, b"{}", &body)?;
    if !response_body.is_empty() {
        return Err(CliError::local(
            "INVALID_FRAME",
            "password change returned an unexpected response body",
        ));
    }
    print_json::<PasswordChangedResponse>(&metadata)
}

pub fn recovery_rotate(state_dir: &Path, password_stdin: bool) -> Result<(), CliError> {
    let password = super::read_password(password_stdin, "Vault password (step-up): ")?;
    let body = proof_body(false, &password);
    let (metadata, recovery) = admin_with_response_timeout(state_dir, LIFECYCLE_RESPONSE_TIMEOUT)?
        .call(admin_msg::RECOVERY_ROTATE, b"{}", &body)?;
    let receipt: RecoveryRotatedResponse = serde_json::from_slice(&metadata)
        .map_err(|_| CliError::local("INVALID_FRAME", "broker returned invalid response"))?;
    if !receipt.rotated
        || recovery.is_empty()
        || recovery.len() > 128
        || !recovery.starts_with(b"RKREC1-")
        || !recovery
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(CliError::local(
            "INVALID_FRAME",
            "broker returned invalid recovery material",
        ));
    }

    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(b"RECOVERY KEY (shown exactly once, store it offline):\n")
        .and_then(|_| stdout.write_all(&recovery))
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|error| CliError::local("OUTPUT_FAILED", format!("cannot write output: {error}")))
}
