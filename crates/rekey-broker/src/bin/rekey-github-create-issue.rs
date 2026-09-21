//! Fixed reference sidecar: only public JSON enters and normalized JSON leaves.
use rekey_connector::github_issue::MAX_ISSUE_WIRE_BYTES;
use rekey_connector::normalize_native_envelope;
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    io::stdin()
        .take((MAX_ISSUE_WIRE_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let output = normalize_native_envelope(&input)?;
    io::stdout().write_all(&output)?;
    Ok(())
}
