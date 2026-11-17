//! Reflected-secret sealing guarantees embedded-base64 detection only from 16
//! bytes (v3 §9.2), so every credential save path warns about shorter values.
//! Pipes and the App get a structured code; a terminal gets the sentence.
use std::io::Write;

const MINIMUM_SEALED_BYTES: usize = 16;
const HUMAN: &str = "warning: this credential is shorter than 16 bytes; reflected-secret sealing has limited coverage for embedded encodings. Use the provider's complete key.";

/// Called only after a completed save; a failed warning never fails it.
pub(super) fn warn_if_short(secret: &[u8]) {
    if let Some(line) = notice(secret.len(), crate::client::json_output()) {
        let _ = writeln!(std::io::stderr(), "{line}");
    }
}

fn notice(length: usize, json: bool) -> Option<String> {
    if length >= MINIMUM_SEALED_BYTES {
        return None;
    }
    Some(if json {
        serde_json::json!({ "warnings": ["SHORT_CREDENTIAL"] }).to_string()
    } else {
        HUMAN.to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::notice;

    #[test]
    fn only_values_below_sixteen_bytes_warn_in_each_output_mode() {
        assert_eq!(
            notice(15, true).as_deref(),
            Some(r#"{"warnings":["SHORT_CREDENTIAL"]}"#)
        );
        assert!(notice(1, false).unwrap().contains("shorter than 16 bytes"));
        assert_eq!(notice(16, true), None);
        assert_eq!(notice(64, false), None);
    }
}
