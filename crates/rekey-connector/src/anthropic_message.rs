//! Public Anthropic message operation contract. No identities, credentials, or IO.
use serde::{Deserialize, Serialize};

/// Bounds the complete request or response envelope, including JSON escaping.
pub const MAX_MESSAGE_WIRE_BYTES: usize = 256 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Messages {
    messages: Vec<Message>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: Role,
    content: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    User,
    Assistant,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum MessageEnvelope {
    CreateMessage(Messages),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid Anthropic message public request")]
pub struct InvalidMessageBody;

impl Messages {
    fn validate(&self) -> Result<(), InvalidMessageBody> {
        if self.messages.is_empty()
            || self.messages.len() > 128
            || self
                .messages
                .iter()
                .any(|message| message.content.is_empty())
        {
            return Err(InvalidMessageBody);
        }
        Ok(())
    }

    fn canonical(&self) -> Result<Vec<u8>, InvalidMessageBody> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| InvalidMessageBody)
    }
}

impl MessageEnvelope {
    fn canonical_body(&self) -> Result<Vec<u8>, InvalidMessageBody> {
        match self {
            Self::CreateMessage(messages) => messages.canonical(),
        }
    }
}

fn parse_body(input: &[u8]) -> Result<MessageEnvelope, InvalidMessageBody> {
    if input.len() > MAX_MESSAGE_WIRE_BYTES {
        return Err(InvalidMessageBody);
    }
    let messages: Messages = serde_json::from_slice(input).map_err(|_| InvalidMessageBody)?;
    messages.validate()?;
    Ok(MessageEnvelope::CreateMessage(messages))
}

pub fn normalize_message_body(input: &[u8]) -> Result<Vec<u8>, InvalidMessageBody> {
    parse_body(input)?.canonical_body()
}

/// Returns the closed canonical envelope and its trusted messages object.
pub fn prepare(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), InvalidMessageBody> {
    let request = parse_body(input)?;
    let body = request.canonical_body()?;
    let envelope = serde_json::to_vec(&request).map_err(|_| InvalidMessageBody)?;
    if envelope.len() > MAX_MESSAGE_WIRE_BYTES {
        return Err(InvalidMessageBody);
    }
    Ok((envelope, body))
}

pub fn normalize_message_envelope(input: &[u8]) -> Result<Vec<u8>, InvalidMessageBody> {
    if input.len() > MAX_MESSAGE_WIRE_BYTES {
        return Err(InvalidMessageBody);
    }
    let request: MessageEnvelope = serde_json::from_slice(input).map_err(|_| InvalidMessageBody)?;
    request.canonical_body()?;
    let output = serde_json::to_vec(&request).map_err(|_| InvalidMessageBody)?;
    if output.len() > MAX_MESSAGE_WIRE_BYTES {
        return Err(InvalidMessageBody);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_body_contract_and_normalization() {
        assert_eq!(
            normalize_message_body(
                br#"{ "messages": [ { "content": "hello", "role": "user" } ] }"#
            )
            .unwrap(),
            br#"{"messages":[{"role":"user","content":"hello"}]}"#
        );
        for body in [
            br#"{"messages":[]}"#.as_slice(),
            br#"{}"#,
            br#"{"messages":[{"role":"user","content":""}]}"#,
            br#"{"messages":[{"role":"system","content":"hello"}]}"#,
            br#"{"messages":[{"role":"user","content":"hello","name":"x"}]}"#,
            br#"{"messages":[{"role":"user","content":"hello"}],"stream":true}"#,
            br#"{"messages":[{"role":"user","content":"hello"}],"messages":[{"role":"user","content":"hello"}]}"#,
            br#"{"messages":[{"role":"user","content":"hello","content":"hello"}]}"#,
            br#"{"messages":[{"role":"user","role":"user","content":"hello"}]}"#,
        ] {
            assert!(normalize_message_body(body).is_err(), "{body:?}");
        }
        let too_many = serde_json::json!({
            "messages": (0..129)
                .map(|_| serde_json::json!({"role":"user","content":"x"}))
                .collect::<Vec<_>>()
        });
        assert!(normalize_message_body(&serde_json::to_vec(&too_many).unwrap()).is_err());
        let max_ok = serde_json::json!({
            "messages": (0..128)
                .map(|_| serde_json::json!({"role":"user","content":"x"}))
                .collect::<Vec<_>>()
        });
        assert!(normalize_message_body(&serde_json::to_vec(&max_ok).unwrap()).is_ok());
    }

    #[test]
    fn create_message_envelope_is_canonical_and_closed() {
        let body = br#"{ "messages": [ { "content": "hello", "role": "user" } ] }"#;
        let expected = br#"{"operation":"create_message","body":{"messages":[{"role":"user","content":"hello"}]}}"#;
        let (envelope, canonical_body) = prepare(body).unwrap();
        assert_eq!(envelope, expected);
        assert_eq!(canonical_body, normalize_message_body(body).unwrap());
        assert_eq!(normalize_message_envelope(&envelope).unwrap(), expected);
        for input in [
            r#"{"operation":"unknown","body":{"messages":[{"role":"user","content":"hello"}]}}"#,
            r#"{"operation":"create_issue","body":{"title":"t"}}"#,
            r#"{"operation":"create_message","body":{"messages":[]}}"#,
            r#"{"operation":"create_message","body":{"messages":[{"role":"user","content":"hello"}],"route":"evil"}}"#,
            r#"{"operation":"create_message","body":{"messages":[{"role":"user","content":"hello"}]},"route":"evil"}"#,
            r#"{"operation":"create_message","operation":"create_message","body":{"messages":[{"role":"user","content":"hello"}]}}"#,
            r#"{"body":{"messages":[{"role":"user","content":"hello"}]},"operation":"create_message","operation":"create_message"}"#,
        ] {
            assert!(
                normalize_message_envelope(input.as_bytes()).is_err(),
                "{input}"
            );
        }
        assert!(normalize_message_envelope(&vec![b' '; MAX_MESSAGE_WIRE_BYTES + 1]).is_err());
    }
}
