//! One fixed Anthropic text projection. Raw provider frames never leave Broker.
use std::time::Instant;

use rekey_domain::action::FixedHttpAction;
use rekey_domain::ipc::{TEXT_STREAM_CHUNK_MAX_BYTES, TextStreamStatus};
use serde::Deserialize;
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use super::{ExecuteRequest, contains_secret, headers_contain_secret};
use crate::error::BrokerError;
use crate::upstream::{UpstreamRequest, UpstreamStreamResponse};

pub(crate) enum TextStreamEvent {
    Admitted { deadline: Instant },
    Chunk(Vec<u8>),
    Terminal(TextStreamStatus),
}
pub(crate) type TextStreamSender = mpsc::Sender<TextStreamEvent>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Messages {
    messages: Vec<Message>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Message {
    role: Role,
    content: String,
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
enum Role {
    User,
    Assistant,
}

pub(super) fn validate(request: &ExecuteRequest) -> Result<(), &'static str> {
    if request.content_type.as_deref() != Some("application/json")
        || !request.extra_headers.is_empty()
    {
        return Err("invalid-stream-parameters");
    }
    let messages: Messages =
        serde_json::from_slice(&request.body).map_err(|_| "invalid-stream-parameters")?;
    if messages.messages.is_empty()
        || messages.messages.len() > 128
        || messages.messages.iter().any(|m| m.content.is_empty())
    {
        return Err("invalid-stream-parameters");
    }
    Ok(())
}

pub(super) fn configure(
    action: &FixedHttpAction,
    request: &ExecuteRequest,
    upstream: &mut UpstreamRequest,
) -> Result<(), BrokerError> {
    let config = action
        .text_stream
        .as_ref()
        .ok_or(BrokerError::Denied("stream-action-required"))?;
    let messages: Messages = serde_json::from_slice(&request.body)
        .map_err(|_| BrokerError::Denied("invalid-stream-parameters"))?;
    let messages: Vec<_> = messages
        .messages
        .into_iter()
        .map(|m| serde_json::json!({"role":m.role,"content":m.content}))
        .collect();
    upstream.body = Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({
            "model":config.model,"max_tokens":config.max_tokens,"stream":true,"messages":messages
        }))
        .map_err(|_| BrokerError::Denied("invalid-stream-parameters"))?,
    );
    if upstream.body.len() > action.request_policy.max_body_bytes as usize {
        return Err(BrokerError::Denied("request-too-large"));
    }
    upstream.headers = vec![
        ("content-type".into(), "application/json".into()),
        ("anthropic-version".into(), "2023-06-01".into()),
    ];
    Ok(())
}

/// All buffers have the Action response bound. Keep the full bounded history so
/// scan starts can retain encoding context, and never copy an unchecked prefix.
struct Sealer {
    bytes: Zeroizing<Vec<u8>>,
    emitted: usize,
    hold: usize,
    limit: usize,
}
impl Sealer {
    fn new(needles: &[Zeroizing<Vec<u8>>], limit: usize) -> Result<Self, BrokerError> {
        let hold = needles
            .iter()
            .map(|n| n.len())
            .max()
            .unwrap_or(0)
            .checked_mul(3)
            .and_then(|n| n.checked_add(2))
            .ok_or(BrokerError::ResponseSecurityViolation)?;
        Ok(Self {
            bytes: Zeroizing::new(Vec::with_capacity(limit)),
            emitted: 0,
            hold,
            limit,
        })
    }
    fn push(&mut self, bytes: &[u8], needles: &[Zeroizing<Vec<u8>>]) -> Result<(), BrokerError> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(BrokerError::Upstream("response-too-large"));
        }
        // Potential newly completed matches start at most 3*M bytes back.
        // Two more bytes retain percent-normalization context at the cut.
        let start = self.bytes.len().saturating_sub(self.hold);
        self.bytes.extend_from_slice(bytes);
        if contains_secret(&self.bytes[start..], needles) {
            return Err(BrokerError::ResponseSecurityViolation);
        }
        Ok(())
    }
    async fn release(
        &mut self,
        final_text: bool,
        sender: &TextStreamSender,
    ) -> Result<(), BrokerError> {
        let text = std::str::from_utf8(&self.bytes)
            .map_err(|_| BrokerError::Upstream("invalid-stream"))?;
        let mut end = if final_text {
            text.len()
        } else {
            text.len().saturating_sub(self.hold)
        };
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        while self.emitted < end {
            let mut chunk_end = end.min(self.emitted + TEXT_STREAM_CHUNK_MAX_BYTES);
            while !text.is_char_boundary(chunk_end) {
                chunk_end -= 1;
            }
            if sender
                .send(TextStreamEvent::Chunk(
                    self.bytes[self.emitted..chunk_end].to_vec(),
                ))
                .await
                .is_err()
            {
                // Disconnected clients own no cleanup. Continue the runtime-owned
                // request to its checked terminal audit without retaining output.
                self.emitted = end;
                return Ok(());
            }
            self.emitted = chunk_end;
        }
        Ok(())
    }
}

struct ParsedJson(serde_json::Value);
fn wipe_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_json),
        serde_json::Value::Object(m) => {
            for (mut key, mut value) in std::mem::take(m) {
                key.zeroize();
                wipe_json(&mut value);
            }
        }
        _ => {}
    }
}
impl Drop for ParsedJson {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

#[derive(Default)]
struct Projection {
    state: u8,
    reason: Option<TextStreamStatus>,
}
impl Projection {
    fn event(&mut self, bytes: &[u8]) -> Result<Option<Zeroizing<String>>, BrokerError> {
        let bad = || BrokerError::Upstream("invalid-stream");
        let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
        let mut event = None;
        let mut data = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("event: ") {
                if event.replace(value).is_some() {
                    return Err(bad());
                }
            } else if let Some(value) = line.strip_prefix("data: ") {
                if data.replace(value).is_some() {
                    return Err(bad());
                }
            } else if !line.is_empty() {
                return Err(bad());
            }
        }
        let json = ParsedJson(serde_json::from_str(data.ok_or_else(bad)?).map_err(|_| bad())?);
        let value = &json.0;
        let kind = value["type"].as_str().ok_or_else(bad)?;
        if event != Some(kind) {
            return Err(bad());
        }
        match (kind, self.state) {
            ("ping", 0..=4) => {}
            ("message_start", 0)
                if value["message"]["role"] == "assistant"
                    && value["message"]["content"]
                        .as_array()
                        .is_some_and(|a| a.is_empty())
                    && value["message"]["stop_reason"].is_null() =>
            {
                self.state = 1
            }
            ("content_block_start", 1)
                if value["index"] == 0
                    && value["content_block"]["type"] == "text"
                    && value["content_block"]["text"] == "" =>
            {
                self.state = 2
            }
            ("content_block_delta", 2)
                if value["index"] == 0 && value["delta"]["type"] == "text_delta" =>
            {
                return Ok(Some(Zeroizing::new(
                    value["delta"]["text"].as_str().ok_or_else(bad)?.to_owned(),
                )));
            }
            ("content_block_stop", 2) if value["index"] == 0 => self.state = 3,
            ("message_delta", 3) if value["delta"]["stop_sequence"].is_null() => {
                self.reason = Some(match value["delta"]["stop_reason"].as_str() {
                    Some("end_turn") => TextStreamStatus::Completed,
                    Some("max_tokens" | "refusal") => TextStreamStatus::Incomplete,
                    _ => return Err(bad()),
                });
                self.state = 4;
            }
            ("message_stop", 4) => self.state = 5,
            _ => return Err(bad()),
        }
        Ok(None)
    }
}

fn event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|w| w == b"\n\n").map(|p| (p, 2));
    let crlf = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| (p, 4));
    lf.into_iter()
        .chain(crlf)
        .min_by_key(|(position, _)| *position)
}

pub(super) async fn run(
    mut response: UpstreamStreamResponse,
    needles: Vec<Zeroizing<Vec<u8>>>,
    limit: usize,
    sender: &TextStreamSender,
) -> Result<TextStreamStatus, BrokerError> {
    if response.status != 200
        || headers_contain_secret(&response.headers, &needles)
        || !response.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type")
                && value.split(';').next() == Some("text/event-stream")
        })
    {
        return Err(BrokerError::Upstream("invalid-stream-response"));
    }
    let mut raw = Sealer::new(&needles, limit)?;
    let mut text = Sealer::new(&needles, limit)?;
    let mut projection = Projection::default();
    let mut pending = Zeroizing::new(Vec::with_capacity(limit));
    while let Some(chunk) = response
        .body
        .next_chunk()
        .await
        .map_err(|_| BrokerError::Upstream("stream-transport"))?
    {
        raw.push(&chunk, &needles)?;
        if chunk.len() > limit.saturating_sub(pending.len()) {
            return Err(BrokerError::Upstream("response-too-large"));
        }
        pending.extend_from_slice(&chunk);
        let mut used = 0;
        loop {
            let rest = &pending[used..];
            let boundary = event_boundary(rest);
            let Some((end, width)) = boundary else { break };
            if let Some(delta) = projection.event(&rest[..end])? {
                text.push(delta.as_bytes(), &needles)?;
                text.release(false, sender).await?;
            }
            used += end + width;
        }
        if used > 0 {
            let remaining = pending.len() - used;
            pending.copy_within(used.., 0);
            pending[remaining..].zeroize();
            pending.truncate(remaining);
        }
    }
    if !pending.is_empty() || projection.state != 5 {
        return Err(BrokerError::Upstream("truncated-stream"));
    }
    let status = projection
        .reason
        .ok_or(BrokerError::Upstream("invalid-stream"))?;
    if status == TextStreamStatus::Completed {
        text.release(true, sender).await?;
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::super::sealing::sealing_needles;
    use super::*;

    #[tokio::test]
    async fn every_split_withholds_secret_sources_including_normalization_lookahead() {
        for (secret, reflected) in [
            (&b"ab"[..], &b"ab"[..]),
            (b"ab", b"%61%62"),
            (b"ab", b"%25%36%31%25%36%32"),
            (b"ab", b"YWI="),
            (b"a", b"%A0"),
        ] {
            let needles = sealing_needles(secret, secret);
            for split in 0..=reflected.len() {
                let (sender, mut receiver) = mpsc::channel(32);
                let mut sealer = Sealer::new(&needles, 4096).unwrap();
                sealer.push(&vec![b'z'; 256], &needles).unwrap();
                sealer.release(false, &sender).await.unwrap();
                let first = sealer.push(&reflected[..split], &needles);
                let blocked = if first.is_err() {
                    true
                } else {
                    sealer.release(false, &sender).await.unwrap();
                    sealer.push(&reflected[split..], &needles).is_err()
                };
                assert!(blocked, "split {split}");
                drop(sender);
                let mut released = Vec::new();
                while let Some(TextStreamEvent::Chunk(chunk)) = receiver.recv().await {
                    released.extend(chunk);
                }
                assert!(!released.is_empty(), "test must exercise early release");
                assert!(
                    released.iter().all(|b| *b == b'z'),
                    "secret-source bytes escaped at split {split}"
                );
            }
        }
    }

    #[tokio::test]
    async fn utf8_release_never_splits_a_character_and_pending_suffix_is_preserved() {
        let needles = sealing_needles(b"some-token", b"some-token");
        let (sender, mut receiver) = mpsc::channel(32);
        let text = "界".repeat(600);
        let mut sealer = Sealer::new(&needles, 4096).unwrap();
        sealer.push(text.as_bytes(), &needles).unwrap();
        sealer.release(false, &sender).await.unwrap();
        assert!(sealer.bytes.len() - sealer.emitted >= sealer.hold);
        sealer.release(true, &sender).await.unwrap();
        drop(sender);
        let mut result = Vec::new();
        while let Some(TextStreamEvent::Chunk(chunk)) = receiver.recv().await {
            assert!(std::str::from_utf8(&chunk).is_ok());
            result.extend(chunk);
        }
        assert_eq!(result, text.as_bytes());
    }

    #[test]
    fn json_escapes_are_projected_before_cross_delta_sealing() {
        let mut projection = Projection {
            state: 2,
            reason: None,
        };
        let needles = sealing_needles(b"ab", b"ab");
        let mut sealer = Sealer::new(&needles, 4096).unwrap();
        for (index, json) in [r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\u0061"}}"#,r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"\u0062"}}"#].iter().enumerate() {
            let event = format!("event: content_block_delta\ndata: {json}");
            let text = projection.event(event.as_bytes()).unwrap().unwrap();
            assert_eq!(sealer.push(text.as_bytes(), &needles).is_err(), index == 1);
        }
    }

    #[test]
    fn mixed_sse_newlines_have_identical_projection_at_every_network_cut() {
        let wire = concat!(
            "event: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"content\":[],\"stop_reason\":null}}\r\n\r\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\r\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"界\\u0061\"}}\r\n\r\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null}}\n\n",
            "event: message_stop\r\ndata: {\"type\":\"message_stop\"}\r\n\r\n"
        ).as_bytes();
        for split in 0..=wire.len() {
            let mut pending = Vec::new();
            let mut projection = Projection::default();
            let mut result = String::new();
            for part in [&wire[..split], &wire[split..]] {
                pending.extend_from_slice(part);
                while let Some((end, width)) = event_boundary(&pending) {
                    if let Some(text) = projection.event(&pending[..end]).unwrap() {
                        result.push_str(&text);
                    }
                    pending.drain(..end + width);
                }
            }
            assert!(pending.is_empty());
            assert_eq!(projection.state, 5, "split {split}");
            assert_eq!(result, "界a");
        }
        // Every truncation before the final delimiter is incomplete, including
        // UTF-8, JSON escape and event-line boundaries.
        for end in 0..wire.len() {
            let mut pending = wire[..end].to_vec();
            let mut projection = Projection::default();
            while let Some((end, width)) = event_boundary(&pending) {
                projection.event(&pending[..end]).unwrap();
                pending.drain(..end + width);
            }
            assert!(projection.state != 5 || !pending.is_empty());
        }
    }
}
