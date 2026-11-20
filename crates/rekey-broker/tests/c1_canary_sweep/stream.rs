//! C1 / I1 for LLM streaming through the local HTTP gateway, the only
//! streaming caller surface. Every received byte, also of a stream cut
//! mid-flight, and the text an SDK assembles from the deltas are checked.
use std::collections::VecDeque;

use data_encoding::{BASE64, BASE64URL_NOPAD};
use rekey_broker::upstream::{UpstreamBody, UpstreamChunkFuture, UpstreamStreamResponse};
use serde_json::{Value, json};

use super::{Fixture, Sweep, contains, percent_encode, unicode_escape};

/// Synthetic LLM API key; quotes, `/`, `+`, `=` and the space make every
/// encoded form differ from the raw bytes.
pub(super) const LLM_KEY: &[u8] = br#"c1-llm-key/5d+"quoted" tail=a1"#;

type Headers = Vec<(&'static str, String)>;

struct Chunks(VecDeque<Vec<u8>>);

impl UpstreamBody for Chunks {
    fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
        let next = self.0.pop_front();
        Box::pin(async move { Ok(next.map(Into::into)) })
    }
}

fn stream_reply(
    status: u16,
    headers: &[(&str, String)],
    chunks: Vec<Vec<u8>>,
) -> UpstreamStreamResponse {
    UpstreamStreamResponse {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone()))
            .collect::<Vec<_>>()
            .into(),
        body: Box::new(Chunks(chunks.into())),
    }
}

/// One complete SSE stream whose text deltas are the given JSON string
/// literals, one event per delta, in the protocol's own framing.
fn sse_events(protocol: &str, deltas: &[String]) -> Vec<String> {
    let event = |json: String| format!("data: {json}\n\n");
    if protocol == "messages" {
        let mut events = vec![
            event(json!({"type":"message_start","message":{"id":"m","type":"message","content":[],"usage":{"output_tokens":0}}}).to_string()),
            event(json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}).to_string()),
        ];
        events.extend(deltas.iter().map(|text| {
            event(format!(
                r#"{{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":{text}}}}}"#
            ))
        }));
        events.push(event(
            json!({"type":"content_block_stop","index":0}).to_string(),
        ));
        events.push(event(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}).to_string()));
        events.push(event(json!({"type":"message_stop"}).to_string()));
        events
    } else {
        let mut events: Vec<String> = deltas
            .iter()
            .map(|text| {
                event(format!(
                    r#"{{"id":"c","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":{text}}},"finish_reason":null}}]}}"#
                ))
            })
            .collect();
        events.push(event(json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}).to_string()));
        events.push(event(json!({"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"completion_tokens":7}}).to_string()));
        events.push("data: [DONE]\n\n".to_owned());
        events
    }
}

/// Splits the chunk that holds the key inside its plain-ASCII prefix.
fn split_at_key(chunks: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let marker = b"c1-llm-key";
    chunks
        .into_iter()
        .flat_map(
            |mut chunk| match chunk.windows(marker.len()).position(|w| w == marker) {
                Some(at) => {
                    let second = chunk.split_off(at + b"c1-llm".len());
                    vec![chunk, second]
                }
                None => vec![chunk],
            },
        )
        .collect()
}

/// The text an SDK assembles from the deltas, which may join a split key.
fn assembled(protocol: &str, body: &[u8]) -> Vec<u8> {
    let mut text = Vec::new();
    for line in String::from_utf8_lossy(body).lines() {
        let Some(data) = line.strip_prefix("data: ") else {
            continue;
        };
        let Ok(event) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        let delta = if protocol == "messages" {
            &event["delta"]["text"]
        } else {
            &event["choices"][0]["delta"]["content"]
        };
        if let Some(delta) = delta.as_str() {
            text.extend_from_slice(delta.as_bytes());
        }
    }
    text
}

/// Sends one streaming request; checks the status, headers, every received
/// byte (also after an aborted stream) and the assembled delta text.
async fn stream_exchange(
    sweep: &mut Sweep,
    what: &str,
    protocol: &str,
    request: reqwest::RequestBuilder,
) -> (u16, Vec<u8>) {
    let mut response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let mut output = format!("HTTP {status}\n").into_bytes();
    for (name, value) in response.headers() {
        output.extend_from_slice(name.as_str().as_bytes());
        output.extend_from_slice(b": ");
        output.extend_from_slice(value.as_bytes());
        output.push(b'\n');
    }
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        body.extend_from_slice(&chunk);
    }
    output.extend_from_slice(&body);
    sweep.check("stream", what, &output);
    sweep.check(
        "stream",
        &format!("{what} (assembled)"),
        &assembled(protocol, &body),
    );
    (status, body)
}

pub(super) async fn llm_stream_sweep(f: &Fixture, sweep: &mut Sweep) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let key = std::str::from_utf8(LLM_KEY).unwrap();
    let literal = |text: &str| serde_json::to_string(text).unwrap();
    let (head, tail) = key.split_at(key.len() / 2);
    for (protocol, connection, path) in [
        ("messages", "llm-messages", "/v1/messages"),
        ("chat", "llm-chat", "/v1/chat/completions"),
    ] {
        let url = format!("{}/c/{connection}{path}", f.service_url);
        let request = || {
            client
                .post(&url)
                .bearer_auth("rekey")
                .header("content-type", "application/json")
                .body(
                    json!({"model":"synthetic-model","messages":[{"role":"user","content":"sweep"}],
                        "max_tokens":16,"stream":true})
                    .to_string(),
                )
        };
        let sse = vec![("content-type", "text/event-stream".to_owned())];
        let events = |deltas: &[String]| -> Vec<Vec<u8>> {
            sse_events(protocol, deltas)
                .into_iter()
                .map(String::into_bytes)
                .collect()
        };
        // A safe stream is delivered and settles.
        f.streams.lock().unwrap().push_back(stream_reply(
            200,
            &sse,
            events(&[literal("safe "), literal("output")]),
        ));
        let what = format!("{protocol} safe stream");
        let (status, body) = stream_exchange(sweep, &what, protocol, request()).await;
        assert_eq!(status, 200, "{what}");
        assert_eq!(assembled(protocol, &body), b"safe output", "{what}");
        // The key in one delta, across deltas, across transport chunks and
        // in each supported encoding never reaches the SDK.
        let whole = events(&[literal("before "), literal(key), literal(" after")]);
        let split_chunk = split_at_key(vec![whole.concat()]);
        // A large safe prefix is released before the key arrives, so the
        // stream must be cut mid-flight rather than refused up front.
        let prefix = literal(&"safe output ".repeat(1024));
        let late = events(&[prefix.clone(), literal(key)]);
        let late_split = events(&[prefix.clone(), literal(head), literal(tail)]);
        let late_chunk = split_at_key(events(&[prefix.clone(), literal(key)]));
        let reflections: Vec<(&str, u16, Headers, Vec<Vec<u8>>)> = vec![
            ("key after released output", 200, sse.clone(), late),
            (
                "key split across deltas after released output",
                200,
                sse.clone(),
                late_split,
            ),
            (
                "key split across chunks after released output",
                200,
                sse.clone(),
                late_chunk,
            ),
            ("key in one delta", 200, sse.clone(), whole),
            (
                "key split across deltas",
                200,
                sse.clone(),
                events(&[literal(head), literal(tail)]),
            ),
            ("key split across chunks", 200, sse.clone(), split_chunk),
            (
                "base64 key in a delta",
                200,
                sse.clone(),
                events(&[literal(&BASE64.encode(LLM_KEY))]),
            ),
            (
                "unicode-escaped key in a delta",
                200,
                sse.clone(),
                events(&[format!("\"{}\"", unicode_escape(key, false))]),
            ),
            (
                "percent-encoded key in a delta",
                200,
                sse.clone(),
                events(&[literal(
                    std::str::from_utf8(&percent_encode(LLM_KEY, true, false)).unwrap(),
                )]),
            ),
            (
                "error status echo",
                429,
                vec![("content-type", "application/json".to_owned())],
                vec![json!({"error":{"message":key}}).to_string().into_bytes()],
            ),
            (
                "header echo",
                200,
                vec![
                    ("content-type", "text/event-stream".to_owned()),
                    ("request-id", BASE64URL_NOPAD.encode(LLM_KEY)),
                ],
                events(&[literal("safe")]),
            ),
        ];
        for (name, status, headers, chunks) in reflections {
            f.streams
                .lock()
                .unwrap()
                .push_back(stream_reply(status, &headers, chunks));
            let what = format!("{protocol} {name}");
            let (_, body) = stream_exchange(sweep, &what, protocol, request()).await;
            // A cut stream never ends with a success terminal.
            for terminal in [b"message_stop".as_slice(), b"[DONE]"] {
                assert!(!contains(&body, terminal), "{what}");
            }
            assert!(f.streams.lock().unwrap().is_empty(), "{protocol} {name}");
        }
    }
    assert_eq!(f.upstream_requests(), 0);
}

#[test]
fn stream_oracle_finds_a_key_split_across_deltas_only_when_assembled() {
    let mut sweep = Sweep::new();
    sweep.refuse("LLM key", LLM_KEY);
    let key = std::str::from_utf8(LLM_KEY).unwrap();
    let (head, tail) = key.split_at(key.len() / 2);
    for protocol in ["messages", "chat"] {
        let deltas = [head, tail].map(|text| serde_json::to_string(text).unwrap());
        let raw = sse_events(protocol, &deltas).concat().into_bytes();
        assert_eq!(
            sweep.find(&raw),
            None,
            "{protocol}: raw events hide the key"
        );
        assert!(
            sweep.find(&assembled(protocol, &raw)).is_some(),
            "{protocol}: assembled text must expose the key"
        );
    }
}
