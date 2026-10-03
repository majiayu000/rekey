//! Bounded, lossless provider SSE. Only checked prefixes precede durable settlement.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use rekey_domain::ipc::TextStreamStatus;
use rekey_policy::{ProfileLlmProtocol, parse_profile_llm_event, profile_llm_output_value};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

use super::sealing::{contains_secret, headers_contain_secret};
use super::text_stream::{Sealer, TextStreamSender};
use crate::error::BrokerError;
use crate::upstream::UpstreamStreamResponse;

fn invalid() -> BrokerError {
    BrokerError::Upstream("invalid-stream")
}
fn index(value: &Value, name: &str) -> Result<u64, BrokerError> {
    value.get(name).and_then(Value::as_u64).ok_or_else(invalid)
}
fn string<'a>(value: &'a Value, name: &str) -> Result<&'a str, BrokerError> {
    value.get(name).and_then(Value::as_str).ok_or_else(invalid)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Anthropic(u64, &'static str),
    Chat(u64, &'static str),
    Responses(String, u64, u64, &'static str),
}
impl Drop for Key {
    fn drop(&mut self) {
        if let Self::Responses(id, ..) = self {
            id.zeroize();
        }
    }
}
impl Key {
    fn allocated(&self) -> usize {
        std::mem::size_of::<Self>()
            + match self {
                Self::Responses(id, ..) => id.len(),
                _ => 0,
            }
    }
}
#[derive(Default)]
struct Tail {
    bytes: Zeroizing<Vec<u8>>,
    total: usize,
    // A raw frame remains withheld while any of its decoded bytes is in the tail.
    frames: VecDeque<(usize, usize)>,
}
impl Tail {
    fn push(
        &mut self,
        value: &str,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        if value.is_empty() {
            return Ok(());
        }
        self.bytes.extend_from_slice(value.as_bytes());
        if contains_secret(&self.bytes, needles) {
            return Err(BrokerError::ResponseSecurityViolation);
        }
        self.total = self.total.checked_add(value.len()).ok_or_else(invalid)?;
        self.frames.push_back((self.total, frame));
        let keep = self.bytes.len().min(hold);
        let offset = self.bytes.len() - keep;
        self.bytes.copy_within(offset.., 0);
        self.bytes[keep..].zeroize();
        self.bytes.truncate(keep);
        while self
            .frames
            .front()
            .is_some_and(|(end, _)| *end <= self.total.saturating_sub(hold))
        {
            self.frames.pop_front();
        }
        Ok(())
    }
}

struct ResponseItem {
    id: String,
    added: bool,
    done: bool,
    content_parts: u64,
    summary_parts: u64,
    // Only the SDK's ordered output_text view, not another parsed response.
    text_parts: BTreeMap<u64, Zeroizing<String>>,
}
impl Drop for ResponseItem {
    fn drop(&mut self) {
        self.id.zeroize();
    }
}

struct Observer {
    protocol: ProfileLlmProtocol,
    channels: BTreeMap<Key, Tail>,
    closed: BTreeSet<Key>,
    blocks: BTreeSet<u64>,
    stopped_blocks: BTreeSet<u64>,
    identity: Option<String>,
    // Provider assembly identity only, charged to the same response bound.
    items: BTreeMap<u64, ResponseItem>,
    last_usage: Option<u64>,
    poisoned: bool,
    reason: Option<TextStreamStatus>,
    terminal: Option<(usize, TextStreamStatus)>,
    done_marker_seen: bool,
}
impl Observer {
    fn new(protocol: ProfileLlmProtocol) -> Self {
        Self {
            protocol,
            channels: BTreeMap::new(),
            closed: BTreeSet::new(),
            blocks: BTreeSet::new(),
            stopped_blocks: BTreeSet::new(),
            identity: None,
            items: BTreeMap::new(),
            last_usage: None,
            poisoned: false,
            reason: None,
            terminal: None,
            done_marker_seen: false,
        }
    }
    fn identity(&mut self, id: &str) -> Result<(), BrokerError> {
        if id.is_empty() || self.identity.as_deref().is_some_and(|old| old != id) {
            return Err(invalid());
        }
        if self.identity.is_none() {
            self.identity = Some(id.to_owned());
        }
        Ok(())
    }
    fn usage(&mut self, value: Option<u64>) {
        match value {
            Some(n) if n <= i64::MAX as u64 && self.last_usage.is_none_or(|old| n >= old) => {
                self.last_usage = Some(n)
            }
            _ => self.poisoned = true,
        }
    }
    fn append(
        &mut self,
        key: Key,
        text: &str,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        if self.closed.contains(&key) {
            return Err(invalid());
        }
        self.channels
            .entry(key)
            .or_default()
            .push(text, frame, hold, needles)
    }
    fn close(&mut self, key: Key) {
        self.channels.remove(&key);
        self.closed.insert(key);
    }
    fn watermark(&self, raw: usize) -> usize {
        self.channels
            .values()
            .filter_map(|tail| tail.frames.front().map(|(_, start)| *start))
            .chain(self.terminal.map(|(start, _)| start))
            .fold(raw, usize::min)
    }
    fn retained(&self) -> usize {
        self.channels
            .iter()
            .map(|(key, tail)| {
                key.allocated()
                    + tail.bytes.len()
                    + tail.frames.len() * std::mem::size_of::<(usize, usize)>()
            })
            .sum::<usize>()
            + self.closed.iter().map(Key::allocated).sum::<usize>()
            + (self.blocks.len() + self.stopped_blocks.len()) * std::mem::size_of::<u64>()
            + self.identity.as_ref().map_or(0, String::len)
            + self
                .items
                .values()
                .map(|item| {
                    item.id.len()
                        + std::mem::size_of::<(u64, ResponseItem)>()
                        + item
                            .text_parts
                            .values()
                            .map(|text| {
                                text.len() + std::mem::size_of::<(u64, Zeroizing<String>)>()
                            })
                            .sum::<usize>()
                })
                .sum::<usize>()
    }
    fn event(
        &mut self,
        name: Option<&str>,
        value: &Value,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        if self.terminal.is_some() {
            return Err(invalid());
        }
        match self.protocol {
            ProfileLlmProtocol::AnthropicMessages => {
                self.anthropic(name, value, frame, hold, needles)
            }
            ProfileLlmProtocol::OpenAiChat => self.chat(value, frame, hold, needles),
            ProfileLlmProtocol::OpenAiResponses => {
                self.responses(name, value, frame, hold, needles)
            }
            _ => Err(invalid()),
        }
    }
    fn done(&mut self, frame: usize) -> Result<(), BrokerError> {
        if self.protocol == ProfileLlmProtocol::OpenAiResponses
            && self.terminal.is_some()
            && !self.done_marker_seen
        {
            self.done_marker_seen = true;
            return Ok(());
        }
        if self.protocol != ProfileLlmProtocol::OpenAiChat
            || self.terminal.is_some()
            || self.identity.is_none()
            || self.reason.is_none()
        {
            return Err(invalid());
        }
        self.terminal = Some((frame, self.reason.ok_or_else(invalid)?));
        Ok(())
    }
    fn anthropic(
        &mut self,
        name: Option<&str>,
        v: &Value,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        let kind = string(v, "type")?;
        if name.is_some_and(|name| name != kind) {
            return Err(invalid());
        }
        match kind {
            "ping" => {}
            "message_start" if self.identity.is_none() => {
                if !v["message"]["content"]
                    .as_array()
                    .is_some_and(Vec::is_empty)
                {
                    return Err(invalid());
                }
                self.identity(string(&v["message"], "id")?)?;
            }
            "message_start" | "error" => return Err(invalid()),
            "content_block_start" => {
                if self.identity.is_none() {
                    return Err(invalid());
                }
                let i = index(v, "index")?;
                if self.stopped_blocks.contains(&i) || !self.blocks.insert(i) {
                    return Err(invalid());
                }
                let block = &v["content_block"];
                for field in ["text", "thinking", "signature"] {
                    if let Some(value) = block.get(field) {
                        let text = value.as_str().ok_or_else(invalid)?;
                        self.append(Key::Anthropic(i, field), text, frame, hold, needles)?;
                        if field == "text" {
                            self.append(Key::Anthropic(0, "all-text"), text, frame, hold, needles)?;
                        }
                    }
                }
            }
            "content_block_delta" => {
                let i = index(v, "index")?;
                if !self.blocks.contains(&i) {
                    return Err(invalid());
                }
                let delta = &v["delta"];
                // Citations are complete structured values, not appendable text.
                // observe_frame already scanned every decoded key/string once.
                if string(delta, "type")? == "citations_delta" {
                    if !delta.get("citation").is_some_and(Value::is_object)
                        || delta
                            .as_object()
                            .ok_or_else(invalid)?
                            .keys()
                            .any(|key| key != "type" && key != "citation")
                    {
                        return Err(invalid());
                    }
                    return Ok(());
                }
                let field = match string(delta, "type")? {
                    "text_delta" => "text",
                    "thinking_delta" => "thinking",
                    "input_json_delta" => "partial_json",
                    "signature_delta" => "signature",
                    _ => return Err(invalid()),
                };
                if delta
                    .as_object()
                    .ok_or_else(invalid)?
                    .keys()
                    .any(|key| key != "type" && key != field)
                {
                    return Err(invalid());
                }
                self.append(
                    Key::Anthropic(i, field),
                    string(delta, field)?,
                    frame,
                    hold,
                    needles,
                )?;
                if field == "text" {
                    self.append(
                        Key::Anthropic(0, "all-text"),
                        string(delta, field)?,
                        frame,
                        hold,
                        needles,
                    )?;
                }
            }
            "content_block_stop" => {
                let i = index(v, "index")?;
                if !self.blocks.remove(&i) {
                    return Err(invalid());
                }
                self.stopped_blocks.insert(i);
                for field in ["text", "thinking", "partial_json", "signature"] {
                    self.close(Key::Anthropic(i, field));
                }
            }
            "message_delta" => {
                if self.identity.is_none() {
                    return Err(invalid());
                }
                self.usage(
                    v.get("usage")
                        .and_then(|u| u.get("output_tokens"))
                        .and_then(Value::as_u64),
                );
                if let Some(reason) = v["delta"].get("stop_reason").filter(|v| !v.is_null()) {
                    let reason = reason
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .ok_or_else(invalid)?;
                    let status = if matches!(reason, "max_tokens" | "refusal") {
                        TextStreamStatus::Incomplete
                    } else {
                        TextStreamStatus::Completed
                    };
                    if self.reason.is_some_and(|old| old != status) {
                        return Err(invalid());
                    }
                    self.reason = Some(status);
                }
            }
            "message_stop" => {
                if !self.blocks.is_empty() || self.identity.is_none() {
                    return Err(invalid());
                }
                self.terminal = Some((frame, self.reason.ok_or_else(invalid)?));
            }
            other if other.ends_with("_delta") => return Err(invalid()),
            _ if v.get("delta").is_some() => return Err(invalid()),
            _ => {} // Non-incremental future metadata is still fully secret scanned.
        }
        Ok(())
    }
    fn chat(
        &mut self,
        v: &Value,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        if string(v, "object")? != "chat.completion.chunk" {
            return Err(invalid());
        }
        self.identity(string(v, "id")?)?;
        let choices = v["choices"].as_array().ok_or_else(invalid)?;
        if let Some(usage) = v.get("usage").filter(|v| !v.is_null()) {
            if !choices.is_empty() {
                self.poisoned = true;
            }
            self.usage(usage.get("completion_tokens").and_then(Value::as_u64));
        }
        if choices.len() > 1 {
            return Err(invalid());
        }
        for choice in choices {
            if index(choice, "index")? != 0 || self.reason.is_some() {
                return Err(invalid());
            }
            let delta = choice["delta"].as_object().ok_or_else(invalid)?;
            for (field, value) in delta {
                if value.is_null() {
                    continue;
                }
                match field.as_str() {
                    "role" if value == "assistant" => {}
                    "content" | "refusal" => {
                        let field = if field == "content" {
                            "content"
                        } else {
                            "refusal"
                        };
                        self.append(
                            Key::Chat(0, field),
                            value.as_str().ok_or_else(invalid)?,
                            frame,
                            hold,
                            needles,
                        )?;
                    }
                    "tool_calls" => {
                        for call in value.as_array().ok_or_else(invalid)? {
                            let i = index(call, "index")?;
                            if call.as_object().ok_or_else(invalid)?.keys().any(|key| {
                                !matches!(key.as_str(), "index" | "id" | "type" | "function")
                            }) || call.get("function").is_some_and(|function| {
                                !function.as_object().is_some_and(|object| {
                                    object
                                        .keys()
                                        .all(|key| matches!(key.as_str(), "name" | "arguments"))
                                })
                            }) {
                                return Err(invalid());
                            }
                            for (object, field, key) in [
                                (call, "id", "tool-id"),
                                (&call["function"], "name", "tool-name"),
                                (&call["function"], "arguments", "tool-arguments"),
                            ] {
                                if let Some(value) = object.get(field).filter(|v| !v.is_null()) {
                                    self.append(
                                        Key::Chat(i, key),
                                        value.as_str().ok_or_else(invalid)?,
                                        frame,
                                        hold,
                                        needles,
                                    )?;
                                }
                            }
                        }
                    }
                    "function_call" => {
                        if value
                            .as_object()
                            .ok_or_else(invalid)?
                            .keys()
                            .any(|key| !matches!(key.as_str(), "name" | "arguments"))
                        {
                            return Err(invalid());
                        }
                        for (field, key) in [
                            ("name", "function-name"),
                            ("arguments", "function-arguments"),
                        ] {
                            if let Some(value) = value.get(field).filter(|v| !v.is_null()) {
                                self.append(
                                    Key::Chat(0, key),
                                    value.as_str().ok_or_else(invalid)?,
                                    frame,
                                    hold,
                                    needles,
                                )?;
                            }
                        }
                    }
                    _ => return Err(invalid()),
                }
            }
            if let Some(reason) = choice.get("finish_reason").filter(|v| !v.is_null()) {
                let reason = reason
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(invalid)?;
                self.reason = Some(if matches!(reason, "length" | "content_filter") {
                    TextStreamStatus::Incomplete
                } else {
                    TextStreamStatus::Completed
                });
            }
        }
        Ok(())
    }
    fn bind_response_item(&mut self, output: u64, id: &str) -> Result<(), BrokerError> {
        if self.identity.is_none()
            || id.is_empty()
            || self
                .items
                .get(&output)
                .is_some_and(|old| old.id != id || old.done)
        {
            return Err(invalid());
        }
        self.items.entry(output).or_insert_with(|| ResponseItem {
            id: id.to_owned(),
            added: false,
            done: false,
            content_parts: 0,
            summary_parts: 0,
            text_parts: BTreeMap::new(),
        });
        Ok(())
    }
    fn seed_response_part(
        &mut self,
        position: (&str, u64, u64),
        part: &Value,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        let (field, member) = match string(part, "type")? {
            "output_text" => ("text", "text"),
            "refusal" => ("refusal", "refusal"),
            "reasoning_text" => ("reasoning", "text"),
            "summary_text" => ("summary", "text"),
            _ => return Err(invalid()),
        };
        let text = string(part, member)?;
        self.append(
            Key::Responses(position.0.to_owned(), position.1, position.2, field),
            text,
            frame,
            hold,
            needles,
        )?;
        if field == "text" {
            self.response_text((position.1, position.2), text, false)?;
        }
        Ok(())
    }
    fn response_text(
        &mut self,
        position: (u64, u64),
        text: &str,
        append: bool,
    ) -> Result<(), BrokerError> {
        let parts = &mut self
            .items
            .get_mut(&position.0)
            .ok_or_else(invalid)?
            .text_parts;
        if append {
            parts.entry(position.1).or_default().push_str(text);
        } else {
            parts.insert(position.1, Zeroizing::new(text.to_owned()));
        }
        Ok(())
    }
    fn response_part_snapshot(
        &mut self,
        output: u64,
        part: u64,
        value: &Value,
    ) -> Result<(), BrokerError> {
        if string(value, "type")? == "output_text" {
            self.response_text((output, part), string(value, "text")?, false)?;
        } else {
            self.items
                .get_mut(&output)
                .ok_or_else(invalid)?
                .text_parts
                .remove(&part);
        }
        Ok(())
    }
    fn response_item_snapshot(&mut self, output: u64, item: &Value) -> Result<(), BrokerError> {
        self.items
            .get_mut(&output)
            .ok_or_else(invalid)?
            .text_parts
            .clear();
        if string(item, "type")? == "message" {
            for (i, part) in item["content"]
                .as_array()
                .ok_or_else(invalid)?
                .iter()
                .enumerate()
            {
                self.response_part_snapshot(output, i as u64, part)?;
            }
        }
        Ok(())
    }
    fn scan_response_text(
        &self,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        // Ordered concatenation matches SDK output_text, including replacement
        // snapshots and out-of-order deltas. Only one bounded scratch tail.
        let mut joined = Tail::default();
        for text in self
            .items
            .values()
            .flat_map(|item| item.text_parts.values())
        {
            joined.push(text, 0, hold, needles)?;
        }
        Ok(())
    }
    fn scan_response_snapshot(
        value: &Value,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        // Some terminal events omit output; callers retain the current view.
        let Some(output) = value.get("output") else {
            return Ok(());
        };
        let mut joined = Tail::default();
        for item in output.as_array().ok_or_else(invalid)? {
            if string(item, "type")? == "message" {
                for part in item["content"].as_array().ok_or_else(invalid)? {
                    if string(part, "type")? == "output_text" {
                        joined.push(string(part, "text")?, 0, hold, needles)?;
                    }
                }
            }
        }
        Ok(())
    }
    fn responses(
        &mut self,
        name: Option<&str>,
        v: &Value,
        frame: usize,
        hold: usize,
        needles: &[Zeroizing<Vec<u8>>],
    ) -> Result<(), BrokerError> {
        let kind = string(v, "type")?;
        if name.is_some_and(|name| name != kind) {
            return Err(invalid());
        }
        if matches!(kind, "response.created" | "response.in_progress") {
            if !v["response"]["output"]
                .as_array()
                .is_some_and(Vec::is_empty)
            {
                return Err(invalid());
            }
            self.identity(string(&v["response"], "id")?)?;
        } else if matches!(
            kind,
            "response.output_item.added" | "response.output_item.done"
        ) {
            let output = index(v, "output_index")?;
            let item = &v["item"];
            let id = string(item, "id")?;
            self.bind_response_item(output, id)?;
            if kind.ends_with(".done") {
                self.response_item_snapshot(output, item)?;
                self.items.get_mut(&output).ok_or_else(invalid)?.done = true;
            }
            if kind.ends_with(".added") {
                let assembly = self.items.get_mut(&output).ok_or_else(invalid)?;
                if assembly.added || assembly.content_parts != 0 || assembly.summary_parts != 0 {
                    return Err(invalid());
                }
                assembly.added = true;
                match string(item, "type")? {
                    "function_call" | "custom_tool_call" => {
                        let (member, field) = if item["type"] == "function_call" {
                            ("arguments", "arguments")
                        } else {
                            ("input", "custom-input")
                        };
                        self.append(
                            Key::Responses(id.to_owned(), output, 0, field),
                            string(item, member)?,
                            frame,
                            hold,
                            needles,
                        )?;
                    }
                    "message" => {
                        self.items
                            .get_mut(&output)
                            .ok_or_else(invalid)?
                            .content_parts =
                            item["content"].as_array().ok_or_else(invalid)?.len() as u64;
                        for (i, part) in item["content"]
                            .as_array()
                            .ok_or_else(invalid)?
                            .iter()
                            .enumerate()
                        {
                            self.seed_response_part(
                                (id, output, i as u64),
                                part,
                                frame,
                                hold,
                                needles,
                            )?;
                        }
                    }
                    "reasoning" => {
                        for member in ["content", "summary"] {
                            if let Some(parts) = item.get(member).filter(|v| !v.is_null()) {
                                let parts = parts.as_array().ok_or_else(invalid)?;
                                let assembly = self.items.get_mut(&output).ok_or_else(invalid)?;
                                if member == "content" {
                                    assembly.content_parts = parts.len() as u64;
                                } else {
                                    assembly.summary_parts = parts.len() as u64;
                                }
                                for (i, part) in parts.iter().enumerate() {
                                    self.seed_response_part(
                                        (id, output, i as u64),
                                        part,
                                        frame,
                                        hold,
                                        needles,
                                    )?;
                                }
                            }
                        }
                    }
                    _ => {} // Complete non-incremental items were already string scanned.
                }
            }
        } else if matches!(
            kind,
            "response.content_part.added"
                | "response.content_part.done"
                | "response.reasoning_summary_part.added"
                | "response.reasoning_summary_part.done"
        ) {
            let output = index(v, "output_index")?;
            let id = string(v, "item_id")?;
            self.bind_response_item(output, id)?;
            if kind.ends_with(".added") {
                let subindex = if kind.starts_with("response.reasoning_summary_part") {
                    "summary_index"
                } else {
                    "content_index"
                };
                let declared = index(v, subindex)?;
                let assembly = self.items.get_mut(&output).ok_or_else(invalid)?;
                let count = if subindex == "content_index" {
                    &mut assembly.content_parts
                } else {
                    &mut assembly.summary_parts
                };
                if declared != *count {
                    return Err(invalid());
                }
                *count = count.checked_add(1).ok_or_else(invalid)?;
                self.seed_response_part((id, output, declared), &v["part"], frame, hold, needles)?;
            } else {
                let (member, fields): (&str, &[&'static str]) =
                    if kind.starts_with("response.reasoning_summary_part") {
                        ("summary_index", &["summary"])
                    } else {
                        ("content_index", &["text", "refusal", "reasoning"])
                    };
                let part = index(v, member)?;
                if member == "content_index" {
                    self.response_part_snapshot(output, part, &v["part"])?;
                }
                for field in fields {
                    self.close(Key::Responses(id.to_owned(), output, part, field));
                }
            }
        } else if matches!(kind, "response.completed" | "response.incomplete") {
            if self.identity.is_none() {
                return Err(invalid());
            }
            self.identity(string(&v["response"], "id")?)?;
            let status = if kind == "response.completed" {
                "completed"
            } else {
                "incomplete"
            };
            if string(&v["response"], "status")? != status {
                return Err(invalid());
            }
            Self::scan_response_snapshot(&v["response"], hold, needles)?;
            self.usage(profile_llm_output_value(self.protocol, &v["response"]));
            self.terminal = Some((
                frame,
                if status == "completed" {
                    TextStreamStatus::Completed
                } else {
                    TextStreamStatus::Incomplete
                },
            ));
        } else if matches!(kind, "error" | "response.failed") {
            return Err(invalid());
        } else if kind.ends_with(".delta") || kind.ends_with(".done") {
            let (field, subindex) = match kind
                .strip_suffix(".delta")
                .or_else(|| kind.strip_suffix(".done"))
            {
                Some("response.output_text") => ("text", Some("content_index")),
                Some("response.refusal") => ("refusal", Some("content_index")),
                Some("response.reasoning_text") => ("reasoning", Some("content_index")),
                Some("response.reasoning_summary_text") => ("summary", Some("summary_index")),
                Some("response.function_call_arguments") => ("arguments", None),
                Some("response.custom_tool_call_input") => ("custom-input", None),
                _ if kind.ends_with(".delta") => return Err(invalid()),
                _ => return Ok(()),
            };
            if self.identity.is_none() {
                return Err(invalid());
            }
            let output = index(v, "output_index")?;
            let id = string(v, "item_id")?;
            self.bind_response_item(output, id)?;
            let part = subindex
                .map(|field| index(v, field))
                .transpose()?
                .unwrap_or(0);
            let key = Key::Responses(id.to_owned(), output, part, field);
            if kind.ends_with(".delta") {
                self.append(key, string(v, "delta")?, frame, hold, needles)?;
                if field == "text" {
                    self.response_text((output, part), string(v, "delta")?, true)?;
                }
            } else {
                if field == "text" {
                    self.response_text((output, part), string(v, "text")?, false)?;
                }
                if field == "custom-input" {
                    string(v, "input")?;
                }
                self.close(key);
            }
        } else if v.get("delta").is_some() || kind.contains("delta") {
            return Err(invalid());
        }
        self.scan_response_text(hold, needles)
    }
}
impl Drop for Observer {
    fn drop(&mut self) {
        if let Some(id) = &mut self.identity {
            id.zeroize();
        }
    }
}

fn scan_json(value: &Value, needles: &[Zeroizing<Vec<u8>>]) -> Result<(), BrokerError> {
    match value {
        Value::String(s) if contains_secret(s.as_bytes(), needles) => {
            return Err(BrokerError::ResponseSecurityViolation);
        }
        Value::Array(values) => {
            for value in values {
                scan_json(value, needles)?;
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                if contains_secret(key.as_bytes(), needles) {
                    return Err(BrokerError::ResponseSecurityViolation);
                }
                scan_json(value, needles)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// End of a complete frame, including its empty line; a split CRLF stays pending.
fn boundary(bytes: &[u8], scan: &mut usize, line: &mut usize, eof: bool) -> Option<usize> {
    while *scan < bytes.len() {
        let width = match bytes[*scan] {
            b'\n' => 1,
            b'\r' if *scan + 1 == bytes.len() && !eof => return None,
            b'\r' if bytes.get(*scan + 1) == Some(&b'\n') => 2,
            b'\r' => 1,
            _ => {
                *scan += 1;
                continue;
            }
        };
        let empty = *line == *scan;
        *scan += width;
        *line = *scan;
        if empty {
            return Some(*scan);
        }
    }
    None
}

fn observe_frame(
    observer: &mut Observer,
    bytes: &[u8],
    start: usize,
    hold: usize,
    needles: &[Zeroizing<Vec<u8>>],
) -> Result<(), BrokerError> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut name = None;
    let mut data = Zeroizing::new(String::new());
    let mut data_seen = false;
    for line in text.split(['\r', '\n']) {
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" if name.replace(value).is_some() => return Err(invalid()),
            "event" => {}
            "data" => {
                if data_seen {
                    data.push('\n');
                }
                data.push_str(value);
                data_seen = true;
            }
            _ => {} // SSE id/retry/unknown fields are preserved, never interpreted as authorization.
        }
    }
    if !data_seen {
        return Ok(());
    }
    if data.as_str() == "[DONE]" {
        return observer.done(start);
    }
    let value = parse_profile_llm_event(data.as_bytes()).map_err(|_| invalid())?;
    scan_json(value.value(), needles)?;
    observer.event(name, value.value(), start, hold, needles)
}

pub(super) struct Complete {
    raw: Sealer,
    output: Option<u64>,
    status: TextStreamStatus,
}
impl Complete {
    pub(super) fn output_tokens(&self) -> Option<u64> {
        self.output
    }
    pub(super) fn status(&self) -> TextStreamStatus {
        self.status
    }
    /// Called only after terminal settlement/audit commits, never by the parser.
    pub(super) async fn release(&mut self, sender: &TextStreamSender) -> Result<(), BrokerError> {
        self.raw
            .release_through(self.raw.bytes().len(), sender)
            .await
    }
}

pub(super) async fn run(
    mut response: UpstreamStreamResponse,
    needles: Vec<Zeroizing<Vec<u8>>>,
    limit: usize,
    sender: &TextStreamSender,
    protocol: ProfileLlmProtocol,
) -> Result<Complete, BrokerError> {
    let mut mime = 0;
    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("content-type") {
            mime += 1;
            if !value
                .split(';')
                .next()
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream"))
            {
                return Err(invalid());
            }
        }
        if name.eq_ignore_ascii_case("content-encoding")
            && !value.trim().eq_ignore_ascii_case("identity")
        {
            return Err(invalid());
        }
    }
    if response.status != 200 || mime != 1 || headers_contain_secret(&response.headers, &needles) {
        return Err(invalid());
    }
    let mut raw = Sealer::new(&needles, limit)?;
    let mut observer = Observer::new(protocol);
    let mut cursor = 0;
    let mut scan = 0;
    let mut line = 0;
    let mut frames = VecDeque::new();
    loop {
        let chunk = response
            .body
            .next_chunk()
            .await
            .map_err(|_| BrokerError::Upstream("stream-transport"))?;
        let eof = chunk.is_none();
        if let Some(chunk) = chunk {
            raw.push(&chunk, &needles)?;
        }
        while let Some(end) = boundary(raw.bytes(), &mut scan, &mut line, eof) {
            observe_frame(
                &mut observer,
                &raw.bytes()[cursor..end],
                cursor,
                raw.hold(),
                &needles,
            )?;
            cursor = end;
            frames.push_back(cursor);
            let retained = raw
                .bytes()
                .len()
                .checked_add(observer.retained())
                .and_then(|n| n.checked_add(frames.len() * std::mem::size_of::<usize>()));
            if retained.is_none_or(|n| n > limit) {
                return Err(BrokerError::Upstream("response-too-large"));
            }
            let watermark = observer.watermark(raw.bytes().len().saturating_sub(raw.hold()));
            let mut end = None;
            while frames.front().is_some_and(|end| *end <= watermark) {
                end = frames.pop_front();
            }
            if let Some(end) = end {
                raw.release_through(end, sender).await?;
            }
            tokio::task::yield_now().await;
        }
        if eof {
            break;
        }
    }
    if cursor != raw.bytes().len() {
        return Err(BrokerError::Upstream("truncated-stream"));
    }
    let (_, status) = observer
        .terminal
        .ok_or(BrokerError::Upstream("truncated-stream"))?;
    let output = if observer.poisoned {
        None
    } else {
        observer.last_usage
    };
    Ok(Complete {
        raw,
        output,
        status,
    })
}

#[cfg(test)]
mod tests {
    use super::super::text_stream::TextStreamEvent;
    use super::*;
    use crate::upstream::{UpstreamBody, UpstreamChunkFuture, UpstreamError};
    use serde_json::json;
    use tokio::sync::mpsc;

    struct Chunks {
        chunks: VecDeque<Vec<u8>>,
        error: bool,
    }
    impl UpstreamBody for Chunks {
        fn next_chunk(&mut self) -> UpstreamChunkFuture<'_> {
            Box::pin(async {
                match self.chunks.pop_front() {
                    Some(bytes) => Ok(Some(bytes.into())),
                    None if self.error => Err(UpstreamError::Transport),
                    None => Ok(None),
                }
            })
        }
    }
    fn event(value: Value) -> String {
        format!("data: {value}\n\n")
    }
    fn anthropic(parts: &[&str], usage: Value) -> String {
        let mut raw = event(json!({"type":"message_start","message":{"id":"m","content":[]}}));
        raw += &event(
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        );
        for part in parts {
            raw += &event(
                json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":part}}),
            );
        }
        raw += &event(json!({"type":"content_block_stop","index":0}));
        raw += &event(
            json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":usage}}),
        );
        raw + &event(json!({"type":"message_stop"}))
    }
    fn chat(parts: &[&str], usage: Value) -> String {
        let mut raw = String::new();
        for part in parts {
            raw += &event(
                json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":part},"finish_reason":null}],"usage":null}),
            );
        }
        raw += &event(
            json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        );
        raw += &event(
            json!({"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"completion_tokens":usage}}),
        );
        raw + "data: [DONE]\n\n"
    }
    fn responses(parts: &[&str], usage: Value) -> String {
        let mut raw = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        for part in parts {
            raw += &event(
                json!({"type":"response.output_text.delta","item_id":"i","output_index":0,"content_index":0,"delta":part}),
            );
        }
        raw += &event(
            json!({"type":"response.output_text.done","item_id":"i","output_index":0,"content_index":0,"text":parts.concat()}),
        );
        raw + &event(
            json!({"type":"response.completed","response":{"id":"r","status":"completed","usage":{"output_tokens":usage}}}),
        )
    }
    fn response(bytes: &[u8], split: usize, error: bool) -> UpstreamStreamResponse {
        UpstreamStreamResponse {
            status: 200,
            headers: vec![(
                "content-type".into(),
                "text/event-stream; charset=utf-8".into(),
            )]
            .into(),
            body: Box::new(Chunks {
                chunks: bytes.chunks(split.max(1)).map(<[u8]>::to_vec).collect(),
                error,
            }),
        }
    }
    fn drain(rx: &mut mpsc::Receiver<TextStreamEvent>) -> Vec<u8> {
        let mut out = Vec::new();
        while let Ok(TextStreamEvent::Chunk(bytes)) = rx.try_recv() {
            out.extend(bytes);
        }
        out
    }
    #[tokio::test]
    async fn responses_optional_done_preserves_bytes_and_holds_terminal() {
        let raw = responses(&["OK"], json!(7)) + "data: [DONE]\n\n";
        for split in [1, 7, raw.len()] {
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(raw.as_bytes(), split, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await
            .unwrap();
            let mut out = drain(&mut rx);
            assert!(!String::from_utf8_lossy(&out).contains("response.completed"));
            assert_eq!(complete.output_tokens(), Some(7));
            complete.release(&tx).await.unwrap();
            out.extend(drain(&mut rx));
            assert_eq!(out, raw.as_bytes());
        }
    }

    #[tokio::test]
    async fn responses_done_rejects_early_duplicate_and_trailing_data() {
        let good = responses(&["OK"], json!(7)) + "data: [DONE]\n\n";
        for raw in [
            "data: [DONE]\n\n".to_owned() + &responses(&["OK"], json!(7)),
            good.clone() + "data: [DONE]\n\n",
            good.clone()
                + &event(
                    json!({"type":"response.output_text.delta","item_id":"i","output_index":0,"content_index":0,"delta":"late"}),
                ),
            good + &event(
                json!({"type":"response.completed","response":{"id":"r","status":"completed","secret":"synthetic-secret-1234"}}),
            ),
        ] {
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiResponses,
                )
                .await
                .is_err()
            );
            let out = drain(&mut rx);
            assert!(!String::from_utf8_lossy(&out).contains("response.completed"));
            assert!(!String::from_utf8_lossy(&out).contains("synthetic-secret-1234"));
        }
    }

    #[tokio::test]
    async fn three_providers_preserve_bytes_and_hold_terminal_until_explicit_release() {
        for (protocol, raw, terminal) in [
            (
                ProfileLlmProtocol::AnthropicMessages,
                anthropic(&["hi ", "世界"], json!(7)),
                "message_stop",
            ),
            (
                ProfileLlmProtocol::OpenAiChat,
                chat(&["hi ", "世界"], json!(7)),
                "[DONE]",
            ),
            (
                ProfileLlmProtocol::OpenAiResponses,
                responses(&["hi ", "世界"], json!(7)),
                "response.completed",
            ),
        ] {
            for split in [1, 2, 3, 7, 31, raw.len()] {
                let (tx, mut rx) = mpsc::channel(4096);
                let mut complete = run(
                    response(raw.as_bytes(), split, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    protocol,
                )
                .await
                .unwrap();
                let mut out = drain(&mut rx);
                assert!(!String::from_utf8_lossy(&out).contains(terminal));
                assert_eq!(complete.output_tokens(), Some(7));
                assert_eq!(complete.status(), TextStreamStatus::Completed);
                complete.release(&tx).await.unwrap();
                out.extend(drain(&mut rx));
                assert_eq!(out, raw.as_bytes());
            }
        }
    }
    #[tokio::test]
    async fn secret_split_across_semantic_deltas_never_releases_first_fragment() {
        let secret = b"synthetic-secret-1234";
        for (protocol, make) in [
            (
                ProfileLlmProtocol::AnthropicMessages,
                anthropic as fn(&[&str], Value) -> String,
            ),
            (ProfileLlmProtocol::OpenAiChat, chat),
            (ProfileLlmProtocol::OpenAiResponses, responses),
        ] {
            for at in 1..secret.len() {
                let left = std::str::from_utf8(&secret[..at]).unwrap();
                let right = std::str::from_utf8(&secret[at..]).unwrap();
                let raw = make(&[&"z".repeat(200), left, right], json!(7));
                let (tx, mut rx) = mpsc::channel(4096);
                let result = run(
                    response(raw.as_bytes(), 1, false),
                    vec![secret.to_vec().into()],
                    65536,
                    &tx,
                    protocol,
                )
                .await;
                assert!(matches!(
                    result,
                    Err(BrokerError::ResponseSecurityViolation)
                ));
                let out = drain(&mut rx);
                assert!(
                    !String::from_utf8_lossy(&out).contains(&serde_json::to_string(left).unwrap())
                );
            }
        }
    }
    #[tokio::test]
    async fn usage_missing_bad_regressing_and_complete_incomplete_are_distinct() {
        for usage in [
            Value::Null,
            json!(-1),
            json!(1.5),
            json!("7"),
            json!(u64::MAX),
        ] {
            let (tx, _rx) = mpsc::channel(4096);
            let complete = run(
                response(anthropic(&["safe"], usage).as_bytes(), 7, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages,
            )
            .await
            .unwrap();
            assert_eq!(complete.output_tokens(), None);
            assert_eq!(complete.status(), TextStreamStatus::Completed);
        }
        let raw = anthropic(&["safe"], json!(7)).replace(
            "data: {\"type\":\"message_stop\"}",
            &format!(
                "{}data: {{\"type\":\"message_stop\"}}",
                event(json!({"type":"message_delta","delta":{},"usage":{"output_tokens":3}}))
            ),
        );
        let (tx, _rx) = mpsc::channel(4096);
        assert_eq!(
            run(
                response(raw.as_bytes(), 1, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages
            )
            .await
            .unwrap()
            .output_tokens(),
            None
        );
        let raw = responses(&["safe"], json!(4))
            .replace("response.completed", "response.incomplete")
            .replace("\"status\":\"completed\"", "\"status\":\"incomplete\"");
        let complete = run(
            response(raw.as_bytes(), 1, false),
            vec![],
            65536,
            &tx,
            ProfileLlmProtocol::OpenAiResponses,
        )
        .await
        .unwrap();
        assert_eq!(complete.output_tokens(), Some(4));
        assert_eq!(complete.status(), TextStreamStatus::Incomplete);
    }
    #[tokio::test]
    async fn truncated_error_conflicting_terminal_and_encoding_fail_closed() {
        let good = chat(&["safe"], json!(7));
        for raw in [
            good.trim_end_matches("data: [DONE]\n\n").to_owned(),
            format!("{good}data: [DONE]\n\n"),
            format!("{good}data: {{"),
            good.replace(
                "\"completion_tokens\":7",
                "\"completion_tokens\":7,\"completion_tokens\":0",
            ),
        ] {
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(
                run(
                    response(raw.as_bytes(), 3, false),
                    vec![],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiChat
                )
                .await
                .is_err()
            );
            assert!(!String::from_utf8_lossy(&drain(&mut rx)).contains("[DONE]"));
        }
        for encoding in ["gzip", "br", "identity, gzip"] {
            let mut res = response(good.as_bytes(), 3, false);
            res.headers = vec![
                ("content-type".into(), "text/event-stream".into()),
                ("content-encoding".into(), encoding.into()),
            ]
            .into();
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(
                run(res, vec![], 65536, &tx, ProfileLlmProtocol::OpenAiChat)
                    .await
                    .is_err()
            );
            assert!(drain(&mut rx).is_empty());
        }
        let (tx, _rx) = mpsc::channel(4096);
        assert!(
            run(
                response(good.as_bytes(), 7, true),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiChat
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn comments_multiline_crlf_and_cr_are_lossless_but_unknown_delta_is_rejected() {
        let original = anthropic(&["safe"], json!(7));
        for line in ["\n", "\r\n", "\r"] {
            let raw = format!(
                ": safe comment\n\n{}",
                original.replace("data: {", "data: \ndata: {")
            )
            .replace('\n', line);
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(raw.as_bytes(), 1, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages,
            )
            .await
            .unwrap();
            let mut out = drain(&mut rx);
            complete.release(&tx).await.unwrap();
            out.extend(drain(&mut rx));
            assert_eq!(out, raw.as_bytes());
        }
        let raw = original.replace("text_delta", "unknown_delta");
        let (tx, _rx) = mpsc::channel(4096);
        assert!(
            run(
                response(raw.as_bytes(), 1, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages
            )
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn unknown_nested_chat_delta_semantics_never_release_the_frame() {
        for delta in [
            json!({"tool_calls":[{"index":0,"future_arguments":"unknown-fragment"}]}),
            json!({"tool_calls":[{"index":0,"function":{"future_arguments":"unknown-fragment"}}]}),
            json!({"function_call":{"future_arguments":"unknown-fragment"}}),
        ] {
            let raw = event(
                json!({"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":delta,"finish_reason":null}]}),
            );
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiChat
                )
                .await
                .is_err()
            );
            assert!(drain(&mut rx).is_empty());
        }
    }

    #[tokio::test]
    async fn tool_inner_unicode_and_initial_block_text_use_the_same_decoded_tail() {
        let secret = b"synthetic-secret-1234";
        for parts in [
            ["synthetic-", r"\u0073ecret-1234"],
            [r"synthetic-\u00", "73ecret-1234"],
        ] {
            let raw = anthropic(&parts, json!(7))
                .replace("text_delta", "input_json_delta")
                .replace("\"text\":", "\"partial_json\":");
            let (tx, _rx) = mpsc::channel(4096);
            assert!(matches!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![secret.to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::AnthropicMessages
                )
                .await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
        }
        let raw = anthropic(&["secret-1234"], json!(7))
            .replace("\"text\":\"\"", "\"text\":\"synthetic-\"");
        let (tx, _rx) = mpsc::channel(4096);
        assert!(matches!(
            run(
                response(raw.as_bytes(), 1, false),
                vec![secret.to_vec().into()],
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages
            )
            .await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
    }
    #[tokio::test]
    async fn retained_field_state_is_charged_to_response_bound_and_disconnect_keeps_usage() {
        let raw = anthropic(&["safe"], json!(7));
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let complete = run(
            response(raw.as_bytes(), 1, false),
            vec![],
            65536,
            &tx,
            ProfileLlmProtocol::AnthropicMessages,
        )
        .await
        .unwrap();
        assert_eq!(complete.output_tokens(), Some(7));
        assert!(
            run(
                response(raw.as_bytes(), 1, false),
                vec![],
                raw.len(),
                &tx,
                ProfileLlmProtocol::AnthropicMessages
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn slow_receiver_backpressure_preserves_bytes_and_withholds_terminal() {
        let part = "safe output ".repeat(100);
        let raw = chat(&[&part, &part, &part, &part, &part], json!(7));
        let expected = raw.clone();
        let (tx, mut rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            let mut complete = run(
                response(raw.as_bytes(), 17, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiChat,
            )
            .await
            .unwrap();
            assert_eq!(complete.output_tokens(), Some(7));
            complete.release(&tx).await.unwrap();
        });
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        let mut output = Vec::new();
        while let Some(TextStreamEvent::Chunk(bytes)) = rx.recv().await {
            assert!(bytes.len() <= 16 * 1024);
            output.extend(bytes);
            tokio::task::yield_now().await;
        }
        task.await.unwrap();
        assert_eq!(output, expected.as_bytes());
    }

    #[tokio::test]
    async fn tools_thinking_and_interleaved_blocks_are_preserved_without_projection() {
        let mut raw = event(json!({"type":"message_start","message":{"id":"m","content":[]}}));
        for (i, kind) in [(0, "tool_use"), (1, "thinking")] {
            raw += &event(
                json!({"type":"content_block_start","index":i,"content_block":{"type":kind,"id":format!("b{i}"),"input":{}}}),
            );
        }
        for (i, kind, field, value) in [
            (0, "input_json_delta", "partial_json", "{\"x\": "),
            (1, "thinking_delta", "thinking", "thinking first"),
            (0, "input_json_delta", "partial_json", "1}"),
            (1, "signature_delta", "signature", "signed-data"),
        ] {
            let mut delta = json!({"type":kind});
            delta[field] = value.into();
            raw += &event(json!({"type":"content_block_delta","index":i,"delta":delta}));
        }
        for i in [1, 0] {
            raw += &event(json!({"type":"content_block_stop","index":i}));
        }
        raw += &event(
            json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}),
        );
        raw += &event(json!({"type":"message_stop"}));
        let (tx, mut rx) = mpsc::channel(4096);
        let mut complete = run(
            response(raw.as_bytes(), 1, false),
            vec![b"synthetic-secret-1234".to_vec().into()],
            65536,
            &tx,
            ProfileLlmProtocol::AnthropicMessages,
        )
        .await
        .unwrap();
        let mut out = drain(&mut rx);
        assert_eq!(complete.output_tokens(), Some(9));
        complete.release(&tx).await.unwrap();
        out.extend(drain(&mut rx));
        assert_eq!(out, raw.as_bytes());
    }
    #[tokio::test]
    async fn reflected_encodings_and_separate_text_blocks_cannot_leak() {
        let secret = b"synthetic-secret-1234";
        let needles = super::super::sealing::sealing_needles(secret, secret);
        let unicode = secret
            .iter()
            .map(|b| format!("\\u{b:04x}"))
            .collect::<String>();
        for encoded in [
            unicode,
            data_encoding::BASE64.encode(secret),
            data_encoding::HEXLOWER.encode(secret),
            secret.iter().map(|b| format!("%{b:02x}")).collect(),
        ] {
            let raw = anthropic(&[&encoded], json!(7));
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(matches!(
                run(
                    response(raw.as_bytes(), 1, false),
                    needles.clone(),
                    65536,
                    &tx,
                    ProfileLlmProtocol::AnthropicMessages
                )
                .await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
            assert!(!String::from_utf8_lossy(&drain(&mut rx)).contains(&encoded));
        }
        let first = anthropic(&["synthetic-"], json!(7));
        let second = event(
            json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}),
        ) + &event(
            json!({"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"secret-1234"}}),
        ) + &event(json!({"type":"content_block_stop","index":1}));
        let raw = first.replace(
            "data: {\"delta\":{\"stop_reason\":\"end_turn\"}",
            &format!("{second}data: {{\"delta\":{{\"stop_reason\":\"end_turn\"}}"),
        );
        assert!(raw.contains("\"index\":1"));
        let (tx, mut rx) = mpsc::channel(4096);
        assert!(matches!(
            run(
                response(raw.as_bytes(), 1, false),
                needles,
                65536,
                &tx,
                ProfileLlmProtocol::AnthropicMessages
            )
            .await,
            Err(BrokerError::ResponseSecurityViolation)
        ));
        assert!(!String::from_utf8_lossy(&drain(&mut rx)).contains("synthetic-"));
    }
    #[tokio::test]
    async fn custom_tool_input_is_lossless_and_sealed_across_delta_and_done() {
        fn custom(parts: &[&str], complete: &str) -> String {
            let mut raw =
                event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
            for part in parts {
                raw += &event(
                    json!({"type":"response.custom_tool_call_input.delta","item_id":"tool","output_index":0,"delta":part}),
                );
            }
            raw += &event(
                json!({"type":"response.custom_tool_call_input.done","item_id":"tool","output_index":0,"input":complete}),
            );
            raw += &event(
                json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
            );
            raw
        }
        let good = custom(
            &["*** Begin Patch\n", "+工具内容\n", "*** End Patch"],
            "*** Begin Patch\n+工具内容\n*** End Patch",
        );
        for size in [1, 3, good.len()] {
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(good.as_bytes(), size, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await
            .unwrap();
            assert_eq!(complete.output_tokens(), Some(7));
            let mut output = drain(&mut rx);
            assert!(!String::from_utf8_lossy(&output).contains("response.completed"));
            complete.release(&tx).await.unwrap();
            output.extend(drain(&mut rx));
            assert_eq!(output, good.as_bytes());
        }
        for raw in [
            custom(&["synthetic-", "secret-1234"], "safe"),
            custom(&[r"synthetic-\u00", "73ecret-1234"], "safe"),
            custom(&["safe"], "synthetic-secret-1234"),
        ] {
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(matches!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiResponses
                )
                .await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
            let output = drain(&mut rx);
            assert!(!String::from_utf8_lossy(&output).contains("synthetic-"));
            assert!(!String::from_utf8_lossy(&output).contains("response.completed"));
        }
        let mut reopened = good.clone();
        reopened.insert_str(
            good.rfind("data: ").unwrap(),
            &event(json!({"type":"response.custom_tool_call_input.delta","item_id":"tool","output_index":0,"delta":"late"})),
        );
        let (tx, _rx) = mpsc::channel(4096);
        assert!(
            run(
                response(reopened.as_bytes(), 1, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn citations_are_complete_scanned_objects_and_keep_original_bytes() {
        fn cited(citation: Value) -> String {
            anthropic(&["safe text"], json!(7)).replace("data: {\"index\":0,\"type\":\"content_block_stop\"}", &format!("{}data: {{\"index\":0,\"type\":\"content_block_stop\"}}", event(json!({"type":"content_block_delta","index":0,"delta":{"type":"citations_delta","citation":citation}}))))
        }
        let good = cited(
            json!({"type":"char_location","cited_text":"公开引用","document_index":0,"document_title":"guide","start_char_index":0,"end_char_index":4}),
        );
        assert!(good.contains("citations_delta"));
        let (tx, mut rx) = mpsc::channel(4096);
        let mut complete = run(
            response(good.as_bytes(), 1, false),
            vec![],
            65536,
            &tx,
            ProfileLlmProtocol::AnthropicMessages,
        )
        .await
        .unwrap();
        let mut output = drain(&mut rx);
        complete.release(&tx).await.unwrap();
        output.extend(drain(&mut rx));
        assert_eq!(output, good.as_bytes());
        for raw in [
            cited(json!({"type":"char_location","cited_text":"synthetic-secret-1234"})),
            cited(
                json!({"type":"web_search_result_location","url":r"https://example.test/synthetic-\u0073ecret-1234"}),
            ),
        ] {
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(matches!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::AnthropicMessages
                )
                .await,
                Err(BrokerError::ResponseSecurityViolation)
            ));
            assert!(!String::from_utf8_lossy(&drain(&mut rx)).contains("citations_delta"));
        }
    }
    #[tokio::test]
    async fn added_initial_values_and_item_identity_cannot_split_one_sdk_string() {
        let prefix = "synthetic-";
        let suffix = "secret-1234";
        let secret = b"synthetic-secret-1234";
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        let cases = [
            (
                "arguments-initial",
                event(
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"function_call","arguments":prefix}}),
                ),
                "response.function_call_arguments.delta",
                "a",
            ),
            (
                "custom-initial",
                event(
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"custom_tool_call","input":prefix}}),
                ),
                "response.custom_tool_call_input.delta",
                "a",
            ),
            (
                "text-part-initial",
                event(
                    json!({"type":"response.content_part.added","output_index":0,"item_id":"a","content_index":0,"part":{"type":"output_text","text":prefix}}),
                ),
                "response.output_text.delta",
                "a",
            ),
            (
                "message-initial",
                event(
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":prefix}]}}),
                ),
                "response.output_text.delta",
                "a",
            ),
            (
                "summary-initial",
                event(
                    json!({"type":"response.reasoning_summary_part.added","output_index":0,"item_id":"a","summary_index":0,"part":{"type":"summary_text","text":prefix}}),
                ),
                "response.reasoning_summary_text.delta",
                "a",
            ),
            (
                "arguments-id-change",
                event(
                    json!({"type":"response.function_call_arguments.delta","output_index":0,"item_id":"a","delta":prefix}),
                ),
                "response.function_call_arguments.delta",
                "b",
            ),
            (
                "custom-id-change",
                event(
                    json!({"type":"response.custom_tool_call_input.delta","output_index":0,"item_id":"a","delta":prefix}),
                ),
                "response.custom_tool_call_input.delta",
                "b",
            ),
        ];
        let mut escaped = Vec::new();
        for (case, first, kind, id) in cases {
            let raw = format!(
                "{created}{first}: {}\n\n{}{terminal}",
                "padding".repeat(100),
                event(
                    json!({"type":kind,"output_index":0,"item_id":id,"content_index":0,"summary_index":0,"delta":suffix})
                )
            );
            let (tx, mut rx) = mpsc::channel(4096);
            let outcome = run(
                response(raw.as_bytes(), 7, false),
                vec![secret.to_vec().into()],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await;
            let mut out = drain(&mut rx);
            let prefix_sent_before_completion = String::from_utf8_lossy(&out).contains(prefix);
            if let Ok(mut complete) = outcome {
                complete.release(&tx).await.unwrap();
                out.extend(drain(&mut rx));
                let suffix_sent = String::from_utf8_lossy(&out).contains(suffix);
                eprintln!(
                    "{case}: initial prefix already emitted={prefix_sent_before_completion}, suffix emitted={suffix_sent}"
                );
                escaped.push(case);
            } else {
                assert!(
                    !prefix_sent_before_completion,
                    "{case}: unsafe initial frame was released"
                );
                assert!(!String::from_utf8_lossy(&out).contains(suffix));
            }
        }
        assert!(
            escaped.is_empty(),
            "unblocked SDK concatenations: {escaped:?}"
        );
    }
    #[tokio::test]
    async fn responses_initial_empty_and_nonempty_values_remain_lossless() {
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        for prefix in ["", "safe initial "] {
            for (added, kind) in [
                (
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"function_call","arguments":prefix}}),
                    "response.function_call_arguments.delta",
                ),
                (
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"custom_tool_call","input":prefix}}),
                    "response.custom_tool_call_input.delta",
                ),
                (
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":prefix}]}}),
                    "response.output_text.delta",
                ),
                (
                    json!({"type":"response.content_part.added","output_index":0,"item_id":"a","content_index":0,"part":{"type":"refusal","refusal":prefix}}),
                    "response.refusal.delta",
                ),
                (
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"reasoning","content":[{"type":"reasoning_text","text":prefix}],"summary":[]}}),
                    "response.reasoning_text.delta",
                ),
                (
                    json!({"type":"response.reasoning_summary_part.added","output_index":0,"item_id":"a","summary_index":0,"part":{"type":"summary_text","text":prefix}}),
                    "response.reasoning_summary_text.delta",
                ),
            ] {
                let raw = format!(
                    "{created}{}{delta}{terminal}",
                    event(added),
                    delta = event(
                        json!({"type":kind,"item_id":"a","output_index":0,"content_index":0,"summary_index":0,"delta":"safe suffix"})
                    )
                );
                let (tx, mut rx) = mpsc::channel(4096);
                let mut complete = run(
                    response(raw.as_bytes(), 1, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiResponses,
                )
                .await
                .unwrap();
                let mut out = drain(&mut rx);
                complete.release(&tx).await.unwrap();
                out.extend(drain(&mut rx));
                assert_eq!(out, raw.as_bytes());
            }
        }
        // Added parts append after any initial snapshot parts, rather than reset
        // their index to zero; both message and reasoning arrays keep this rule.
        for (item_type, array, part_type, event_type, index_field) in [
            (
                "message",
                "content",
                "output_text",
                "response.content_part.added",
                "content_index",
            ),
            (
                "reasoning",
                "content",
                "reasoning_text",
                "response.content_part.added",
                "content_index",
            ),
            (
                "reasoning",
                "summary",
                "summary_text",
                "response.reasoning_summary_part.added",
                "summary_index",
            ),
        ] {
            let mut item = json!({"id":"a","type":item_type});
            item[array] = json!([{"type":part_type,"text":"safe initial"}]);
            let mut added = json!({"type":event_type,"item_id":"a","output_index":0,"part":{"type":part_type,"text":"safe next"}});
            added[index_field] = json!(1);
            let raw = format!(
                "{created}{}{}{terminal}",
                event(json!({"type":"response.output_item.added","output_index":0,"item":item})),
                event(added)
            );
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(raw.as_bytes(), 1, false),
                vec![],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await
            .unwrap();
            let mut out = drain(&mut rx);
            complete.release(&tx).await.unwrap();
            out.extend(drain(&mut rx));
            assert_eq!(out, raw.as_bytes());
        }
    }

    #[tokio::test]
    async fn responses_added_and_done_bind_identity_and_stop_reopened_fields() {
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        let initial = event(
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[]}}),
        );
        for bad in [
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"b","type":"message","content":[]}}),
            json!({"type":"response.output_item.done","output_index":0,"item":{"id":"b","type":"message","content":[]}}),
            json!({"type":"response.content_part.added","item_id":"b","output_index":0,"content_index":0,"part":{"type":"output_text","text":"safe"}}),
            json!({"type":"response.content_part.done","item_id":"b","output_index":0,"content_index":0,"part":{"type":"output_text","text":"safe"}}),
            json!({"type":"response.reasoning_summary_part.done","item_id":"b","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":"safe"}}),
            json!({"type":"response.content_part.added","item_id":"a","output_index":0,"content_index":1,"part":{"type":"refusal","refusal":"safe"}}),
            json!({"type":"response.reasoning_summary_part.added","item_id":"a","output_index":0,"summary_index":1,"part":{"type":"summary_text","text":"safe"}}),
        ] {
            let raw = format!("{created}{initial}{}{terminal}", event(bad));
            let (tx, _rx) = mpsc::channel(4096);
            assert!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiResponses
                )
                .await
                .is_err()
            );
        }
        for done in [
            json!({"type":"response.output_item.done","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"}]}}),
            json!({"type":"response.content_part.done","item_id":"a","output_index":0,"content_index":0,"part":{"type":"output_text","text":"synthetic-"}}),
        ] {
            let raw = format!(
                "{created}{initial}{}{}{terminal}",
                event(done),
                event(
                    json!({"type":"response.output_text.delta","item_id":"a","output_index":0,"content_index":0,"delta":"secret-1234"})
                )
            );
            let (tx, mut rx) = mpsc::channel(4096);
            assert!(
                run(
                    response(raw.as_bytes(), 1, false),
                    vec![b"synthetic-secret-1234".to_vec().into()],
                    65536,
                    &tx,
                    ProfileLlmProtocol::OpenAiResponses
                )
                .await
                .is_err()
            );
            assert!(!String::from_utf8_lossy(&drain(&mut rx)).contains("secret-1234"));
        }
    }
    #[tokio::test]
    async fn done_snapshots_cannot_build_secret_across_sdk_output_text_parts() {
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let initial = event(
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":""}]}}),
        );
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        let next = event(
            json!({"type":"response.content_part.added","output_index":0,"item_id":"a","content_index":1,"part":{"type":"output_text","text":"secret-1234"}}),
        );
        let mut missed = Vec::new();
        for (case, updates) in [
            (
                "text-done",
                format!(
                    "{}{next}",
                    event(
                        json!({"type":"response.output_text.done","output_index":0,"item_id":"a","content_index":0,"text":"synthetic-"})
                    )
                ),
            ),
            (
                "part-done",
                format!(
                    "{}{next}",
                    event(
                        json!({"type":"response.content_part.done","output_index":0,"item_id":"a","content_index":0,"part":{"type":"output_text","text":"synthetic-"}})
                    )
                ),
            ),
            (
                "item-done",
                event(
                    json!({"type":"response.output_item.done","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"},{"type":"output_text","text":"secret-1234"}]}}),
                ),
            ),
            (
                "terminal-snapshot",
                event(
                    json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7},"output":[{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"},{"type":"output_text","text":"secret-1234"}]}]}}),
                ),
            ),
        ] {
            let raw = format!(
                "{created}{initial}{updates}{}",
                if case == "terminal-snapshot" {
                    ""
                } else {
                    terminal.as_str()
                }
            );
            let (tx, mut rx) = mpsc::channel(4096);
            let result = run(
                response(raw.as_bytes(), 7, false),
                vec![b"synthetic-secret-1234".to_vec().into()],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await;
            let mut emitted = drain(&mut rx);
            if let Ok(mut complete) = result {
                complete.release(&tx).await.unwrap();
                emitted.extend(drain(&mut rx));
                let text = String::from_utf8_lossy(&emitted);
                eprintln!(
                    "{case}: prefix emitted={}, suffix emitted={}",
                    text.contains("synthetic-"),
                    text.contains("secret-1234")
                );
                missed.push(case);
            } else {
                let text = String::from_utf8_lossy(&emitted);
                assert!(
                    !(text.contains("synthetic-") && text.contains("secret-1234")),
                    "{case}"
                );
            }
        }
        assert!(
            missed.is_empty(),
            "unblocked SDK snapshot concatenations: {missed:?}"
        );
    }

    #[tokio::test]
    async fn responses_done_replace_text_instead_of_appending_stale_values() {
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let initial = event(
            json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"}]}}),
        );
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        for replacement in [
            json!({"type":"response.output_text.done","output_index":0,"item_id":"a","content_index":0,"text":"secret-1234"}),
            json!({"type":"response.content_part.done","output_index":0,"item_id":"a","content_index":0,"part":{"type":"output_text","text":"secret-1234"}}),
            json!({"type":"response.output_item.done","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":"secret-1234"}]}}),
        ] {
            let raw = format!("{created}{initial}{}{terminal}", event(replacement));
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(raw.as_bytes(), 1, false),
                vec![b"synthetic-secret-1234".to_vec().into()],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await
            .unwrap();
            assert_eq!(complete.output_tokens(), Some(7));
            let mut out = drain(&mut rx);
            assert!(!String::from_utf8_lossy(&out).contains("response.completed"));
            complete.release(&tx).await.unwrap();
            out.extend(drain(&mut rx));
            assert_eq!(out, raw.as_bytes());
        }
        // A replacement that removes output_text must also remove that part
        // from the projection before later output_text is joined.
        for replacement in [
            json!({"type":"response.content_part.done","output_index":0,"item_id":"a","content_index":0,"part":{"type":"refusal","refusal":"safe"}}),
            json!({"type":"response.output_item.done","output_index":0,"item":{"id":"a","type":"message","content":[]}}),
        ] {
            let next = event(
                json!({"type":"response.output_item.added","output_index":1,"item":{"id":"b","type":"message","content":[{"type":"output_text","text":"secret-1234"}]}}),
            );
            let raw = format!("{created}{initial}{}{next}{terminal}", event(replacement));
            let (tx, mut rx) = mpsc::channel(4096);
            let mut complete = run(
                response(raw.as_bytes(), 7, false),
                vec![b"synthetic-secret-1234".to_vec().into()],
                65536,
                &tx,
                ProfileLlmProtocol::OpenAiResponses,
            )
            .await
            .unwrap();
            let mut out = drain(&mut rx);
            complete.release(&tx).await.unwrap();
            out.extend(drain(&mut rx));
            assert_eq!(out, raw.as_bytes());
        }
    }

    #[tokio::test]
    async fn responses_snapshot_projection_uses_output_and_part_order_not_event_order() {
        let created = event(json!({"type":"response.created","response":{"id":"r","output":[]}}));
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        for (initial, replacement) in [
            (
                event(
                    json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":""},{"type":"output_text","text":"secret-1234"}]}}),
                ),
                json!({"type":"response.output_text.done","output_index":0,"item_id":"a","content_index":0,"text":"synthetic-"}),
            ),
            (
                format!(
                    "{}{}",
                    event(
                        json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[]}})
                    ),
                    event(
                        json!({"type":"response.output_item.added","output_index":1,"item":{"id":"b","type":"message","content":[{"type":"output_text","text":"secret-1234"}]}})
                    )
                ),
                json!({"type":"response.output_item.done","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"}]}}),
            ),
            (
                String::new(),
                json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7},"output":[{"id":"a","type":"message","content":[{"type":"output_text","text":"synthetic-"}]},{"id":"b","type":"message","content":[{"type":"output_text","text":"secret-1234"}]}]}}),
            ),
        ] {
            for encoded in [false, true] {
                let ends = replacement["type"] == "response.completed";
                let raw = format!(
                    "{created}{initial}{}{}",
                    event(replacement.clone()),
                    if ends { "" } else { &terminal }
                );
                let raw = if encoded {
                    raw.replace("synthetic-", r"synth\u0065tic-")
                        .replace("secret-1234", r"\u0073ecret-1234")
                } else {
                    raw
                };
                let (tx, _rx) = mpsc::channel(4096);
                assert!(matches!(
                    run(
                        response(raw.as_bytes(), 1, false),
                        vec![b"synthetic-secret-1234".to_vec().into()],
                        65536,
                        &tx,
                        ProfileLlmProtocol::OpenAiResponses
                    )
                    .await,
                    Err(BrokerError::ResponseSecurityViolation)
                ));
            }
        }
    }

    #[tokio::test]
    async fn responses_snapshot_projection_is_charged_to_the_response_bound() {
        let created = json!({"type":"response.created","response":{"id":"r","output":[]}});
        let empty = json!({"type":"response.output_item.added","output_index":0,"item":{"id":"a","type":"message","content":[{"type":"output_text","text":""}]}});
        let mut observer = Observer::new(ProfileLlmProtocol::OpenAiResponses);
        observer.event(None, &created, 0, 0, &[]).unwrap();
        observer.event(None, &empty, 0, 0, &[]).unwrap();
        let before = observer.retained();
        let text = "safe ".repeat(1024);
        let done = json!({"type":"response.output_text.done","output_index":0,"item_id":"a","content_index":0,"text":text});
        observer.event(None, &done, 0, 0, &[]).unwrap();
        assert!(observer.retained() >= before + text.len());
        let terminal = event(
            json!({"type":"response.completed","response":{"id":"r","object":"response","status":"completed","usage":{"output_tokens":7}}}),
        );
        let raw = format!(
            "{}{}{}{terminal}",
            event(created),
            event(empty),
            event(done)
        );
        let (tx, _rx) = mpsc::channel(4096);
        assert!(
            run(
                response(raw.as_bytes(), 1, false),
                vec![],
                raw.len(),
                &tx,
                ProfileLlmProtocol::OpenAiResponses
            )
            .await
            .is_err()
        );
    }
}
