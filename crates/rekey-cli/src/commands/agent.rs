//! Public, token-free Agent commands. Credentials stay behind the IPC boundary.
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_domain::action::FixedMethod;
use rekey_domain::ids::{ApprovalRequestId, RequestId};
use rekey_domain::ipc::{
    AwaitAccessMeta, AwaitAccessResponse, AwaitUnlockMeta, AwaitUnlockResponse, CallMeta,
    CallResponseMetadata, Channel, DescribeMeta, DescribeResponse, ListCapabilitiesResponse,
    LocalApprovalState, LocalApprovalStateResponse, LocalAwaitApprovalMeta,
    LocalCancelApprovalMeta, RequestAccessMeta, RequestAccessResponse, agent_msg,
};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::client::{CliError, Client};

fn metadata(value: &impl Serialize) -> Result<Vec<u8>, CliError> {
    serde_json::to_vec(value)
        .map_err(|_| CliError::local("INVALID_INPUT", "cannot encode Agent request"))
}
fn public(
    socket: &Path,
    opcode: u16,
    value: &impl Serialize,
    timeout_s: u16,
) -> Result<Value, CliError> {
    let (meta, body) = Client::connect_with_response_timeout(
        socket,
        Channel::Agent,
        Duration::from_secs(u64::from(timeout_s) + 10),
    )?
    .call(opcode, &metadata(value)?, &[])?;
    let envelope: Value = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public response metadata"))?;
    if envelope != json!({}) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "public response metadata must be empty",
        ));
    }
    serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public response body"))
}
pub fn list(socket: &Path, as_json: bool) -> Result<(), CliError> {
    let inventory = public(socket, agent_msg::LIST_CAPABILITIES, &json!({}), 30)?;
    let typed: ListCapabilitiesResponse = serde_json::from_value(inventory.clone())
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid capabilities response"))?;
    if as_json {
        return super::write_json(&inventory);
    }
    let mut output = std::io::stdout().lock();
    for connection in typed.connections {
        writeln!(
            output,
            "{}  {}  read={:?} write={:?} grade={:?}",
            connection.connection,
            connection.origin.as_str(),
            connection.read,
            connection.write,
            connection.grade
        )
        .map_err(|e| CliError::local("OUTPUT_FAILED", e.to_string()))?;
        for operation in connection.operations {
            writeln!(output, "  {}", operation.name)
                .map_err(|e| CliError::local("OUTPUT_FAILED", e.to_string()))?;
        }
    }
    for grant in typed.derived_credentials {
        writeln!(
            output,
            "{}  T1 {} effect={:?} max_ttl={}s; Agent receives temporary credentials",
            grant.connection, grant.kind, grant.effect, grant.max_ttl_seconds
        )
        .map_err(|e| CliError::local("OUTPUT_FAILED", e.to_string()))?;
    }
    if let Some(url) = typed.service_url {
        writeln!(output, "Local service: {url}; placeholder key: rekey")
            .map_err(|e| CliError::local("OUTPUT_FAILED", e.to_string()))?;
    }
    Ok(())
}
pub fn describe(socket: &Path, operation: String) -> Result<(), CliError> {
    let response: DescribeResponse = decode(public(
        socket,
        agent_msg::DESCRIBE,
        &DescribeMeta { operation },
        30,
    )?)?;
    super::write_json(&response)
}
pub fn request(
    socket: &Path,
    provider: String,
    operation: Option<String>,
    reason: String,
) -> Result<(), CliError> {
    let response: RequestAccessResponse = decode(public(
        socket,
        agent_msg::REQUEST_ACCESS,
        &RequestAccessMeta {
            provider: Some(provider),
            connection: None,
            operation,
            reason,
        },
        30,
    )?)?;
    super::write_json(&response)
}
pub fn await_access(socket: &Path, request_id: RequestId, timeout_s: u16) -> Result<(), CliError> {
    let response: AwaitAccessResponse = decode(public(
        socket,
        agent_msg::AWAIT_ACCESS,
        &AwaitAccessMeta {
            request_id,
            timeout_s,
        },
        timeout_s,
    )?)?;
    super::write_json(&response)
}
pub fn await_unlock(socket: &Path, timeout_s: u16) -> Result<(), CliError> {
    let response: AwaitUnlockResponse = decode(public(
        socket,
        agent_msg::AWAIT_UNLOCK,
        &AwaitUnlockMeta { timeout_s },
        timeout_s,
    )?)?;
    super::write_json(&response)
}
fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, CliError> {
    serde_json::from_value(value)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public response fields"))
}
fn approval_state(
    value: Value,
    request_id: ApprovalRequestId,
) -> Result<LocalApprovalStateResponse, CliError> {
    let response: LocalApprovalStateResponse = decode(value)?;
    if response.approval_request_id != request_id || response.expires_at_ms <= 0 {
        return Err(CliError::local(
            "INVALID_FRAME",
            "approval response does not match request",
        ));
    }
    Ok(response)
}
pub fn approval(
    socket: &Path,
    request_id: ApprovalRequestId,
    timeout_s: u16,
    cancel: bool,
) -> Result<(), CliError> {
    let result = if cancel {
        public(
            socket,
            agent_msg::CANCEL_APPROVAL,
            &LocalCancelApprovalMeta { request_id },
            30,
        )?
    } else {
        public(
            socket,
            agent_msg::AWAIT_APPROVAL,
            &LocalAwaitApprovalMeta {
                request_id,
                timeout_s,
            },
            timeout_s,
        )?
    };
    super::write_json(&approval_state(result, request_id)?)
}

#[derive(Default)]
struct CallOptions {
    args: BTreeMap<String, String>,
    query: BTreeMap<String, String>,
    headers: Vec<(String, String)>,
    body_file: Option<PathBuf>,
    dry_run: bool,
    no_wait: bool,
    approval: Option<ApprovalRequestId>,
}
fn parse_call_options(raw: &[String]) -> Result<CallOptions, CliError> {
    let mut options = CallOptions::default();
    let mut input = raw.iter();
    while let Some(flag) = input.next() {
        if flag == "--dry-run" {
            options.dry_run = true;
            continue;
        }
        if flag == "--no-wait" {
            options.no_wait = true;
            continue;
        }
        let name = flag
            .strip_prefix("--")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| CliError::local("USAGE", "operation parameters use --name value"))?;
        let (name, inline) = name
            .split_once('=')
            .map_or((name, None), |(a, b)| (a, Some(b)));
        let value = inline
            .or_else(|| input.next().map(String::as_str))
            .ok_or_else(|| CliError::local("USAGE", "operation option requires a value"))?;
        match name {
            "body-file" => options.body_file = Some(PathBuf::from(value)),
            "approval" => {
                options.approval = Some(
                    value
                        .parse()
                        .map_err(|_| CliError::local("USAGE", "invalid approval request ID"))?,
                )
            }
            "query" => {
                let (key, value) = value
                    .split_once('=')
                    .ok_or_else(|| CliError::local("USAGE", "query uses name=value"))?;
                if options.query.insert(key.into(), value.into()).is_some() {
                    return Err(CliError::local("USAGE", "duplicate query parameter"));
                }
            }
            "header" => {
                let (key, value) = value
                    .split_once(':')
                    .ok_or_else(|| CliError::local("USAGE", "header uses name:value"))?;
                options
                    .headers
                    .push((key.trim().into(), value.trim().into()));
            }
            _ => {
                if options.args.insert(name.into(), value.into()).is_some() {
                    return Err(CliError::local("USAGE", "duplicate operation parameter"));
                }
            }
        }
    }
    Ok(options)
}
pub fn call(socket: &Path, operation: String, raw: Vec<String>) -> Result<(), CliError> {
    let options = parse_call_options(&raw)?;
    let mut request = CallMeta::operation(operation, options.args);
    request.query = options.query;
    request.headers = options.headers;
    request.dry_run = options.dry_run;
    request.approval_request_id = options.approval;
    let body = match options.body_file {
        Some(path) => super::read_regular_file_bounded(
            &path,
            rekey_domain::ipc::AGENT_BODY_MAX_BYTES as usize,
            "request body",
        )?,
        None => Zeroizing::new(Vec::new()),
    };
    execute(socket, request, &body, options.no_wait)
}
#[allow(clippy::too_many_arguments)]
pub fn http(
    socket: &Path,
    connection: String,
    method: String,
    path: String,
    json_body: Option<String>,
    body_file: Option<PathBuf>,
    query: Vec<String>,
    headers: Vec<String>,
    dry_run: bool,
    no_wait: bool,
    approval: Option<ApprovalRequestId>,
) -> Result<(), CliError> {
    let method = FixedMethod::parse(&method.to_ascii_uppercase())
        .map_err(|_| CliError::local("USAGE", "unsupported HTTP method"))?;
    let mut request = CallMeta::http(connection, method, path);
    request.query = super::policy_approval::request_values(&query)?;
    request.headers = super::policy_approval::request_headers(&headers)?;
    request.dry_run = dry_run;
    request.approval_request_id = approval;
    let body = if let Some(text) = json_body {
        serde_json::from_str::<Value>(&text)
            .map_err(|_| CliError::local("USAGE", "request JSON is invalid"))?;
        request
            .headers
            .push(("content-type".into(), "application/json".into()));
        Zeroizing::new(text.into_bytes())
    } else {
        super::policy_approval::request_body(body_file.as_deref())?
    };
    execute(socket, request, &body, no_wait)
}
fn execute(
    socket: &Path,
    mut request: CallMeta,
    body: &[u8],
    no_wait: bool,
) -> Result<(), CliError> {
    let invoke = |request: &CallMeta| {
        Client::connect_with_response_timeout(socket, Channel::Agent, Duration::from_secs(130))?
            .call(agent_msg::CALL, &metadata(request)?, body)
    };
    let (meta, body) = match invoke(&request) {
        Err(error) if error.code == "APPROVAL_REQUIRED" && !no_wait && !request.dry_run => {
            let Some(challenge) = error.approval.as_ref() else {
                return Err(error);
            };
            let decision = public(
                socket,
                agent_msg::AWAIT_APPROVAL,
                &LocalAwaitApprovalMeta {
                    request_id: challenge.challenge_id,
                    timeout_s: 120,
                },
                120,
            )?;
            let decision = approval_state(decision, challenge.challenge_id)?;
            if decision.state != LocalApprovalState::Approved {
                return Err(error);
            }
            request.approval_request_id = Some(challenge.challenge_id);
            invoke(&request)?
        }
        result => result?,
    };
    if request.dry_run {
        if serde_json::from_slice::<Value>(&meta).ok() != Some(json!({})) {
            return Err(CliError::local("INVALID_FRAME", "invalid dry-run metadata"));
        }
        let preview: Value = serde_json::from_slice(&body)
            .map_err(|_| CliError::local("INVALID_FRAME", "invalid dry-run body"))?;
        return super::write_json(&preview);
    }
    let metadata: CallResponseMetadata = serde_json::from_slice(&meta)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid call response metadata"))?;
    let content = match metadata.body_encoding.as_str() {
        "text" => std::str::from_utf8(&body)
            .map_err(|_| CliError::local("INVALID_FRAME", "call response is invalid UTF-8"))?
            .to_owned(),
        "base64" => data_encoding::BASE64.encode(&body),
        _ => {
            return Err(CliError::local(
                "INVALID_FRAME",
                "unsupported call body encoding",
            ));
        }
    };
    super::write_json(
        &json!({"status":metadata.status,"headers":metadata.headers,"body":content,"body_encoding":metadata.body_encoding}),
    )?;
    if !(200..300).contains(&metadata.status) {
        return Err(CliError::local(
            "UPSTREAM_ERROR",
            "upstream returned a non-success status; inspect the sealed response",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn named_args_keep_public_options_out_of_operation_parameters() {
        let raw = [
            "--owner",
            "example",
            "--repo=project",
            "--title",
            "Bug report",
            "--dry-run",
            "--no-wait",
            "--query",
            "page=2",
            "--header",
            "Accept: application/json",
        ]
        .map(str::to_owned);
        let options = parse_call_options(&raw).unwrap();
        assert_eq!(options.args["title"], "Bug report");
        assert_eq!(options.args["repo"], "project");
        assert!(options.dry_run && options.no_wait);
        assert_eq!(options.query["page"], "2");
        assert_eq!(
            options.headers,
            [("Accept".into(), "application/json".into())]
        );
        assert!(!options.args.contains_key("dry-run"));
        assert!(parse_call_options(&["--owner".into()]).is_err());
        assert!(
            parse_call_options(&["--owner".into(), "a".into(), "--owner".into(), "b".into()])
                .is_err()
        );
    }
}
