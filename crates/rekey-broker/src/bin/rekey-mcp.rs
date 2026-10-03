//! Local MCP transport only. Authority stays behind the agent socket.
// Share the existing pure IPC implementation without adding a CLI dependency.
#[allow(dead_code)]
#[path = "../../../rekey-cli/src/client.rs"]
mod client;

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use rekey_connector::{McpToolDescriptor, adapt_mcp_invocation};
use rekey_domain::action::FixedMethod;
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::{
    Channel, ExecuteResponseMeta, LocalApprovalStateResponse, ProfileActionDefinition,
    ProfileInventoryMeta, ProfileInventoryResponse, agent_msg,
};
use rekey_domain::template::{TemplateValues, ValueRule};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
const VERSION: &str = "2025-11-25";

struct Tool {
    descriptor: McpToolDescriptor,
    operations: BTreeMap<String, ProfileActionDefinition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    operation: Option<String>,
    #[serde(default)]
    params: TemplateValues,
    #[serde(default)]
    query: TemplateValues,
    body: Option<Value>,
    approval_challenge: Option<ApprovalRequestId>,
}

fn value_schema(rules: &BTreeMap<String, ValueRule>, required: bool) -> Value {
    let properties: serde_json::Map<String, Value> = rules.iter().map(|(key, rule)| {
        let schema = match rule {
            ValueRule::Slug => json!({"type":"string","maxLength":100,"pattern":"^[A-Za-z0-9][A-Za-z0-9._-]*$"}),
            ValueRule::Int { min, max } => json!({"type":"string","pattern":"^-?[0-9]+$","description":format!("Decimal integer from {min} through {max}")}),
            ValueRule::Enum(values) => json!({"type":"string","enum":values}),
        };
        (key.clone(), schema)
    }).collect();
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":if required {rules.keys().cloned().collect::<Vec<_>>()} else {Vec::new()}})
}

fn invocation_schema(action: &ProfileActionDefinition, operation: Option<&str>) -> Value {
    let params = action.target.params();
    let query = action.target.query();
    let mut properties = json!({
        "params":value_schema(params, true), "query":value_schema(query, false),
        "approval_challenge":{"type":"string","format":"uuid","description":"After approval, explicitly repeat the original request with its challenge ID. Never retry a completed or indeterminate write."}
    });
    let mut required = Vec::new();
    if let Some(operation) = operation {
        properties["operation"] = json!({"type":"string","const":operation});
        required.push("operation");
    }
    if !params.is_empty() {
        required.push("params");
    }
    if action.method != FixedMethod::Get {
        properties["body"] = match &action.body_schema {
            Some(schema) => json!({"allOf":[{"type":"object"},schema]}),
            None => json!({"type":"object"}),
        };
        required.push("body");
    }
    json!({"type":"object","additionalProperties":false,"properties":properties,"required":required,
        "description":format!("{} {}{}", action.method.as_str(), action.origin.as_str(), action.target.path_pattern())})
}

fn inventory_tools(
    inventory: ProfileInventoryResponse,
) -> Result<BTreeMap<String, Tool>, client::CliError> {
    let invalid = || client::CliError::local("INVALID_FRAME", "invalid Profile inventory");
    let mut definitions = BTreeMap::new();
    for action in inventory.actions {
        if definitions
            .insert((action.action_id, action.version), action)
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut tools = BTreeMap::new();
    for grant in inventory.profile.grants {
        for capability in grant.capabilities {
            let mut operations = BTreeMap::new();
            for reference in capability.actions {
                let action = definitions
                    .remove(&(reference.action_id, reference.version))
                    .ok_or_else(invalid)?;
                if operations
                    .insert(action.action_index.to_string(), action)
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            let anchor = operations
                .values()
                .min_by_key(|action| action.action_index)
                .ok_or_else(invalid)?;
            let name = format!("rekey.{}.v{}", anchor.action_id, anchor.version);
            let input_schema = if operations.len() == 1 {
                invocation_schema(anchor, None)
            } else {
                json!({"type":"object","oneOf":operations.iter().map(|(operation, action)|invocation_schema(action, Some(operation))).collect::<Vec<_>>()})
            };
            let descriptor = McpToolDescriptor { name: name.clone(), title: format!("{} / {}", grant.instance, capability.capability),
                description: "Execute a Profile-authorized template capability. Current policy and approval still apply.".into(), input_schema };
            if tools
                .insert(
                    name,
                    Tool {
                        descriptor,
                        operations,
                    },
                )
                .is_some()
            {
                return Err(invalid());
            }
        }
    }
    if !definitions.is_empty() || tools.is_empty() {
        return Err(invalid());
    }
    Ok(tools)
}

fn approval_tool(name: &str) -> Value {
    json!({"name":name,"description":if name == "await_approval" {"Wait up to 120 seconds for your local approval. This never approves or executes an action."} else {"Cancel your local approval request. This never executes an action."},"inputSchema":{"type":"object","additionalProperties":false,"properties":{"challenge_id":{"type":"string","format":"uuid"}},"required":["challenge_id"]}})
}

struct Server {
    socket: PathBuf,
    token: Zeroizing<String>,
    tools: BTreeMap<String, Tool>,
    initialized: bool,
    ready: bool,
}

impl Server {
    fn from_environment() -> Self {
        Self {
            socket: std::env::var_os("REKEY_AGENT_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_default(),
            token: Zeroizing::new(std::env::var("REKEY_CAPABILITY").unwrap_or_default()),
            tools: BTreeMap::new(),
            initialized: false,
            ready: false,
        }
    }

    fn require_session(&self) -> Result<(), client::CliError> {
        if self.token.is_empty() || self.socket.as_os_str().is_empty() {
            return Err(client::CliError::local(
                "NEEDS_SESSION",
                "Run rekey run to provide a Profile session",
            ));
        }
        if !self.socket.is_absolute() {
            return Err(client::CliError::local(
                "IPC_UNAVAILABLE",
                "agent socket must be absolute",
            ));
        }
        Ok(())
    }

    fn refresh_tools(&mut self) -> Result<(), client::CliError> {
        // The previous list is never a source of authority, including failures.
        self.tools.clear();
        self.require_session()?;
        let metadata = Zeroizing::new(
            serde_json::to_vec(&ProfileInventoryMeta {
                capability_token: self.token.to_string(),
            })
            .map_err(|_| {
                client::CliError::local("INVALID_FRAME", "cannot encode inventory request")
            })?,
        );
        let (metadata, body) = client::Client::connect(&self.socket, Channel::Agent)?.call(
            agent_msg::PROFILE_INVENTORY,
            &metadata,
            &[],
        )?;
        let public: Value = serde_json::from_slice(&metadata)
            .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid inventory metadata"))?;
        if public.as_object().is_none_or(|value| !value.is_empty()) {
            return Err(client::CliError::local(
                "INVALID_FRAME",
                "invalid inventory metadata",
            ));
        }
        let inventory = serde_json::from_slice(&body)
            .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid inventory body"))?;
        self.tools = inventory_tools(inventory)?;
        Ok(())
    }

    fn handle(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request.get("method").and_then(Value::as_str);
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || method.is_none()
            || request
                .get("id")
                .is_some_and(|v| !v.is_string() && !v.is_i64() && !v.is_u64())
            || request.get("params").is_some_and(|v| !v.is_object())
        {
            return Some(error(Value::Null, -32600, "Invalid request"));
        }
        let method = method.unwrap();
        if request.get("id").is_none() {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            return None;
        }
        let params = &request["params"];
        let result = match method {
            "initialize" if !self.initialized => {
                if !params["protocolVersion"].is_string()
                    || !params["capabilities"].is_object()
                    || !params["clientInfo"]["name"].is_string()
                    || !params["clientInfo"]["version"].is_string()
                {
                    return Some(error(id, -32602, "Invalid initialization parameters"));
                }
                self.initialized = true;
                let version = if params["protocolVersion"] == "2025-06-18" {
                    "2025-06-18"
                } else {
                    VERSION
                };
                json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"rekey-mcp","version":env!("CARGO_PKG_VERSION")},"instructions":"Only operator-authorized fixed actions are available. Await approval, then explicitly repeat the same request with approval_challenge. Never retry completed or indeterminate writes."})
            }
            "ping" => json!({}),
            _ if !self.ready => return Some(error(id, -32600, "Complete initialization first")),
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Some(error(id, -32602, "Cursor is not supported"));
                }
                if let Err(failure) = self.refresh_tools() {
                    return Some(
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Rekey inventory unavailable","data":public_error(&failure)}}),
                    );
                }
                let mut tools = self
                    .tools
                    .values()
                    .map(|tool| {
                        serde_json::to_value(&tool.descriptor).expect("serializable descriptor")
                    })
                    .collect::<Vec<_>>();
                tools.extend([
                    approval_tool("await_approval"),
                    approval_tool("cancel_approval"),
                ]);
                json!({"tools":tools})
            }
            "tools/call"
                if matches!(
                    params["name"].as_str(),
                    Some("await_approval" | "cancel_approval")
                ) =>
            {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ApprovalArguments {
                    challenge_id: ApprovalRequestId,
                }
                let Ok(arguments) =
                    serde_json::from_value::<ApprovalArguments>(params["arguments"].clone())
                else {
                    return Some(error(id, -32602, "A challenge_id is required"));
                };
                if let Err(failure) = self.require_session() {
                    return Some(json!({"jsonrpc":"2.0","id":id,"result":broker_error(&failure)}));
                }
                let await_decision = params["name"] == "await_approval";
                #[derive(Serialize)]
                struct ApprovalRequest<'a> {
                    capability_token: &'a str,
                    approval_request_id: ApprovalRequestId,
                }
                let mut meta = Zeroizing::new(Vec::new());
                if serde_json::to_writer(
                    &mut *meta,
                    &ApprovalRequest {
                        capability_token: &self.token,
                        approval_request_id: arguments.challenge_id,
                    },
                )
                .is_err()
                {
                    return Some(error(id, -32603, "Cannot encode broker request"));
                }
                let result = client::Client::connect_with_response_timeout(
                    &self.socket,
                    Channel::Agent,
                    if await_decision {
                        Duration::from_secs(130)
                    } else {
                        client::IO_TIMEOUT
                    },
                )
                .and_then(|mut client| {
                    client.call(
                        if await_decision {
                            agent_msg::AWAIT_APPROVAL
                        } else {
                            agent_msg::CANCEL_APPROVAL
                        },
                        &meta,
                        &[],
                    )
                });
                match result {
                    Ok((metadata, body)) if body.is_empty() => {
                        match serde_json::from_slice::<LocalApprovalStateResponse>(&metadata) {
                            Ok(state)
                                if state.approval_request_id == arguments.challenge_id
                                    && state.expires_at_ms > 0 =>
                            {
                                let result = json!({"challenge_id":state.approval_request_id,"state":state.state,"expires_at_ms":state.expires_at_ms});
                                json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":false})
                            }
                            _ => tool_error("INVALID_FRAME"),
                        }
                    }
                    Ok(_) => tool_error("INVALID_FRAME"),
                    Err(error) => broker_error(&error),
                }
            }
            "tools/call" => {
                if let Err(failure) = self.refresh_tools() {
                    return Some(json!({"jsonrpc":"2.0","id":id,"result":broker_error(&failure)}));
                }
                let Some(tool) = params["name"]
                    .as_str()
                    .and_then(|name| self.tools.get(name))
                else {
                    return Some(error(id, -32602, "Unknown tool"));
                };
                let raw_arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let Ok(arguments) = serde_json::from_value::<Arguments>(raw_arguments.clone())
                else {
                    return Some(error(id, -32602, "Invalid Rekey tool arguments"));
                };
                let action = if tool.operations.len() == 1 {
                    if raw_arguments.get("operation").is_some() {
                        return Some(error(
                            id,
                            -32602,
                            "This capability does not accept an operation",
                        ));
                    }
                    tool.operations
                        .values()
                        .next()
                        .expect("nonempty projected tool")
                } else {
                    let Some(action) = arguments
                        .operation
                        .as_ref()
                        .and_then(|operation| tool.operations.get(operation))
                    else {
                        return Some(error(id, -32602, "Select a declared operation"));
                    };
                    action
                };
                let action_ref = ActionVersionRef {
                    action_id: action.action_id,
                    version: action.version,
                };
                let (content_type, body) = if action.method == FixedMethod::Get {
                    if raw_arguments.get("body").is_some() {
                        return Some(error(id, -32602, "GET actions do not accept a body"));
                    }
                    (None, Vec::new())
                } else {
                    let Some(body) = arguments.body else {
                        return Some(error(id, -32602, "A body object is required"));
                    };
                    let Ok(invocation) = adapt_mcp_invocation(action_ref, &body) else {
                        return Some(error(id, -32602, "The body must be an object"));
                    };
                    (
                        (!action.fixed_content_type).then_some(invocation.content_type),
                        invocation.body,
                    )
                };
                #[derive(Serialize)]
                struct Execute<'a> {
                    capability_token: &'a str,
                    action_id: rekey_domain::ids::ActionId,
                    action_version: u64,
                    content_type: Option<&'a str>,
                    extra_headers: &'a [(String, String)],
                    params: &'a TemplateValues,
                    query: &'a TemplateValues,
                    approval_grants: [String; 0],
                    local_approval_request_id: Option<ApprovalRequestId>,
                }
                let metadata = Execute {
                    capability_token: &self.token,
                    action_id: action_ref.action_id,
                    action_version: action_ref.version,
                    content_type,
                    extra_headers: &[],
                    params: &arguments.params,
                    query: &arguments.query,
                    approval_grants: [],
                    local_approval_request_id: arguments.approval_challenge,
                };
                let mut meta = Zeroizing::new(Vec::new());
                if serde_json::to_writer(&mut *meta, &metadata).is_err() {
                    return Some(error(id, -32603, "Cannot encode broker request"));
                }
                let execution = client::Client::connect_with_response_timeout(
                    &self.socket,
                    Channel::Agent,
                    Duration::from_secs(130),
                )
                .and_then(|mut client| {
                    client.call(agent_msg::EXECUTE_FIXED_HTTP_ACTION, &meta, &body)
                });
                match execution {
                    Ok((metadata, body)) => {
                        match serde_json::from_slice::<ExecuteResponseMeta>(&metadata) {
                            Ok(metadata) if metadata.body_len as usize == body.len() => {
                                execution_result(metadata, &body)
                            }
                            _ => tool_error("INVALID_FRAME"),
                        }
                    }
                    Err(err) => broker_error(&err),
                }
            }
            _ => return Some(error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

fn tool_error(code: &str) -> Value {
    json!({"isError":true,"content":[{"type":"text","text":format!("Rekey failed ({code}). Ask the operator to inspect access and audit records. Completion may be indeterminate; do not retry writes automatically.")}]})
}

fn public_error(error: &client::CliError) -> Value {
    let mut result = json!({"code":error.code,"retryable":error.retryable});
    if let Some(approval) = &error.approval {
        result["approval"] = json!(approval);
    }
    if error.code == "NEEDS_SESSION" {
        result["message"] = json!("Run rekey run to provide a Profile session");
    }
    result
}

fn broker_error(error: &client::CliError) -> Value {
    let result = public_error(error);
    json!({"isError":true,"structuredContent":result,"content":[{"type":"text","text":result.to_string()}]})
}

fn execution_result(metadata: ExecuteResponseMeta, body: &[u8]) -> Value {
    let mime = metadata
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
        .unwrap_or("application/octet-stream");
    let media_type = mime
        .split(';')
        .next()
        .unwrap_or(mime)
        .trim()
        .to_ascii_lowercase();
    let content = if media_type.starts_with("text/") || media_type == "application/json" {
        let Ok(text) = std::str::from_utf8(body) else {
            return tool_error("INVALID_FRAME");
        };
        json!({"type":"text","text":text})
    } else {
        json!({"type":"resource","resource":{"uri":"rekey:///response","mimeType":mime,"blob":data_encoding::BASE64.encode(body)}})
    };
    json!({"content":[content],"structuredContent":{"upstream_status":metadata.upstream_status,"headers":metadata.headers,"mime_type":mime},"isError":!(200..300).contains(&metadata.upstream_status)})
}

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !args.is_empty() {
        return Err("usage: rekey-mcp (inside rekey run)");
    }
    let mut server = Server::from_environment();
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    loop {
        let mut line = Vec::new();
        let count = input
            .by_ref()
            .take((LIMIT + 1) as u64)
            .read_until(b'\n', &mut line)
            .map_err(|_| "cannot read MCP input")?;
        if count == 0 {
            return Ok(());
        }
        if count > LIMIT {
            return Err("MCP input exceeds 1 MiB");
        }
        let response = match serde_json::from_slice(&line) {
            Ok(request) => server.handle(request),
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)
                .map_err(|_| "cannot write MCP response")?;
            output
                .write_all(b"\n")
                .and_then(|_| output.flush())
                .map_err(|_| "cannot flush MCP response")?;
        }
    }
}

fn main() {
    if let Err(message) = run() {
        eprintln!("rekey-mcp: {message}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ipc::{FRAME_HEADER_LEN, FrameHeader, resp_msg};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn request_header(stream: &mut std::os::unix::net::UnixStream) -> FrameHeader {
        let mut header = [0; FRAME_HEADER_LEN];
        // The real client verifies the peer after connect, before writing.
        // Start the fixture's short frame budget only once that work is done.
        stream.set_read_timeout(Some(client::IO_TIMEOUT)).unwrap();
        stream.read_exact(&mut header[..1]).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.read_exact(&mut header[1..]).unwrap();
        FrameHeader::decode(&header).unwrap()
    }

    fn response(mime: &str) -> ExecuteResponseMeta {
        serde_json::from_value(
            json!({"upstream_status":403,"headers":[["Content-Type",mime]],"body_len":2}),
        )
        .unwrap()
    }

    #[test]
    fn response_preserves_mime_status_and_strict_text_or_binary() {
        let text = execution_result(response("application/json; charset=utf-8"), b"{}");
        assert_eq!(text["content"][0]["text"], "{}");
        assert_eq!(text["structuredContent"]["upstream_status"], 403);
        assert_eq!(text["isError"], true);
        let invalid = execution_result(response("text/plain"), &[255, 254]);
        assert!(
            invalid["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("INVALID_FRAME")
        );
        let binary = execution_result(response("application/octet-stream"), &[255, 254]);
        assert_eq!(binary["content"][0]["type"], "resource");
        assert_eq!(
            binary["content"][0]["resource"]["mimeType"],
            "application/octet-stream"
        );
        assert_eq!(binary["content"][0]["resource"]["blob"], "//4=");
    }

    #[test]
    fn arguments_keep_approval_and_target_outside_the_body() {
        let challenge = ApprovalRequestId::new_random();
        let arguments: Arguments = serde_json::from_value(json!({"body":{"approval_challenge":"body text"},"params":{"owner":"example"},"query":{"page":"2"},"approval_challenge":challenge})).unwrap();
        assert_eq!(arguments.approval_challenge, Some(challenge));
        assert_eq!(arguments.body.unwrap()["approval_challenge"], "body text");
        assert_eq!(arguments.params["owner"], "example");
        assert_eq!(arguments.query["page"], "2");
        for invalid in [
            json!({"body":{},"capability":"override"}),
            json!({"body":{},"approval_challenge":"bad"}),
            json!({"body":{},"query":{"page":2}}),
        ] {
            assert!(serde_json::from_value::<Arguments>(invalid).is_err());
        }
    }

    #[test]
    fn approval_required_retains_typed_fields_without_echoing_broker_text() {
        let challenge = ApprovalRequestId::new_random();
        let mut error = client::CliError::local("APPROVAL_REQUIRED", "never echo this");
        error.approval = Some(rekey_domain::ipc::ApprovalRequired {
            challenge_id: challenge,
            expires_at_ms: 1234,
        });
        let result = broker_error(&error);
        assert_eq!(
            result["structuredContent"]["approval"]["challenge_id"],
            challenge.to_string()
        );
        assert_eq!(result["structuredContent"]["retryable"], false);
        assert!(!result.to_string().contains("never echo this"));
        let text: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(text, result["structuredContent"]);
    }

    #[test]
    fn protocol_negotiation_only_claims_implemented_versions() {
        for (requested, expected) in [
            ("2025-06-18", "2025-06-18"),
            ("2025-11-25", "2025-11-25"),
            ("2099-01-01", "2025-11-25"),
        ] {
            let mut server = Server {
                socket: PathBuf::new(),
                token: Zeroizing::new(String::new()),
                tools: BTreeMap::new(),
                initialized: false,
                ready: false,
            };
            let response = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":requested,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).unwrap();
            assert_eq!(response["result"]["protocolVersion"], expected);
        }
    }

    #[test]
    fn approval_controls_use_only_agent_owner_api_and_validate_response() {
        for (name, state, wrong_id, response_body, expiry, valid) in [
            ("await_approval", "approved", false, false, 1234, true),
            ("await_approval", "pending", false, false, 1234, true),
            ("cancel_approval", "cancelled", false, false, 1234, true),
            ("await_approval", "approved", true, false, 1234, false),
            ("await_approval", "approved", false, true, 1234, false),
            ("await_approval", "approved", false, false, 0, false),
        ] {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let socket = directory.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            let challenge = ApprovalRequestId::new_random();
            let receiver = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let request = request_header(&mut stream);
                assert_eq!(request.channel, Channel::Agent);
                assert_eq!(request.body_len, 0);
                assert_eq!(
                    request.message_type,
                    if name == "await_approval" {
                        agent_msg::AWAIT_APPROVAL
                    } else {
                        agent_msg::CANCEL_APPROVAL
                    }
                );
                let mut metadata = vec![0; request.metadata_len as usize];
                stream.read_exact(&mut metadata).unwrap();
                let metadata: Value = serde_json::from_slice(&metadata).unwrap();
                assert_eq!(
                    metadata,
                    json!({"capability_token":"synthetic-capability","approval_request_id":challenge})
                );
                let reply_id = if wrong_id {
                    ApprovalRequestId::new_random()
                } else {
                    challenge
                };
                let metadata =
                    json!({"approval_request_id":reply_id,"state":state,"expires_at_ms":expiry})
                        .to_string();
                let header = FrameHeader {
                    channel: Channel::Agent,
                    flags: 0,
                    message_type: resp_msg::OK,
                    request_id: request.request_id,
                    metadata_len: metadata.len() as u32,
                    body_len: u32::from(response_body),
                };
                stream.write_all(&header.encode()).unwrap();
                stream.write_all(metadata.as_bytes()).unwrap();
                if response_body {
                    stream.write_all(&[0]).unwrap();
                }
            });
            let mut server = Server {
                socket,
                token: Zeroizing::new("synthetic-capability".to_owned()),
                tools: BTreeMap::new(),
                initialized: true,
                ready: true,
            };
            let reply = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{"challenge_id":challenge}}})).unwrap();
            receiver.join().unwrap();
            assert_eq!(reply["result"]["isError"], !valid);
            if valid {
                assert_eq!(reply["result"]["structuredContent"]["state"], state);
            } else {
                assert!(
                    reply["result"]["content"][0]["text"]
                        .as_str()
                        .unwrap()
                        .contains("INVALID_FRAME")
                );
            }
            assert!(!reply.to_string().contains("synthetic-capability"));
        }
    }

    #[test]
    fn public_fixed_content_type_projection_controls_only_execute_metadata() {
        for fixed_content_type in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let socket = directory.path().join("agent.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
            let action = rekey_domain::ids::ActionId::new_random();
            let principal = rekey_domain::ids::PrincipalId::new_random();
            let name = format!("rekey.{action}.v1");
            let inventory = json!({
                "profile":{"name":"test","principal_id":principal,"grants":[{"instance":"fixture","capabilities":[{"rule":"template-default","capability":"write","actions":[{"action_id":action,"version":1}]}]}],"session":{"ttl_ms":60000,"max_uses":1},"confirm_each_run":false,"isolation":"none","egress":"allow","llm_limits":[]},
                "policy_sha256":"00".repeat(32),"expires_at_ms":4_102_444_800_000_i64,
                "actions":[{"action_id":action,"version":1,"action_index":0,"name":"fixture","origin":"https://api.example.com","method":"POST","target":{"path":"/write","params":{},"query":{}},"body_schema":{"type":"object"},"fixed_content_type":fixed_content_type}]
            });
            let receiver = std::thread::spawn(move || {
                for operation in [
                    agent_msg::PROFILE_INVENTORY,
                    agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                ] {
                    let (mut stream, _) = listener.accept().unwrap();
                    let request = request_header(&mut stream);
                    assert_eq!(request.message_type, operation);
                    let mut metadata = vec![0; request.metadata_len as usize];
                    let mut body = vec![0; request.body_len as usize];
                    stream.read_exact(&mut metadata).unwrap();
                    stream.read_exact(&mut body).unwrap();
                    let metadata: Value = serde_json::from_slice(&metadata).unwrap();
                    assert_eq!(metadata["capability_token"], "synthetic-capability");
                    let (metadata, body) = if operation == agent_msg::PROFILE_INVENTORY {
                        assert!(body.is_empty());
                        (json!({}), serde_json::to_vec(&inventory).unwrap())
                    } else {
                        assert_eq!(metadata["action_id"], action.to_string());
                        assert_eq!(
                            metadata["content_type"],
                            if fixed_content_type {
                                Value::Null
                            } else {
                                json!("application/json")
                            }
                        );
                        assert_eq!(metadata["extra_headers"], json!([]));
                        assert_eq!(body, br#"{"title":"hello"}"#);
                        (
                            json!({"upstream_status":200,"headers":[["content-type","application/json"]],"body_len":2}),
                            b"{}".to_vec(),
                        )
                    };
                    let metadata = serde_json::to_vec(&metadata).unwrap();
                    let header = FrameHeader {
                        channel: Channel::Agent,
                        flags: 0,
                        message_type: resp_msg::OK,
                        request_id: request.request_id,
                        metadata_len: metadata.len() as u32,
                        body_len: body.len() as u32,
                    };
                    stream.write_all(&header.encode()).unwrap();
                    stream.write_all(&metadata).unwrap();
                    stream.write_all(&body).unwrap();
                }
            });
            let mut server = Server {
                socket,
                token: Zeroizing::new("synthetic-capability".into()),
                tools: BTreeMap::new(),
                initialized: true,
                ready: true,
            };
            let reply = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{"body":{"title":"hello"}}}})).unwrap();
            receiver.join().unwrap();
            assert_eq!(reply["result"]["isError"], false);
            assert!(!reply.to_string().contains("synthetic-capability"));
        }
    }

    #[test]
    fn approval_controls_reject_proofs_and_other_arguments_before_connect() {
        let mut server = Server {
            socket: PathBuf::from("/no-socket"),
            token: Zeroizing::new(String::new()),
            tools: BTreeMap::new(),
            initialized: true,
            ready: true,
        };
        for arguments in [
            json!({"challenge_id":"not-a-uuid"}),
            json!({"challenge_id":ApprovalRequestId::new_random(),"proof":"forbidden"}),
            json!({}),
        ] {
            let reply = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"await_approval","arguments":arguments}})).unwrap();
            assert_eq!(reply["error"]["code"], -32602);
        }
    }
}
