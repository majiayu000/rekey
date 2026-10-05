//! Token-free MCP stdio transport. The daemon remains the authority.
#[allow(dead_code)]
#[path = "../../../rekey-cli/src/client.rs"]
mod client;

use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use rekey_domain::action::FixedMethod;
use rekey_domain::ids::{ApprovalRequestId, RequestId};
use rekey_domain::ipc::{
    AwaitAccessMeta, AwaitAccessResponse, AwaitUnlockMeta, AwaitUnlockResponse, CallMeta,
    CallResponseMetadata, Channel, DescribeMeta, DescribeResponse, DryRunResponse,
    ListCapabilitiesResponse, LocalApprovalStateResponse, LocalAwaitApprovalMeta,
    LocalCancelApprovalMeta, RequestAccessMeta, RequestAccessResponse, agent_msg,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const LIMIT: usize = 1024 * 1024;
const VERSION: &str = "2025-11-25";
const GENERIC_TOOL_COUNT: usize = 9;

#[derive(Parser)]
#[command(
    name = "rekey-mcp",
    version,
    about = "Rekey MCP transport; no token required"
)]
struct Options {
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    agent_socket: Option<PathBuf>,
}
struct NamedTool {
    descriptor: Value,
    connection: String,
    operation: String,
}
struct Server {
    socket: PathBuf,
    tools: BTreeMap<String, NamedTool>,
    initialized: bool,
    ready: bool,
}

fn descriptor(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({"name":name,"description":format!("{description} This tool never returns secrets."),"inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required}})
}
fn generic_tools() -> Vec<Value> {
    vec![
        descriptor(
            "list_capabilities",
            "List connections, named operations, read/write decisions and T0/T1 grades.",
            json!({}),
            &[],
        ),
        descriptor(
            "describe",
            "Describe a named operation's parameters and applicable rules.",
            json!({"operation":{"type":"string"}}),
            &["operation"],
        ),
        descriptor(
            "call",
            "Call a named operation under signed rules. After approval, repeat the original request with approval_request_id; never retry a completed or indeterminate write.",
            json!({"operation":{"type":"string"},"connection":{"type":"string"},"args":{"type":"object"},"body":{},"dry_run":{"type":"boolean"},"approval_request_id":{"type":"string","format":"uuid"}}),
            &["operation", "args"],
        ),
        descriptor(
            "http",
            "Call a Connection's HTTP path under signed rules; dry_run previews without executing.",
            json!({"connection":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"query":{"type":"object","additionalProperties":{"type":"string"}},"headers":{"type":"array","items":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}},"body":{},"dry_run":{"type":"boolean"},"approval_request_id":{"type":"string","format":"uuid"}}),
            &["connection", "method", "path"],
        ),
        descriptor(
            "request_access",
            "Ask the user to add a Connection or permission in the App. Specify either provider or connection. Do not ask the user for a key. Wait for the returned request ID with await_access.",
            json!({"provider":{"type":"string"},"connection":{"type":"string"},"operation":{"type":"string"},"reason":{"type":"string","maxLength":500}}),
            &["reason"],
        ),
        descriptor(
            "await_access",
            "Wait for an access request to be granted, rejected or expired. This never grants permission or executes a call; after GRANTED, explicitly retry the original request.",
            json!({"request_id":{"type":"string","format":"uuid"},"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &["request_id"],
        ),
        descriptor(
            "await_approval",
            "Wait for a user's approval; this does not approve or execute the request.",
            json!({"request_id":{"type":"string","format":"uuid"},"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &["request_id"],
        ),
        descriptor(
            "cancel_approval",
            "Cancel a pending approval request; this does not execute the request.",
            json!({"request_id":{"type":"string","format":"uuid"}}),
            &["request_id"],
        ),
        descriptor(
            "await_unlock",
            "Wait for the user to unlock the vault, then explicitly retry the original request.",
            json!({"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &[],
        ),
    ]
}
fn named_tools(
    inventory: ListCapabilitiesResponse,
) -> Result<BTreeMap<String, NamedTool>, client::CliError> {
    let count: usize = inventory
        .connections
        .iter()
        .map(|c| c.operations.len())
        .sum();
    if count + GENERIC_TOOL_COUNT > 40 {
        return Ok(BTreeMap::new());
    }
    let mut tools = BTreeMap::new();
    for connection in inventory.connections {
        for operation in connection.operations {
            let name = operation.name.replace('.', "_");
            let mut schema = operation.parameters.clone();
            let Some(object) = schema.as_object_mut() else {
                return Err(client::CliError::local(
                    "INVALID_FRAME",
                    "invalid operation schema",
                ));
            };
            let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut)
            else {
                return Err(client::CliError::local(
                    "INVALID_FRAME",
                    "invalid operation parameter schema",
                ));
            };
            properties.insert("dry_run".into(), json!({"type":"boolean"}));
            properties.insert(
                "approval_request_id".into(),
                json!({"type":"string","format":"uuid"}),
            );
            let descriptor = json!({"name":name,"description":format!("{} This tool never returns secrets. After approval, repeat the same request with approval_request_id.",operation.description),"inputSchema":schema});
            if tools
                .insert(
                    name,
                    NamedTool {
                        descriptor,
                        connection: connection.connection.clone(),
                        operation: operation.name,
                    },
                )
                .is_some()
            {
                // Multiple Connections can share the same preset. Generic call can
                // name the Connection explicitly; never choose one by accident.
                return Ok(BTreeMap::new());
            }
        }
    }
    Ok(tools)
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, client::CliError> {
    serde_json::to_vec(value)
        .map_err(|_| client::CliError::local("INVALID_INPUT", "cannot encode request"))
}
fn public_json(metadata: &[u8], body: &[u8]) -> Result<Value, client::CliError> {
    if serde_json::from_slice::<Value>(metadata).ok() != Some(json!({})) {
        return Err(client::CliError::local(
            "INVALID_FRAME",
            "public response metadata must be empty",
        ));
    }
    serde_json::from_slice(body)
        .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid public response body"))
}
fn checked<T: serde::de::DeserializeOwned + Serialize>(
    value: Value,
) -> Result<Value, client::CliError> {
    let response: T = serde_json::from_value(value)
        .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid public response fields"))?;
    serde_json::to_value(response)
        .map_err(|_| client::CliError::local("INVALID_FRAME", "cannot encode public response"))
}
fn approval_result(value: Value, request_id: ApprovalRequestId) -> Result<Value, client::CliError> {
    let response: LocalApprovalStateResponse = serde_json::from_value(value)
        .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid approval response"))?;
    if response.approval_request_id != request_id || response.expires_at_ms <= 0 {
        return Err(client::CliError::local(
            "INVALID_FRAME",
            "approval response does not match request",
        ));
    }
    Ok(text_result(
        serde_json::to_value(response).expect("serializable approval"),
    ))
}
fn text_result(result: Value) -> Value {
    json!({"content":[{"type":"text","text":result.to_string()}],"structuredContent":result,"isError":false})
}
fn public_error(error: &client::CliError) -> Value {
    json!({"code":error.code,"message":error.message,"next":error.next,"retryable":error.retryable,"request_id":error.request_id,"approval":error.approval})
}
fn broker_error(error: &client::CliError) -> Value {
    let result = public_error(error);
    json!({"isError":true,"structuredContent":result,"content":[{"type":"text","text":result.to_string()}]})
}
fn execution_result(
    metadata: CallResponseMetadata,
    body: &[u8],
) -> Result<Value, client::CliError> {
    let encoded = match metadata.body_encoding.as_str() {
        "text" => std::str::from_utf8(body)
            .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid text response"))?
            .to_owned(),
        "base64" => data_encoding::BASE64.encode(body),
        _ => {
            return Err(client::CliError::local(
                "INVALID_FRAME",
                "unsupported response encoding",
            ));
        }
    };
    let mime = metadata
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| "application/octet-stream".into());
    let mut result = json!({"status":metadata.status,"headers":metadata.headers,"body":encoded,"body_encoding":metadata.body_encoding,"mime_type":mime});
    if !(200..300).contains(&metadata.status) {
        result["code"] = json!("UPSTREAM_ERROR");
        result["next"] = json!(
            "Inspect the returned status and sealed response body. Do not automatically repeat a write."
        );
    }
    Ok(
        json!({"content":[{"type":"text","text":if metadata.body_encoding == "text" {result["body"].as_str().unwrap().to_owned()} else {result.to_string()}}],"structuredContent":result,"isError":!(200..300).contains(&metadata.status)}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CallArguments {
    operation: String,
    #[serde(default)]
    connection: String,
    #[serde(default)]
    args: BTreeMap<String, Value>,
    body: Option<Value>,
    #[serde(default)]
    dry_run: bool,
    approval_request_id: Option<ApprovalRequestId>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpArguments {
    connection: String,
    method: FixedMethod,
    path: String,
    #[serde(default)]
    query: BTreeMap<String, String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    body: Option<Value>,
    #[serde(default)]
    dry_run: bool,
    approval_request_id: Option<ApprovalRequestId>,
}
fn argument_strings(arguments: BTreeMap<String, Value>) -> BTreeMap<String, String> {
    arguments
        .into_iter()
        .map(|(name, value)| {
            (
                name,
                value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string()),
            )
        })
        .collect()
}
fn default_timeout() -> u16 {
    120
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WaitArguments {
    request_id: ApprovalRequestId,
    #[serde(default = "default_timeout")]
    timeout_s: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessWaitArguments {
    request_id: RequestId,
    #[serde(default = "default_timeout")]
    timeout_s: u16,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnlockArguments {
    #[serde(default = "default_timeout")]
    timeout_s: u16,
}
fn valid_timeout(timeout: u16) -> Result<u16, client::CliError> {
    if (1..=120).contains(&timeout) {
        Ok(timeout)
    } else {
        Err(client::CliError::local(
            "INVALID_INPUT",
            "timeout_s must be between 1 and 120",
        ))
    }
}
impl Server {
    fn public(
        &self,
        opcode: u16,
        value: &impl Serialize,
        timeout_s: u16,
    ) -> Result<Value, client::CliError> {
        let (meta, body) = client::Client::connect_with_response_timeout(
            &self.socket,
            Channel::Agent,
            Duration::from_secs(u64::from(timeout_s) + 10),
        )?
        .call(opcode, &encode(value)?, &[])?;
        public_json(&meta, &body)
    }
    fn refresh_tools(&mut self) -> Result<(), client::CliError> {
        self.tools.clear();
        let inventory = self.public(agent_msg::LIST_CAPABILITIES, &json!({}), 30)?;
        self.tools = named_tools(
            serde_json::from_value(inventory)
                .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid inventory"))?,
        )?;
        Ok(())
    }
    fn invoke(&self, request: CallMeta, body: Option<Value>) -> Result<Value, client::CliError> {
        let body = body
            .map(|body| encode(&body))
            .transpose()?
            .unwrap_or_default();
        let (meta, body) = client::Client::connect_with_response_timeout(
            &self.socket,
            Channel::Agent,
            Duration::from_secs(130),
        )?
        .call(agent_msg::CALL, &encode(&request)?, &body)?;
        if request.dry_run {
            return public_json(&meta, &body)
                .and_then(checked::<DryRunResponse>)
                .map(text_result);
        }
        execution_result(
            serde_json::from_slice(&meta)
                .map_err(|_| client::CliError::local("INVALID_FRAME", "invalid call response"))?,
            &body,
        )
    }
    fn call_tool(&mut self, name: &str, arguments: Value) -> Result<Value, client::CliError> {
        let invalid = || client::CliError::local("INVALID_INPUT", "invalid tool arguments");
        match name {
            "list_capabilities" => {
                if arguments != json!({}) {
                    return Err(invalid());
                }
                self.public(agent_msg::LIST_CAPABILITIES, &json!({}), 30)
                    .and_then(checked::<ListCapabilitiesResponse>)
                    .map(text_result)
            }
            "describe" => {
                let request: DescribeMeta =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                self.public(agent_msg::DESCRIBE, &request, 30)
                    .and_then(checked::<DescribeResponse>)
                    .map(text_result)
            }
            "request_access" => {
                let request: RequestAccessMeta =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                self.public(agent_msg::REQUEST_ACCESS, &request, 30)
                    .and_then(checked::<RequestAccessResponse>)
                    .map(|mut value| {
                        value["next"] = json!(format!("Call await_access with request_id {}. After GRANTED, explicitly retry the original request.", value["request_id"].as_str().unwrap()));
                        text_result(value)
                    })
            }
            "await_access" => {
                let request: AccessWaitArguments =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                let timeout_s = valid_timeout(request.timeout_s)?;
                self.public(
                    agent_msg::AWAIT_ACCESS,
                    &AwaitAccessMeta {
                        request_id: request.request_id,
                        timeout_s,
                    },
                    timeout_s,
                )
                .and_then(checked::<AwaitAccessResponse>)
                .map(text_result)
            }
            "await_approval" => {
                let request: WaitArguments =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                let timeout_s = valid_timeout(request.timeout_s)?;
                self.public(
                    agent_msg::AWAIT_APPROVAL,
                    &LocalAwaitApprovalMeta {
                        request_id: request.request_id,
                        timeout_s,
                    },
                    timeout_s,
                )
                .and_then(|value| approval_result(value, request.request_id))
            }
            "cancel_approval" => {
                let request: LocalCancelApprovalMeta =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                self.public(agent_msg::CANCEL_APPROVAL, &request, 30)
                    .and_then(|value| approval_result(value, request.request_id))
            }
            "await_unlock" => {
                let request: UnlockArguments =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                let timeout_s = valid_timeout(request.timeout_s)?;
                self.public(
                    agent_msg::AWAIT_UNLOCK,
                    &AwaitUnlockMeta { timeout_s },
                    timeout_s,
                )
                .and_then(checked::<AwaitUnlockResponse>)
                .map(text_result)
            }
            "http" => {
                let args: HttpArguments =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                let mut request = CallMeta::http(args.connection, args.method, args.path);
                request.query = args.query;
                request.headers = args.headers;
                request.dry_run = args.dry_run;
                request.approval_request_id = args.approval_request_id;
                self.invoke(request, args.body)
            }
            "call" => {
                let args: CallArguments =
                    serde_json::from_value(arguments).map_err(|_| invalid())?;
                let mut request = CallMeta::operation(args.operation, argument_strings(args.args));
                request.connection = args.connection;
                request.dry_run = args.dry_run;
                request.approval_request_id = args.approval_request_id;
                self.invoke(request, args.body)
            }
            _ => {
                self.refresh_tools()?;
                let tool = self.tools.get(name).ok_or_else(|| {
                    client::CliError::local("INVALID_INPUT", "unknown tool; call list_capabilities")
                })?;
                let mut args = arguments.as_object().cloned().ok_or_else(invalid)?;
                let dry_run = args
                    .remove("dry_run")
                    .map(|v| v.as_bool().ok_or_else(invalid))
                    .transpose()?
                    .unwrap_or(false);
                let approval_request_id = args
                    .remove("approval_request_id")
                    .map(|v| serde_json::from_value(v).map_err(|_| invalid()))
                    .transpose()?;
                let mut request = CallMeta::operation(
                    tool.operation.clone(),
                    argument_strings(args.into_iter().collect()),
                );
                request.connection = tool.connection.clone();
                request.dry_run = dry_run;
                request.approval_request_id = approval_request_id;
                self.invoke(request, None)
            }
        }
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
                json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"rekey-mcp","version":env!("CARGO_PKG_VERSION")},"instructions":"Use list_capabilities and describe before calling. Never request keys from the user. Follow error.next to request access or await unlock/approval. After approval, repeat the same request with approval_request_id; never retry completed or indeterminate writes."})
            }
            "ping" => json!({}),
            _ if !self.ready => return Some(error(id, -32600, "Complete initialization first")),
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Some(error(id, -32602, "Cursor is not supported"));
                }
                // Generic recovery/request tools stay discoverable when the vault
                // is locked or unavailable. Inventory is never authorization.
                let failure = self.refresh_tools().err();
                if let Some(failure) = &failure
                    && !matches!(
                        failure.code.as_str(),
                        "IPC_UNAVAILABLE" | "LOCKED" | "NOT_CONFIGURED"
                    )
                {
                    return Some(
                        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32000,"message":"Rekey inventory unavailable","data":public_error(failure)}}),
                    );
                }
                let mut tools = generic_tools();
                if let Some(failure) = failure {
                    for tool in &mut tools {
                        let description = tool["description"].as_str().unwrap().to_owned();
                        tool["description"] = json!(format!(
                            "{description} Connection inventory is unavailable ({}); tool calls report the next step.",
                            failure.code
                        ));
                    }
                }
                tools.extend(self.tools.values().map(|tool| tool.descriptor.clone()));
                json!({"tools":tools})
            }
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    return Some(error(id, -32602, "Tool name is required"));
                };
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match self.call_tool(name, args) {
                    Ok(result) => result,
                    Err(failure) => broker_error(&failure),
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
fn run() -> Result<(), &'static str> {
    let options = Options::parse();
    let socket = match options.agent_socket {
        Some(socket) => socket,
        None => options
            .state_dir
            .or_else(|| std::env::home_dir().map(|home| home.join(".rekey")))
            .ok_or("cannot resolve home directory")?
            .join("runtime/agent.sock"),
    };
    let mut server = Server {
        socket,
        tools: BTreeMap::new(),
        initialized: false,
        ready: false,
    };
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
    use std::os::unix::net::{UnixListener, UnixStream};

    fn server(socket: PathBuf) -> Server {
        Server {
            socket,
            tools: BTreeMap::new(),
            initialized: true,
            ready: true,
        }
    }
    fn inventory(count: usize) -> ListCapabilitiesResponse {
        serde_json::from_value(json!({"connections":[{"connection":"github","preset":"github","origin":"https://api.github.com","grade":"T0","read":"allow","write":"approve","operations":(0..count).map(|i|json!({"name":format!("github.operation_{i}"),"description":"Read an issue","method":"GET","path":"/issues/{id}","parameters":{"type":"object","additionalProperties":false,"properties":{"id":{"type":"string"}},"required":["id"]}})).collect::<Vec<_>>()}],"derived_credentials":[],"service_url":"http://127.0.0.1:7787"})).unwrap()
    }
    fn read_request(stream: &mut UnixStream) -> (FrameHeader, Value, Vec<u8>) {
        stream.set_read_timeout(Some(client::IO_TIMEOUT)).unwrap();
        let mut bytes = [0; FRAME_HEADER_LEN];
        stream.read_exact(&mut bytes).unwrap();
        let header = FrameHeader::decode(&bytes).unwrap();
        let mut metadata = vec![0; header.metadata_len as usize];
        let mut body = vec![0; header.body_len as usize];
        stream.read_exact(&mut metadata).unwrap();
        stream.read_exact(&mut body).unwrap();
        (header, serde_json::from_slice(&metadata).unwrap(), body)
    }
    fn reply(
        stream: &mut UnixStream,
        header: &FrameHeader,
        metadata: Value,
        body: &[u8],
        kind: u16,
    ) {
        let metadata = metadata.to_string();
        stream
            .write_all(
                &FrameHeader {
                    channel: Channel::Agent,
                    flags: 0,
                    message_type: kind,
                    request_id: header.request_id,
                    metadata_len: metadata.len() as u32,
                    body_len: body.len() as u32,
                }
                .encode(),
            )
            .unwrap();
        stream.write_all(metadata.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, UnixListener) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        (dir, socket, listener)
    }
    #[test]
    fn tool_limit_and_schema_projection_preserve_named_parameters() {
        let tools = named_tools(inventory(31)).unwrap();
        assert_eq!(tools.len() + GENERIC_TOOL_COUNT, 40);
        let tool = &tools["github_operation_0"];
        assert_eq!(tool.descriptor["inputSchema"]["required"], json!(["id"]));
        assert_eq!(
            tool.descriptor["inputSchema"]["properties"]["dry_run"]["type"],
            "boolean"
        );
        assert!(
            tool.descriptor["description"]
                .as_str()
                .unwrap()
                .contains("never returns secrets")
        );
        assert!(named_tools(inventory(32)).unwrap().is_empty());
        for tool in generic_tools() {
            assert!(
                tool["description"]
                    .as_str()
                    .unwrap()
                    .contains("never returns secrets")
            );
        }
    }
    #[test]
    fn protocol_negotiates_only_supported_versions() {
        for (requested, expected) in [
            ("2025-06-18", "2025-06-18"),
            ("2025-11-25", "2025-11-25"),
            ("2099-01-01", "2025-11-25"),
        ] {
            let mut server = server(PathBuf::new());
            server.initialized = false;
            server.ready = false;
            let response = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":requested,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).unwrap();
            assert_eq!(response["result"]["protocolVersion"], expected);
        }
    }
    #[test]
    fn http_forwards_body_outside_metadata_and_never_supplies_a_token() {
        let (_dir, socket, listener) = fixture();
        let receiver = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let (header, metadata, body) = read_request(&mut stream);
            assert_eq!(header.message_type, agent_msg::CALL);
            assert_eq!(metadata["connection"], "github");
            assert_eq!(metadata["method"], "POST");
            assert!(metadata.get("body").is_none());
            assert!(metadata.get("capability_token").is_none());
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"title":"Bug"})
            );
            reply(
                &mut stream,
                &header,
                json!({"status":201,"headers":[["content-type","application/json"]],"body_encoding":"text"}),
                b"{\"id\":1}",
                resp_msg::OK,
            );
        });
        let response = server(socket).call_tool("http", json!({"connection":"github","method":"POST","path":"/repos/example/repo/issues","body":{"title":"Bug"}})).unwrap();
        assert_eq!(response["structuredContent"]["status"], 201);
        assert_eq!(response["structuredContent"]["body"], "{\"id\":1}");
        receiver.join().unwrap();
    }
    #[test]
    fn approval_and_unlock_use_public_json_and_bounded_token_free_requests() {
        for name in [
            "await_access",
            "await_approval",
            "cancel_approval",
            "await_unlock",
        ] {
            let (_dir, socket, listener) = fixture();
            let id = ApprovalRequestId::new_random();
            let receiver = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (header, metadata, body) = read_request(&mut stream);
                assert!(body.is_empty());
                assert!(metadata.get("capability_token").is_none());
                assert_eq!(
                    header.message_type,
                    match name {
                        "await_access" => agent_msg::AWAIT_ACCESS,
                        "await_approval" => agent_msg::AWAIT_APPROVAL,
                        "cancel_approval" => agent_msg::CANCEL_APPROVAL,
                        _ => agent_msg::AWAIT_UNLOCK,
                    }
                );
                if name != "await_unlock" {
                    assert_eq!(metadata["request_id"], id.to_string());
                }
                reply(
                    &mut stream,
                    &header,
                    json!({}),
                    if name == "await_unlock" {
                        json!({"unlocked":true})
                    } else if name == "await_access" {
                        json!({"status":"GRANTED"})
                    } else {
                        json!({"approval_request_id":id,"state":"approved","expires_at_ms":1234})
                    }
                    .to_string()
                    .as_bytes(),
                    resp_msg::OK,
                );
            });
            let args = if name == "await_unlock" {
                json!({"timeout_s":1})
            } else if matches!(name, "await_approval" | "await_access") {
                json!({"request_id":id,"timeout_s":1})
            } else {
                json!({"request_id":id})
            };
            let response = server(socket).call_tool(name, args).unwrap();
            if name == "await_unlock" {
                assert_eq!(response["structuredContent"]["unlocked"], true);
            } else if name == "await_access" {
                assert_eq!(response["structuredContent"]["status"], "GRANTED");
            } else {
                assert_eq!(response["structuredContent"]["state"], "approved");
            }
            receiver.join().unwrap();
        }
        assert!(valid_timeout(121).is_err());
        assert!(valid_timeout(0).is_err());
    }
    #[test]
    fn recoverable_inventory_error_keeps_generic_tools_but_integrity_failure_surfaces() {
        for (code, is_error) in [("LOCKED", false), ("INVALID_FRAME", true)] {
            let (_dir, socket, listener) = fixture();
            let receiver = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let (header, _, _) = read_request(&mut stream);
                reply(
                    &mut stream,
                    &header,
                    json!({"request_id":header.request_id,"code":code,"message":"inventory unavailable","next":"Call await_unlock()","retryable":false}),
                    &[],
                    resp_msg::ERROR,
                );
            });
            let result = server(socket)
                .handle(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
                .unwrap();
            assert_eq!(result.get("error").is_some(), is_error);
            if is_error {
                assert_eq!(result["error"]["data"]["next"], "Call await_unlock()");
            } else {
                assert_eq!(
                    result["result"]["tools"].as_array().unwrap().len(),
                    GENERIC_TOOL_COUNT
                );
                assert!(
                    result["result"]["tools"][0]["description"]
                        .as_str()
                        .unwrap()
                        .contains("inventory is unavailable")
                );
            }
            receiver.join().unwrap();
        }
    }
    #[test]
    fn sealed_binary_response_preserves_status_mime_and_next_step() {
        let response = execution_result(
            CallResponseMetadata {
                status: 403,
                headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                body_encoding: "base64".into(),
            },
            &[255, 254],
        )
        .unwrap();
        assert_eq!(response["structuredContent"]["body"], "//4=");
        assert_eq!(
            response["structuredContent"]["mime_type"],
            "application/octet-stream"
        );
        assert_eq!(response["isError"], true);
        let mut failure = client::CliError::local("DENIED", "Rule denied");
        failure.next = Some("Call request_access".into());
        assert_eq!(
            broker_error(&failure)["structuredContent"]["next"],
            "Call request_access"
        );
    }
}
