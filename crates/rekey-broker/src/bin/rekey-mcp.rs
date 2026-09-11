//! Local MCP transport only. Authority stays behind the agent socket.
// Share the existing pure IPC implementation without adding a CLI dependency.
#[allow(dead_code)]
#[path = "../../../rekey-cli/src/client.rs"]
mod client;

use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{BufRead, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rekey_connector::{McpToolDescriptor, adapt_mcp_invocation, project_mcp_tool};
use rekey_domain::action::{FixedHttpAction, FixedMethod};
use rekey_domain::capability::ActionVersionRef;
use rekey_domain::ipc::{Channel, ExecuteResponseMeta, agent_msg};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const LIMIT: usize = 1024 * 1024;
const VERSION: &str = "2025-06-18";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    agent_socket: PathBuf,
    session_file: PathBuf,
    tools: Vec<ToolFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolFile {
    action_file: PathBuf,
    input_schema: Value,
    #[serde(default)]
    headers: Vec<(String, String)>,
}

struct Tool {
    descriptor: McpToolDescriptor,
    action: ActionVersionRef,
    headers: Vec<(String, String)>,
}

struct Server {
    socket: PathBuf,
    token: Zeroizing<String>,
    tools: BTreeMap<String, Tool>,
    initialized: bool,
    ready: bool,
}

fn private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, &'static str> {
    if !path.is_absolute() {
        return Err("handoff paths must be absolute");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open private handoff file")?;
    let metadata = file.metadata().map_err(|_| "cannot inspect handoff file")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
        || metadata.len() > LIMIT as u64
    {
        return Err("handoff must be bounded caller-owned private regular file");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read handoff file")?;
    if bytes.len() > LIMIT {
        return Err("handoff file too large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid handoff JSON")
}

impl Server {
    fn load(path: &Path) -> Result<Self, &'static str> {
        let manifest: Manifest = private_json(path)?;
        if !manifest.agent_socket.is_absolute() {
            return Err("agent socket must be absolute");
        }
        #[derive(Deserialize)]
        struct Session {
            capability_token: String,
        }
        let session: Session = private_json(&manifest.session_file)?;
        let token = Zeroizing::new(session.capability_token);
        if token.is_empty() {
            return Err("empty capability");
        }
        let mut tools = BTreeMap::new();
        for entry in manifest.tools {
            let action: FixedHttpAction = private_json(&entry.action_file)?;
            if !action.enabled {
                return Err("disabled action in manifest");
            }
            // adapt_mcp_invocation always sends application/json bodies. Closed
            // no-body GET profiles (GitHub list-repos, Keycloak target GET) reject
            // that shape, so refuse to advertise tools that can never succeed.
            if action.method == FixedMethod::Get {
                return Err("no-body GET actions are incompatible with MCP JSON invocation");
            }
            let descriptor = project_mcp_tool(&action, &entry.input_schema)
                .map_err(|_| "invalid manifest action")?;
            let tool = Tool {
                descriptor,
                action: ActionVersionRef {
                    action_id: action.id,
                    version: action.version,
                },
                headers: entry.headers,
            };
            if tools.insert(tool.descriptor.name.clone(), tool).is_some() {
                return Err("duplicate manifest action");
            }
        }
        Ok(Self {
            socket: manifest.agent_socket,
            token,
            tools,
            initialized: false,
            ready: false,
        })
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
                json!({"protocolVersion":VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"rekey-mcp","version":env!("CARGO_PKG_VERSION")},"instructions":"Only operator-authorized fixed actions are available. Never retry writes automatically; ask the operator about errors, expiry or approvals."})
            }
            "ping" => json!({}),
            _ if !self.ready => return Some(error(id, -32600, "Complete initialization first")),
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Some(error(id, -32602, "Cursor is not supported"));
                }
                json!({"tools":self.tools.values().map(|tool| &tool.descriptor).collect::<Vec<_>>()})
            }
            "tools/call" => {
                let Some(tool) = params["name"]
                    .as_str()
                    .and_then(|name| self.tools.get(name))
                else {
                    return Some(error(id, -32602, "Unknown tool"));
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let Ok(invocation) = adapt_mcp_invocation(tool.action, &arguments) else {
                    return Some(error(id, -32602, "Tool arguments must be an object"));
                };
                #[derive(Serialize)]
                struct Execute<'a> {
                    capability_token: &'a str,
                    action_id: rekey_domain::ids::ActionId,
                    action_version: u64,
                    content_type: &'a str,
                    extra_headers: &'a [(String, String)],
                    approval_grants: [String; 0],
                }
                let metadata = Execute {
                    capability_token: &self.token,
                    action_id: invocation.action.action_id,
                    action_version: invocation.action.version,
                    content_type: invocation.content_type,
                    extra_headers: &tool.headers,
                    approval_grants: [],
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
                    client.call(
                        agent_msg::EXECUTE_FIXED_HTTP_ACTION,
                        &meta,
                        &invocation.body,
                    )
                });
                match execution {
                    Ok((metadata, body)) => {
                        match serde_json::from_slice::<ExecuteResponseMeta>(&metadata) {
                            Ok(metadata) if metadata.body_len as usize == body.len() => {
                                let text = json!({"upstream_status":metadata.upstream_status,"headers":metadata.headers,"body_base64":data_encoding::BASE64.encode(&body)}).to_string();
                                json!({"content":[{"type":"text","text":text}],"isError":!(200..300).contains(&metadata.upstream_status)})
                            }
                            _ => tool_error("INVALID_FRAME"),
                        }
                    }
                    Err(err) => tool_error(&err.code),
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

fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--manifest" {
        return Err("usage: rekey-mcp --manifest /absolute/path/mcp.json");
    }
    let mut server = Server::load(Path::new(&args[1]))?;
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
