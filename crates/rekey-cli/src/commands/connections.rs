//! Signed Connection editing bases and user-owned access decisions over admin IPC.
use crate::client::CliError;
use rekey_domain::connection::Preset;
use rekey_domain::ids::RequestId;
use rekey_domain::ipc::{
    AccessRequestStatus, AwaitAccessResponse, ConnectionListResponse, ProofKind, admin_msg,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::path::Path;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessRequest {
    request_id: RequestId,
    caller: String,
    provider: Option<String>,
    connection: Option<String>,
    operation: Option<String>,
    reason: String,
    created_at_ms: i64,
    expires_at_ms: i64,
    status: AccessRequestStatus,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessList {
    requests: Vec<AccessRequest>,
    blocked_callers: Vec<String>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockState {
    blocked: bool,
}
fn public<T: DeserializeOwned + Serialize>(
    state_dir: &Path,
    opcode: u16,
    request: Value,
    proof: Option<(ProofKind, bool)>,
) -> Result<(), CliError> {
    let mut client = super::admin(state_dir)?;
    let metadata = serde_json::to_vec(&request)
        .map_err(|_| CliError::local("USAGE", "cannot encode Connection request"))?;
    let body = match proof {
        Some((kind, stdin)) => super::proof_body(kind, &super::read_step_up(kind, stdin)?),
        None => zeroize::Zeroizing::new(Vec::new()),
    };
    let (metadata, body) = client.call(opcode, &metadata, &body)?;
    if serde_json::from_slice::<Value>(&metadata).ok() != Some(json!({})) {
        return Err(CliError::local(
            "INVALID_FRAME",
            "public admin response metadata must be empty",
        ));
    }
    let response: T = serde_json::from_slice(&body)
        .map_err(|_| CliError::local("INVALID_FRAME", "invalid public admin response fields"))?;
    super::write_json(&response)
}
pub fn list(state_dir: &Path) -> Result<(), CliError> {
    public::<ConnectionListResponse>(state_dir, admin_msg::PROFILE_LIST, json!({}), None)
}
pub fn preset(
    state_dir: &Path,
    preset: String,
    origin: Option<String>,
    header: Option<String>,
    prefix: Option<String>,
) -> Result<(), CliError> {
    public::<Preset>(
        state_dir,
        admin_msg::TEMPLATE_CATALOG,
        json!({"preset":preset,"origin":origin,"header":header,"prefix":prefix}),
        None,
    )
}
pub fn access_list(state_dir: &Path) -> Result<(), CliError> {
    public::<AccessList>(
        state_dir,
        admin_msg::ACCESS_RESOLVE,
        json!({"action":"list"}),
        None,
    )
}
pub fn resolve(
    state_dir: &Path,
    request_id: RequestId,
    granted: bool,
    block_caller: bool,
    kind: ProofKind,
    stdin: bool,
) -> Result<(), CliError> {
    public::<AwaitAccessResponse>(
        state_dir,
        admin_msg::ACCESS_RESOLVE,
        json!({"action":"resolve","request_id":request_id,"granted":granted,"block_caller":block_caller}),
        Some((kind, stdin)),
    )
}
pub fn block(
    state_dir: &Path,
    caller: String,
    blocked: bool,
    kind: ProofKind,
    stdin: bool,
) -> Result<(), CliError> {
    public::<BlockState>(
        state_dir,
        admin_msg::ACCESS_RESOLVE,
        json!({"action":"block","caller":caller,"blocked":blocked}),
        Some((kind, stdin)),
    )
}
