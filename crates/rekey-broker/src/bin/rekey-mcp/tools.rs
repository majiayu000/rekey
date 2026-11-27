//! Generic MCP tool descriptors and their client-facing annotations.
use serde_json::{Value, json};

/// MCP tool annotations. Clients such as Codex skip their own per-call prompt
/// only for tools marked read-only; Rekey still enforces signed rules and
/// approvals for every call.
pub(crate) fn annotations(read_only: bool, destructive: bool, open_world: bool) -> Value {
    json!({"readOnlyHint":read_only,"destructiveHint":destructive,"idempotentHint":read_only,"openWorldHint":open_world})
}
const LOCAL_READ: (bool, bool, bool) = (true, false, false);
const LOCAL_STATE: (bool, bool, bool) = (false, false, false);
const UPSTREAM: (bool, bool, bool) = (false, true, true);
fn descriptor(
    name: &str,
    description: &str,
    properties: Value,
    required: &[&str],
    (read_only, destructive, open_world): (bool, bool, bool),
) -> Value {
    json!({"name":name,"description":format!("{description} This tool never returns secrets."),"inputSchema":{"type":"object","additionalProperties":false,"properties":properties,"required":required},"annotations":annotations(read_only,destructive,open_world)})
}
pub(crate) fn generic_tools() -> Vec<Value> {
    vec![
        descriptor(
            "list_capabilities",
            "List connections, named operations, read/write decisions and T0/T1 grades.",
            json!({}),
            &[],
            LOCAL_READ,
        ),
        descriptor(
            "describe",
            "Describe a named operation's parameters, example arguments, rules and the rule its example matches. Pass connection when several Connections share the operation name.",
            json!({"operation":{"type":"string"},"connection":{"type":"string"}}),
            &["operation"],
            LOCAL_READ,
        ),
        descriptor(
            "call",
            "Call a named operation under signed rules; pass connection when several Connections share the operation name. After approval, repeat the original request with approval_request_id; never retry a completed or indeterminate write.",
            json!({"operation":{"type":"string"},"connection":{"type":"string"},"args":{"type":"object"},"body":{},"dry_run":{"type":"boolean"},"approval_request_id":{"type":"string","format":"uuid"}}),
            &["operation", "args"],
            UPSTREAM,
        ),
        descriptor(
            "http",
            "Call a Connection's HTTP path under signed rules; dry_run previews without executing.",
            json!({"connection":{"type":"string"},"method":{"type":"string","enum":["GET","HEAD","POST","PUT","PATCH","DELETE"]},"path":{"type":"string"},"query":{"type":"object","additionalProperties":{"type":"string"}},"headers":{"type":"array","items":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2}},"body":{},"dry_run":{"type":"boolean"},"approval_request_id":{"type":"string","format":"uuid"}}),
            &["connection", "method", "path"],
            UPSTREAM,
        ),
        descriptor(
            "request_access",
            "Ask the user to add a Connection or permission in the App. Specify either provider (a preset name or family, such as github for github-pat or github-oauth) or connection, and a full operation name if needed. Do not ask the user for a key. Wait for the returned request ID with await_access.",
            json!({"provider":{"type":"string"},"connection":{"type":"string"},"operation":{"type":"string"},"reason":{"type":"string","maxLength":500}}),
            &["reason"],
            LOCAL_STATE,
        ),
        descriptor(
            "await_access",
            "Wait for an access request to be granted, rejected or expired. This never grants permission or executes a call; after GRANTED, explicitly retry the original request.",
            json!({"request_id":{"type":"string","format":"uuid"},"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &["request_id"],
            LOCAL_READ,
        ),
        descriptor(
            "await_approval",
            "Wait for a user's approval. Pass approval.challenge_id from the APPROVAL_REQUIRED error as request_id, not the error's top-level request_id. This does not approve or execute the request; afterwards retry the same call with approval_request_id set to that challenge_id.",
            json!({"request_id":{"type":"string","format":"uuid"},"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &["request_id"],
            LOCAL_READ,
        ),
        descriptor(
            "cancel_approval",
            "Cancel a pending approval request. Pass approval.challenge_id from the APPROVAL_REQUIRED error as request_id. This does not execute the request.",
            json!({"request_id":{"type":"string","format":"uuid"}}),
            &["request_id"],
            LOCAL_STATE,
        ),
        descriptor(
            "await_unlock",
            "Wait for the user to unlock the vault, then explicitly retry the original request.",
            json!({"timeout_s":{"type":"integer","minimum":1,"maximum":120,"default":120}}),
            &[],
            LOCAL_READ,
        ),
    ]
}
