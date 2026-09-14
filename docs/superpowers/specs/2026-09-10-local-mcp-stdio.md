# MCP-03: local stdio adapter

## Scope and protocol

One same-user local Codex host launches `rekey-mcp --manifest /absolute/path/mcp.json`.
A live probe of codex-cli 0.151.0 on 2026-09-10 sent `initialize` with
`protocolVersion: "2025-06-18"`. This server implements only that protocol revision.
The connector's existing pure descriptor/invocation projection is reused; its
2026-07-28 design reference does not select the runtime wire protocol.

Sources checked on 2026-09-10:
- https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
- https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning

The modern revision removes initialize and requires per-request metadata; it is
outside this host's supported slice. No dual-version fallback is added.

## Operator handoff

The operator registers actions, issues a bounded session and activates an
externally signed policy using existing trusted CLI flows. The adapter cannot
perform Admin operations, issue/refresh capabilities, sign policies or approve
requests. An expired/denied/locked call requires operator intervention.

Manifest and every referenced JSON file must be caller-owned regular files with
no group/other permissions. Symlinks are refused. All paths are absolute.

```json
{
  "agent_socket": "/absolute/state/runtime/agent.sock",
  "session_file": "/absolute/handoff/session.json",
  "tools": [
    {
      "action_file": "/absolute/handoff/registered-action.json",
      "headers": [["accept", "application/json"]],
      "input_schema": {"type": "object", "required": ["title"], "properties": {"title": {"type": "string"}}}
    }
  ]
}
```

`session.json` is the existing `rekey session create` response; only its
`capability_token` is consumed. `registered-action.json` is an existing full
registered FixedHttpAction, as emitted by agent-quickstart.py. The manifest is
an explicit exposure list, not authority: the broker checks the real Action,
session and policy on every invocation. The required `input_schema` is the operator-reviewed parameter schema from the
activated policy binding, projected unchanged through `project_mcp_tool` so the
host sees required fields and properties. The broker remains the authoritative
parameter validator. The adapter does not fetch schema network references or
duplicate the policy validator.

## Runtime

A separate binary in rekey-broker reuses the pure CLI Unix IPC client source;
rekey-cli dependencies do not change. The adapter references only domain,
connector, serde, libc and zeroize APIs, never broker authority/vault APIs.

Newline-delimited JSON-RPC stdout contains protocol responses only. Input frames
are bounded at 1 MiB. `initialize`, `notifications/initialized`, `ping`,
`tools/list` and `tools/call` are supported. Tools are deterministic and static
for the lifetime of the process. Invalid JSON, envelopes, parameters, unknown
methods/tools and pre-initialization calls fail explicitly. Notifications have
no response. A finite sequential execution uses the existing 130-second broker
response deadline; cancellation is best effort and cannot undo an upstream
write. The adapter never retries a request. EOF exits after the current bounded
call; forced process termination is available to the host.

Call arguments are JSON objects passed through `adapt_mcp_invocation`. Only
manifest-controlled headers and action IDs enter IPC. Because that adapter always
emits a nonempty `application/json` body, manifest load rejects closed no-body
GET Actions (for example GitHub `GET /installation/repositories` and Keycloak
target GET) so they are never advertised as tools. The capability is read
once into zeroizing storage, never accepted from MCP arguments or emitted in
stdout/stderr/argv/env. A successful broker response is returned as text containing
upstream status, selected headers and a base64 body (preserving arbitrary bytes).
Non-2xx HTTP status and broker failures set `isError: true`; broker error codes
are retained but free-form error messages and request contents are not reflected.
IPC failures explicitly warn that completion may be indeterminate and forbid
automatic write retries. Response bytes are already broker-sealed.

## Acceptance

Focused integration tests run the actual rekey-mcp process against real
BrokerRuntime/AuthorityWorker/SQLite with the existing fake upstream test seam.
They cover initialization, tool listing/call, malformed input, unknown tools,
owner-only handoff enforcement, success, policy denial, expiry and locked state,
and assert no credential/capability in either output stream. A live Codex startup
probe verifies host initialization and tools/list without triggering a write.

## Local host launch and observed validation

Build with `cargo build -p rekey-broker --bin rekey-mcp`. A Codex MCP server entry
uses the absolute resulting executable as `command` and
`["--manifest", "/absolute/handoff/mcp.json"]` as `args`; no `env` or token argument
is needed. Release packaging and other hosts are outside this slice.

On 2026-09-10, a CLI-issued session and CLI-activated signed policy were exercised
through the repository's `p1_policy_fixture` process and its local CA/TLS server.
One real CLI call and one real MCP call succeeded; parameter denial and locked
MCP calls did not increase the two upstream hits. A live codex-cli 0.151.0 launch
against this binary completed initialize and tools/list (one exposed tool), with
zero writes during discovery. The integration tests additionally exercise real
broker capability expiry, reflected-secret rejection and HTTP non-2xx responses.

Focused commands:

```sh
cargo check --workspace
cargo test -p rekey-broker --test mcp_stdio
cargo test -p rekey-broker --bin rekey-mcp
```
