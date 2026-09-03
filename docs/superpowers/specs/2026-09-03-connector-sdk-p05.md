# Rekey P-05 Connector SDK Contract

**Date:** 2026-09-03

**Status:** Proposed for implementation

**Tracking:** [Issue #27](https://github.com/majiayu000/rekey/issues/27)

**Scope:** one versioned, compile-time registry for Rekey-owned connector contracts,
plus pure MCP and OAuth projections

## 1. Goal

P-05 replaces the Broker's implicit `CredentialKind` branching with one typed
contract that describes which fixed action profile may use a credential and
which credential effects the Broker will perform. The contract is reusable by
tests and adapters, but it is not a plugin execution API: decrypted credentials,
network requests, deadlines, audit, response sealing, lease cleanup, and
revocation remain owned by the Broker.

The first registry contains only the behavior that already exists:

- `fixed-http-header@1`: inject an opaque credential into the Admin-selected
  protected header of a fixed HTTPS Action.
- `github-app-installation@1`: sign a bounded GitHub App JWT, exchange it for one
  installation token, hold that token only for the bounded request, and revoke
  it before success.

This creates the contract P-06 can extend without claiming that the existing
single GitHub profile is already a general provider connector.

## 2. Standards baseline

The MCP projection follows the versioned
[2026-07-28 MCP Tools specification](https://modelcontextprotocol.io/specification/2026-07-28/server/tools):
tool names are stable and use only the recommended ASCII name characters,
`inputSchema` is a JSON Schema 2020-12 object, and listing order is deterministic.
P-05 does not implement an MCP server or MCP OAuth resource server. In
particular, MCP client authorization and upstream provider authorization are
separate token domains as required by the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization);
an MCP access token is never forwarded to an upstream Action.

The OAuth projection models the public, non-secret fields of an
[RFC 8693 token exchange](https://www.rfc-editor.org/rfc/rfc8693.html): fixed
token endpoint, target resource or audience, subject/requested token types, and
the required extension grant type. It deliberately does not render a request
containing a subject token. A future registered connector must supply sensitive
values inside the Broker's zeroizing execution boundary. The current GitHub App
exchange remains provider-defined and must not be mislabeled as RFC 8693.

## 3. Frozen boundaries

P-05 must preserve all current Foundation contracts:

- Agent API remains `ExecuteFixedHttpAction`; no get/read/export secret,
  arbitrary sign, arbitrary exchange, arbitrary URL, or proxy operation exists.
- `rekey-cli` remains a pure IPC client and does not depend on the connector,
  Broker, Vault, crypto, SQLite, or HTTP stacks.
- Registry entries are compiled into the trusted binary. No filesystem search,
  remote registry, dynamic library, subprocess, WASM, download, or runtime code
  loading exists.
- A registry entry cannot receive a credential or perform IO. It only identifies
  the already-implemented Broker path and declares its ordered effects.
- The Broker remains the only owner of the Authority handle, prepared
  credential, lifecycle gate, absolute action deadline, network transport,
  response sealing, audit chain, and terminal outcome.
- Connector selection happens after `execution.started` and credential
  preparation but before any credential-derived bytes or remote effect.
  Selection failure commits a blocked terminal and performs no signing,
  exchange, injection, or upstream request.
- Existing GitHub mismatches remain fail-closed. An opaque token cannot fall
  back to header injection on the reserved GitHub profile, and a GitHub App
  credential cannot run an unrelated fixed action.
- Default deployment stays G1. The bounded Linux namespace/container reference
  remains the only G2 evidence.

## 4. Crate and dependency direction

Add one IO-free workspace crate, `rekey-connector`:

```text
rekey-domain <- rekey-connector <- rekey-broker
      ^                                  |
      +----------- rekey-policy <--------+
```

`rekey-connector` may depend on `rekey-domain`, `serde`, and `serde_json`. It
must not depend on Tokio, tracing, HTTP/TLS, crypto, SQLite, `rekey-vault`, or
`rekey-broker`. Neither `rekey-domain` nor `rekey-policy` depends on it. The CLI
dependency graph remains unchanged.

The new crate owns only the connector contract, built-in registry, MCP
projection, OAuth descriptor, and contract-test helpers. It contains no secret
type and no callback/trait through which third-party code can execute.

## 5. Versioned connector contract

The public contract format version is `1`. Its core types are closed enums and
borrowed static descriptors:

```rust
pub const CONNECTOR_CONTRACT_FORMAT_VERSION: u16 = 1;

pub enum BuiltInConnector {
    FixedHttpHeaderV1,
    GitHubAppInstallationV1,
}

pub enum CredentialEffect {
    Inject,
    Sign,
    Exchange,
    Lease,
    Revoke,
}

pub struct ConnectorContract {
    pub format_version: u16,
    pub id: &'static str,
    pub version: u16,
    pub credential_kind: CredentialKind,
    pub effects: &'static [CredentialEffect],
    pub source: ConnectorSource,
    pub isolation: ConnectorIsolation,
    pub remote_effect: bool,
    pub revoke_before_success: bool,
}
```

The exact built-in contracts are:

| Connector | Credential kind | Ordered effects | Source / isolation | Remote | Revoke before success |
| --- | --- | --- | --- | --- | --- |
| `fixed-http-header@1` | `opaque-token` | `inject` | built-in binary / Broker process | yes | no |
| `github-app-installation@1` | `github-app-installation` | `sign → exchange → lease → revoke` | built-in binary / Broker process | yes | yes |

The registry is a deterministic static slice ordered by `(id, version)`. IDs
use lowercase ASCII letters, digits, and hyphens; versions are non-zero. The
contract testkit checks uniqueness, ordering, format version, non-empty effect
sequences, and the two lifecycle invariants: `lease` requires later `revoke`,
and `revoke_before_success` requires a final `revoke` effect. Source and
isolation are closed to `BuiltInBinary` and `BrokerProcess`; independent
connector signatures and stronger isolation belong to P-10. This test helper
does not validate runtime plugins because P-05 has none.

## 6. Selection and Broker integration

`resolve_builtin(credential_kind, action)` returns one `BuiltInConnector` or a
closed `ConnectorSelectionError::SelectionRejected`:

1. `OpaqueToken` plus a non-reserved fixed HTTPS action resolves to
   `FixedHttpHeaderV1`.
2. `GitHubAppInstallation` resolves to `GitHubAppInstallationV1`; the existing
   Broker-owned profile validation then rejects every non-matching action before
   signing or network IO.
3. `OpaqueToken` plus the reserved GitHub profile is rejected, preserving the current
   no-fallback rule.

The exact GitHub origin, method, path, auth header, prefix, empty-body, and
header conditions continue to be checked by `GitHubAppCredential::validate_action`.
The registry only centralizes the credential-kind/action-profile routing; it
does not duplicate the executor's request validation.

`ActionExecutor::run_started` matches the resolved `BuiltInConnector`, then
enters the existing opaque or GitHub implementation. Audit event names,
deadlines, lifecycle gates, error mapping, sealing needles, and output bytes do
not change. Connector descriptors never enter audit rows because they contain
no runtime decision beyond the already-audited Action and Credential kinds.

## 7. MCP projection

The SDK exposes a pure projection from an authorized Action binding to an MCP
tool descriptor. It does not list actions by itself and cannot open either UDS.

- Name: `rekey.<action_uuid>.v<action_version>`. This is deterministic, unique
  within one Rekey server, under 128 characters, and contains only MCP's
  recommended characters.
- Title: the existing Action display name.
- Description: states that the tool executes an Admin-registered fixed action;
  it does not reveal credentials, policy internals, or capability tokens.
- Input schema: the binding's existing JSON Schema, only when its root explicitly
  declares `"type": "object"`. Every other root returns
  `UnsupportedInputSchema`; P-05 does not partially evaluate composition, wrap
  the schema, or silently change request semantics. A schema containing
  `x-mcp-header` at any depth is also rejected so arguments cannot be mirrored
  into transport headers.
- Output schema: absent. Existing fixed Actions may return arbitrary bounded
  bytes, so claiming structured output would be false.
- Ordering: projections are sorted by `(name, action_id, version)`.

The invocation adapter accepts only an object argument, serializes it once as
JSON, sets `application/json`, and returns the exact `ActionVersionRef` plus
body for the existing Agent IPC call. Capability tokens are host-owned
out-of-band state and never appear in the tool name, description, schema, or
arguments. P-05 does not use MCP `x-mcp-header` and therefore cannot mirror
tool arguments into network headers.

## 8. OAuth projection

`OAuthTokenExchangeDescriptor` contains only fixed public configuration:

- HTTPS token endpoint with exact path and no query/fragment.
- one typed target selector: an HTTPS `resource` origin/path or a bounded
  `audience` identifier.
- `subject_token_type` and optional `requested_token_type` from the closed RFC
  set `access_token`, `refresh_token`, `id_token`, or `jwt`.
- fixed grant type
  `urn:ietf:params:oauth:grant-type:token-exchange`.
- whether a captured issued token requires bounded revocation before success.

Construction relies on the existing `HttpsOrigin` and `ExactPath` types for the
endpoint and resource, while the `OAuthTarget` enum makes zero or multiple
targets unrepresentable. It rejects empty, oversized, whitespace, or control
characters in an audience. The closed token-type enum emits the corresponding
registered URI and accepts no arbitrary URI. The descriptor never accepts
`subject_token`, `actor_token`, client secret, access token, refresh token,
authorization header, or arbitrary extra form fields. Serialization exposes a
redacted metadata view only; no form-body renderer exists in P-05.

No built-in registry entry uses this descriptor in P-05. It is the typed
adapter contract for a later provider implementation, while the existing
GitHub entry declares a provider-defined exchange. This is not evidence of live
OAuth interoperability, an authorization server, discovery, refresh, or token
persistence.

## 9. Testkit and evidence

The crate's public `testkit` module provides bounded assertions for downstream
built-in connectors:

- registry contract validity and deterministic order;
- exact effect sequence and lifecycle flags;
- selection acceptance/rejection matrix;
- MCP descriptor stability, object-schema rejection, and absence of secret or
  capability fields;
- OAuth descriptor valid/invalid matrix and redacted serialization.

Repository integration tests additionally prove that runtime selection matches
the descriptor and that the existing opaque and GitHub execution paths keep
their exact outcomes. The real P-05 acceptance is the single security job's
combination of `scripts/p0-acceptance.sh`, `scripts/p2-github-app.sh`, and the
focused `scripts/p5-connector-sdk.sh` contract gate. Together they run release
binaries, a real BrokerRuntime, Admin/Agent UDS, SQLite, and the existing local
TLS fixtures; execute one opaque Action and the closed GitHub three-stage flow;
and scan state, logs, audit, projections, and captured Agent responses for
credential, JWT, installation-token, capability, and subject-token fields.

Required local gates:

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p rekey-connector
bash scripts/p5-connector-sdk.sh
cargo audit
cargo audit --file fuzz/Cargo.lock
cargo +nightly-2026-09-01 check --manifest-path fuzz/Cargo.toml
```

The repository mechanical searches and `rekey-cli` negative dependency tree
remain mandatory. CI must pass Ubuntu P0, macOS P0, bounded Linux G2, all fuzz
targets, and performance on the exact PR head and again on the merge commit.

## 10. Expected files

- `Cargo.toml`, `Cargo.lock`: add the pure workspace crate.
- `crates/rekey-connector/Cargo.toml`, `src/lib.rs`: contract, registry,
  selection, MCP/OAuth projection, and testkit.
- `crates/rekey-connector/tests/contract.rs`: public SDK contract tests.
- `crates/rekey-broker/src/executor.rs`, `github_app.rs`: route through the
  registry without changing execution behavior.
- `crates/rekey-broker/tests/connector_contract.rs`: runtime/contract binding.
- `scripts/p5-connector-sdk.sh`: release-process black-box and canary gate.
- README, user guide, threat model, Feature Truth Matrix, and closeout plan:
  precise capability and non-goal statements.

If implementation requires an executable plugin ABI, a new dynamic config
surface, connector-owned IO, a new Agent operation, credential migration, or a
provider beyond the two current built-ins, this spec must be revised before
code changes. Those additions are not implied by P-05.

## 11. Completion criteria

P-05 is complete only when:

1. The versioned static contract and two existing built-ins are implemented.
2. Broker routing uses the registry and all mismatches fail before credential
   effects or network IO.
3. MCP and OAuth projections satisfy the bounded behavior above without
   carrying secrets or creating a new transport/server.
4. Unit, integration, release black-box, failure, canary, mechanical, audit,
   fuzz-build, and full workspace gates pass.
5. Public docs say `Connector SDK contract available`, not `general provider
   connector`, `MCP server`, or `OAuth interoperability`.
6. Exact-head CI is green, self-review has no unresolved finding, the signed
   squash merge is verified, and post-main CI is green.

## 12. Explicit non-goals

- P-06 GitHub writes, broader permissions, multiple repositories/installations,
  webhook handling, or provider fixtures.
- P-07 external Vault/KMS/keychain/HSM CredentialSource implementations.
- P-08 metrics/tracing.
- P-09 egress launcher changes.
- P-10 process/WASM isolation, resource limits, connector signatures, or
  third-party code loading.
- Dynamic/remote registries, package installation, marketplace, connector
  discovery, hot reload, compatibility shims, or v1 migration.
- MCP transport/server, OAuth authorization server/client registration,
  discovery, browser consent, refresh-token storage, or live provider exchange.
- Any expansion of G1/G2, Alpha release, SIEM, control-plane, multi-tenant, or
  enterprise-readiness claims.
