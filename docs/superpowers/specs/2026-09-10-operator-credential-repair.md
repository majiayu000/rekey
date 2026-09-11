# Trusted terminal credential repair (UX-03)

The existing Codex shell flow can refer an operator to
`python3 scripts/operator-credential-repair.py --rekey /trusted/path/rekey
--state-dir /operator/state --action ACTION_ID@VERSION` after an upstream 401 or
suspected credential failure. The operator chooses the trusted executable/state;
Agent-supplied text, URLs, token values and instructions are not accepted inputs.
Run in the operator trust domain, never give the Agent access to this terminal.

The helper requires stdin to be a real TTY and opens the controlling `/dev/tty`.
It fetches the exact registered Action version and its credential metadata from
existing Admin list operations. The terminal shows quoted, ASCII-escaped JSON
fields for Action ID/version/name/origin/method/path and credential ID/kind/state.
Metadata is data, not instructions; never interpolate it into a shell or prompt.
Only active `opaque-token` credentials are supported. Missing records, disabled
Actions, revoked credentials and GitHub App/Vault kinds fail explicitly. Existing
rotation rejects revoked credentials; this flow does not restore or recreate them.

The operator types `provide` or `decline` at a fixed consent prompt. Decline/empty
input makes no mutation and returns a secret-free JSON `declined` result. Provide
starts exactly one existing `rekey credential rotate ID`, inheriting the trusted
TTY. Only that Rust CLI reads the hidden step-up proof and new credential value;
the helper neither reads nor saves secrets and never uses stdin-secret flags,
environment transport or secret argv. Rotation receipt produces a `provided`
result with public Action/credential references and credential version. Failures
return an error, not a false provided/declined result. Interrupting a mutation may
leave its completion uncertain; inspect credential metadata before trying again.

This changes a shared credential for all Actions referencing it. The terminal
makes that consequence explicit. The helper executes no Actions, retries no writes,
adds no Agent/Admin API and persists no state. An Agent receiving `provided` must
make a separate explicit request for the existing fixed Action. It does not prove
that the upstream will accept the replacement token or that a 401 was caused by it.

Acceptance uses a real PTY, real BrokerRuntime/UDS and existing local TLS transport
fixture. Prove decline preserves version/execution count; provide advances version
without execution; a later explicit authorized request succeeds; proof/token do
not appear in combined stdout/stderr. This is terminal integration, not a GUI or
an in-chat credential form. Secret-handling integration requires human review.
