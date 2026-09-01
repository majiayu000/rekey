# Rekey v2 closeout security review

Date: 2026-09-01

Remediation commit: `3b2b3e60cd8b787678871de03a75671b8b534460`

Reviewer: Codex, in a fresh closeout-review session independent of the pre-existing core implementation

This report covers the M-04, M-05, and M-06 review scopes. The reviewer did
not author the pre-existing crypto, persistence, IPC, lifecycle, upstream, or
GitHub App implementation being reviewed. The reviewer did author the
remediations listed below. This is an independent implementation review for
the PR record; it is not a third-party human audit and does not satisfy the
separate M-10 GitHub `Approved` requirement.

## Threat assumptions and method

The review used the documented G1 default: an untrusted Agent may control
Agent inputs and disconnect or crash, but same-user `ptrace`, direct process
memory access, host root, kernel compromise, and direct Agent egress are out
of scope. The Linux G2 evidence was treated only as proof for the named
container/namespace topology. It was not extrapolated to default deployment,
macOS, arbitrary Linux isolation, host root, or kernel attackers.

The review combined source inspection, contract-to-implementation comparison,
adversarial tests, release-process harnesses, dependency audit, and mechanical
API/dependency searches. Files inspected included:

- M-04: `rekey-vault` crypto, bootstrap, durable IO, AuthorityWorker, SQLite
  schema/store/integrity, backup/restore, and all vault contract tests.
- M-05: domain IPC codec, broker and CLI frame IO, peer identity, socket/runtime
  ownership, session registry, lifecycle, execution supervisor, audit tracker,
  admin/agent dispatch, malicious-broker tests, and Linux G2 harness.
- M-06: action invariants, request validation, upstream screening/transport,
  executor ordering and sealing, GitHub App effect, audit ordering, adversarial
  HTTP, reflected-secret, screened-upstream, streaming-sealing, and GitHub App
  harnesses.

## Findings ledger

| ID | Severity | Scope | Finding | Disposition |
| --- | --- | --- | --- | --- |
| R-01 | Medium | M-04 | Authority and bootstrap wall-clock failures silently became timestamp `0`, weakening audit and receipt integrity. | Fixed in the remediation commit. Clock conversion is checked once in `rekey-vault`; init, restore, mutations, backup, and audit creation now fail with `CLOCK_UNAVAILABLE`. A pre-epoch regression test passes. |
| R-02 | Medium | M-05/M-06 | Broker wall-clock failures silently became 1970. Session monotonic deadlines limited capability impact, but policy expiry evaluation could treat an expired snapshot as current. | Fixed in the remediation commit. Admin and execution paths now propagate `CLOCK_UNAVAILABLE`; policy evaluation cannot continue with a fabricated time. A pre-epoch regression test passes. |
| R-03 | Low | M-05 | Successful broker metadata was printed as lossy text when it was not JSON, and CLI response-body writes ignored stdout errors. | Fixed in the remediation commit. Invalid success metadata returns `INVALID_FRAME`; all JSON/body writes propagate `OUTPUT_FAILED`; the malicious-broker suite includes invalid success JSON. |
| R-04 | Low | M-05 | The forged-response test wrote header and payload separately. A correctly rejecting macOS client could close after the forged header and make the test server panic on the later write. | Fixed in the remediation commit by sending the complete small forged frame in one write; rejection assertions are unchanged. |
| R-05 | Low | M-06 | Fake-IP refusal was documented, but the closeout gate required an executable diagnostic and a safe remediation boundary. | Fixed in the remediation commit. README now gives a `dig` check, exact-host Clash `dns.fake-ip-filter` direction, and explicitly forbids weakening IP screening or using proxy environment variables. |

Final finding counts: Critical 0, High 0, Medium 2 fixed / 0 open, Low 3 fixed / 0 open.

## M-04 verdict: crypto and persistence

PASS for the documented Foundation boundary.

- Argon2id password KDF parameters are bounded and encoded; recovery uses a
  domain-separated HKDF path. Password and recovery proofs unwrap a VRK-bound
  wrapper and cannot substitute a wrapper from another root key.
- AES-256-GCM nonces are generated internally. The fixed 84-byte binary AAD
  binds purpose, vault, object, version, credential kind, suite, and
  constraints. Unknown format discriminators fail before serving.
- VRK, KEK, DEK, secret input, prepared credentials, ciphertext-bearing
  response buffers, and sensitive CLI buffers use zeroizing ownership at the
  relevant boundary. There is no raw Secret getter on the Agent surface.
- Credential lifecycle metadata is sealed and verified before mutation or
  preparation. Cross-vault, cross-credential, version rollback, purpose swap,
  state swap, orphan row, and payload tamper tests fail closed.
- SQLite uses STRICT tables, WAL, `synchronous=FULL`, explicit transactions,
  integrity checks, format discriminators, and atomic audit/mutation paths.
  Init and restore markers prevent partially installed vaults from serving.
- Backup requires an external destination, create-new semantics, durable copy,
  receipt hash, and audit ordering. Restore checks the supplied SHA-256, proof,
  complete state/payload integrity, checkpoint, rename, and directory fsync.

Accepted residual risk: replaying a complete, previously valid database
snapshot is not detected in G1 because there is no external monotonic anchor.
The review does not claim rollback protection.

## M-05 verdict: IPC, identity, and lifecycle

PASS for G1 and for the bounded Linux G2 reference evidence.

- Admin and Agent use separate Unix sockets. Channel and message dispatch do
  not provide an Agent admin mutation, Secret read/export, or downgrade path.
- Frame headers, section lengths, channels, message types, response request ID,
  error envelopes, and successful JSON metadata are bounded or strictly
  checked. Malformed and partial frames close or fail the connection.
- Peer identity comes from `getpeereid` on macOS or `SO_PEERCRED` on Linux.
  Socket type, owner, mode, inode, runtime owner/mode, symlink changes, and
  replaceable ancestor conditions are checked around connect.
- Capabilities store only token hashes, pin exact Action versions, have use and
  concurrency caps, combine wall-clock expiry with monotonic deadlines, and
  are revoked on lock, idle lock, drain, shutdown, and restart.
- The lifecycle coordinator closes remote-effect admission before stop. The
  execution supervisor, terminal tracker, and tests cover disconnect, panic,
  cancellation, drain races, and audit failures without abandoning an
  admitted execution silently.

Accepted residual risks: G1 does not resist a hostile same-user debugger or
direct process-memory reader. The Linux G2 harness does not establish macOS G2,
host-root resistance, kernel resistance, or a general deployment profile.

## M-06 verdict: execution, SSRF, sealing, and GitHub App

PASS for fixed HTTP Actions and the closed GitHub App Installation profile.

- Action definitions fix HTTPS origin, method, exact path, credential header,
  timeouts, request bounds, and response bounds. Agent-controlled auth,
  forbidden headers, duplicate headers, unknown metadata, and oversized bodies
  are rejected before upstream execution.
- DNS results are rejected as a group if any answer is non-public. IPv4,
  explicit allocated IPv6, IPv4-mapped, well-known NAT64, and 6to4 addresses
  use the documented default-deny screening. The selected address is pinned to
  the Action host used for URL, Host, and TLS SNI.
- Reqwest uses rustls, no proxy environment, no redirects, bounded connect and
  total timeouts, and a buffered response limit. Redirect, private/reserved
  address, oversized body, truncated body, and stream error paths fail closed.
- Response headers and body are completely buffered and scanned before Agent
  success. Raw, full auth value, base64, base64url, percent encoding, headers,
  and chunk-boundary cases are covered. A hit returns an error without partial
  or trailing response bytes.
- The GitHub App profile is typed and fixed to its three-stage operation. Its
  total deadline is not reset, token revocation occurs before success, and
  disconnect or SIGTERM does not bind cleanup to the Agent connection. The
  ordered connector and terminal audit paths are covered by the local harness.

Accepted residual risks: response sealing does not promise detection of every
compression, encryption, hash-derived, or application-specific encoding. Live
GitHub evidence remains the single disposable App/repository run recorded in
the Feature Truth Matrix; this review reran the local TLS mock harness and does
not generalize the result into a connector SDK or release claim.

## Verification evidence

Environment: macOS arm64, Rust 1.95.0, Cargo 1.95.0. All commands below were
run after the final remediation and returned exit code 0:

```text
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
scripts/p0-acceptance.sh
scripts/p0-durability.sh
scripts/p1-streaming-sealing.sh
scripts/p2-github-app.sh
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src
rg -n 'get_secret\b|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli
cargo tree -p rekey-cli -e normal
git diff --check
```

`cargo audit` scanned 308 locked dependencies against 1,235 RustSec
advisories and reported no vulnerability. Both mechanical API searches had no
matches. The CLI dependency tree contained none of `rusqlite`, `aes-gcm`,
`argon2`, `reqwest`, `rekey-vault`, or `rekey-broker`.
