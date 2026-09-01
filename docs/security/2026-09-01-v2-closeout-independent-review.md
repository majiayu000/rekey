# Rekey v2 closeout security review

Date: 2026-09-01
Last updated: 2026-09-02

Remediation commits: `3b2b3e60cd8b787678871de03a75671b8b534460`,
`28dfb95235544af4ef341e4d36b57b7ac85fa1fc`,
`93201384e3b90d0e5f8c5d312f754483f0836b2b`,
`1e30c9947eb9c85d36bb61186bd9ebd249a0444c`,
`1b4fc86af6a88242770449148740852234de310e`,
`c3d6d02703873c9715fd06961d5a44f04552e0a5`,
`3ed327017282d3a90d61b605e5a45f0694aea32e`,
`b6224f8f14a05f2c33857ff6d11e3645f780beb0`,
`fe2c3b0aa70a2c3913d775b9a51644b37639146b`,
`1cad5f7b486045371c75eabaf896b8d4061edb83`,
`89d31a5fbda0a47ea1bb14e338ccbf522c996faa`,
`b123b8c4f6948ae273f8a62c1fd29898bbc3ec91`,
`601ad028b69f4678b751df500c323d38524004b2`,
`62a99e54276be0dbd7488e91132c1f5f64f21d34`,
`0adb1e8121a1110cb2864229f1143656aad8e940`,
`f32f6aebd5009a0920792515e95f9e0a6355a6bf`,
`d09684e199405c065d9f3cfaed520dd377303138`,
`afbc4a3b19f704edae826896c618e88fdd984d9e`,
`f6687884c57a75d43d60ebdfe67ed51d6bd40f24`,
`2fcd3d00d320feadb26ee95db0f4cccbe672bda8`,
`645bab6176ee72c290db9de7d5f8b76a19fd0f81`,
`89cc7455cb3337873f150e7160f49997f08dc411`,
`9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5`,
`1f008d16141b1106ccd0e0caa1bef9dd59c82bed`,
`38d67cfa2898c8aa95af83809c7fedea79e2f8fc`, and
`ac2e513c938e4abe349be445bcd6a6b1b9da252c`

Reviewer: Codex, in a fresh closeout-review session independent of the pre-existing core implementation

This report covers the M-04, M-05, and M-06 review scopes. The reviewer did
not author the pre-existing crypto, persistence, IPC, lifecycle, upstream, or
GitHub App implementation being reviewed. The reviewer did author the
remediations listed below. This is an independent implementation review for
the PR record; it is not a third-party human audit and does not satisfy the
separate M-10 GitHub `Approved` requirement.

After the first remediation, the GitHub Codex integration reviewed commit
`00d2e99e60c7324d4e8dbebb7e673e8cbd59c3f2` and reported seven additional
findings in [PR review 5078854490](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5078854490).
All seven were reproduced, fixed, regression-tested, and included below.

A second GitHub Codex review of commit
`936f5e42e8fac7816a0ecc239b565fcef4ba8939` reported six more findings in
[PR review 5079372965](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5079372965).
All six were reproduced, fixed, regression-tested, and included below. The
final cross-platform gate then exposed one additional idle-lock race; that
finding was fixed in production code and retained in this ledger rather than
dismissed as CI noise.

A third GitHub Codex review of commit
`c3d6d02703873c9715fd06961d5a44f04552e0a5` reported four more findings in
[PR review 5079811447](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5079811447).
All four were reproduced, fixed, regression-tested, and included below.

A fourth GitHub Codex review of commit
`3ed327017282d3a90d61b605e5a45f0694aea32e` reported seven more findings in
[PR review 5080025220](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5080025220).
All seven were reproduced, fixed, regression-tested, and included below.

A fifth GitHub Codex review of commit
`b6224f8f14a05f2c33857ff6d11e3645f780beb0` reported nine more findings in
[PR review 5080416419](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5080416419).
All nine were reproduced, fixed, regression-tested, and included below.

A sixth GitHub Codex review of commit
`fe2c3b0aa70a2c3913d775b9a51644b37639146b` reported five more findings in
[PR review 5080779837](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5080779837).
All five were reproduced, fixed in
`1cad5f7b486045371c75eabaf896b8d4061edb83`, regression-tested, and included
below.

A seventh GitHub Codex review of commit
`1cad5f7b486045371c75eabaf896b8d4061edb83` reported six more findings in
[PR review 5081036246](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5081036246).
All six were reproduced, fixed in
`89d31a5fbda0a47ea1bb14e338ccbf522c996faa`, regression-tested, and included
below.

An eighth GitHub Codex review of commit
`89d31a5fbda0a47ea1bb14e338ccbf522c996faa` reported three more findings in
[PR review 5081236402](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5081236402).
All three were reproduced, fixed in
`b123b8c4f6948ae273f8a62c1fd29898bbc3ec91`, regression-tested, and included
below.

A ninth GitHub Codex review of commit
`b123b8c4f6948ae273f8a62c1fd29898bbc3ec91` reported three more findings in
[PR review 5081382514](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5081382514).
All three were reproduced, fixed in
`601ad028b69f4678b751df500c323d38524004b2`, regression-tested, and included
below.

A tenth GitHub Codex review of commit
`601ad028b69f4678b751df500c323d38524004b2` reported five more findings in
[PR review 5081572983](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5081572983).
All five were reproduced, fixed in
`62a99e54276be0dbd7488e91132c1f5f64f21d34`, regression-tested, and included
below. A fresh local lifecycle review then found one related idle-lock race;
it was fixed in `0adb1e8121a1110cb2864229f1143656aad8e940` and retained in this
ledger.

An eleventh GitHub Codex review of commit
`0adb1e8121a1110cb2864229f1143656aad8e940` reported three more findings in
[PR review 5081875051](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5081875051).
All three were reproduced, fixed in
`f32f6aebd5009a0920792515e95f9e0a6355a6bf`, regression-tested, and included
below.

A twelfth GitHub Codex review of commit
`f32f6aebd5009a0920792515e95f9e0a6355a6bf` reported five more findings in
[PR review 5082064077](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5082064077).
All five were reproduced, fixed in
`d09684e199405c065d9f3cfaed520dd377303138`, regression-tested, and included
below.

A thirteenth GitHub Codex review of commit
`d09684e199405c065d9f3cfaed520dd377303138` reported six more findings in
[PR review 5082287940](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5082287940).
All six were reproduced, fixed in
`afbc4a3b19f704edae826896c618e88fdd984d9e`, regression-tested, and included
below.

A fourteenth GitHub Codex review of commit
`afbc4a3b19f704edae826896c618e88fdd984d9e` reported eight more findings in
[PR review 5082588323](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5082588323).
All eight were reproduced, fixed in
`f6687884c57a75d43d60ebdfe67ed51d6bd40f24`, regression-tested, and included
below.

A fifteenth GitHub Codex review of commit
`f6687884c57a75d43d60ebdfe67ed51d6bd40f24` reported five more findings in
[PR review 5082850580](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5082850580).
All five were reproduced, fixed in
`2fcd3d00d320feadb26ee95db0f4cccbe672bda8`, regression-tested, and included
below.

A sixteenth GitHub Codex review of commit
`2fcd3d00d320feadb26ee95db0f4cccbe672bda8` reported two more findings in
[PR review 5083109965](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083109965).
Both were reproduced, fixed in
`645bab6176ee72c290db9de7d5f8b76a19fd0f81`, regression-tested, and included
below.

A seventeenth GitHub Codex review of commit
`645bab6176ee72c290db9de7d5f8b76a19fd0f81` reported three more findings in
[PR review 5083249319](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083249319).
All three were reproduced, fixed in
`89cc7455cb3337873f150e7160f49997f08dc411`, regression-tested, and included
below.

An eighteenth GitHub Codex review of commit
`89cc7455cb3337873f150e7160f49997f08dc411` reported three more findings in
[PR review 5083399934](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083399934).
All three were reproduced, fixed in
`9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5`, regression-tested, and included
below.

A nineteenth GitHub Codex review of commit
`9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5` reported four more findings in
[PR review 5083552467](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083552467).
All four were reproduced, fixed in
`1f008d16141b1106ccd0e0caa1bef9dd59c82bed`, regression-tested, and included
below.

A twentieth GitHub Codex review of commit
`1f008d16141b1106ccd0e0caa1bef9dd59c82bed` reported four more findings in
[PR review 5083699274](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083699274).
All four were reproduced, fixed in
`38d67cfa2898c8aa95af83809c7fedea79e2f8fc`, regression-tested, and included
below.

A twenty-first GitHub Codex review of commit
`38d67cfa2898c8aa95af83809c7fedea79e2f8fc` reported two more findings in
[PR review 5083798893](https://github.com/majiayu000/rekey/pull/10#pullrequestreview-5083798893).
Both were reproduced, fixed in
`ac2e513c938e4abe349be445bcd6a6b1b9da252c`, regression-tested, and included
below. The exact-head follow-up then
[reported no major issues](https://github.com/majiayu000/rekey/pull/10#issuecomment-5501637084),
and a second exact-head run independently returned the same result.

The final branch-head CI replay then exposed two nondeterministic acceptance
preconditions rather than product-code failures. Two lifecycle tests used a
fixed delay instead of observing upstream admission; this was corrected in
`27ba2f85924dbd54691717e455cc240167138a3d`. The ordinary GitHub App success
flow also used the minimum two-second Action deadline for three TLS legs and
durable fixture traces; `9551fe1caa75f89f4591916e8b7440b3974240fe`
separated that ordinary acceptance budget from the dedicated deadline case.
The lifecycle suite passed ten consecutive runs, the GitHub App harness passed
three consecutive runs, and the exact-head follow-up on `9551fe1caa`
[reported no major issues](https://github.com/majiayu000/rekey/pull/10#issuecomment-5502049226).

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
| R-06 | Medium | M-04 | Audit event clock or entropy failure returned before the fail-closed branch, so unlock could report failure while leaving the worker unlocked with the VRK resident. | Fixed in the second remediation commit. Audit event construction errors now fault the worker before returning. |
| R-07 | Medium | M-05 | Credential revocation only found active Action versions, so a session pinned to a retired version was not invalidated when that version referenced the revoked credential. | Fixed in the second remediation commit. Every Action version is queried and Action IDs are deduplicated; the authority contract covers an old and new credential across an Action update. |
| R-08 | Medium | M-05/M-06 | DNS resolution was outside the Action timeout, and ordinary HTTP credential preparation did not reduce the remaining upstream budget. | Fixed in the second remediation commit. One absolute Action deadline now covers preparation, DNS, and HTTP; DNS has a timeout regression test. |
| R-09 | Medium | M-05 | A failed or timed-out Authority status request skipped shutdown proof verification, permitting a proofless stop while the vault might be unlocked. | Fixed in the second remediation commit. Proof is required unless Authority positively reports `locked`; unknown state and verification errors reject. The already-faulted terminal-audit fail-stop path preserves its sticky audit error. |
| R-10 | Low | M-05 | The root quick-start build command did not select the CLI or broker binaries because the integration host is the only default workspace member. | Fixed in the second remediation commit. README explicitly builds `rekey-cli` and `rekey-broker`. |
| R-11 | Low | M-05 | Unused expired sessions were never removed from the in-memory registry during compaction. | Fixed in the second remediation commit. Compaction drops monotonic-expired entries while retaining in-flight entries; a regression test covers repeated admission. |
| R-12 | Low | M-04 | Credential rotation accepted an empty Secret and could retire the usable version in favor of an empty credential. | Fixed in the second remediation commit. Rotation applies the creation-time non-empty invariant before loading or mutating the credential; the lifecycle contract proves the version remains unchanged. |
| R-13 | Medium | M-04 | Credential and Action transactional mutations faulted the worker only when appending an already-built audit event failed; clock or entropy failure while constructing the mandatory audit could return without faulting. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. A single fail-stop helper now covers audit construction and append failure for every transactional credential and Action mutation. Trigger-based regression tests prove the worker becomes faulted. |
| R-14 | Low | M-05 | Policy activation verified proof outside the lifecycle coordinator, so a concurrent lock could complete before the in-memory policy snapshot was replaced. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. Policy activation now holds the coordinator across proof verification and snapshot replacement. |
| R-15 | Medium | M-05 | Credential revocation released the lifecycle coordinator before looking up affected Actions and invalidating sessions, allowing a concurrent SessionCreate to admit a capability pinned to the revoked credential. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. Revocation now holds the coordinator through the durable mutation, Action lookup, and session invalidation. |
| R-16 | Medium | M-06 | Redirect and oversized-response failures occur after a remote effect may have happened, but were recorded as `execution.blocked`, which falsely implies no effect. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. Post-response redirects, response overflow, and transport failures are `execution.indeterminate`; pre-effect private-address screening remains `execution.blocked`. Unit, audit-log, and streaming harness assertions cover the split. |
| R-17 | Low | M-05 | Successful credential and Action list operations did not refresh idle activity, allowing an actively used administrative broker to idle-lock. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. Both list commands refresh activity on success, with lifecycle regression coverage. |
| R-18 | Medium | M-06 | Percent-encoded reflected-secret sealing normalized the hex pair only when both digits had the same case, allowing mixed-case escapes to bypass detection. | Fixed in `93201384e3b90d0e5f8c5d312f754483f0836b2b`. Each hex digit is normalized independently; unit and end-to-end mixed-case tests pass. The sealing helpers moved to a focused module to keep the executor below its enforced size limit. |
| R-19 | Medium | M-05 | Idle-lock checked activity before acquiring the lifecycle coordinator. A successful SessionCreate could complete after that snapshot, then be immediately followed by a drain based on stale idle state. | Fixed in `c3d6d02703873c9715fd06961d5a44f04552e0a5`. Idle activity is re-read under the coordinator and successful `session.created` completion refreshes activity. The original CI-failing test passed 20 consecutive local repetitions and the full Ubuntu/macOS gate. |
| R-20 | Medium | M-04 | SQLite errors at the final commit of a transaction containing a mutation and its mandatory audit event were mapped as ordinary storage failures, so the worker did not fault even though the outcome was uncertain. | Fixed in `3ed327017282d3a90d61b605e5a45f0694aea32e`. Every audited transaction uses one commit helper that maps final commit failure to `AUDIT_COMMIT_FAILED`; a deferred foreign-key regression exercises an actual commit-time failure. |
| R-21 | Medium | M-05 | Credential add and rotate checked the lifecycle only before parsing, allowing a concurrent lock to enter draining before the durable mutation began. | Fixed in `3ed327017282d3a90d61b605e5a45f0694aea32e`. Both operations hold the lifecycle coordinator across a final Running check and the Authority mutation. |
| R-22 | Medium | M-05 | Credential revocation committed before the fallible Action lookup used for session invalidation. A post-commit lookup failure could leave valid multi-Action capabilities without a repairable targeted cleanup path. | Fixed in `3ed327017282d3a90d61b605e5a45f0694aea32e`. The all-version Action lookup now occurs before revocation while the lifecycle coordinator is held; lookup failure leaves the credential unmodified, and successful revocation is followed only by infallible in-memory invalidation. |
| R-23 | Medium | M-05/M-06 | Credential preparation awaited the Authority without the Action deadline, so queue or storage stalls could exceed the fixed Action timeout before DNS or HTTP began. | Fixed in `3ed327017282d3a90d61b605e5a45f0694aea32e`. Preparation is bounded by the same absolute deadline as DNS and HTTP; expiry records a pre-effect blocked terminal and never opens remote-effect admission. |
| R-24 | Medium | M-06 | A GitHub App token-exchange transport failure could occur after the request reached GitHub but was recorded as blocked, falsely implying that no installation token had been minted. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. The connector preserves whether a remote effect is possible and records uncertain exchange outcomes as `execution.indeterminate`; a regression test covers the without-token branch. |
| R-25 | Low | M-05 | Successful Admin status requests did not refresh idle activity, so an operator actively monitoring the broker could still be idle-locked. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Admin status now uses the activity-refreshing Authority command and lifecycle tests cover the behavior. |
| R-26 | Low | M-05 | Several typed CLI success paths printed structurally invalid broker JSON after only checking that it was syntactically valid JSON. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Typed responses are deserialized and validated before output; malicious-broker tests cover forged success shapes. |
| R-27 | Low | M-05 | Session admission could remain live when submission of the mandatory `session.created` audit was rejected before reaching the worker. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Any audit submission or commit failure revokes the new session before returning the error. |
| R-28 | Low | M-05 | Persisted credential-integrity errors crossed the Agent boundary with a storage-specific code, exposing internal vault state and creating an unstable Agent contract. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Agent IPC maps storage-integrity failures to the uniform credential-unavailable response while the Authority still faults internally. |
| R-29 | Low | M-05 | The shutdown drain deadline could be fully consumed before the Admin response was written, causing a successful stop to look like an IPC failure. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Shutdown reserves a bounded response interval while preserving the single irreversible stop path; a deadline-exhaustion regression passes. |
| R-30 | Low | M-04 | Malformed persisted Argon2 parameters were surfaced as a generic crypto failure instead of a storage-integrity failure. | Fixed in `b6224f8f14a05f2c33857ff6d11e3645f780beb0`. Persisted KDF corruption now maps to `STORAGE_INTEGRITY_FAILED` and follows the Authority fault path. |
| R-31 | Medium | M-06 | A mutating upstream response containing a reflected Secret was recorded as blocked even though the remote effect had already occurred. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Reflected-secret terminals are indeterminate for ordinary fixed Actions and GitHub App effects; the lifecycle test and streaming harness assert the new audit contract. |
| R-32 | Medium | M-05/M-06 | The trusted Action timeout was loaded only after capability admission, so `action_get` could wait behind a long Authority operation without any deadline. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Session creation pins each immutable Action timeout; one absolute deadline starts at initial admission and bounds Action lookup, policy lock acquisition, started-audit commit, preparation, DNS, and HTTP. |
| R-33 | Low | M-04 | The restore specification still claimed format version 4 even though the current schema and implementation accept only version 5. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. The spec now accepts only v5 and explicitly rejects v1 through v4 and unknown future versions. |
| R-34 | Low | M-05/M-06 | Response metadata writers could exceed the 64 KiB frame limit; an execution could commit `execution.finished` and then fail to emit a valid response frame. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Frame and Admin writers reject oversized sections, while execution validates the exact serialized response metadata before committing success. Unit tests prove rejection occurs before frame bytes or success audit. |
| R-35 | Low | M-05 | Admin shutdown still required a step-up proof after the Authority had positively faulted and zeroized the VRK, making graceful process termination impossible. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Positively locked or faulted states permit proofless shutdown; unlocked or unknown states still require proof. |
| R-36 | Low | M-04/M-05 | Malformed persisted Action rows returned an integrity error but did not fault and zeroize the Authority worker. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Action get/list/reference and update reads share the persisted-integrity fault path; a tampered-origin regression proves the worker becomes faulted. |
| R-37 | Medium | M-04 | Copyable caller-side VRK and DEK arrays remained on the stack because key constructors zeroized only their by-value parameter copy. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Key constructors accept mutable caller buffers and zeroize them after protected ownership is established; contract tests assert the input arrays are zero. |
| R-38 | Low | M-04 | Intermediate Base32 recovery-key strings were ordinary `String` values and were not zeroized on drop. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Both encoded and normalized intermediate strings now use `Zeroizing`, while decoded buffers retain explicit zeroization on all exits. |
| R-39 | Low | M-04/M-05 | `Uuid::new_v4` performed hidden OS randomness inside the pure domain crate and made production ID creation infallible at the API boundary. | Fixed in `fe2c3b0aa70a2c3913d775b9a51644b37639146b`. Broker, vault, and CLI obtain entropy through fallible OS RNG calls and pass bytes to pure typed constructors; the domain no longer enables UUID v4 randomness. Release workspace compilation verifies production call sites. |
| R-40 | Medium | M-06 | Percent sealing left unreserved Secret bytes literal, so an upstream reflection such as `%61%62%63` could evade every encoded needle. | Fixed in `1cad5f7b486045371c75eabaf896b8d4061edb83`. Sealing includes a fully percent-escaped representation of every Secret byte; unit, end-to-end, and chunk-boundary harness coverage prove rejection. |
| R-41 | Low | M-04 | Negative persisted Action versions were cast to `u64::MAX`, allowing a corrupted row to pass domain validation and remain executable. | Fixed in `1cad5f7b486045371c75eabaf896b8d4061edb83`. Persisted credential and Action versions share one checked positive conversion; a corruption regression proves the Authority faults and zeroizes. |
| R-42 | Low | M-05 | Bodyless Admin messages accepted and silently discarded attached request bodies. | Fixed in `1cad5f7b486045371c75eabaf896b8d4061edb83`. Status, credential list, Action list, policy status, and lock share strict empty-request validation; the IPC regression also proves a rejected lock does not mutate lifecycle state. |
| R-43 | Low | M-05 | A policy version above `i64::MAX` passed domain validation but overflowed the signed durable audit column and could fault the Authority on first use. | Fixed in `1cad5f7b486045371c75eabaf896b8d4061edb83`. Policy versions are bounded to the durable signed range with exact boundary tests. |
| R-44 | Low | M-05 | CLI response timeouts reset across partial reads and frame sections, allowing a slow-drip broker to hold the client beyond the documented total response limit. | Fixed in `1cad5f7b486045371c75eabaf896b8d4061edb83`. One absolute deadline now covers header, metadata, and body; poll-gated nonblocking reads preserve that bound across partial delivery, with a slow-drip regression. |
| R-45 | Medium | M-06 | Selectively percent-encoded Secret bytes, such as `a%62c`, could evade both raw and all-byte percent representations. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. Response candidates are percent-decoded before raw-needle comparison; unit, end-to-end, and chunk-boundary harness cases prove rejection. |
| R-46 | Medium | M-05 | Pre-start denial audits could wait behind a long Authority operation beyond the Action deadline while retaining an in-flight permit. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. Action lookup and every pre-start denial audit share the same absolute deadline; a pending-operation regression proves timeout. |
| R-47 | Low | M-06 | The normative spec required a reflected-secret `execution.blocked` terminal after implementation and the release harness correctly classified the possible remote effect as indeterminate. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. The spec now requires `execution.indeterminate(reflected-secret)`. |
| R-48 | Medium | M-04 | A mode-0700 state directory owned by another user passed bootstrap validation, allowing that owner to replace durable Authority files. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. State directories must be owned by the broker effective UID as well as have restrictive mode bits; init and restore revalidate the boundary. |
| R-49 | Low | M-05 | Large session TTL values overflowed unit conversion, panicking in debug builds or wrapping in release builds. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. TTL conversion uses checked multiplication and returns `USAGE` on overflow. |
| R-50 | Low | M-05 | Broker startup accepted a symlinked Agent runtime directory that the CLI subsequently rejected, yielding a service that could not be used through the configured endpoint. | Fixed in `89d31a5fbda0a47ea1bb14e338ccbf522c996faa`. Broker endpoint validation now rejects an existing final runtime-directory symlink consistently with the client. |
| R-51 | Medium | M-06 | The connector authorization audit could wait behind a long Authority operation beyond the Action deadline before the GitHub remote-effect gate. | Fixed in `b123b8c4f6948ae273f8a62c1fd29898bbc3ec91`. The authorization audit uses the same absolute Action deadline and records a pre-effect blocked terminal on timeout. |
| R-52 | Low | M-06 | The normative GitHub App contract required a blocked terminal when token revocation failed even though a token had already been minted and revoke outcome could be uncertain. | Fixed in `b123b8c4f6948ae273f8a62c1fd29898bbc3ec91`. The spec now requires `execution.indeterminate`, matching implementation and remote-effect semantics. |
| R-53 | Low | M-05 | Explicit lock began its drain deadline only after unbounded lifecycle coordinator acquisition, so it could mutate state after the CLI had timed out. | Fixed in `b123b8c4f6948ae273f8a62c1fd29898bbc3ec91`. Lock deadlines now begin before coordinator acquisition; timeout returns `AUTHORITY_BUSY`, and a regression proves the canceled waiter cannot acquire later. |
| R-54 | Medium | M-05/M-06 | A connector-audit timeout synchronously awaited its terminal audit behind the same Authority backlog, retaining the execution permit beyond the Action deadline. | Fixed in `601ad028b69f4678b751df500c323d38524004b2`. Timed-out pre-effect paths transfer terminal ownership to the independent tracker before returning. |
| R-55 | Low | M-05 | Large idle-lock duration values overflowed unchecked unit conversion before validation. | Fixed in `601ad028b69f4678b751df500c323d38524004b2`. Duration parsing uses checked multiplication and rejects overflow as usage error. |
| R-56 | Low | M-05 | CLI Admin mutations always encoded password proof even though the wire contract also permits recovery proof. | Fixed in `601ad028b69f4678b751df500c323d38524004b2`. Admin step-up commands accept an explicit recovery selector and preserve the chosen proof kind through delegation. |
| R-57 | Medium | M-05/M-06 | Credential-prepare timeout still synchronously waited for its terminal audit after the Action deadline. | Fixed in `62a99e54276be0dbd7488e91132c1f5f64f21d34`. The timeout path transfers the terminal to the tracker without a second Authority wait. |
| R-58 | Medium | M-05/M-06 | Post-effect GitHub connector audit ordering could wait without the Action deadline and retain the execution permit. | Fixed in `62a99e54276be0dbd7488e91132c1f5f64f21d34`. Ordered connector and terminal audit ownership is transferred to the independent audit worker when the deadline is exhausted. |
| R-59 | Low | M-05 | `--body-file` read an unbounded regular file, FIFO, or device before the Agent frame limit was enforced. | Fixed in `62a99e54276be0dbd7488e91132c1f5f64f21d34`. The CLI reads at most the body limit plus one byte and rejects overflow before request construction. |
| R-60 | Medium | M-04/M-05 | CLI stdin Secret reads used a reallocating, unbounded `String`, risking denial of service and residual Secret prefixes in freed allocations. | Fixed in `62a99e54276be0dbd7488e91132c1f5f64f21d34`. One fixed-capacity zeroizing buffer enforces the Admin body bound before parsing. |
| R-61 | Medium | M-04 | A database with no mandatory active password or recovery wrapper passed the trusted open boundary and started permanently locked. | Fixed in `62a99e54276be0dbd7488e91132c1f5f64f21d34`. Open now requires exactly one active wrapper of each kind; deletion regressions fail with storage-integrity error. |
| R-62 | Medium | M-05 | Activity-refreshing Admin reads could complete concurrently with an idle-lock decision based on stale activity. | Fixed in `0adb1e8121a1110cb2864229f1143656aad8e940`. Status, credential list, Action list, and policy status serialize with the lifecycle coordinator; repeated race coverage passes. |
| R-63 | Medium | M-04 | Fixed-shape wrapper fields such as salt and wrapped VRK were not validated when the database opened. | Fixed in `f32f6aebd5009a0920792515e95f9e0a6355a6bf`. The trusted open boundary validates SQLite storage classes and exact field lengths before serving. |
| R-64 | Low | M-06 | Noncanonical Agent extra-header names could evade duplicate checks and fail only after remote-effect admission. | Fixed in `f32f6aebd5009a0920792515e95f9e0a6355a6bf`. Supplied names must equal their validated canonical form before policy evaluation. |
| R-65 | Low | M-04/M-05 | Non-UTF-8 backup output paths were lossy-converted, allowing the broker to create a different path from the one supplied. | Fixed in `f32f6aebd5009a0920792515e95f9e0a6355a6bf`. Non-UTF-8 backup paths are rejected at the CLI boundary. |
| R-66 | Medium | M-04/M-05 | Delegated `rekeyd` password-stdin input was unbounded and reallocating. | Fixed in `d09684e199405c065d9f3cfaed520dd377303138`. The delegated path uses bounded zeroizing storage and rejects oversized input. |
| R-67 | Low | M-04/M-05 | Restore delegation lossy-converted non-UTF-8 input paths. | Fixed in `d09684e199405c065d9f3cfaed520dd377303138`. Delegation preserves the input `OsStr` instead of converting through display text. |
| R-68 | Medium | M-04/M-06 | Credential preparation copied the complete decrypted payload into a second heap allocation. | Fixed in `d09684e199405c065d9f3cfaed520dd377303138`. Existing zeroizing plaintext ownership moves directly into the consume-once `PreparedCredential`. |
| R-69 | Low | M-05 | Action upsert could commit an Action whose serialized success response exceeded the Admin frame limit. | Fixed in `d09684e199405c065d9f3cfaed520dd377303138`. The exact prospective success representation is checked before mutation. |
| R-70 | Low | M-04/M-05 | Fallibly generated typed IDs did not normalize UUID v4 version and RFC variant bits. | Fixed in `d09684e199405c065d9f3cfaed520dd377303138`. Pure constructors normalize random bytes to UUID v4, with deterministic format tests. |
| R-71 | Low | M-04/M-05 | The bounded delegated stdin reader still waited for EOF after receiving the complete first Secret line. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. It consumes one byte at a time into bounded zeroizing storage and returns immediately at newline; a poll-counting regression proves no later read. |
| R-72 | Low | M-05 | Individually valid Actions could accumulate into an Action list response larger than the Admin frame limit. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. Create/update preflight the complete prospective catalog response under the lifecycle coordinator. |
| R-73 | Medium | M-05/M-06 | Invalid credential, extra-header, or content-type bytes could fail locally only after the remote-effect gate and be audited as indeterminate. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. Direct Agent header values are bounded ASCII and the complete credential-bearing outbound header set is validated before effect admission; regressions prove blocked audit and zero transport calls. |
| R-74 | Medium | M-04 | Open compared the stored schema digest with the compiled digest but did not prove the live SQLite schema retained required indexes, constraints, and STRICT declarations. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. The live schema is normalized and compared with a fresh in-memory v5 schema at the trusted open boundary. |
| R-75 | Medium | M-04/M-05 | Ordinary Admin mutations queued behind a long operation could commit after the client deadline and disconnect. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. One server-side deadline bounds lifecycle and Authority waits; mutation commands reject expired work at dequeue and immediately before durable commit, while backup shares the coordinator. |
| R-76 | Medium | M-06 | Rekey-owned upstream response-header clones were not zeroized when sealing rejected a reflection or body streaming failed. | Fixed in `afbc4a3b19f704edae826896c618e88fdd984d9e`. Owned response header names and values remain in zeroizing storage through streaming and sealing; ordinary strings are materialized only for clean allowlisted output. |
| R-77 | Low | M-05 | The CLI's bounded stdin Secret reader still waited for EOF after receiving the required one or two complete lines. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. It reads into fixed-capacity zeroizing storage one byte at a time and returns at the required newline; a poll-counting regression proves no later read. |
| R-78 | Low | M-05 | Individually valid credentials could accumulate into a credential list response larger than the Admin frame limit. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. Credential add preflights the complete prospective catalog under the lifecycle coordinator before mutation. |
| R-79 | Low | M-05 | Action update catalog preflight appended the new version without removing the Action's existing active entry and could reject a valid near-limit replacement. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. Update preflight replaces the matching active entry; a regression proves replacement succeeds where append would exceed the frame. |
| R-80 | Low | M-05 | A cross-UID G2 agent runtime with a symlink in an ancestor was accepted by broker startup but rejected by the client. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. Cross-UID startup checks every existing component consistently with the client; same-UID G1 retains the final-component check. |
| R-81 | Medium | M-04 | A privileged broker could open a database or existing WAL/SHM entry owned by another user because file hardening validated only mode after opening. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. Every existing SQLite bundle entry must be a regular, non-symlink file owned by the broker EUID before SQLite open/configuration and is revalidated after chmod. |
| R-82 | Medium | M-05 | Policy activation could commit `policy.activated(success)` just before the Admin deadline and then reject publication, leaving durable success without active state. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. After successful audit commit, the infallible in-memory publication completes in the same linearized activation. |
| R-83 | Low | M-05 | Agent status frames could declare and force allocation of an execute-sized body before the empty-body contract was checked. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. Body limits are selected immediately after header decode; only execute accepts a body, while status returns explicit `INVALID_FRAME` without reading or allocating the declared body. |
| R-84 | Medium | M-05/M-06 | Unknown fields inside a parameter scope were ignored, so a future or malformed constraint beside `any_validated` could silently broaden authorization. | Fixed in `f6687884c57a75d43d60ebdfe67ed51d6bd40f24`. `ParameterScope` denies unknown fields and uses an empty struct variant so unsupported semantics fail closed; wire JSON remains unchanged. |
| R-85 | Medium | M-04 | The trusted open boundary accepted a truncated or malformed vault-integrity ciphertext, allowing a live vault to issue a backup that restore later rejected. | Fixed in `2fcd3d00d320feadb26ee95db0f4cccbe672bda8`. Vault header crypto fields now require their exact storage classes and 40-byte AEAD ciphertext shape before the row is trusted; truncation has a reopen regression. |
| R-86 | Low | M-05 | An execution could finish and refresh Authority activity after idle status was read but before the stale branch entered drain. | Fixed in `2fcd3d00d320feadb26ee95db0f4cccbe672bda8`. While holding the lifecycle coordinator, idle locking observes zero in-flight permits and then re-reads activity; a delayed execution regression proves completion prevents the stale lock. |
| R-87 | Medium | M-05 | Cross-UID G2 startup accepted an Agent-owned writable or group/world-writable runtime ancestor even though the CLI rejected the resulting replaceable socket path. | Fixed in `2fcd3d00d320feadb26ee95db0f4cccbe672bda8`. Broker startup now rejects symlinks, non-directories, writable shared ancestors, and admitted-Agent-owned writable ancestors through the mount boundary. The Linux G2 attack harness passes. |
| R-88 | Low | M-04/M-05 | Interactive init copied the recovery-key confirmation suffix and prompt result into ordinary heap buffers that were not wiped on drop. | Fixed in `2fcd3d00d320feadb26ee95db0f4cccbe672bda8`. Both confirmation fragments use `Zeroizing` ownership and comparison no longer constructs ordinary `String` or `Vec<char>` intermediates. |
| R-89 | Medium | M-05/M-06 | Policy expiration relied only on wall time, so clock rollback could extend an activated snapshot or revive one that had already denied as expired. | Fixed in `2fcd3d00d320feadb26ee95db0f4cccbe672bda8`. Each activation captures a monotonic deadline and an irreversible expiry latch; unit tests cover monotonic expiry and rollback after observed wall-clock expiry. |
| R-90 | Low | M-05 | Updating a disabled Action removed the old entry from catalog preflight even though the store retained the disabled row, so a near-limit update could make Action list exceed the frame limit. | Fixed in `645bab6176ee72c290db9de7d5f8b76a19fd0f81`. Action upsert retires every non-retired prior version, making durable list behavior match replacement preflight; a disable-then-update storage regression proves only the new active version remains listed. |
| R-91 | Medium | M-05 | Default runtime preparation followed an existing `<state-dir>/runtime` symlink, changed its target permissions, and bound sockets through a path the official CLI rejected. | Fixed in `645bab6176ee72c290db9de7d5f8b76a19fd0f81`. Runtime preparation rejects a symlink before chmod or bind and revalidates the resulting directory with `symlink_metadata`; the regression proves the symlink target is untouched. |
| R-92 | Medium | M-06 | GitHub token revocation retried one captured token until the entire cleanup budget expired, preventing later captured tokens from receiving even one revoke attempt. | Fixed in `89cc7455cb3337873f150e7160f49997f08dc411`. Cleanup gives every captured token one bounded revoke attempt before spending remaining budget on retries. |
| R-93 | Medium | M-05 | The CLI accepted an Admin socket owned by an allowed Agent UID in a cross-UID runtime, exposing owner-only Admin operations to that peer. | Fixed in `89cc7455cb3337873f150e7160f49997f08dc411`. Admin endpoints always require the caller EUID and mode 0600; cross-UID allowance remains Agent-only. |
| R-94 | Low | M-06 | Duplicate GitHub installation permission keys were accepted and their effective scope depended on JSON map overwrite behavior. | Fixed in `89cc7455cb3337873f150e7160f49997f08dc411`. Duplicate permission keys fail closed before exchange, with regression coverage. |
| R-95 | Medium | M-05 | Session create and revoke success-audit commits could wait indefinitely beyond the Admin deadline. | Fixed in `9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5`. Both operations use non-cancelable, deadline-aware audit completion and preserve state/audit ordering. |
| R-96 | Low | M-05 | The GitHub App profile field could fit the generic Admin frame while exceeding the field bound assumed by the CLI. | Fixed in `9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5`. GitHub profiles share the explicit 64 KiB field limit at both IPC endpoints. |
| R-97 | Low | M-05 | Successful policy activation did not refresh Authority activity and could be followed by an idle lock based on stale use. | Fixed in `9b50c7d80ef9c491f7ac6d2bae1e3e56202ad9b5`. Durable activation success refreshes activity under the lifecycle coordinator. |
| R-98 | Low | M-05 | Direct Admin clients could encode individually oversized proof or Secret fields inside a body that remained under the aggregate frame limit. | Fixed in `1f008d16141b1106ccd0e0caa1bef9dd59c82bed`. Zero-copy decoding enforces each 64 KiB field bound after message-specific pre-allocation checks. |
| R-99 | Low | M-05 | CLI stdin applied the field limit to the combined one- or two-line buffer instead of to each Secret line. | Fixed in `1f008d16141b1106ccd0e0caa1bef9dd59c82bed`. Each line has an independent bound and exact-boundary regression coverage. |
| R-100 | Low | M-05 | Canceling a session audit wait at the deadline could leave durable success and in-memory session state out of sync. | Fixed in `1f008d16141b1106ccd0e0caa1bef9dd59c82bed`. Session audit completion remains owned after client timeout and state transitions follow the committed outcome. |
| R-101 | Medium | M-05 | Unlock queued behind an active drain and could reopen admission after the original caller had timed out. | Fixed in `1f008d16141b1106ccd0e0caa1bef9dd59c82bed`. Unlock uses non-waiting coordinator acquisition and returns busy while a drain owns lifecycle. |
| R-102 | Low | M-05 | A CRLF-terminated proof or Secret exactly 64 KiB long was rejected because the trailing carriage return counted toward the field limit. | Fixed in `38d67cfa2898c8aa95af83809c7fedea79e2f8fc`. LF and CRLF terminators are excluded and an exact-boundary CRLF regression passes. |
| R-103 | Medium | M-05/M-06 | Stop selection could close remote-effect admission while unlock owned the coordinator, then unlock could reopen it before central stop acquired the coordinator. | Fixed in `38d67cfa2898c8aa95af83809c7fedea79e2f8fc`. Stop-pending became sticky across the unlock transition and the SIGTERM regression holds the coordinator while proving admission remains closed. |
| R-104 | Medium | M-05/M-06 | Session revoke committed its success audit before blocking new capability acquisition, leaving a window for a post-audit execution permit. | Fixed in `38d67cfa2898c8aa95af83809c7fedea79e2f8fc`. SessionRegistry revocation is the admission linearization point before durable success; audit failure still faults the runtime. |
| R-105 | Low | M-05 | Bodyless and unknown Admin messages could force allocation and reading of a large body before dispatcher rejection. | Fixed in `38d67cfa2898c8aa95af83809c7fedea79e2f8fc`. Their pre-allocation body limit is zero and the connection closes before body read. |
| R-106 | Medium | M-05/M-06 | Separate stop-pending and admission atomics left a short observable gate-reopen window even with a second stop check. | Fixed in `ac2e513c938e4abe349be445bcd6a6b1b9da252c`. One atomic gate state now linearizes CLOSED-to-OPEN against STOP_PENDING, so the losing transition cannot expose admission. |
| R-107 | Low | M-05 | If stop won after Authority unlock but before lifecycle Running, the Authority remained unlocked while lifecycle stayed Locked and future operations wedged. | Fixed in `ac2e513c938e4abe349be445bcd6a6b1b9da252c`. The losing unlock path revokes sessions, relocks Authority, clears policy, restores Locked lifecycle, and the service-manager race proves the final causal signal-lock audit. |

Final finding counts: Critical 0, High 0, Medium 51 fixed / 0 open, Low 56 fixed / 0 open.

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
cargo check --workspace --release
cargo build --release --workspace
cargo audit
scripts/p0-acceptance.sh
scripts/p0-runtime-faults.sh
scripts/p0-crash-recovery.sh
scripts/p0-durability.sh
scripts/p1-policy-acceptance.sh
scripts/p1-streaming-sealing.sh
scripts/p2-github-app.sh
scripts/p1-service-manager.sh
scripts/p1-linux-g2.sh
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src
rg -n 'get_secret\b|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli
cargo tree -p rekey-cli -e normal
git diff --check
```

`cargo audit` scanned 308 locked dependencies against 1,236 RustSec
advisories and reported no vulnerability. Both mechanical API searches had no
matches. The CLI dependency tree contained none of `rusqlite`, `aes-gcm`,
`argon2`, `reqwest`, `rekey-vault`, or `rekey-broker`.

The final local evidence above was collected at validation head
`9551fe1caa75f89f4591916e8b7440b3974240fe`. GitHub Actions
[security-gate run 33571564907](https://github.com/majiayu000/rekey/actions/runs/33571564907)
is the corresponding successful cross-platform run: Ubuntu P0, macOS P0, and
the bounded Linux G2 reference job all passed.
