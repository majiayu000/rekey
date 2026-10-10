# Shared SSH/Profile owner capacity acceptance

Related: #70. Builds on PR #74 (`fa734a5`) and uses the current Worker-native SSH protocol; the historical SSH control opcode is not restored.

Implemented: 16 shared live owners, seven short admin requests, 23 accepted normal admin connections and one capacity responder. Registry ownership is Weak; control/registration/execution ownership is strong. Registration EOF drains queued work and cannot deliver a token; cancellation prevents subsequent admission. No storage, wire or public configuration changes.

Focused local results: all 15 Profile IPC tests, six Profile runtime tests (including a cancelled registration blocked in real SQLite), eight native SSH integration tests, and the manual real OpenSSH comparison pass. Profile lab fixtures were missing the mandatory policy8 `derived_credentials` field; the fixtures now describe the current format. This does not establish full lab runtime acceptance.

OpenSSH comparison: each row counts all 16 attempted Ed25519 git-namespace signatures. Keys, messages, sockets and vaults were disposable local fixtures. Rekey has audit/policy checks that the baseline does not; these are latency observations, not equivalent security or superiority claims.

| Backend | Concurrency | Failed / attempted | Mean microseconds | p95 microseconds |
|---|---:|---:|---:|---:|
| OpenSSH agent | 1 | 0 / 16 | 4887 | 5975 |
| OpenSSH agent | 4 | 0 / 16 | 6986 | 7794 |
| OpenSSH agent | 16 | 0 / 16 | 11830 | 14319 |
| Rekey | 1 | 0 / 16 | 5660 | 6847 |
| Rekey | 4 | 0 / 16 | 9477 | 10173 |
| Rekey | 16 | 0 / 16 | 19326 | 22061 |

Reproduce: `cargo test -p rekey-broker --test ssh_agent real_openssh_concurrency_comparison_counts_every_failure -- --ignored --nocapture`. Hardware/device guarantees, full lab runtime and gateway replacement cleanup remain separate. Current-head CI/review and merge remain required before closing #70.
