# Storage fault-injection gate

The H-02 gate combines deterministic SQLite/filesystem contract tests with a
real Linux `ENOSPC` run. The real run accepts only a distinct 8 to 128 MiB
filesystem mount, and CI supplies a disposable owner-only 32 MiB tmpfs; it
cannot fill the runner root filesystem. `.github/workflows/security-gate.yml`
mounts and unmounts that filesystem and runs the tests serially.

| Boundary | Evidence | Required behavior |
| --- | --- | --- |
| audit commit | `enospc_faults::audit_enospc_faults_the_worker` and `fault_injection::audit_commit_failure_faults_the_worker` | return `AUDIT_COMMIT_FAILED` and fault the worker |
| credential mutation | `enospc_faults::credential_mutation_enospc_is_atomic_and_retryable` and `fault_injection::transactional_mutation_audit_failure_faults_the_worker` | never report success or leave a partial credential; fault if the mandatory audit commit fails |
| WAL checkpoint | `store::sqlite::tests::busy_wal_checkpoint_is_not_reported_as_success` | a busy or incomplete checkpoint is a storage error |
| backup | `enospc_faults::backup_enospc_returns_no_receipt_and_requires_a_new_path` and `backup_restore` | return no receipt, retain an authorized partial external path, and require a new path for retry |
| restore | `enospc_faults::restore_enospc_cleans_internal_artifacts_and_retries` and `backup_restore` | leave no servable vault, clean known internal artifacts, and succeed after space is restored |
| rename/fsync | `bootstrap::tests::final_rename_failure_keeps_restore_blocked_until_cleanup`, `backup_restore`, `bootstrap_contract`, and `durable` tests | fail explicitly; an install-path blocker is not deleted, the incomplete marker remains, and cleanup restores a retryable state only after the blocker is removed |
| permissions | `bootstrap_contract`, `durable`, broker runtime and peer tests | reject insecure ownership/modes and verify owner-only files and directories |

An ordinary test run compiles the ENOSPC tests but the four exhaustion cases
return immediately when `REKEY_ENOSPC_DIR` is absent. The mount guard always
runs and rejects an ordinary directory. To exercise the real path manually on
Linux, use only a newly mounted disposable tmpfs and run:

```bash
REKEY_ENOSPC_DIR=/path/to/disposable-tmpfs \
  cargo test -p rekey-vault --test enospc_faults -- --test-threads=1 --nocapture
```

The operator must unmount the disposable filesystem afterwards. Never point
`REKEY_ENOSPC_DIR` at a normal workspace, home, state, or system directory.
