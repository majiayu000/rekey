# Durable PKI issuance acceptance

Related: #71; implementation is integrated in PR #74 on the fresh 0.5 development line (vault27/policy8). Published 0.4 vault26 files are never migrated or read through a second decoder.

The 22 regular cases in `crates/rekey-vault/tests/pki_client_csr.rs` cover constrained CSR validation, reserve-before-key-use, persisted DER and terminal audits, restart/rotation/backup, tamper/replay, extra trigger effects, audit failure, closed receivers, cancellation and a killed reservation owner. Serial revocation and CRL cases are additional scope; they do not replace the issuance ledger checks.

`scripts/test-pki-process.py` complements those Worker tests with actual CLI/daemon processes. It creates a real previous-release vault, verifies format26 and refusal without modifying previous files, creates a separate format27 vault, imports a disposable CA, signs two CSRs across a daemon restart, compares delivered DER with stored facts, checks unique serials and paired started/terminal audits. Offline inspection uses immutable SQLite reads to avoid observer-created sidecars. Every state directory and HOME is temporary; passwords/private keys travel through stdin and subprocess output is checked for secret reflection. The prior release package is extracted without installation; pass its actual packaged bin directory rather than `Payload/usr/local/bin` absolute symlinks.

Example (OpenSSL 3 required):

```sh
cargo build --locked -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
python3 scripts/test-pki-process.py --binaries target/debug --previous-binaries /path/to/extracted/Rekey.app/Contents/Resources/bin --openssl /path/to/openssl --output /tmp/pki-process-receipt.json
```

A receipt records the Git SHA and both daemon binary hashes. Real process acceptance also passed on committed product candidate `0122aa3` after the owner-capacity fix: two certificates, paired started/terminal audits, restart retention and distinct serials; actual v0.4 format26 was rejected with previous files preserved. Candidate daemon SHA-256: `1ecf2717c25aed1931019bfbba73564c4a532128cfd55b1b55790a07fd9119ab`. Rerun after further product-code changes. This is software acceptance only: no release installation, real CA, Agent PKI admission, hardware/device guarantee or overall PKI parity. Close #71 only after its implementation and acceptance commits are merged with current-head gates.
