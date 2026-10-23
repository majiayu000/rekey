# Authentication handoff submission — 2026-10-23

Decision: submit the bounded native-authentication correction on top of main
`26bf862296e7b3f6660c6dc47c52f995d0f959ec` (including the new provider presets).
Keep fresh A2 proof and the existing installed trust. No password cache, new grant,
trust replacement, migration, or format change is part of this patch.

This branch contains CLI-to-App public option handoff, signer preflight and existing
software-key signing, saved-credential reuse, canonical draft projection, and the
installed signer ID before first policy activation. The App never reads a CLI
remembered-unlock file to approve operations. Other pending remembered-ticket,
approval, MCP, and error-guidance work is not included.

The earlier combined local dogfood candidate passed signed installation readback,
system-authentication unlock, existing software-signer detection, unchanged policy
and credential identity, and an authenticated read-only GitHub request. That build
included other pending local changes and predates the new provider-presets base;
it is not proof that this exact submission head has been installed. Actual policy
signing prompt counts and hardware-key acceptance remain device gates.

## Local validation

- `cargo check --workspace --all-targets` and Clippy with `-D warnings`: passed.
- `cargo test --workspace --offline -- --test-threads=1`: 1,048 passed, 0 failed,
  14 ignored across 105 test groups, including documentation tests.
- Swift UI typecheck and the executable Connection contract: passed, retaining
  all 18 API-key and six OAuth presets from the updated main branch.
- The real Swift/CLI/Broker fixture: passed with an existing software signer,
  unsorted reviewed connections, unchanged trust, cancellation and A1-as-A2
  rejection, and activation with synthetic presence instead of a password.
- `scripts/test-cli-add.py`: passed, including trust and credential reuse,
  invalid-input refusals, discovery and remembered-unlock restart/revocation.
- Format, diff whitespace, forbidden-API searches and the CLI dependency boundary:
  passed.

All live fixtures used disposable synthetic vaults. These results do not establish
Touch ID/Secure Enclave prompt counts or installation of this exact branch.

The PR's macOS/Linux P0 checks and review threads are separate merge gates.
