# Contributing

Open an issue before a behavior or security-model change. Rekey v2 is a
breaking codebase; do not add v1 migration, compatibility shims, secret-read
APIs, arbitrary proxying, or broader G2 claims without an accepted spec.

## Local gates

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo tree -p rekey-cli -e normal
git diff --check
```

The following searches must have no matches:

```bash
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src
rg -n 'get_secret\b|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli
```

The CLI dependency tree must not contain `rusqlite`, `aes-gcm`, `argon2`,
`reqwest`, `rekey-vault`, or `rekey-broker`. Run focused acceptance scripts for
the affected surface; CI runs the complete security gate.

## Commits and pull requests

Every commit must carry a Developer Certificate of Origin sign-off:

```bash
git commit -s
```

By signing off, you certify the contribution under the Developer Certificate
of Origin 1.1. Pull requests must explain scope, security-boundary impact,
tests, failure paths, and documentation changes. Required checks and review
conversations must be complete before merge. Do not force-push `main`, weaken
tests, expose secrets, or hide AI attribution in source or commits.
