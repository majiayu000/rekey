# 2026-10-09 experiment integration record

## Baseline and ownership

- Published baseline: `origin/main` at `d4bdda1572dbc9944d14efed97376d71a7f7969f`, vault26 / policy7.
- Connect-on-open repair: `5c21c0c` (denial-backoff fixture) and `0d74833` (native startup), based on that baseline.
- Combined working branch: `integrate/experiments-20261009`. Main SSH kinds 11/12/13, Worker signer and signed Connection ownership are retained.
- Experimental aggregate: `b57d84456136127a7277449120a1652306fa89d1`. This aggregate is a source of bounded changes, not a replacement checkout or a merge of its superseded product architecture.
- Development format contract: [unified experiments](../specs/2026-10-09-unified-experiments.md), 0.5.0-alpha.1 / vault27 / policy8. There is no upgrade or migration for the user's installed App/vault; both are untouched by this integration.

## Branch disposition

The local `codex/competitive-*` inventory contains 32 distinct heads. Multiple branch names at one head are aliases. The following is a provenance inventory; ancestry alone does not claim the old behavior is retained.

| Head | Branch suffixes | Provenance |
|---|---|---|
| `fae4f0d5ae26` | `action-collection-integrity-20261007`, `ssh-approval-ui-20261008` | covered by team-ssh aggregate; adapted to current contract |
| `46eee11a15ee` | `action-scratch-20261008` | reviewed separately (see disposition below) |
| `043a0206473b` | `bench-20261005`, `ledger-20261005`, `perf-20261005`, `stream-20261005` | already in main |
| `2b88f1e02303` | `child-event-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `438ef252ce35` | `decoded-tail-20261006`, `multisession-bench-20261006`, `next-20261005` | reviewed separately (see disposition below) |
| `3963dd305c79` | `foundation-20261005`, `metadata-tail-20261005`, `transform-guards-20261005` | covered by team-ssh aggregate; adapted to current contract |
| `2d37c3b4e7a4` | `integrated-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `0d50c3d9748a` | `json-map-20261006` | reviewed separately (see disposition below) |
| `4cd99ce0b7e3` | `literal-prefilter-20261005`, `sse-cpu-20261005` | covered by team-ssh aggregate; adapted to current contract |
| `89c33bfaa2ab` | `mtls-action-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `2f0ee7d9fe51` | `pki-ca-import-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `888af3a7c7df` | `pki-client-csr-20261007` | covered by team-ssh aggregate; adapted to current contract |
| `734c6c4cea47` | `pki-durable-issuance-20261007` | covered by team-ssh aggregate; adapted to current contract |
| `6fbd21467e5e` | `pki-full-crl-20261007` | covered by team-ssh aggregate; adapted to current contract |
| `c871f723775f` | `pki-serial-revoke-20261007` | covered by team-ssh aggregate; adapted to current contract |
| `1cd7d5521175` | `private-cli-20261006`, `ssh-cli-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `f5d5b4822c86` | `private-storage-20261005` | covered by team-ssh aggregate; adapted to current contract |
| `61f7f752d061` | `sse-boundary-20261006` | reviewed separately (see disposition below) |
| `6556984d4ac1` | `sse-data-borrow-20261006` | reviewed separately (see disposition below) |
| `2e1a152929e6` | `sse-parse-micro-20261006`, `sse-yield-20261005` | reviewed separately (see disposition below) |
| `021eb9b13edc` | `sse-tcp-20261005` | covered by team-ssh aggregate; adapted to current contract |
| `9943fdbc569a` | `ssh-action-storage-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `dc0e632283db` | `ssh-codec-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `1e801f226fa9` | `ssh-daemon-owner-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `b0dd301c1d7f` | `ssh-frontdoor-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `e1cca21eccec` | `ssh-integrated-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `5ac8ee079144` | `ssh-local-approval-20261008`, `team-ssh-signer-20261008` | covered by team-ssh aggregate; adapted to current contract |
| `0c8c2af1995a` | `ssh-public-policy-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `f149eeade1cf` | `ssh-signature-pending-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `42ead8dd3b67` | `ssh-signing-20261006` | reviewed separately (see disposition below) |
| `fa32d99c211a` | `ssh-typed-prepare-20261006` | covered by team-ssh aggregate; adapted to current contract |
| `b57d84456136` | `team-ssh-20261008` | covered by team-ssh aggregate; adapted to current contract |

Separate-head decisions:

- `46eee11`: adapt HTTP action authentication scratch-buffer reuse; do not import the superseded SSH action collection.
- `dee2dc5` / `0d50c3d`: retain direct canonical JSON map serialization and duplicate/equivalence tests.
- `6556984` / `61f7f75`: retain single-data-field SSE borrowing and boundary scanner, including frozen byte-loop equivalence and split/reflection tests.
- `2e1a152` and the literal-prefilter work (`c62bd0c`, beneath the reviewed performance heads): already represented by main's stream scheduling/sealing implementation; no duplicate path.
- `438ef25`: its measurement/review artifacts remain historical, not combined-head performance proof.
- `42ead8d`: superseded consume-only SSH scalar signer is not imported; current Worker-owned native SSH signing is retained.
- Team-SSH aggregate changes are adapted: private kinds become 16/17, mTLS is signed Connection auth, CA facts use the existing generation MAC, and SSH approval/budgets extend current signed SSH keys. No parallel SSH action DB, private-key export, old kind aliases or Agent CA admission is introduced.
- Child watcher `2b88f1e`: lab `run` retains main profile launching and adopts macOS kqueue/Linux pidfd wait ownership. Linux runtime acceptance remains CI work; the two child-wait regressions are now in the PR security gate on both operating systems.

## Verification

Combined-head local software gates passed. Raw logs are retained in the repository common Git directory at `.git/codex/evidence/experiments-integrated-20261009`; `source.json` binds the final commit/tree and installed-App hash. Prior branch counts are not reused as combined-head passes.

| Check | Result |
|---|---|
| `cargo fmt --all --check`, `git diff --check` | passed |
| `cargo check --workspace --all-targets --offline` | passed, default and `--features lab` |
| `cargo clippy --workspace --all-targets --offline -- -D warnings` | passed, default and `--features lab` |
| `cargo test --workspace --offline` | 1,032 passed, 0 failed, 13 explicit ignores |
| `cargo test -p rekey-cli --features lab --bin rekey child_wait --offline` | 2 passed, macOS; Linux added to the PR gate |
| Full native App, Connection model and CLI contract builds | passed with `-warnings-as-errors` |
| Native Connection model, real Swift/CLI/Broker and startup-only contracts | passed; mTLS and external SSH/budget fields preserved |
| `python3 scripts/test-human-vault.py target/debug/rekey` | passed |
| CLI normal dependency boundary, forbidden API searches | passed, no forbidden dependencies or matches |
| Changed shell/Python/YAML syntax | passed |
| `cargo audit --file Cargo.lock --json` | 0 vulnerabilities, no warnings; advisory DB updated 2026-10-08 |

The default workspace includes 4 mTLS, 8 broker SSH, 9 offline signer, 22 client CSR, 2 CA contract, 12 action integrity, 4 DEK and 30 storage contracts. It does not turn ignored device/provider/load fixtures into passes. Full lab runtime acceptance remains the lab CI gate, not a claimed local full-suite run.

Failure history retained during integration:

- mTLS mutation drain initially waited on a coordinator held by the mutator; cancellation now interrupts gate acquisition, and the real TLS owner-drain regression passes.
- Default SSH external challenge retrieval was still gated as lab; the current LocalCalls path is now reachable in default, with the old SessionRegistry path remaining lab-only.
- Two 100 ms PKI presign deadline fixtures contended with SQL-heavy tests; the PKI binary serializes its asynchronous fixtures without changing product deadlines or weakening assertions.
- Lab connector selection needed explicit rejection of private mTLS and CA kinds; neither can enter generic header connectors.
- The copied PKI revoke envelope assertion expected OIDC overhead despite the explicit local-only A2 contract; it now asserts the same bounded proof body in both configurations.
- The DEK immutable-state fixture expected a ten-column header. It now expects eleven columns including the new authenticated `pki_digest`; full equality except generation/MAC remains enforced.
- Old-version rejection fixtures derive their schema from current SQL; their synthetic INSERT now supplies the PKI digest placeholder. All thirty storage contracts pass with the original unsupported-version and no-backfill assertions. Removing the PKI header column instead was rejected as the wrong fixture shape for this format-discriminator test.

## External SSH approval workflow

Use `rekey approval review ID` and `rekey approval get ID` to obtain the public SSH review and challenge. Decode the CLI review's `review_json` string, then build the signer request as `{ "challenge": CHALLENGE_ENVELOPE, "ssh": DECODED_REVIEW.ssh }`; the key declaration is the exact SSH entry from the signed policy. Run the existing `rekey-approval-sign review/sign` flow with that declaration supplied as `--action`; review hash acknowledgement, distinct signer identity and private-file protections remain required. Submit one or two signed grants together as a JSON array on stdin to `rekey approval submit ID`. The native approval pane directs external challenges to this workflow; local Presence cannot substitute for external quorum.

## Remaining evidence boundaries

Real Touch ID, Secure Enclave, Keychain, installed App behavior, Linux event-wait runtime, real provider/CA deployment and public packaging/release are separate gates. This integration makes no combined-head speedup claim and does not implement Agent PKI admission or HA. Experimental branches are retained for provenance.
