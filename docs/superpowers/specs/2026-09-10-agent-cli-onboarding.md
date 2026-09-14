# Personal developer CLI onboarding

Outcome: one explicit shell-tool integration usable by Codex CLI. Implement
`scripts/agent-quickstart.py` on top of the existing `rekey` binary. No new
Agent operation, credential store, signer, MCP server, or network transport.

1. `prepare` connects to an unlocked broker, optionally records a credential
   through the CLI hidden TTY, creates a fixed GitHub issue Action, issues a
   15-minute/10-use session, and writes an unsigned, exact-principal policy
   draft. An existing Action can instead be selected with an explicit schema.
2. Operator reviews and externally signs the draft, then uses the existing
   trust-install and activate commands. Every mutation keeps its own step-up.
   Onboarding refuses an already persisted policy, because replacing other
   grants with a one-Action draft would be unsafe.
3. `execute` reads the short-lived session from an owner-only regular file,
   passes the capability to `rekey execute --capability -` through stdin,
   and returns the sealed upstream response. HTTP errors exit nonzero.
   It does not retry writes: lost responses may follow committed effects.
4. Credential repair stays in the operator terminal using credential rotate;
   the Agent receives an error and asks the operator to repair access, without
   asking for a password/token in the chat. Operator explicitly retries.

Deferred UX note: if operator testing shows that credential setup is a primary
onboarding blocker, a future host client may render a contextual credential
enrollment card backed by the Admin API. Trusted Action and credential metadata
must remain separate from Agent-provided explanation; the Agent receives only a
provided/declined result, never the secret through env, argv, stdin, files, or a
secret-read API. This onboarding slice does not add that UI or change Agent IPC.

The handoff directory is newly created with mode 0700; artifacts use exclusive
0600 creation. No upstream credential, password, signing key, or capability
is put in argv/env or the generated Agent instructions. Same-user filesystem
and process access remain outside G1 isolation claims.

Verification: Python tests exercise capability handling, hostile handoff files,
and HTTP error propagation; real CLI/broker tests check default denial, signed
policy activation and session revocation. Public GitHub and Vault evidence
requires dedicated operator-provided environments and is recorded separately.
Other providers remain deferred pending a concrete use case.

## Local follow-up evidence (2026-09-10)

`REKEY_QUICKSTART_REAL=1 PYTHONDONTWRITEBYTECODE=1 python3
scripts/test-agent-quickstart.py` now invokes the actual onboarding script in
a pseudo-terminal, including credential entry and all three step-up prompts.
It waits for terminal echo to be disabled before sending test inputs and
asserts that neither password nor credential appears in the transcript.
No mocked CLI or mocked TTY is used for the real broker test.

A current Codex tool invocation also exercised `execute` against a fixed
read-only `GET https://api.github.com/repos/majiayu000/rekey-ci-dogfood`, using
a synthetic canary in `x-api-key`, not a GitHub credential. The call returned
exit 6 / `UPSTREAM_FAILED` with no response. At that time local DNS returned
`198.18.0.42` for `api.github.com`. This is blocked-path evidence only; it is
not an authenticated GitHub success or GitHub App field validation.

Remaining field prerequisites are real DNS for that host, dedicated GitHub App
test material, and an operator-designated public HTTPS Vault environment.
Neither production screening nor the local proxy configuration was weakened.

After the operator authorized an exact `api.github.com` real-DNS exception,
the same public read succeeded with HTTP 200. A credential rotation followed
by another read also returned 200; credential revocation then produced exit 4.
`docs/evidence/agent-cli-public-read-2026-09-10.json` records the result. This
is a current Codex shell-host execution with an anonymous GitHub endpoint and
a synthetic credential, not GitHub App authentication or write evidence.
