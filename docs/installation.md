# Install, upgrade, service, and uninstall

Pre-tag candidate snapshot; current publication status is recorded on the
[GitHub release](https://github.com/majiayu000/rekey/releases/tag/v0.3.0-alpha.2) and its complete workflow.

This page describes the **0.3.0-alpha.2 unpublished candidate and release
workflow**, not proof of an available 0.3 download. Product version 0.3 represents the existing v3 design
without claiming 1.0 maturity; historical tags and releases remain unchanged.
macOS distribution is a signed, notarized `.pkg` for
macOS 14+ on Apple Silicon; Linux uses an Ubuntu 24.04 x86_64 archive. There is
no default macOS tar/zip installation path and no published Homebrew tap.
The release-local `rekey.rb` is generated from the final pkg bytes.

A release is usable only after its tagged workflow, installed-package checks
and public-download smoke finish successfully. Failed public smoke withdraws
the prerelease to draft. Local software checks do not establish Developer ID
provisioning, device Keychain access, Touch ID, or a fresh-account install.
Those signed-device gates remain required before making L1 claims.

## macOS pkg or release-local Homebrew cask

Use an actual tag from a completed release; `TAG_FROM_COMPLETED_RELEASE` below
is a placeholder, not a published version. Confirm the tag's release notes and
checks before continuing.

```bash
REKEY_VERSION='TAG_FROM_COMPLETED_RELEASE'
gh release download "$REKEY_VERSION" --repo majiayu000/rekey \
  --pattern "rekey-${REKEY_VERSION}-macos.pkg" \
  --pattern rekey.rb --pattern SHA256SUMS
gh attestation verify "rekey-${REKEY_VERSION}-macos.pkg" --repo majiayu000/rekey
shasum -a 256 -c SHA256SUMS --ignore-missing
pkgutil --check-signature "rekey-${REKEY_VERSION}-macos.pkg"
spctl --assess --type install --verbose=4 "rekey-${REKEY_VERSION}-macos.pkg"
```

Choose **one** installation method: open the verified pkg in Installer, or
review the downloaded cask's exact URL, SHA256 and uninstall receipt and run:

```bash
HOMEBREW_DEVELOPER=1 brew install --cask ./rekey.rb
```

Current Homebrew normally rejects casks loaded from file paths. The command
above opts in for this invocation only; it does not change global settings or
create a tap. A cask is executable Ruby: verify its release source and checksum
and review its contents first. If local-file loading is explicitly prohibited
by your Homebrew configuration, use the verified pkg instead of overriding that
policy. [Homebrew local-path policy](https://docs.brew.sh/Manpage#environment)

The cask installs the same signed pkg and uses its actual SHA256; it does not
bypass Gatekeeper, provisioning or the Installer checks. This command uses a
local release asset, not a tap. Homebrew's pkg uninstall mechanism removes
receipt-tracked files. [Homebrew cask documentation](https://docs.brew.sh/Cask-Cookbook#stanza-uninstall)

The pkg installs `/Applications/Rekey.app` and links `rekey`, `rekeyd`, and
`rekey-mcp` in `/usr/local/bin`. Do not overwrite another installation's files.
Keep the App at that installed path. The App owns the opt-in SMAppService login
item; do not separately install a generated LaunchAgent for this package.

```bash
rekey setup
rekey add anthropic
# Use a model confirmed for your provider account:
rekey run claude-code --client claude-code -- claude --model YOUR_MODEL
```

Setup opens the App for mode selection, vault creation and human authentication.
Save the recovery key when displayed. The App handles credential entry, Profile
review and signing; Agent processes receive capabilities, never provider keys.
If provisioning, login-item approval or policy signing is unavailable, fix that
reported prerequisite; do not replace the signed daemon with a source binary.

## Linux download and user-owned installation

After selecting a completed release as above:

```bash
REKEY_TARGET=x86_64-unknown-linux-gnu
gh release download "$REKEY_VERSION" --repo majiayu000/rekey \
  --pattern "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz" --pattern SHA256SUMS
gh attestation verify "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz" --repo majiayu000/rekey
sha256sum --check --ignore-missing SHA256SUMS
tar -xzf "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz"
REKEY_RELEASE_DIR="$PWD/rekey-${REKEY_VERSION}-${REKEY_TARGET}"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$REKEY_RELEASE_DIR/rekey" "$REKEY_RELEASE_DIR/rekeyd" \
  "$REKEY_RELEASE_DIR/rekey-mcp" "$REKEY_RELEASE_DIR/rekey-policy-sign" \
  "$REKEY_RELEASE_DIR/rekey-approval-sign" "$HOME/.local/bin/"
export PATH="$HOME/.local/bin:$PATH"
rekey --version
rekeyd --version
umask 077
rekey init --mode team
```

Both binaries must match the chosen release tag. Keep all five binaries
alongside each other. Linux uses team mode and the external signing workflow;
the macOS personal signing/UI path is unavailable. Save the one-time recovery
key separately. Losing both password and recovery key loses the vault.

## systemd user service

Initialize the vault first, then run these commands as the owning non-root
logged-in user. No `sudo`, `User=` or system-wide unit is involved:

```bash
REKEY_USER_UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
mkdir -p "$REKEY_USER_UNIT_DIR"
python3 "$REKEY_RELEASE_DIR/rekey-service-unit.py" systemd-user \
  --rekeyd "$HOME/.local/bin/rekeyd" --state-dir "$HOME/.rekey" \
  > "$REKEY_USER_UNIT_DIR/rekey.service"
systemd-analyze --user verify "$REKEY_USER_UNIT_DIR/rekey.service"
systemctl --user daemon-reload
systemctl --user enable --now rekey.service
systemctl --user status rekey.service
journalctl --user -u rekey.service
rekey unlock
```

The service starts locked and targets the user manager's `default.target`.
It follows the user manager's lifetime; this does not enable lingering or
promise startup before login. A missing user bus requires a working user
session, not falling back to a root system service. [systemd user target](https://github.com/systemd/systemd/blob/main/man/systemd.special.xml)

To stop or remove this unit (vault data remains):

```bash
systemctl --user disable --now rekey.service
rm "$REKEY_USER_UNIT_DIR/rekey.service"
systemctl --user daemon-reload
```

For development-only macOS builds, the generator retains its `launchd` mode.
That is a manual development service path, not the signed pkg's SMAppService
installation path.

## Dedicated-account system service (optional Linux deployment)

Use a dedicated non-root account. These commands intentionally show every
privileged step:

```bash
sudo useradd --system --create-home --home-dir /var/lib/rekey --shell /usr/sbin/nologin rekey
sudo install -m 0755 "$REKEY_RELEASE_DIR/rekey" /usr/local/bin/rekey
sudo install -m 0755 "$REKEY_RELEASE_DIR/rekeyd" /usr/local/bin/rekeyd
sudo install -d -m 0700 -o rekey -g rekey /var/lib/rekey/state
sudo -u rekey /usr/local/bin/rekey --state-dir /var/lib/rekey/state init --mode team
sudo python3 "$REKEY_RELEASE_DIR/rekey-service-unit.py" systemd \
  --rekeyd /usr/local/bin/rekeyd \
  --state-dir /var/lib/rekey/state \
  --run-as-user rekey > rekey.service
systemd-analyze verify rekey.service
sudo install -m 0644 rekey.service /etc/systemd/system/rekey.service
sudo systemctl daemon-reload
sudo systemctl enable --now rekey.service
sudo systemctl status rekey.service
sudo journalctl -u rekey.service
```

Run Admin commands as the `rekey` account because `admin.sock` is owner-only.
The service starts locked. Stop, reload after an upgrade, and uninstall with:

```bash
sudo systemctl stop rekey.service
sudo systemctl daemon-reload
sudo systemctl start rekey.service
sudo systemctl disable --now rekey.service
sudo rm /etc/systemd/system/rekey.service
sudo systemctl daemon-reload
```

For the bounded Linux G2 reference, use `--agent-socket` with the UID/GID and
runtime-directory layout documented in the repository file
`scripts/p1-linux-g2.sh` (not shipped in the release archive). Do not make
the state directory or Admin socket group-writable.

Linux `rekey agent-run` additionally needs Linux 5.11 or newer with
`close_range(CLOSE_RANGE_CLOEXEC)` permitted, `bubblewrap`, and that same disjoint
Agent socket. Ubuntu black-box evidence is limited to the harnessed child
failing public TCP/UDP probes while still using `agent.sock`. It is not macOS
G2, not Adversarially Verified isolation, and not a substitute for the Docker
attack harness.

On Ubuntu 24.04 and later, AppArmor restricts unprivileged user namespaces.
`bwrap --unshare-user --unshare-net` then fails with `RTM_NEWADDR: Operation
not permitted` unless a bwrap userns profile is loaded. Install
`apparmor-profiles` and load the extra profile; do not disable
`kernel.apparmor_restrict_unprivileged_userns`.

```bash
sudo apt-get install -y bubblewrap apparmor-profiles
sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
  /etc/apparmor.d/bwrap-userns-restrict
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

## macOS Agent isolation (experimental)

`rekey agent-run` selects the fixed `macos-seatbelt-v1` profile on macOS.
It requires `/usr/bin/sandbox-exec`; this is a deprecated Apple interface,
so support is limited to tested system builds (currently 26.5.1 / 25F80 arm64).
No installation of a CA, VM, global service, or network proxy is needed.

Start `rekeyd serve --state-dir "$STATE" --agent-runtime-dir "$AGENT_RUNTIME"`
with the same disjoint endpoint layout used on Linux. Run from a directory
containing only the Agent's code, disjoint from both the state and Agent
runtime directories. HOME, shared temporary parents, and paths overlapping
`/System/Volumes` are rejected as code directories. Overlap checks compare
directory identities to reject APFS and case aliases. The code directory is
readable, not writable.
The child starts in a fresh temporary directory, also used for HOME/TMPDIR.

```bash
# STATE, AGENT_RUNTIME, AGENT_CODE and AGENT_BIN are operator-selected paths.
AGENT_SOCKET="$(realpath "$AGENT_RUNTIME/agent.sock")"
cd "$AGENT_CODE"
rekey --state-dir "$STATE" --agent-socket "$AGENT_SOCKET" agent-run -- "$AGENT_BIN"
```

Use the canonical socket path inside the Agent too: aliases such as `/var`
versus `/private/var` are not separate network permissions. When the Agent
needs a capability, add `--capability-stdin` before `--` and pipe the capability
into stdin; it is placed only in the child's `REKEY_CAPABILITY` environment.
The child's stdin is `/dev/null`. Parent environment variables are dropped.
Only designated system/Homebrew runtime reads and the exact executable are
added beyond the code directory. Arbitrary interpreters/toolchains are not
all guaranteed compatible; do not widen the policy silently on failure.

No direct IP egress, other local sockets, or Mach service grants are provided.
Missing launcher, invalid profile and spawn errors never retry unsandboxed.
The launcher waits for the direct child and forwards its exit code (signal
termination maps to 5). Descendants remain sandboxed after launcher death;
there is no guarantee of killing all descendants. Killing the launcher can
leave its `rekey-agent-*` scratch directory behind. Parent-provided output
files/pipes/TTYs are explicitly delegated; network-socket output is rejected.

The code directory must not contain credential copies or hard links to
protected files. This profile does not defend against a malicious external
same-UID host process, host root, or kernel compromise. It does not upgrade
G1 to G2 or implement Windows/plugin isolation. See the
[feature truth matrix](product-foundation/feature-truth-matrix.md).

## Lab reference integrations (source builds)

The following native plugin/sidecar, legacy independent text-stream and metrics
paths require a source build with `--features lab`. GitHub App credential
management remains available; the personal path uses the GitHub PAT template.
The common Profile LLM raw-SSE path is a default v3 feature and is separate from
the legacy text-only connector below.

### GitHub reference connector

The source implementation of GitHub CreateIssue and CreateIssueComment uses the bundled
`rekey-github-create-issue` sidecar on macOS. Build it with the Broker package
and keep it beside `rekeyd` when copying binaries. Default v3 archives and the macOS pkg do not ship this lab sidecar.
A missing sidecar fails either mutation call instead of running it unsandboxed.

For a lab source build, install the three matching binaries together:

```bash
cargo build --release --features lab -p rekey-cli --bin rekey -p rekey-broker --bins
install -m 0755 target/release/rekey target/release/rekeyd \
  target/release/rekey-github-create-issue "$HOME/.local/bin/"
```

Current unreleased source uses state/backup format **25**. It rejects earlier
formats without migration. Vault25 / policy6 are frozen across all 0.3 releases,
including prereleases. Initialize a new empty state directory for an older format; keep
older binaries with their matching state and backups.

An Admin may instead bind a local executable to one exact Action version with
`native_plugin` in the Action JSON. Registration stores the approved
absolute path, expected SHA-256 and either `github-issues-v1` or
`anthropic-messages-v1`; it does not run or inspect the file. Each execution
verifies its bytes before starting the isolated snapshot. Missing or changed
files fail without falling back to the bundled sidecar. See
[the closed native plugin contract](superpowers/specs/2026-09-16-native-action-plugin.md)
and [the GitHub registration history](superpowers/specs/2026-09-16-action-plugin-registration.md).

Updating the Action creates a new binding version. Existing sessions retain
their old version; preserve separate artifact paths when both must run. Backups
include the binding, not the executable. Restore requires supplying the same
path and digest again. Explicit bindings support macOS and Linux GNU x86_64/aarch64;
other platforms fail. Linux unregistered built-in operations remain in-process.

On Linux, install system bubblewrap at `/usr/bin/bwrap` and allow unprivileged
user, PID, network, IPC and UTS namespaces. Linux 5.11+ is required for descriptor
cleanup. The fixed GNU runtime files are the architecture loader plus `libc.so.6`,
`libm.so.6` and `libgcc_s.so.1` under the Debian/Ubuntu multiarch library paths.
Only those files and the artifact are mounted into a read-only root. Missing
dependencies or denied namespace setup fail the call; no unrestricted fallback
exists. Ubuntu 24.04+ also requires an AppArmor profile allowing bwrap userns,
as described in the Linux Agent setup above.

Only the selected operation and public issue/comment text enter the reference process. The Broker keeps all
credentials, authorization, HTTP execution, response checks and revocation.
The macOS Seatbelt profile denies networking and process creation; memory is
watched by sampling and can overshoot. Linux uses a separate namespace root and
default-deny seccomp filter, with a 64 MiB per-process virtual-address limit
that survives re-exec. This is not a total physical-memory limit. CPU and
wall-clock deadlines apply on both platforms. Linux parent-death cleanup is
verified after payload startup, not throughout the bwrap initialization window.
This is a bounded reference integration, not a third-party plugin registry.

## Independent text streaming (source build)

An Admin can register an opaque-token Action with `text_stream: {"model":
"ADMIN_CHOSEN_MODEL", "max_tokens": 1024}` and the fixed Anthropic Messages
endpoint. See [the exact Action and stream contract](superpowers/specs/2026-09-16-anthropic-text-stream.md).
The Agent supplies only bounded user/assistant text messages:

```bash
rekey --agent-socket "$AGENT_SOCKET" execute-text-stream "$ACTION_VERSION" \
  --capability - --body-file messages.json
```

Supply the capability through stdin. Text appears incrementally; exit zero means
completed. Failure or incomplete output exits nonzero, and already printed text
cannot be recalled. Do not treat a displayed prefix as success or automatically
retry a failed call. Existing `execute` remains fully buffered and rejects
stream-only Actions; MCP does not expose these Actions. Local fixture tests do
not establish live Anthropic account/model compatibility.

## Local metrics file

The source build supports one-shot textfile publication for a separately managed
collector. Prepare an existing physical directory owned by the Admin job user,
normally mode 0750 with the collector's read-only group. Keep it separate from
the vault state directory. Symlink components and untrusted writable ancestors
are rejected. Ensure ACLs grant no extra read/write/delete access to other identities,
including permissions inherited by new files; the CLI validates POSIX mode/owner,
not platform ACLs.

```bash
rekey --state-dir "$STATE" metrics --prometheus --textfile-dir "$METRICS_DIR"
```

Success atomically replaces only `rekey.prom`, at mode 0640 with the directory's
group. It also works while the Broker is locked. A validated, locked producer
removes old output when sampling or publication fails; validation failure and
lock contention leave files untouched. Errors are reported through the CLI.
A killed or unscheduled job can leave stale output: consumers must check file
mtime and collector health, and must not interpret old data as current health.

This command installs no scheduler, collector, listener or alerts. The existing
`rekey metrics` JSON and `rekey metrics --prometheus` stdout modes remain available.
See the [local metrics contract](superpowers/specs/2026-09-16-local-metrics.md)
and [external collection specification](superpowers/specs/2026-09-16-external-capabilities.md).

## Format changes and restore

The 0.3 candidate uses vault/backup format **25** and policy snapshot
format **6**. These durable formats are frozen across all 0.3 releases, including prereleases.
No older vault, backup or policy format is migrated or backfilled, now or after GA.
All 0.3 releases must preserve the durable format; an incompatible format
requires a separately planned release line and prior SPEC revision. Renumbering
from v3.0.0-alpha.4 does not require reinitializing vault25 / policy6. Keep old
binaries, state and backups together; initialize a new empty directory for an
incompatible format rather than pointing new binaries at old state.

Back up and verify a receipt before changing an installation. A supported
same-format restore requires authenticated preview, visible source generation
and external high-water context, and explicit confirmation with password or
recovery proof. Ordinary unlock is not rollback consent. Follow the matching
binary's `rekey restore --help` and rollback confirmation flow; never delete
external generation history to make an old snapshot unlock.

## Upgrade and uninstall

On macOS, first disable login startup in Rekey.app, shut down the daemon using
its fresh-proof shutdown action, and quit the App. Confirm it has stopped before
replacing or removing files. For a cask installation, then run:

```bash
brew uninstall --cask rekey
```

The cask matches only the exact `com.starlight.rekey.pkg` receipt. It supplies
no service-stop hook, signal, `zap`, vault deletion or Keychain deletion. For a
manual pkg installation, remove only `/Applications/Rekey.app` and the three
`/usr/local/bin` links after verifying that each link still points into that
App; forgetting a receipt alone does not remove its files. Preserve state and
Keychain history across uninstall and reinstall.

For a Linux user installation, stop/disable its user unit as above, then remove
only the five binaries you installed in `$HOME/.local/bin`. The optional system
service above has its own explicitly privileged stop/removal procedure.
Encrypted vault data, recovery material and generation history are not uninstall
artifacts and must remain untouched.
