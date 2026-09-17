# Install, upgrade, service, and uninstall

This file describes the `v2.0.0-alpha.2` archive (vault schema v9). It ships
two archives: macOS 14 arm64 and Ubuntu 24.04 x86_64. See
[the platform matrix](alpha-scope.md) before installing.

The tagged workflow publishes a prerelease before public-URL smoke. Install
`v2.0.0-alpha.2` from GitHub only after that smoke succeeds; a smoke failure
withdraws the Release to draft. Until then, `v2.0.0-alpha.1` remains the last
completed public download (schema v5). There is no in-place upgrade from any pre-v9
format, including v1 and v4–v8.

## Download and verify

Set the version and target for your platform:

```bash
REKEY_VERSION=v2.0.0-alpha.2
REKEY_TARGET=aarch64-apple-darwin       # macOS 14 arm64
# REKEY_TARGET=x86_64-unknown-linux-gnu # Ubuntu 24.04 x86_64

gh release download "$REKEY_VERSION" --repo majiayu000/rekey \
  --pattern "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz" \
  --pattern SHA256SUMS
gh attestation verify "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz" \
  --repo majiayu000/rekey
shasum -a 256 -c SHA256SUMS --ignore-missing
tar -xzf "rekey-${REKEY_VERSION}-${REKEY_TARGET}.tar.gz"
REKEY_RELEASE_DIR="$PWD/rekey-${REKEY_VERSION}-${REKEY_TARGET}"
```

`gh attestation verify` verifies the GitHub/Sigstore build provenance. The
Release also carries the SPDX SBOM, provenance bundle, SBOM attestation bundle,
and per-archive checksum.

## User-owned installation

This path does not use `sudo`:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 "$REKEY_RELEASE_DIR/rekey" "$HOME/.local/bin/rekey"
install -m 0755 "$REKEY_RELEASE_DIR/rekeyd" "$HOME/.local/bin/rekeyd"
export PATH="$HOME/.local/bin:$PATH"
command -v rekey rekeyd
rekey --version
rekeyd --version
```

Both commands must print `2.0.0-alpha.2`. Rekey finds `rekeyd` beside `rekey`
or on `PATH`; install both into the same directory.

## Initialize

```bash
umask 077
rekey init
```

Save the recovery key immediately in a separate secure location. It is shown
once. Losing both the password and recovery key permanently loses access to
the vault.

## launchd user service

The release archive includes `rekey-service-unit.py`. Initialize the vault
before installing the service, then generate and load a user LaunchAgent:

```bash
mkdir -p "$HOME/Library/LaunchAgents"
python3 "$REKEY_RELEASE_DIR/rekey-service-unit.py" launchd \
  --rekeyd "$HOME/.local/bin/rekeyd" \
  --state-dir "$HOME/.rekey" \
  --label io.github.majiayu000.rekey \
  > "$HOME/Library/LaunchAgents/io.github.majiayu000.rekey.plist"
plutil -lint "$HOME/Library/LaunchAgents/io.github.majiayu000.rekey.plist"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/io.github.majiayu000.rekey.plist"
launchctl print "gui/$(id -u)/io.github.majiayu000.rekey"
rekey status
```

The service starts locked. Use `rekey unlock` after boot. Logs are
`~/.rekey/rekeyd.stdout.log` and `~/.rekey/rekeyd.stderr.log`.

Stop, reload after a binary upgrade, and uninstall the definition with:

```bash
launchctl bootout "gui/$(id -u)/io.github.majiayu000.rekey"
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/io.github.majiayu000.rekey.plist"
launchctl bootout "gui/$(id -u)/io.github.majiayu000.rekey"
rm "$HOME/Library/LaunchAgents/io.github.majiayu000.rekey.plist"
```

## systemd system service

Use a dedicated non-root account. These commands intentionally show every
privileged step:

```bash
sudo useradd --system --create-home --home-dir /var/lib/rekey --shell /usr/sbin/nologin rekey
sudo install -m 0755 "$REKEY_RELEASE_DIR/rekey" /usr/local/bin/rekey
sudo install -m 0755 "$REKEY_RELEASE_DIR/rekeyd" /usr/local/bin/rekeyd
sudo install -d -m 0700 -o rekey -g rekey /var/lib/rekey/state
sudo -u rekey /usr/local/bin/rekey --state-dir /var/lib/rekey/state init
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

## GitHub reference connector (macOS and Linux source builds)

The source implementation of GitHub CreateIssue and CreateIssueComment uses the bundled
`rekey-github-create-issue` sidecar on macOS. Build it with the Broker package
and keep it beside `rekeyd` when copying binaries. The source archive and macOS
app build include it; published alpha.2 archives do not gain this feature.
A missing sidecar fails either mutation call instead of running it unsandboxed.

For a source build, install all three binaries together (the published alpha.2
installation above describes its historical archive):

```bash
cargo build --release -p rekey-cli --bin rekey -p rekey-broker --bins
install -m 0755 target/release/rekey target/release/rekeyd \
  target/release/rekey-github-create-issue "$HOME/.local/bin/"
```

Current source uses state/backup format **14**. It rejects earlier formats,
including 13, without migration. Initialize a new empty state directory; keep
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

## Cross-version install and rollback

These steps apply whenever the new archive uses a different vault format,
including `v2.0.0-alpha.1` (schema v5) to `v2.0.0-alpha.2` (schema v9).
Release notes that say the format is unchanged may replace only the two
binaries; **do not treat that as the path from alpha.1 to v9**.

### Keep the old environment

1. Using the **old** binaries, create and verify a backup as described in the
   operations runbook. Save the receipt and its SHA-256 off the state
   directory.
2. Stop the old service and confirm both sockets and the process are gone.
3. Leave the old state directory untouched. Keep the matching old `rekey` and
   `rekeyd` binaries (copy them aside before installing new ones into the same
   PATH directory).

The old backup restores only with those old binaries into a newly created
empty directory. It is not a migration entry into v9.

### Install the new version into a new directory

1. Verify the new archive (checksum and attestation).
2. Install the new `rekey` and `rekeyd` without pointing them at the old state
   directory.
3. Initialize a **new empty** state directory (`rekey --state-dir NEW_DIR init`).
4. Recreate credentials, Actions, policy trust, signed policy, and any
   workload or Vault source profiles through supported Admin operations.
5. Unlock, mint a new session, and complete one authorized execute.

`rekey status` on a v9 broker reports `"format_version": 9`. A v5 archive
reports `5`. Mismatched state is rejected and left untouched.

### Roll back

1. Stop the new broker.
2. Leave any v9 directory alone; do not open it with the old binaries.
3. Restore the saved pre-cut backup into a **new empty** directory using the
   old binaries and the matching SHA-256.
4. Start the old broker locked, unlock, and run one fixed Action.

Never point an older binary at state already opened by a newer incompatible
version. Never point a v9 binary at v1, v4–v8, or any other pre-v9 state.

## Uninstall

First unload/disable the service and confirm no `rekeyd` process remains.
Remove only the files installed for Rekey:

```bash
rm "$HOME/.local/bin/rekey" "$HOME/.local/bin/rekeyd" # user install
# sudo rm /usr/local/bin/rekey /usr/local/bin/rekeyd   # system install
```

To retain encrypted data, leave `~/.rekey` or `/var/lib/rekey/state` untouched.
To delete data permanently, remove that exact state directory only after a
verified backup and explicit operator decision. Deleted vault and recovery
material cannot be reconstructed by Rekey.
