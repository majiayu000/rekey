# Install, upgrade, service, and uninstall

The only supported public Alpha is still `v2.0.0-alpha.1` (vault schema v5).
It ships two archives: macOS 14 arm64 and Ubuntu 24.04 x86_64. See
[the platform matrix](alpha-scope.md) before installing.

Development head and the frozen `v2.0.0-alpha.2` candidate use vault schema v9.
That later tag is not implied by these install steps until it exists. There is
no in-place upgrade from v5–v8.

## Download and verify

Set the version and target for your platform:

```bash
REKEY_VERSION=v2.0.0-alpha.1
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

Both commands must print `2.0.0-alpha.1`. Rekey finds `rekeyd` beside `rekey`
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

Linux `rekey agent-run` additionally needs `bubblewrap` and that same disjoint
Agent socket. It denies IP egress for one launched command. It is not macOS
G2 and is not a substitute for the Docker attack harness.

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

## Cross-version install and rollback

These steps apply whenever the new archive uses a different vault format,
including `v2.0.0-alpha.1` (schema v5) to development head or `v2.0.0-alpha.2`
(schema v9). Release notes that say the format is unchanged may replace only
the two binaries; **do not treat that as the path from alpha.1 to v9**.

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
version. Never point a v9 binary at v5/v6/v7/v8 or v1 state.

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
