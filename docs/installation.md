# Install, upgrade, service, and uninstall

The public Alpha ships only two supported archives: macOS 14 arm64 and Ubuntu
24.04 x86_64. See [the platform matrix](alpha-scope.md) before installing.

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
runtime-directory layout documented by `scripts/p1-linux-g2.sh`. Do not make
the state directory or Admin socket group-writable.

## Upgrade and rollback

1. Create and verify a backup as described in the operations runbook.
2. Stop the service and confirm both sockets and the process are gone.
3. Verify the new archive and replace only `rekey` and `rekeyd`.
4. Start locked, check status, unlock, and run one fixed Action.

If the new version opened incompatible state, do not reuse that directory with
the old binary. Restore the pre-upgrade backup into an empty directory instead.

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
