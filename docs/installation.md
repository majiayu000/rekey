# Install, upgrade, service, and uninstall

The source candidate is **0.4.0-alpha.1** (vault26 / policy7). Publication and available artifacts are determined by [GitHub Releases](https://github.com/majiayu000/rekey/releases), not this page. The 0.3 vault format is rejected: create a new state directory; there is no migration or overwrite.

macOS distribution uses a Developer ID signed, notarized pkg with independently provisioned App and daemon, for macOS 14+ on Apple Silicon. Linux uses the released Ubuntu 24.04 x86_64 archive. No public Homebrew tap is claimed. Verify the actual completed release, package bytes, signature and public smoke before installation. Hardware Touch ID, SE, login-item and C16 checks are independent of software tests.

After installation, open the App with `rekey setup`, add a key with `rekey add github-pat`, review/sign its Connection, run `rekey connect claude-code` (or `codex`), then start the Agent normally. Local calls require no tokens. Profile/run and personal isolation launchers are removed; see [README](../README.md) for the 0.4 call model.

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
rekey add github-pat
# Review and sign the Connection in the App.
rekey connect claude-code
claude
```

Setup opens the App for mode selection, vault creation and human authentication.
Save the recovery key when displayed. The App handles credential entry and
Connection review/signing. Agent processes call Rekey without local tokens and
receive sealed call results. T1 derivation explicitly returns short-lived credentials.
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

## Lab source builds

Personal Seatbelt/netns launchers, Profile/capability APIs and enterprise integrations
are archived behind `--features lab`; they are not part of the default 0.4 archive
or App. The lab compile and lint checks do not prove those historical runtime
fixtures work with the new policy format. See the [feature truth matrix](product-foundation/feature-truth-matrix.md)
and [active SPEC](superpowers/specs/2026-10-05-rekey-agent-call-model.md).

## Format changes and restore

The 0.4 candidate uses vault/backup format **26** and policy snapshot format **7**.
A 0.3 vault or backup cannot be opened or restored by 0.4. Keep the old binary,
state directory and backups together; create a new empty 0.4 directory and add
credentials/sign Connections again. No migration, backfill or overwrite occurs.

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
