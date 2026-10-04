#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "Rekey pkg: $*" >&2; exit 1; }
usage() {
  echo 'Usage: build-macos-pkg.sh [--app Rekey.app] [--output-dir DIR] --installer-identity "Developer ID Installer: ... (TEAM)"'
  echo '       build-macos-pkg.sh [--app FIXTURE.app] [--output-dir DIR] --unsigned'
  echo '--unsigned is only for local payload inspection; do not install or distribute its output.'
}
APP="$ROOT/target/macos-ui/Rekey.app"
OUTPUT="$ROOT/target/macos-pkg"
IDENTITY=""
UNSIGNED=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app|--output-dir|--installer-identity)
      [[ $# -ge 2 && -n "$2" ]] || fail "missing value for $1"
      case "$1" in --app) APP="$2" ;; --output-dir) OUTPUT="$2" ;; --installer-identity) IDENTITY="$2" ;; esac
      shift 2 ;;
    --unsigned) UNSIGNED=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done
[[ "$(uname -s)" == Darwin ]] || fail 'macOS is required'
if [[ "$UNSIGNED" == 1 ]]; then
  [[ -z "$IDENTITY" ]] || fail '--unsigned cannot be combined with a signing identity'
  echo 'Rekey pkg: UNSIGNED local structure fixture; not notarized; do not install or distribute.' >&2
else
  [[ "$IDENTITY" == Developer\ ID\ Installer:* ]] || fail 'an explicit Developer ID Installer identity is required'
  [[ "$IDENTITY" =~ \(([A-Z0-9]{10})\)$ ]] || fail 'Installer identity must include its Team ID'
  TEAM="${BASH_REMATCH[1]}"
fi
[[ -d "$APP" && ! -L "$APP" ]] || fail 'input must be a real App bundle directory'
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
STAGE="$(mktemp -d "$OUTPUT/.rekey-pkg.XXXXXX")"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/root/Applications" "$STAGE/root/usr/local/bin"
ditto "$APP" "$STAGE/root/Applications/Rekey.app"
APP="$STAGE/root/Applications/Rekey.app"
for binary in Rekey ../Helpers/RekeyDaemon.app/Contents/MacOS/rekeyd ../Resources/bin/rekey ../Resources/bin/rekey-mcp ../Resources/bin/rekey-policy-sign ../Resources/bin/rekey-approval-sign; do
  path="$APP/Contents/MacOS/$binary"
  [[ -f "$path" && -x "$path" && ! -L "$path" ]] || fail "missing or redirected executable: $binary"
done
cmp -s "$ROOT/apps/macos/Resources/com.rekey.rekeyd.plist" "$APP/Contents/Library/LaunchAgents/com.rekey.rekeyd.plist" || fail 'App must contain the current static LaunchAgent plist'
VERSION="$(python3 - "$APP" <<'PY'
import os, pathlib, plistlib, re, sys
app = pathlib.Path(sys.argv[1])
link = app / "Contents/Resources/bin/rekeyd"
expected = "../../Helpers/RekeyDaemon.app/Contents/MacOS/rekeyd"
if not link.is_symlink() or os.readlink(link) != expected:
    raise SystemExit("Rekey pkg: daemon CLI link must have the fixed internal target")
for path in app.rglob("*"):
    if path.is_symlink() and path != link:
        raise SystemExit("Rekey pkg: unexpected App symlink: " + str(path.relative_to(app)))
with open(app / "Contents/Info.plist", "rb") as file:
    info = plistlib.load(file)
version = info.get("RekeyVersion", "")
match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version)
if not match or info.get("CFBundleIdentifier") != "com.starlight.rekey" or info.get("CFBundleExecutable") != "Rekey":
    raise SystemExit("Rekey pkg: invalid bundle identity or RekeyVersion")
if any(info.get(key) != match[1] for key in ("CFBundleVersion", "CFBundleShortVersionString")):
    raise SystemExit("Rekey pkg: bundle numeric versions do not match RekeyVersion")
with open(app / "Contents/Helpers/RekeyDaemon.app/Contents/Info.plist", "rb") as file:
    daemon = plistlib.load(file)
if daemon.get("CFBundleIdentifier") != "com.rekey.rekeyd" or daemon.get("CFBundleExecutable") != "rekeyd" or daemon.get("CFBundlePackageType") != "APPL":
    raise SystemExit("Rekey pkg: invalid nested daemon bundle identity")
if any(daemon.get(key) != info.get(key) for key in ("CFBundleVersion", "CFBundleShortVersionString", "RekeyVersion")):
    raise SystemExit("Rekey pkg: daemon and App versions differ")
print(version)
PY
)"
if [[ "$UNSIGNED" == 0 ]]; then
  # Verify the staged bytes, not an input directory that could change after verification.
  codesign --verify --deep --strict "$APP"
  verify_code() {
    local path="$1" identifier="$2" details runtime_flag
    codesign --verify --strict --test-requirement "=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and certificate leaf[subject.OU] = \"$TEAM\" and identifier \"$identifier\"" "$path"
    details="$(codesign --display --verbose=4 "$path" 2>&1)"
    runtime_flag='flags=0x[[:xdigit:]]+\([^)]*runtime[^)]*\)'
    [[ "$details" =~ $runtime_flag ]] || fail "hardened runtime is required for $identifier"
  }
  verify_code "$APP" com.starlight.rekey
  DAEMON="$APP/Contents/Helpers/RekeyDaemon.app"
  verify_code "$DAEMON" com.rekey.rekeyd
  verify_profile() {
    local bundle="$1" identifier="$2" prefix="$STAGE/$2"
    [[ -f "$bundle/Contents/embedded.provisionprofile" ]] || fail "missing profile: $identifier"
    security cms -D -i "$bundle/Contents/embedded.provisionprofile" -o "$prefix.profile.plist"
    codesign -d --extract-certificates="$prefix.cert-" "$bundle"
    python3 "$ROOT/scripts/prepare-macos-profile.py" "$prefix.profile.plist" "$TEAM" \
      "$prefix.cert-0" "$identifier" "$prefix.expected.plist"
    codesign -d --entitlements :- "$bundle" > "$prefix.actual.plist"
    python3 - "$prefix.expected.plist" "$prefix.actual.plist" <<'PYPROFILE'
import plistlib, sys
expected, actual = (plistlib.load(open(path, "rb")) for path in sys.argv[1:])
if expected != actual:
    raise SystemExit("Rekey pkg: signed entitlements do not match the authorized bundle profile")
PYPROFILE
  }
  verify_profile "$APP" com.starlight.rekey
  verify_profile "$DAEMON" com.rekey.rekeyd
  for binary in rekey rekey-mcp rekey-policy-sign rekey-approval-sign; do
    verify_code "$APP/Contents/Resources/bin/$binary" "com.rekey.$binary"
    codesign -d --entitlements :- "$APP/Contents/Resources/bin/$binary" > "$STAGE/tool.entitlements"
    python3 - "$STAGE/tool.entitlements" <<'PYTOOL'
import pathlib, plistlib, sys
raw = pathlib.Path(sys.argv[1]).read_bytes()
if raw and plistlib.loads(raw):
    raise SystemExit("Rekey pkg: standalone tools must not claim restricted entitlements")
PYTOOL
  done
fi
for binary in rekey rekeyd rekey-mcp; do
  ln -s "/Applications/Rekey.app/Contents/Resources/bin/$binary" "$STAGE/root/usr/local/bin/$binary"
done
suffix=""
if [[ "$UNSIGNED" == 1 ]]; then suffix="-unsigned"; fi
PACKAGE="$OUTPUT/Rekey-$VERSION$suffix.pkg"
[[ ! -e "$PACKAGE" && ! -L "$PACKAGE" ]] || fail "output already exists: $PACKAGE"
pkg_args=(--root "$STAGE/root" --install-location /
  --component-plist "$ROOT/packaging/macos/components.plist"
  --scripts "$ROOT/packaging/macos/scripts" --identifier com.starlight.rekey.pkg
  --version "$VERSION" --ownership recommended)
if [[ "$UNSIGNED" == 0 ]]; then pkg_args+=(--sign "$IDENTITY" --timestamp); fi
pkgbuild "${pkg_args[@]}" "$STAGE/Rekey.pkg"
if [[ "$UNSIGNED" == 0 ]]; then pkgutil --check-signature "$STAGE/Rekey.pkg"; fi
mv "$STAGE/Rekey.pkg" "$PACKAGE"
printf 'Built: %s\n' "$PACKAGE"
