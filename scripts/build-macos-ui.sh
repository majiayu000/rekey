#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ "$(uname -s)" == Darwin ]] || { echo 'Rekey UI requires macOS.' >&2; exit 1; }
# Override build output only; the app always invokes its own bundled CLI.
UI_OUTPUT="${REKEY_UI_OUTPUT:-$ROOT/target/macos-ui}"
CARGO_OUTPUT="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$CARGO_OUTPUT" in /*) ;; *) CARGO_OUTPUT="$ROOT/$CARGO_OUTPUT" ;; esac
identity="${REKEY_SIGNING_IDENTITY:-${APPLE_SIGNING_IDENTITY:--}}"
profile="${REKEY_PROVISIONING_PROFILE:-}"
if [[ "${REKEY_REQUIRE_DEVELOPER_ID:-}" == "1" ]]; then
  if [[ "$identity" != Developer\ ID\ Application:* || -z "$profile" ]]; then
    echo 'Developer ID App builds require an Application identity and REKEY_PROVISIONING_PROFILE.' >&2
    exit 1
  fi
fi
if [[ -n "$profile" && ( "$identity" == "-" || ! -f "$profile" ) ]]; then
  echo 'A provisioning profile requires a signed build and an existing profile file.' >&2
  exit 1
fi
VERSION="$(cargo metadata --locked --offline --no-deps --format-version 1 | python3 -c '
import json, sys
metadata = json.load(sys.stdin)
print(next(p["version"] for p in metadata["packages"] if p["name"] == "rekey-cli" and p["id"] in metadata["workspace_members"]))
')"
cargo build --locked --release -p rekey-cli --bin rekey \
  -p rekey-broker --bin rekeyd --bin rekey-mcp \
  -p rekey-policy --bin rekey-policy-sign --bin rekey-approval-sign
APP="$UI_OUTPUT/Rekey.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin" "$APP/Contents/Library/LaunchAgents"
install -m 0644 apps/macos/Resources/com.rekey.rekeyd.plist "$APP/Contents/Library/LaunchAgents/"
xcrun swiftc -warnings-as-errors -swift-version 5 -O -target "$(uname -m)-apple-macosx14.0" \
  -framework SwiftUI -framework AppKit -framework ServiceManagement \
  apps/macos/BackgroundService.swift apps/macos/PolicySigning.swift apps/macos/PresenceKey.swift apps/macos/Model.swift apps/macos/Forms.swift apps/macos/App.swift \
  -o "$APP/Contents/MacOS/Rekey"
# A reused build-output directory must not retain the lab-only plugin.
rm -f "$APP/Contents/Resources/bin/rekey-github-create-issue"
for binary in rekey rekeyd rekey-mcp rekey-policy-sign rekey-approval-sign; do
  install -m 0755 "$CARGO_OUTPUT/release/$binary" "$APP/Contents/Resources/bin/"
done
ICONSET="$UI_OUTPUT/AppIcon.iconset"
mkdir -p "$ICONSET"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" apps/macos/Resources/AppIcon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  sips -z "$((size * 2))" "$((size * 2))" apps/macos/Resources/AppIcon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Rekey</string>
<key>CFBundleIdentifier</key><string>com.starlight.rekey</string>
<key>CFBundleName</key><string>Rekey</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
python3 - "$APP/Contents/Info.plist" "$VERSION" <<'PY'
import plistlib, re, sys
path, version = sys.argv[1:]
numeric = re.match(r"^[0-9]+\.[0-9]+\.[0-9]+(?=[-+]|$)", version)
if not numeric:
    raise SystemExit("Cargo version must start with major.minor.patch")
with open(path, "rb") as file:
    info = plistlib.load(file)
info.update(CFBundleShortVersionString=numeric[0], CFBundleVersion=numeric[0], RekeyVersion=version)
with open(path, "wb") as file:
    plistlib.dump(info, file)
PY
plutil -lint "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Library/LaunchAgents/com.rekey.rekeyd.plist"
entitlements="$ROOT/apps/macos/Resources/Rekey.entitlements"
if [[ "$identity" == "-" ]]; then
  timestamp_args=(--timestamp=none)
else
  timestamp_args=(--timestamp)
fi
codesign_args=(--force --sign "$identity" --options runtime --entitlements "$entitlements" "${timestamp_args[@]}")
for binary in rekey rekeyd rekey-mcp rekey-policy-sign rekey-approval-sign; do
  codesign "${codesign_args[@]}" --identifier "com.rekey.$binary" "$APP/Contents/Resources/bin/$binary"
done
# Standalone tools do not claim restricted App entitlements. Only the App
# embeds a profile and joins the protected access group.
app_entitlements="$entitlements"
rm -f "$APP/Contents/embedded.provisionprofile"
if [[ -n "$profile" ]]; then
  install -m 0644 "$profile" "$APP/Contents/embedded.provisionprofile"
  security cms -D -i "$APP/Contents/embedded.provisionprofile" -o "$UI_OUTPUT/profile.plist"
  team="$(codesign -d --verbose=4 "$APP/Contents/Resources/bin/rekeyd" 2>&1 | awk -F= '$1 == "TeamIdentifier" {print $2}')"
  app_entitlements="$UI_OUTPUT/Rekey.profile.entitlements"
  codesign -d --extract-certificates "$UI_OUTPUT/signing-certificate-" "$APP/Contents/Resources/bin/rekeyd"
  python3 scripts/prepare-macos-profile.py "$UI_OUTPUT/profile.plist" "$team" \
    "$UI_OUTPUT/signing-certificate-0" "$app_entitlements"
fi
codesign --force --sign "$identity" --options runtime --entitlements "$app_entitlements" \
  "${timestamp_args[@]}" --identifier com.starlight.rekey "$APP"
codesign --verify --deep --strict "$APP"
printf 'Built: %s\n' "$APP"
