#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ "$(uname -s)" == Darwin ]] || { echo 'Rekey UI requires macOS.' >&2; exit 1; }
# Override build output only; the app always invokes its own bundled CLI.
UI_OUTPUT="${REKEY_UI_OUTPUT:-$ROOT/target/macos-ui}"
CARGO_OUTPUT="${CARGO_TARGET_DIR:-$ROOT/target}"
case "$CARGO_OUTPUT" in /*) ;; *) CARGO_OUTPUT="$ROOT/$CARGO_OUTPUT" ;; esac
cargo build --locked --release -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
APP="$UI_OUTPUT/Rekey.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
xcrun swiftc -warnings-as-errors -swift-version 5 -O -target "$(uname -m)-apple-macosx14.0" \
  -framework SwiftUI -framework AppKit \
  apps/macos/Model.swift apps/macos/Forms.swift apps/macos/App.swift \
  -o "$APP/Contents/MacOS/Rekey"
install -m 0755 "$CARGO_OUTPUT/release/rekey" "$CARGO_OUTPUT/release/rekeyd" "$APP/Contents/Resources/bin/"
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
<key>CFBundleIdentifier</key><string>io.github.majiayu000.rekey.ui</string>
<key>CFBundleName</key><string>Rekey</string>
<key>CFBundleIconFile</key><string>AppIcon</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
plutil -lint "$APP/Contents/Info.plist"
codesign --force --deep --sign - "$APP"
printf 'Built: %s\n' "$APP"
