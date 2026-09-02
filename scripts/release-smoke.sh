#!/usr/bin/env bash
# Verify and exercise a downloaded Rekey release archive without using target/.
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  echo "usage: $0 ARCHIVE SHA256_FILE EXPECTED_VERSION" >&2
  exit 2
fi

ARCHIVE="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
CHECKSUM="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
EXPECTED_VERSION="$3"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[[ -f "$ARCHIVE" ]] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }
[[ -f "$CHECKSUM" ]] || { echo "checksum not found: $CHECKSUM" >&2; exit 1; }

(
  cd "$(dirname "$ARCHIVE")"
  shasum -a 256 -c "$CHECKSUM"
)

if tar -tzf "$ARCHIVE" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
  echo "archive contains an unsafe path" >&2
  exit 1
fi

WORKDIR="$(mktemp -d /tmp/rekey-release.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
tar -xzf "$ARCHIVE" -C "$WORKDIR"

BIN_DIR="$WORKDIR/$(basename "$ARCHIVE" .tar.gz)"
REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
[[ -x "$REKEY" && -x "$REKEYD" ]] || { echo "archive lacks executable rekey/rekeyd" >&2; exit 1; }

[[ "$($REKEY --version)" == "rekey $EXPECTED_VERSION" ]]
[[ "$($REKEYD --version)" == "rekeyd $EXPECTED_VERSION" ]]

BIN_DIR="$BIN_DIR" \
REKEY_ACCEPTANCE_REQUIRE_BINARIES=1 \
"$ROOT/scripts/p0-acceptance.sh"

echo "release artifact smoke passed: $EXPECTED_VERSION"
