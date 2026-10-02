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

# Unpack outside /tmp: linux-netns-v1 overlays /tmp, so a child argv from this
# archive would otherwise vanish during P-09 agent-run execute.
unpack_root="${RUNNER_TEMP:-/var/tmp}"
mkdir -p "$unpack_root"
WORKDIR="$(mktemp -d "$unpack_root/rekey-release.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT
tar -xzf "$ARCHIVE" -C "$WORKDIR"

BIN_DIR="$WORKDIR/$(basename "$ARCHIVE" .tar.gz)"
REKEY="$BIN_DIR/rekey"
REKEYD="$BIN_DIR/rekeyd"
[[ -x "$REKEY" && -x "$REKEYD" ]] || { echo "archive lacks executable rekey/rekeyd" >&2; exit 1; }

[[ "$($REKEY --version)" == "rekey $EXPECTED_VERSION" ]]
[[ "$($REKEYD --version)" == "rekeyd $EXPECTED_VERSION" ]]

echo "release-smoke: archive=$ARCHIVE"
echo "release-smoke: bin_dir=$BIN_DIR"
echo "release-smoke: expected_version=$EXPECTED_VERSION"
python3 "$ROOT/scripts/release-archive-inventory.py" "$BIN_DIR" "$EXPECTED_VERSION"

BIN_DIR="$BIN_DIR" \
REKEY_ACCEPTANCE_REQUIRE_BINARIES=1 \
"$ROOT/scripts/p0-acceptance.sh"

BIN_DIR="$BIN_DIR" \
REKEY_ACCEPTANCE_REQUIRE_BINARIES=1 \
"$ROOT/scripts/release-archive-acceptance.sh"

if [[ "$(uname -s)" == Linux ]]; then
  BIN_DIR="$BIN_DIR" \
  REKEY_ACCEPTANCE_REQUIRE_BINARIES=1 \
  "$ROOT/scripts/p9-linux-agent-run.sh"
fi

echo "release artifact smoke passed: $EXPECTED_VERSION"
