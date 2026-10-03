#!/usr/bin/env python3
"""Emit a release-local cask for an already built, signed and stapled pkg.

The release workflow validates the tag against Cargo and the App version before
building the package. This helper only hashes that final artifact; it neither
signs a package nor attests to notarization or publishes a Homebrew tap.
"""

import argparse
import hashlib
import pathlib
import re


VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


def generate(package: pathlib.Path, version: str, repository: str) -> str:
    if VERSION.fullmatch(version) is None:
        raise ValueError("version must be a release version without the v prefix")
    if REPOSITORY.fullmatch(repository) is None:
        raise ValueError("repository must be a GitHub owner/repository")
    expected = f"rekey-v{version}-macos.pkg"
    if package.name != expected:
        raise ValueError(f"package filename must be {expected}")
    if package.is_symlink() or not package.is_file():
        raise ValueError("package must be a regular, non-symlink file")
    digest = hashlib.sha256()
    with package.open("rb") as source:
        if source.read(4) != b"xar!":
            raise ValueError("package must be a flat Installer package (xar)")
        source.seek(0)
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return f'''cask "rekey" do
  version "{version}"
  sha256 "{digest.hexdigest()}"

  url "https://github.com/{repository}/releases/download/v{version}/{expected}"
  name "Rekey"
  desc "Local credential authority for AI agents"
  homepage "https://github.com/{repository}"

  depends_on arch: :arm64
  depends_on macos: :sonoma

  pkg "{expected}"

  uninstall pkgutil: "^com[.]starlight[.]rekey[.]pkg$"

  caveats <<~EOS
    Before upgrade or uninstall, disable login startup and shut down the daemon
    in Rekey.app with a fresh proof, then quit the App. This cask does not stop
    services or delete vault data or Keychain items.
  EOS
end
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=pathlib.Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        cask = generate(args.package, args.version, args.repository)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(cask, end="")


if __name__ == "__main__":
    main()
