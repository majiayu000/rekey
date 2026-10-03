#!/usr/bin/env python3
"""Default: synthetic package structure tests, no install or Keychain access.

--install-smoke is exclusively for disposable macOS CI runners: it verifies and
installs the real signed/notarized package, then exercises the installed public
binaries with synthetic acceptance state. It never runs in the default tests.
"""
import argparse
import hashlib
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DAEMON = pathlib.Path("Contents/Helpers/RekeyDaemon.app")
LINK = "../../Helpers/RekeyDaemon.app/Contents/MacOS/rekeyd"
TOOLS = ("rekey", "rekey-mcp", "rekey-policy-sign", "rekey-approval-sign")
VERSION = "3.0.0-alpha.1"


def run(argv, *, expected=0, **kwargs):
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=120, **kwargs)
    if (expected == 0 and result.returncode != 0) or (expected != 0 and result.returncode == 0):
        raise AssertionError(f"{pathlib.Path(str(argv[0])).name} exit={result.returncode}\n" + result.stderr.decode(errors="replace"))
    return result


def fixture(app, executable):
    for relative, identifier, name in ((pathlib.Path("."), "com.starlight.rekey", "Rekey"), (DAEMON, "com.rekey.rekeyd", "rekeyd")):
        bundle = app / relative
        (bundle / "Contents/MacOS").mkdir(parents=True)
        shutil.copy2(executable, bundle / "Contents/MacOS" / name)
        (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps(dict(
            CFBundleIdentifier=identifier, CFBundleExecutable=name, CFBundlePackageType="APPL",
            CFBundleVersion="3.0.0", CFBundleShortVersionString="3.0.0", RekeyVersion=VERSION)))
    binaries = app / "Contents/Resources/bin"
    binaries.mkdir(parents=True)
    for name in TOOLS:
        shutil.copy2(executable, binaries / name)
    (binaries / "rekeyd").symlink_to(LINK)
    launch = app / "Contents/Library/LaunchAgents"
    launch.mkdir(parents=True)
    shutil.copy2(ROOT / "apps/macos/Resources/com.rekey.rekeyd.plist", launch)


@unittest.skipUnless(sys.platform == "darwin", "macOS pkgbuild fixture")
class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared = tempfile.TemporaryDirectory(prefix="rekey-pkg-tests-")
        cls.executable = pathlib.Path(cls.shared.name) / "synthetic"
        # Compiled but never executed by these tests.
        run(["xcrun", "clang", "-x", "c", "-", "-o", cls.executable], input=b"int main(void) { return 77; }\n")

    @classmethod
    def tearDownClass(cls):
        cls.shared.cleanup()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rekey-pkg-fixture-")
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.app = self.root / "Rekey.app"
        self.output = self.root / "packages"
        fixture(self.app, self.executable)

    def package(self, *args, expected=0):
        return run([ROOT / "scripts/build-macos-pkg.sh", "--app", self.app, "--output-dir", self.output, *args], expected=expected)

    def test_unsigned_is_explicit(self):
        self.package(expected=1)
        self.assertFalse(self.output.exists())

    def test_signed_app_build_requires_separate_daemon_profile_before_build(self):
        profile = self.root / "app-profile"
        profile.write_bytes(b"synthetic-not-a-real-profile")
        env = dict(os.environ, REKEY_SIGNING_IDENTITY="Developer ID Application: Synthetic (TESTTEAM01)",
                   REKEY_PROVISIONING_PROFILE=str(profile), REKEY_DAEMON_PROVISIONING_PROFILE="",
                   REKEY_UI_OUTPUT=str(self.root / "ui"))
        result = run([ROOT / "scripts/build-macos-ui.sh"], expected=1, env=env)
        self.assertIn(b"separate REKEY_PROVISIONING_PROFILE", result.stderr)
        self.assertFalse((self.root / "ui").exists())

    def test_unsigned_identity_conflict_is_rejected(self):
        self.package("--unsigned", "--installer-identity", "Developer ID Installer: Synthetic (TESTTEAM01)", expected=1)

    def test_fixed_payload_and_nested_daemon_survive_pkg_expand(self):
        self.package("--unsigned")
        expanded = self.root / "expanded"
        run(["pkgutil", "--expand-full", self.output / f"Rekey-{VERSION}-unsigned.pkg", expanded])
        payload = expanded / "Payload"
        app = payload / "Applications/Rekey.app"
        self.assertTrue((app / DAEMON / "Contents/MacOS/rekeyd").is_file())
        self.assertEqual(os.readlink(app / "Contents/Resources/bin/rekeyd"), LINK)
        for name in ("rekey", "rekeyd", "rekey-mcp"):
            self.assertEqual(os.readlink(payload / "usr/local/bin" / name), f"/Applications/Rekey.app/Contents/Resources/bin/{name}")
        launch = plistlib.loads((app / "Contents/Library/LaunchAgents/com.rekey.rekeyd.plist").read_bytes())
        self.assertEqual(launch["BundleProgram"], str(DAEMON / "Contents/MacOS/rekeyd"))
        self.assertFalse((expanded / "Scripts/postinstall").exists())

    def test_standalone_daemon_cannot_substitute_for_bundle(self):
        link = self.app / "Contents/Resources/bin/rekeyd"
        link.unlink()
        shutil.copy2(self.executable, link)
        self.package("--unsigned", expected=1)

    def test_wrong_or_absolute_daemon_symlink_rejected(self):
        link = self.app / "Contents/Resources/bin/rekeyd"
        for destination in ("rekey", "/usr/bin/true", "../../Helpers/RekeyDaemon.app/Contents/MacOS/../MacOS/rekeyd"):
            with self.subTest(destination=destination):
                link.unlink()
                link.symlink_to(destination)
                self.package("--unsigned", expected=1)

    def test_additional_symlink_and_redirected_executable_rejected(self):
        link = self.app / "Contents/Resources/foreign"
        link.symlink_to("/tmp")
        self.package("--unsigned", expected=1)
        link.unlink()
        executable = self.app / DAEMON / "Contents/MacOS/rekeyd"
        executable.unlink()
        executable.symlink_to(self.executable)
        self.package("--unsigned", expected=1)

    def test_daemon_identity_version_and_launch_target_must_match(self):
        path = self.app / DAEMON / "Contents/Info.plist"
        original = plistlib.loads(path.read_bytes())
        for key, value in (("CFBundleIdentifier", "com.rekey.wrong"), ("RekeyVersion", "3.0.0-alpha.2")):
            altered = dict(original, **{key: value})
            path.write_bytes(plistlib.dumps(altered))
            self.package("--unsigned", expected=1)
        path.write_bytes(plistlib.dumps(original))
        launch = self.app / "Contents/Library/LaunchAgents/com.rekey.rekeyd.plist"
        data = plistlib.loads(launch.read_bytes())
        data["BundleProgram"] = "Contents/Resources/bin/rekeyd"
        launch.write_bytes(plistlib.dumps(data))
        self.package("--unsigned", expected=1)

    def test_adhoc_nested_signing_order_and_signed_pkg_rejection(self):
        for name in TOOLS:
            run(["codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", "--identifier", "com.rekey." + name, self.app / "Contents/Resources/bin" / name])
        for bundle, identity in ((self.app / DAEMON, "com.rekey.rekeyd"), (self.app, "com.starlight.rekey")):
            run(["codesign", "--force", "--sign", "-", "--options", "runtime", "--timestamp=none", "--identifier", identity, bundle])
        run(["codesign", "--verify", "--deep", "--strict", self.app])
        result = self.package("--installer-identity", "Developer ID Installer: Synthetic (TESTTEAM01)", expected=1)
        self.assertIn(b"code failed to satisfy specified code requirement", result.stderr)

    def test_existing_output_is_not_replaced(self):
        self.package("--unsigned")
        package = self.output / f"Rekey-{VERSION}-unsigned.pkg"
        original = package.read_bytes()
        self.package("--unsigned", expected=1)
        self.assertEqual(package.read_bytes(), original)


def installed_smoke(package, checksum, version):
    if sys.platform != "darwin" or os.environ.get("CI") != "true":
        raise SystemExit("--install-smoke requires an explicitly selected disposable macOS CI runner")
    fields = checksum.read_text().split()
    if len(fields) != 2 or fields[1] != package.name or hashlib.sha256(package.read_bytes()).hexdigest() != fields[0]:
        raise SystemExit("package checksum or filename mismatch")
    run(["pkgutil", "--check-signature", package])
    run(["xcrun", "stapler", "validate", package])
    run(["spctl", "--assess", "--type", "install", package])
    run(["sudo", "installer", "-pkg", package, "-target", "/"])
    app = pathlib.Path("/Applications/Rekey.app")
    binaries = app / "Contents/Resources/bin"
    run(["codesign", "--verify", "--deep", "--strict", app])
    run(["spctl", "--assess", "--type", "execute", app])
    for name in ("rekey", "rekeyd"):
        result = run([binaries / name, "--version"])
        if result.stdout.decode().strip() != f"{name} {version}":
            raise SystemExit("installed version does not match release")
    for name in ("rekey", "rekeyd", "rekey-mcp"):
        if os.readlink(pathlib.Path("/usr/local/bin") / name) != str(binaries / name):
            raise SystemExit("installed CLI link is not owned by Rekey.pkg")
    env = dict(os.environ, BIN_DIR=str(binaries), REKEY_ACCEPTANCE_REQUIRE_BINARIES="1",
               REKEY_SERVICE_REQUIRE_BINARIES="1",
               REKEY_SERVICE_GENERATOR=str(ROOT / "scripts/rekey-service-unit.py"),
               REKEY_SERVICE_MANAGED_DAEMON=str(app / DAEMON / "Contents/MacOS/rekeyd"))
    # Retain the former macOS archive's behavioral and service-manager gates,
    # now using installed package binaries rather than signed standalone tools.
    for script in ("p0-acceptance.sh", "release-archive-acceptance.sh", "p1-service-manager.sh"):
        result = subprocess.run([str(ROOT / "scripts" / script)], env=env, timeout=900)
        if result.returncode:
            raise SystemExit(f"installed package {script} failed: {result.returncode}")
    print("installed notarized pkg acceptance passed: " + version)


if __name__ == "__main__":
    if "--install-smoke" in sys.argv:
        parser = argparse.ArgumentParser(description=__doc__)
        parser.add_argument("--install-smoke", action="store_true", required=True)
        parser.add_argument("--package", type=pathlib.Path, required=True)
        parser.add_argument("--checksum", type=pathlib.Path, required=True)
        parser.add_argument("--version", required=True)
        args = parser.parse_args()
        installed_smoke(args.package.resolve(), args.checksum.resolve(), args.version)
    else:
        unittest.main()
