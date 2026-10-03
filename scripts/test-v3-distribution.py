#!/usr/bin/env python3
"""Portable distribution contract checks; never install or register anything."""

import configparser
import hashlib
import pathlib
import plistlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class DistributionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="rekey-distribution-")
        self.addCleanup(temp.cleanup)
        self.directory = pathlib.Path(temp.name).resolve()
        self.binary = self.directory / 'rekey $bin% "quoted"'
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.state = self.directory / "state $dir%"
        self.state.mkdir()
        # Synthetic bytes test the generator's hash contract, not pkg validity,
        # signing, notarization or an actual install.
        self.package = self.directory / "rekey-v3.0.0-test.1-macos.pkg"
        self.package.write_bytes(b"xar!synthetic package bytes\x00\xff")

    def invoke(self, script, *args):
        return subprocess.run([sys.executable, str(ROOT / "scripts" / script),
                               *map(str, args)], capture_output=True, timeout=10)

    def service(self, mode, *args):
        return self.invoke("rekey-service-unit.py", mode, "--rekeyd", self.binary,
                           "--state-dir", self.state, *args)

    def cask(self, *args):
        return self.invoke("generate-homebrew-cask.py", "--package", self.package,
                           "--version", "3.0.0-test.1", "--repository", "example/rekey", *args)

    def success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        return result.stdout.decode()

    def rejected(self, result):
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(result.stdout, b"")

    def test_user_unit_runs_current_user_and_escapes_paths(self):
        text = self.success(self.service("systemd-user"))
        unit = configparser.ConfigParser(interpolation=None)
        unit.read_string(text)
        self.assertEqual(unit["Install"]["WantedBy"], "default.target")
        self.assertNotIn("User", unit["Service"])
        self.assertNotIn("Wants", unit["Unit"])
        self.assertIn('rekey $$bin%% \\"quoted\\"', unit["Service"]["ExecStart"])
        self.assertIn('state $$dir%%"', unit["Service"]["ExecStart"])
        self.assertEqual(unit["Service"]["TimeoutStopSec"], "130s")
        self.assertEqual(unit["Service"]["UMask"], "0077")
        self.assertEqual(unit["Service"]["Restart"], "on-failure")
        self.assertNotIn("Environment", unit["Service"])

    def test_user_unit_cannot_select_another_identity(self):
        for args in [("--run-as-user", "root"), ("--run-as-user", "nobody"),
                     ("--label", "com.example.rekey")]:
            with self.subTest(args=args):
                self.rejected(self.service("systemd-user", *args))

    def test_system_mode_remains_distinct(self):
        account = next(entry.pw_name for entry in pwd.getpwall() if entry.pw_uid != 0
                       and entry.pw_name.replace("_", "a").replace("-", "a").isalnum())
        text = self.success(self.service("systemd", "--run-as-user", account))
        self.assertIn(f"User={account}\n", text)
        self.assertIn("WantedBy=multi-user.target\n", text)
        self.rejected(self.service("systemd"))
        self.rejected(self.service("systemd", "--run-as-user", "root"))

    def test_launchd_contract_is_unchanged(self):
        result = self.service("launchd", "--label", "com.example.rekey")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        plist = plistlib.loads(result.stdout)
        self.assertEqual(plist["ProgramArguments"], [str(self.binary), "serve", "--state-dir", str(self.state)])
        self.assertEqual(plist["ExitTimeOut"], 130)
        self.assertNotIn("EnvironmentVariables", plist)

    def test_cask_hash_url_and_only_receipt_uninstall(self):
        text = self.success(self.cask())
        self.assertIn(f'sha256 "{hashlib.sha256(self.package.read_bytes()).hexdigest()}"', text)
        self.assertIn('url "https://github.com/example/rekey/releases/download/v3.0.0-test.1/rekey-v3.0.0-test.1-macos.pkg"', text)
        self.assertIn('pkg "rekey-v3.0.0-test.1-macos.pkg"', text)
        self.assertIn("depends_on macos: :sonoma", text)
        self.assertIn('uninstall pkgutil: "^com[.]starlight[.]rekey[.]pkg$"', text)
        for directive in ["signal:", "launchctl:", "quit:", "delete:", "zap ", "preflight", ":no_check"]:
            self.assertNotIn(directive, text)
        self.package.write_bytes(self.package.read_bytes() + b"changed after stapling")
        changed = self.success(self.cask())
        self.assertNotEqual(text, changed)
        self.assertIn(hashlib.sha256(self.package.read_bytes()).hexdigest(), changed)
        self.assertEqual(changed, self.success(self.cask()))

    def test_cask_rejects_metadata_injection_and_version_mismatch(self):
        for args in [("--version", "v3.0.0"), ("--version", '3.0.0";system("id")'),
                     ("--version", "3.0.1"), ("--repository", "../other/rekey"),
                     ("--repository", 'owner/repo#{system("id")}'),
                     ("--repository", "https://github.com/owner/repo")]:
            with self.subTest(args=args):
                self.rejected(self.cask(*args))

    def test_cask_requires_actual_package_bytes(self):
        self.package.write_bytes(b"not a flat package")
        self.rejected(self.cask())
        self.package.unlink()
        self.rejected(self.cask())
        self.package.symlink_to(self.binary)
        self.rejected(self.cask())

    @unittest.skipUnless(shutil.which("ruby"), "Ruby unavailable; no syntax claim")
    def test_generated_cask_ruby_syntax(self):
        cask = self.directory / "rekey.rb"
        cask.write_text(self.success(self.cask()))
        result = subprocess.run(["ruby", "-c", str(cask)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_release_preserves_signed_pkg_gates_and_ships_cask(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertLess(workflow.index('xcrun stapler validate "dist/$package"'),
                        workflow.index("Generate cask from the final notarized package"))
        self.assertIn('pkgutil --check-signature "dist/$package"', workflow)
        self.assertIn('spctl --assess --type install', workflow)
        self.assertIn("            dist/rekey.rb\n", workflow)
        self.assertEqual(workflow.count("cmp expected-rekey.rb downloaded/rekey.rb"), 2)
        self.assertEqual(workflow.count("scripts/test-macos-pkg.py --install-smoke"), 2)
        self.assertIn("needs: [fresh-install, macos-ui]", workflow)
        self.assertIn("withdraw-on-public-smoke-failure:", workflow)


if __name__ == "__main__":
    unittest.main()
