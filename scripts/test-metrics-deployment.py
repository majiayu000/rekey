#!/usr/bin/env python3
"""Check generator subprocess behavior and the actual native deployment tools.

Run `python3 scripts/test-metrics-deployment.py GeneratorTests` for the portable
checks only. The default also requires real promtool and systemd-analyze; missing
tools fail explicitly. PROMTOOL selects an explicit test binary (CI job-local).
This script never installs/starts services, opens listeners, or simulates PromQL.
"""

import os
import pathlib
import plistlib
import pwd
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts/rekey-service-unit.py"
DEPLOY = ROOT / "deploy/prometheus"


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rekey-metrics-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name).resolve()
        self.binary = self.directory / 'installed $rekey% "binary"'
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.state = self.directory / 'state $dir% "quoted"'
        self.state.mkdir()
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.assertNotEqual(os.getuid(), 0, "generator checks require a non-root test account")

    def invoke(self, *args):
        return subprocess.run([sys.executable, str(GENERATOR), *map(str, args)],
                              capture_output=True, timeout=10, check=False)

    def metrics_args(self):
        return ["systemd-metrics-service", "--rekey", self.binary,
                "--state-dir", self.state, "--run-as-user", self.user]

    def success(self, *args):
        result = self.invoke(*args)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        return result.stdout.decode()

    def rejects(self, args, diagnostic):
        result = self.invoke(*args)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertIn(diagnostic, result.stderr.decode())

    def test_metrics_service_exact_command_and_whole_cgroup_timeout(self):
        unit = self.success(*self.metrics_args())
        # Expected escaping is literal, independent of the generator function.
        expected_binary = str(self.directory) + '/installed $$rekey%% \\"binary\\"'
        expected_state = str(self.directory) + '/state $$dir%% \\"quoted\\"'
        self.assertIn(f'ExecStart="{expected_binary}" --state-dir "{expected_state}" metrics --prometheus --textfile-dir /var/lib/rekey-metrics\n', unit)
        for line in ["Type=oneshot", f"User={self.user}", "SupplementaryGroups=rekey-metrics",
                     "TimeoutStartSec=10s", "TimeoutStartFailureMode=kill", "KillMode=control-group",
                     "FinalKillSignal=SIGKILL", "SendSIGKILL=yes", "UMask=0077", "NoNewPrivileges=true"]:
            self.assertIn(line + "\n", unit)
        for unwanted in ["RuntimeMaxSec=", "Restart=", "RemainAfterExit=", "ExecStopPost=", "/bin/sh"]:
            self.assertNotIn(unwanted, unit)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_timer_needs_no_state_and_has_fixed_start_interval(self):
        unit = self.success("systemd-metrics-timer")
        for line in ["OnBootSec=30s", "OnUnitActiveSec=30s", "AccuracySec=1s",
                     "RandomizedDelaySec=0", "Unit=rekey-metrics.service", "WantedBy=timers.target"]:
            self.assertIn(line + "\n", unit)
        for unwanted in ["Persistent=", "OnUnitInactiveSec=", "ExecStart=", "User="]:
            self.assertNotIn(unwanted, unit)

    def test_timer_rejects_every_inapplicable_option(self):
        for name, value in [("--rekey", self.binary), ("--rekeyd", self.binary),
                            ("--state-dir", self.state), ("--label", "fixture"),
                            ("--run-as-user", self.user)]:
            with self.subTest(option=name):
                self.rejects(["systemd-metrics-timer", name, value], "accepts no additional arguments")

    def test_service_requires_its_three_parameters(self):
        args = self.metrics_args()
        for index in [1, 3, 5]:
            with self.subTest(option=args[index]):
                self.rejects(args[:index] + args[index+2:], "requires --rekey, --state-dir and --run-as-user")

    def test_service_rejects_daemon_and_launchd_parameters(self):
        for name, value in [("--rekeyd", self.binary), ("--label", "fixture")]:
            with self.subTest(option=name):
                self.rejects(self.metrics_args() + [name, value], "rejects --rekeyd and --label")

    def test_service_reuses_absolute_executable_and_directory_boundary(self):
        args = self.metrics_args()
        for index, replacement, error in [(2, "relative", "path must be absolute"),
                                           (4, "relative", "path must be absolute"),
                                           (4, self.binary, "state directory is not a directory")]:
            with self.subTest(index=index):
                invalid = list(args)
                invalid[index] = replacement
                self.rejects(invalid, error)
        self.binary.chmod(0o600)
        self.rejects(args, "is not executable")

    def test_service_reuses_nonroot_account_boundary(self):
        args = self.metrics_args()
        for user, diagnostic in [("root", "must run as a non-root user"),
                                 ("bad/user", "invalid name"),
                                 ("rekey_missing_metrics_fixture_9283", "user does not exist")]:
            with self.subTest(user=user):
                self.rejects(args[:-1] + [user], diagnostic)

    def test_original_systemd_daemon_contract(self):
        unit = self.success("systemd", "--rekeyd", self.binary, "--state-dir", self.state,
                            "--run-as-user", self.user)
        for line in ["Type=simple", "Restart=on-failure", "RestartSec=5s", "KillSignal=SIGTERM",
                     "TimeoutStopSec=130s", "UMask=0077", "NoNewPrivileges=true"]:
            self.assertIn(line + "\n", unit)
        self.assertIn(' serve --state-dir ', unit)
        self.assertNotIn("TimeoutStartFailureMode=", unit)
        self.assertNotIn("SupplementaryGroups=", unit)

    def test_original_launchd_preserves_argv_and_stop_ceiling(self):
        result = self.invoke("launchd", "--rekeyd", self.binary, "--state-dir", self.state,
                             "--label", "rekey.fixture")
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        data = plistlib.loads(result.stdout)
        self.assertEqual(data["ProgramArguments"], [str(self.binary), "serve", "--state-dir", str(self.state)])
        self.assertEqual(data["ExitTimeOut"], 130)
        self.assertEqual(data["Umask"], 0o077)
        self.assertTrue(data["KeepAlive"])

    def test_daemon_oidc_profile_path_preserves_symlink_and_quoting(self):
        profile = self.directory / 'profile $oidc% "quoted"'
        profile.symlink_to(self.directory / 'missing-private-profile')
        result = self.invoke("launchd", "--rekeyd", self.binary, "--state-dir", self.state,
                             "--label", "rekey.fixture", "--oidc-admin-profile", profile)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(plistlib.loads(result.stdout)["ProgramArguments"],
                         [str(self.binary), "serve", "--state-dir", str(self.state),
                          "--oidc-admin-profile", str(profile)])
        unit = self.success("systemd", "--rekeyd", self.binary, "--state-dir", self.state,
                            "--run-as-user", self.user, "--oidc-admin-profile", profile)
        expected = str(self.directory) + '/profile $$oidc%% \\"quoted\\"'
        self.assertIn(f' --oidc-admin-profile "{expected}"\n', unit)
        self.assertFalse(profile.exists())

    def test_oidc_profile_rejected_for_metrics_and_unsafe_daemon_paths(self):
        profile = self.directory / 'private-profile'
        self.rejects([*self.metrics_args(), "--oidc-admin-profile", profile],
                     "systemd-metrics-service rejects --oidc-admin-profile")
        self.rejects(["systemd-metrics-timer", "--oidc-admin-profile", profile],
                     "accepts no additional arguments")
        common = ["launchd", "--rekeyd", self.binary, "--state-dir", self.state,
                  "--label", "rekey.fixture", "--oidc-admin-profile"]
        self.rejects(common + ["relative-profile"], "OIDC profile path must be absolute")
        self.rejects(common + [str(profile) + "\n"], "control characters")

    def test_original_required_and_inapplicable_argument_errors(self):
        self.rejects(["systemd"], "the following arguments are required: --rekeyd, --state-dir")
        common = ["--rekeyd", self.binary, "--state-dir", self.state]
        self.rejects(["systemd", *common], "systemd requires --run-as-user and rejects --label")
        self.rejects(["launchd", *common], "launchd requires --label and rejects --run-as-user")
        self.rejects(["launchd", *common, "--label", "invalid/label"], "invalid launchd label")
        self.rejects(["systemd", *common, "--run-as-user", self.user, "--rekey", self.binary], "systemd rejects --rekey")


class NativeToolTests(unittest.TestCase):
    def run_tool(self, command, *, cwd=DEPLOY):
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True,
                                timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_promtool_rules_vectors_and_scrape_config(self):
        tool = os.environ.get("PROMTOOL") or shutil.which("promtool")
        self.assertTrue(tool, "BLOCKED: actual promtool unavailable; set PROMTOOL to the fixed CI binary")
        self.run_tool([tool, "check", "rules", "rekey.rules.yml"])
        self.run_tool([tool, "test", "rules", "rekey.rules.test.yml"])
        self.run_tool([tool, "check", "config", "rekey.scrape.example.yml"])

    def test_actual_systemd_analyze_verifies_generated_units_without_installing(self):
        tool = shutil.which("systemd-analyze")
        self.assertTrue(tool, "BLOCKED: actual systemd-analyze unavailable")
        self.assertNotEqual(os.getuid(), 0, "native verification requires a non-root test account")
        with tempfile.TemporaryDirectory(prefix="rekey-metrics-units-") as raw:
            directory = pathlib.Path(raw)
            binary = directory / "rekey"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o700)
            state = directory / "state"
            state.mkdir()
            user = pwd.getpwuid(os.getuid()).pw_name
            service = subprocess.run([sys.executable, str(GENERATOR), "systemd-metrics-service",
                                      "--rekey", str(binary), "--state-dir", str(state),
                                      "--run-as-user", user], capture_output=True, check=True, timeout=10)
            timer = subprocess.run([sys.executable, str(GENERATOR), "systemd-metrics-timer"],
                                    capture_output=True, check=True, timeout=10)
            (directory / "rekey-metrics.service").write_bytes(service.stdout)
            (directory / "rekey-metrics.timer").write_bytes(timer.stdout)
            self.run_tool([tool, "verify", str(directory / "rekey-metrics.service"),
                           str(directory / "rekey-metrics.timer")], cwd=directory)


if __name__ == "__main__":
    unittest.main()
