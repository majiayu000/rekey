#!/usr/bin/env python3
"""Synthetic provisioning configuration tests; never invokes signing/Keychain."""

import copy
import datetime
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("profile_input", Path(__file__).with_name("prepare-macos-profile.py"))
profile_input = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profile_input)
NOW = datetime.datetime(2026, 10, 3, tzinfo=datetime.timezone.utc)
TEAM = "TESTTEAM01"
CERTIFICATE = b"synthetic-leaf-der"


class ProfileInputTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "TeamIdentifier": [TEAM], "ProvisionsAllDevices": True,
            "DeveloperCertificates": [CERTIFICATE],
            "ExpirationDate": datetime.datetime(2027, 1, 1),
            "Entitlements": {"com.apple.developer.team-identifier": TEAM,
                             "com.apple.application-identifier": TEAM + ".com.starlight.rekey",
                             "keychain-access-groups": [TEAM + ".com.rekey"],
                             "unrelated-entitlement": True}}

    def prepare(self):
        return profile_input.entitlements(self.profile, TEAM, CERTIFICATE, NOW)

    def test_exact_profile_emits_only_required_app_entitlements(self):
        result = self.prepare()
        self.assertEqual(set(result), {"com.apple.application-identifier", "com.apple.developer.team-identifier", "keychain-access-groups"})
        self.assertEqual(result["keychain-access-groups"], [TEAM + ".com.rekey"])

    def test_authorized_wildcards_are_resolved_to_exact_claims(self):
        self.profile["Entitlements"].update({"com.apple.application-identifier": TEAM + ".*",
                                             "keychain-access-groups": [TEAM + ".*"]})
        result = self.prepare()
        self.assertEqual(result["com.apple.application-identifier"], TEAM + ".com.starlight.rekey")
        self.assertEqual(result["keychain-access-groups"], [TEAM + ".com.rekey"])

    def test_wrong_team_rejected(self):
        self.profile["TeamIdentifier"] = ["WRONGTEAM1"]
        with self.assertRaises(ValueError): self.prepare()

    def test_same_team_unlisted_signer_rejected(self):
        self.profile["DeveloperCertificates"] = [b"different-certificate-same-team"]
        with self.assertRaises(ValueError): self.prepare()

    def test_missing_certificate_authorization_rejected(self):
        for certificates in (None, [], "synthetic-leaf-der"):
            with self.subTest(certificates=certificates):
                self.profile["DeveloperCertificates"] = certificates
                with self.assertRaises(ValueError): self.prepare()

    def test_wrong_app_rejected(self):
        self.profile["Entitlements"]["com.apple.application-identifier"] = TEAM + ".com.rekey.v3.keychain"
        with self.assertRaises(ValueError): self.prepare()

    def test_foreign_or_missing_access_group_rejected(self):
        for groups in (None, [], ["OTHERTEAM1.*"], [TEAM + ".com.rekey.v3"], "*"):
            with self.subTest(groups=groups):
                self.profile["Entitlements"]["keychain-access-groups"] = groups
                with self.assertRaises(ValueError): self.prepare()

    def test_expired_and_unbounded_profiles_rejected(self):
        for expiry in (None, "tomorrow", datetime.datetime(2026, 10, 3), datetime.datetime(2026, 1, 1)):
            with self.subTest(expiry=expiry):
                self.profile["ExpirationDate"] = expiry
                with self.assertRaises(ValueError): self.prepare()

    def test_device_scoped_profile_rejected(self):
        self.profile["ProvisionsAllDevices"] = False
        with self.assertRaises(ValueError): self.prepare()

    def test_debug_entitlement_rejected(self):
        for name in ("get-task-allow", "com.apple.security.get-task-allow"):
            with self.subTest(name=name):
                profile = copy.deepcopy(self.profile)
                profile["Entitlements"][name] = True
                with self.assertRaises(ValueError): profile_input.entitlements(profile, TEAM, CERTIFICATE, NOW)

    def test_malformed_profile_and_entitlements_rejected(self):
        for profile in ([], {}, {"TeamIdentifier": [TEAM], "Entitlements": []}):
            with self.subTest(profile=profile):
                with self.assertRaises(ValueError): profile_input.entitlements(profile, TEAM, CERTIFICATE, NOW)


if __name__ == "__main__":
    unittest.main()
