#!/usr/bin/env python3
"""Select minimal App entitlements from a decoded Developer ID profile.

macOS still validates the signed profile and authorizes the entitlement at
runtime. These build checks detect mismatched input; they do not prove V1.
"""

import datetime
import plistlib
import sys
from pathlib import Path


def entitlements(profile, team, certificate, now):
    if not isinstance(profile, dict) or not team or team == "not set" or profile.get("TeamIdentifier") != [team]:
        raise ValueError("profile TeamIdentifier differs from the signed daemon")
    certificates = profile.get("DeveloperCertificates")
    if not certificate or not isinstance(certificates, list) or certificate not in certificates:
        raise ValueError("profile does not authorize the signed daemon's leaf certificate")
    allowed = profile.get("Entitlements", {})
    if not isinstance(allowed, dict) or allowed.get("com.apple.developer.team-identifier") != team:
        raise ValueError("profile does not authorize the signing team")
    expiry = profile.get("ExpirationDate")
    if not isinstance(expiry, datetime.datetime) or expiry.replace(tzinfo=datetime.timezone.utc) <= now:
        raise ValueError("profile is expired or has no expiration date")
    if (profile.get("ProvisionsAllDevices") is not True or allowed.get("get-task-allow", False)
            or allowed.get("com.apple.security.get-task-allow", False)):
        raise ValueError("use a Developer ID distribution profile")

    def permits(pattern, value):
        return isinstance(pattern, str) and (pattern == value or
            (pattern.endswith(".*") and value.startswith(pattern[:-1])))

    app_id = team + ".com.starlight.rekey"
    group = team + ".com.rekey"
    if not permits(allowed.get("com.apple.application-identifier"), app_id):
        raise ValueError("profile does not authorize com.starlight.rekey")
    groups = allowed.get("keychain-access-groups")
    if not isinstance(groups, list) or not any(permits(item, group) for item in groups):
        raise ValueError("profile does not authorize the Rekey keychain access group")
    return {"com.apple.application-identifier": app_id,
            "com.apple.developer.team-identifier": team,
            "keychain-access-groups": [group]}


def main():
    if len(sys.argv) != 5:
        raise ValueError("usage: prepare-macos-profile.py DECODED_PROFILE TEAM LEAF_CERTIFICATE OUTPUT")
    profile = plistlib.loads(Path(sys.argv[1]).read_bytes())
    result = entitlements(profile, sys.argv[2], Path(sys.argv[3]).read_bytes(), datetime.datetime.now(datetime.timezone.utc))
    Path(sys.argv[4]).write_bytes(plistlib.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, plistlib.InvalidFileException) as error:
        sys.exit("Cannot prepare Rekey App profile: " + str(error))
