#!/usr/bin/env python3
"""Fail if a staged Rekey release directory is missing required files or docs links."""

from __future__ import annotations

import re
import sys
from pathlib import Path

MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")


def required_paths(version: str) -> list[str]:
    return [
        "rekey",
        "rekeyd",
        "rekey-service-unit.py",
        "LICENSE",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "SUPPORT.md",
        "docs/alpha-scope.md",
        "docs/installation.md",
        "docs/user-guide.md",
        "docs/operations-runbook.md",
        "docs/product-foundation/feature-truth-matrix.md",
        "docs/product-foundation/threat-model-v2.md",
        f"docs/releases/v{version}.md",
        "docs/superpowers/specs/2026-08-28-credential-authority-v2-foundation.md",
        "docs/superpowers/specs/2026-09-02-password-lifecycle-p01.md",
        "docs/superpowers/specs/2026-09-03-approvals-persistent-policy-p03.md",
        "docs/superpowers/specs/2026-09-03-workload-identity-p04.md",
        "docs/superpowers/specs/2026-09-04-agent-egress-launcher-p09.md",
        "examples/github-create-issue.json",
    ]


def link_target(raw: str) -> str | None:
    target = raw.strip().split()[0].strip("<>")
    if not target or target.startswith(("#", "mailto:", "http://", "https://")):
        return None
    return target.split("#", 1)[0]


def check_markdown_links(root: Path) -> list[str]:
    missing: list[str] = []
    for path in sorted(root.rglob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(text):
            relative = link_target(match.group(1))
            if relative is None:
                continue
            dest = (path.parent / relative).resolve()
            try:
                dest.relative_to(root.resolve())
            except ValueError:
                missing.append(f"{path.relative_to(root)} -> {relative} (escapes archive)")
                continue
            if not dest.exists():
                missing.append(f"{path.relative_to(root)} -> {relative}")
    return missing


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: release-archive-inventory.py ARCHIVE_DIR EXPECTED_VERSION", file=sys.stderr)
        return 2
    root = Path(sys.argv[1]).resolve()
    version = sys.argv[2]
    print(f"release-archive-inventory: dir={root}")
    print(f"release-archive-inventory: expected_version={version}")
    if not root.is_dir():
        print(f"archive directory missing: {root}", file=sys.stderr)
        return 1

    missing = [rel for rel in required_paths(version) if not (root / rel).exists()]
    for name in ("rekey", "rekeyd"):
        binary = root / name
        if binary.exists() and not binary.is_file():
            missing.append(f"{name} is not a file")
        elif binary.is_file() and not (binary.stat().st_mode & 0o111):
            missing.append(f"{name} is not executable")
    if missing:
        print("release archive is missing required files:", file=sys.stderr)
        for item in missing:
            print(f"  {item}", file=sys.stderr)
        return 1

    broken = check_markdown_links(root)
    if broken:
        print("release archive markdown links are missing targets:", file=sys.stderr)
        for item in broken:
            print(f"  {item}", file=sys.stderr)
        return 1
    print("release-archive-inventory: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
