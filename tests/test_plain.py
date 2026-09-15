#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Preview plain() output: the one-sentence summary + approval tier that leads
each review card. Pure function test — writes no state."""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

SAMPLES = [
    # (command, expected tier)
    ("taskkill //PID 20508 //F", "confirm"),          # system-level → confirm
    ("sleep 60; taskkill //PID 20508 //F", "confirm"),
    ("powershell -NoProfile -Command Get-Process", "confirm"),
    ('reg query "HKLM\\Software\\Microsoft\\Windows Script Host\\Settings" 2>&1; echo ---', "confirm"),
    ("od -c deploy.bat | head -3", "safe"),           # read-only
    ("cd /tmp/project && for f in $(find . -name '*x*'); do grep -c y $f; done", "verify"),  # substitution
    ("some-unknown-cmd --x", "verify"),               # unknown
    ("tar -czf out.tgz dir", "normal"),               # file change
]

fails = 0
for cmd, tier in SAMPLES:
    p = guard.plain(cmd)
    ok = p.get("tier") == tier
    if not ok:
        fails += 1
    print("-" * 66)
    print("CMD:", cmd[:70])
    print("  headline:", p["headline"])
    print("  advice  :", p["advice"])
    print("  tier    : %s (%s)" % (p["tier"], "PASS" if ok else "FAIL expected " + tier))

print("\nresult: %s" % ("all passed" if fails == 0 else "%d failed" % fails))
sys.exit(1 if fails else 0)
