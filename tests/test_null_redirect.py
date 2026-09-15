#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression: the policy trio (deny/allow/queue) + /dev/null redirect handling."""
import io
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

CASES = [
    # (command, expected: deny / allow / queue)
    ("rm -rf build", "deny"),
    ("git push origin main", "deny"),
    ("scp f u@h:/t", "deny"),
    ("where claude 2>/dev/null", "allow"),                    # error output discarded
    ("ls x 2>/dev/null; cat y", "allow"),                     # compound, read-only + null redirect
    ("grep ERROR a.log 2>/dev/null | wc -l 2>&1", "allow"),   # null + stream merge
    ("git log 2>NUL", "allow"),                                # Windows NUL
    ("ls | grep x", "allow"),
    ("echo `whoami`", "queue"),                                # command substitution
    ("some-unknown-cmd --x", "queue"),                         # unknown command
]

fails = 0
for cmd, expect in CASES:
    if guard.deny_reason(cmd):
        got = "deny"
    elif guard.auto_allow(cmd):
        got = "allow"
    else:
        got = "queue"
    ok = got == expect
    fails += 0 if ok else 1
    print("%s %-5s | %s" % ("PASS" if ok else "FAIL", got, cmd))

# explanation note wording
r = guard.explain("where claude 2>/dev/null")
print("\nnull-redirect note:", r["notes"])
assert any("writes nothing" in n for n in r["notes"])
r2 = guard.explain("cat a.log > out.txt")
assert any("overwrite a file" in n for n in r2["notes"])
print("write-redirect note:", r2["notes"])

print("\nresult: %s" % ("all passed" if fails == 0 else "%d failed" % fails))
sys.exit(1 if fails else 0)
