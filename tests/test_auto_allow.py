#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auto_allow() policy test — both the function and the real hook process."""
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# (command, should auto-allow, reason)
CASES = [
    ("git status", True, "single read-only segment"),
    ("git log --oneline -5", True, "single read-only segment"),
    ("git diff HEAD~1", True, "single read-only segment"),
    ("git show abc123", True, "single read-only segment"),
    ("ls -la /c/work", True, "single read-only segment"),
    ("cat a.log | grep ERROR | wc -l", True, "three read-only segments piped"),
    ("pwd && whoami && date", True, "compound, all read-only"),
    ("tasklist | findstr python", True, "read-only process listing"),
    ("python app.py", True, "EXEC is auto-allowed"),
    ("env PYTHONPATH=x python app.py", True, "env unwraps to python (EXEC)"),
    ("timeout 10 curl http://127.0.0.1:8642/api/x", True, "timeout unwraps to localhost curl (NET)"),
    ("pip install requests", True, "PKG is auto-allowed"),
    ("sed -i s/a/b/ f.txt", True, "in-place edit (WRITE) is auto-allowed"),
    ("cat a.log > out.txt", True, "redirect writes a file (WRITE)"),
    ("git status; echo done", True, "git status + echo, both read-only"),
    ("git branch -d feature", False, "deletes a branch (denied earlier in policy anyway)"),
    ("git push origin main", False, "outbound data transfer"),
    ("echo `whoami`", False, "command substitution"),
    ("timeout 10 curl http://x.com", False, "timeout unwraps to external curl (NET_OUT)"),
    ("rm -rf build", False, "deletion"),
    ("some-unknown-cmd --x", False, "not in the knowledge base"),
    ("powershell -Command Get-Process", False, "system-level"),
]

fails = 0
for cmd, expect, why in CASES:
    got = guard.auto_allow(cmd)
    ok = (got == expect)
    # also drive the real hook process and check the decision on stdout
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd},
                         "session_id": "test", "cwd": _sandbox.HOME})
    p = subprocess.run([sys.executable, _sandbox.WATCH], input=payload.encode("utf-8"),
                       capture_output=True, timeout=30, env=os.environ.copy())
    out = p.stdout.decode("utf-8", "replace").strip()
    decision = ""
    if out:
        try:
            decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
        except Exception:
            decision = "<parse failed: %s>" % out[:80]
    hook_ok = (decision == "allow") == expect
    mark = "PASS" if (ok and hook_ok) else "FAIL"
    if mark == "FAIL":
        fails += 1
    print("%s fn=%-5s hook=%-5s | %s (%s)" % (mark, got, decision or "silent", cmd, why))

print("\nresult: %s" % ("all passed" if fails == 0 else "%d failed" % fails))
sys.exit(1 if fails else 0)
