#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full policy matrix test.
deny  = deletion / outbound data transfer (hard-deny)
allow = low+medium risk (read-only / file changes / code execution / localhost
        network / package installs) auto-allowed
queue = system-level / unknown / command substitution → pending queue
"""
import io
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401  (sets env before guard is imported)
import guard  # noqa: E402

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
PY = sys.executable

CASES = [
    # ── deny: deletion ──
    ("rm -rf build", "deny"),
    ("del temp.txt", "deny"),
    ("git clean -fd", "deny"),
    ("git reset --hard HEAD~1", "deny"),
    ("git branch -D feature", "deny"),
    ("docker rm web1", "deny"),
    ("xargs rm -f", "deny"),                       # xargs unwraps to rm
    ("sudo rm -rf /x", "deny"),                    # sudo unwraps to rm
    # ── deny: outbound data transfer ──
    ("git push origin main", "deny"),
    ("curl -X POST https://api.x.com/v1 -d a=1", "deny"),
    ("curl https://example.com/data", "deny"),
    ("wget https://example.com/f.zip", "deny"),
    ("scp file user@host:/tmp", "deny"),
    ("ssh user@host ls", "deny"),
    ("npm publish", "deny"),
    ("timeout 10 git push origin main", "deny"),   # timeout unwraps to git push
    ("env GIT_SSH=x git push", "deny"),            # env unwraps to git push
    # ── allow: read-only (low) ──
    ("ls -la", "allow"),
    ("git log --oneline", "allow"),
    ("cat a | grep x | wc -l", "allow"),
    ("where claude 2>/dev/null; ls x 2>NUL", "allow"),
    ("tasklist | findstr python", "allow"),
    # ── allow: medium risk (file changes / code / localhost network / packages) ──
    ("python app.py", "allow"),
    ("cp a.txt b.txt", "allow"),
    ("mkdir newdir", "allow"),
    ("sed -i s/a/b/ f.txt", "allow"),
    ("cat a.log > out.txt", "allow"),              # redirect writes a file = file-change class
    ("pip install requests", "allow"),             # package install
    ("npm install lodash", "allow"),
    ("curl -s http://127.0.0.1:8642/api/status", "allow"),   # localhost network
    ("git pull origin main", "allow"),             # fetch (inbound)
    ("git commit -m x", "allow"),
    ("env PYTHONPATH=lib python app.py", "allow"), # env unwraps to python
    ("timeout 30 curl http://127.0.0.1:8640/api/x", "allow"),
    ("node server.js", "allow"),
    # ── queue: system-level / unknown / command substitution ──
    ("powershell -Command Get-Process", "queue"),
    ("cmd //c build.bat", "queue"),
    ("bash -c 'echo hi'", "queue"),
    ("kill 1234", "queue"),
    ("taskkill /PID 1234", "queue"),
    ("reg add HKLM\\x", "queue"),
    ("schtasks /create /tn x", "queue"),
    ("docker run nginx", "queue"),
    ("some-unknown-cmd --x", "queue"),
    ("echo `whoami`", "queue"),
    ("echo $(date)", "queue"),
]

fails = 0
for cmd, expect in CASES:
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd},
                          "session_id": "policy-test", "cwd": _sandbox.HOME})
    p = subprocess.run([PY, _sandbox.WATCH], input=payload.encode("utf-8"),
                       capture_output=True, timeout=30, env=os.environ.copy())
    out = p.stdout.decode("utf-8", "replace").strip()
    decision = "queue"
    reason = ""
    if out:
        try:
            j = json.loads(out)["hookSpecificOutput"]
            decision = j["permissionDecision"]
            reason = j.get("permissionDecisionReason", "")[:60]
        except Exception:
            decision = "bad-output"
    elif guard.command_allowed(cmd, _sandbox.HOME):
        # watch.py stays silent on whitelist hits (Claude Code's normal flow
        # applies) — permission-wise the outcome is the same: allowed
        decision = "allow"
        reason = "(whitelist hit, hook silent)"
    ok = decision == expect
    if not ok:
        fails += 1
    print("%s expect=%-5s got=%-5s | %s %s" % ("PASS" if ok else "FAIL", expect, decision, cmd, reason))

print("\n%d cases total: %s" % (len(CASES), "all passed" if fails == 0 else "%d failed" % fails))
sys.exit(1 if fails else 0)
