#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""End-to-end test: hook queues → console API lists → approve writes the rule →
whitelist takes effect → dismiss path → cleanup. Runs its own console instance
on a free port; everything stays inside the sandbox HOME/state dir."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

_sandbox.ensure_settings()
_sandbox.reset_state()
SETTINGS = os.path.join(_sandbox.HOME, ".claude", "settings.json")
# a system-level command: under the final policy it is neither auto-allowed
# nor denied — it goes to the review queue
CMD = "taskkill /PID 4242"
DESC = "stop the old server before redeploying"
REJECT_CMD = "schtasks /query"          # also SYS-level → queue, for the dismiss path


# ── pick a free port and start the console ──
s = socket.socket()
s.bind(("127.0.0.1", 0))
PORT = s.getsockname()[1]
s.close()
API = "http://127.0.0.1:%d" % PORT

env = dict(os.environ, BASH_GUARD_PORT=str(PORT))
proc = subprocess.Popen([sys.executable, _sandbox.CONSOLE], env=env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try:
            with urllib.request.urlopen(API + "/api/bash/pending", timeout=2) as r:
                json.loads(r.read().decode("utf-8"))
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("console did not come up")


    def post(path, obj):
        req = urllib.request.Request(API + path, data=json.dumps(obj).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))


    def get(path):
        with urllib.request.urlopen(API + path, timeout=10) as r:
            return json.loads(r.read().decode("utf-8"))


    # 1. hook queues the command
    hook_input = {"tool_name": "Bash", "tool_input": {"command": CMD, "description": DESC},
                  "session_id": "e2e-test", "cwd": _sandbox.HOME}
    p = subprocess.run([sys.executable, _sandbox.WATCH], input=json.dumps(hook_input).encode("utf-8"),
                       capture_output=True, env=os.environ.copy())
    assert p.returncode == 0 and not p.stdout and not p.stderr, "hook should succeed silently"
    print("1. hook queued OK")

    # 2. console API lists it
    d = get("/api/bash/pending")
    item = next((it for it in d["pending"] if it["key"] == " ".join(CMD.split())), None)
    assert item, "API should list the queued command: %s" % d["pending"]
    assert item["desc"] == DESC, "description should survive: %r" % item["desc"]
    assert item["suggest"] == "Bash(%s)" % CMD, "dangerous commands get exact rules: %r" % item["suggest"]
    assert item["plain"]["tier"] == "confirm", "system-level should be the confirm tier"
    print("2. API listing OK, suggest:", item["suggest"])

    # 3. approve
    r = post("/api/bash/approve", {"key": item["key"], "rule": item["suggest"]})
    assert r["ok"], "approve should succeed: %s" % r
    print("3. approve OK:", r["message"])

    # 4. whitelist took effect
    with open(SETTINGS, encoding="utf-8") as f:
        st = json.load(f)
    assert "Bash(%s)" % CMD in st["permissions"]["allow"], "rule should be in settings.json"
    assert guard.command_allowed(CMD, _sandbox.HOME), "the command should now be allowed"
    d = get("/api/bash/pending")
    assert not any(it["key"] == item["key"] for it in d["pending"]), "approved item should leave the queue"
    print("4. whitelist write + effect OK")

    # 5. dismiss path (another system-level command)
    hi2 = {"tool_name": "Bash", "tool_input": {"command": REJECT_CMD, "description": "check tasks"},
           "session_id": "e2e-test", "cwd": _sandbox.HOME}
    subprocess.run([sys.executable, _sandbox.WATCH], input=json.dumps(hi2).encode("utf-8"),
                   capture_output=True, env=os.environ.copy())
    r = post("/api/bash/reject", {"key": " ".join(REJECT_CMD.split())})
    assert r["ok"], "dismiss should succeed: %s" % r
    d = get("/api/bash/pending")
    assert not any(it["key"] == " ".join(REJECT_CMD.split()) for it in d["pending"]), \
        "dismissed item should leave the queue"
    print("5. dismiss path OK")

    # 6. history was recorded
    h = guard._load_json(guard.HISTORY_PATH, [])
    assert any(e.get("action") == "approve" and e.get("rule") == "Bash(%s)" % CMD for e in h), \
        "approval should be recorded in history.json"
    print("6. history OK")

    print("\nend-to-end passed")
finally:
    proc.terminate()
    proc.wait(timeout=10)
