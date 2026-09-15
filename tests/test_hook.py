#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""watch.py smoke test: simulate the stdin Claude Code feeds the hook, check
decisions and queue writes under the final policy (read-only/medium risk is
auto-allowed, only SYS / unknown / substitution lands in the queue)."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

_sandbox.ensure_settings()  # reseed whitelist (previous tests may have approved rules)
_sandbox.reset_state()
cwd = _sandbox.HOME

QUEUE_CMD = "powershell -Command Get-Process"


def run_hook(payload):
    p = subprocess.run([sys.executable, _sandbox.WATCH], input=json.dumps(payload).encode("utf-8"),
                       capture_output=True, timeout=30, env=os.environ.copy())
    return p, p.stdout.decode("utf-8", "replace").strip()


# 1. read-only command → auto-allow decision (not queued)
p, out = run_hook({"tool_name": "Bash", "tool_input": {"command": "git status",
                                                        "description": "show working-tree state"},
                   "session_id": "test-1", "cwd": cwd})
dec = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
assert dec == "allow", "read-only command should be auto-allowed, got %r" % dec
print("1. read-only auto-allow OK")

# 2. whitelisted command (curl prefix seeded) → silent pass-through
p, out = run_hook({"tool_name": "Bash", "tool_input": {"command": "curl -s http://127.0.0.1:8642/api/status",
                                                       "description": "check console status"},
                   "session_id": "test-1", "cwd": cwd})
assert p.returncode == 0 and not out and not p.stderr, "whitelist hit should be silent"
print("2. whitelist hit silent OK")

# 3. system-level command → queued
run_hook({"tool_name": "Bash", "tool_input": {"command": QUEUE_CMD, "description": "inspect processes"},
          "session_id": "test-1", "cwd": cwd})
# 3b. same command again (should dedupe, count+1, sessions accumulate)
run_hook({"tool_name": "Bash", "tool_input": {"command": QUEUE_CMD, "description": ""},
          "session_id": "test-2", "cwd": cwd})
print("3. system-level command queued OK")

# 4. non-Bash tool → ignored
p, out = run_hook({"tool_name": "Write", "tool_input": {"file_path": "x"},
                   "session_id": "test-1", "cwd": cwd})
assert not out, "non-Bash tools must be ignored"
# 5. malformed input → silent
p, out = run_hook({"tool_name": "Bash", "tool_input": {}, "session_id": "test-1", "cwd": cwd})
assert p.returncode == 0 and not out, "empty command must be silent"
# 6. malformed JSON → silent
p = subprocess.run([sys.executable, _sandbox.WATCH], input=b"not json",
                   capture_output=True, timeout=30, env=os.environ.copy())
assert p.returncode == 0 and not p.stdout and not p.stderr, "bad JSON must be silent"
print("4. ignore/malformed handling OK")

print("\n--- pending.json ---")
for it in guard.load_pending():
    print(json.dumps(it, ensure_ascii=False))
    print("  suggest:", guard.suggest_rule(it["cmd"]))

# queue-content assertions
queued = {it["key"] for it in guard.load_pending()}
assert QUEUE_CMD in queued, "system-level command must queue"
assert not any("git status" in k for k in queued), "auto-allowed command must not queue"
assert not any("curl" in k for k in queued), "whitelisted curl must not queue"
# dedupe: QUEUE_CMD arrived twice but is one entry with count=2
qc = [it for it in guard.load_pending() if it["key"] == QUEUE_CMD]
assert len(qc) == 1 and qc[0]["count"] == 2, "second sighting should dedupe into count=2"
assert qc[0]["sessions"] == ["test-1", "test-2"], "sessions should accumulate"

# matching assertions
assert not guard.command_allowed("git status", cwd), "git status not whitelisted"
assert guard.command_allowed("curl -s http://127.0.0.1:8642/api/x", cwd), "curl prefix is allowed"
assert guard.command_allowed("node server.js", cwd), "node is allowed"
assert guard.command_allowed("cd /tmp && node a.js", cwd), "compound with every segment allowed"
assert not guard.command_allowed("cd /tmp && nmap x", cwd), "compound with an unallowed segment"
print("\nall assertions passed")
