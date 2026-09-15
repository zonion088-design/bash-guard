#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Register the bash-guard PreToolUse hook in ~/.claude/settings.json (idempotent)."""
import json
import os
import shutil
import sys
import time

SETTINGS = os.path.join(os.environ.get("BASH_GUARD_HOME") or os.path.expanduser("~"),
                        ".claude", "settings.json")
# Must use forward slashes: on Windows, Claude Code runs hook commands through
# bash, which eats backslashes — the hook would silently never fire.
PY = sys.executable.replace("\\", "/")
WATCH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "watch.py").replace("\\", "/")
HOOK_CMD = PY + " " + WATCH

with open(SETTINGS, encoding="utf-8") as f:
    s = json.load(f)

hooks = s.setdefault("hooks", {})
pre = None
for h in hooks.get("PreToolUse", []):
    if h.get("matcher") == "Bash":
        pre = h
        break
if pre is None:
    pre = {"matcher": "Bash", "hooks": []}
    hooks.setdefault("PreToolUse", []).append(pre)

entry = {"type": "command", "command": HOOK_CMD, "timeout": 15}
# drop old/broken watch.py entries (e.g. backslash paths from earlier versions),
# keep only the freshest registration
pre["hooks"] = [h for h in pre["hooks"] if "watch.py" not in h.get("command", "")]
pre["hooks"].append(entry)

bak = SETTINGS + ".bak-" + time.strftime("%Y%m%d-%H%M%S")
shutil.copy2(SETTINGS, bak)
tmp = SETTINGS + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(s, f, ensure_ascii=False, indent=2)
os.replace(tmp, SETTINGS)
print("hook registered, backup:", bak)
print(json.dumps(s["hooks"], ensure_ascii=False, indent=2))
