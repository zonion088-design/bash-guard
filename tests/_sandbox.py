# Shared test sandbox: a disposable HOME and state dir so the suite never
# touches the real ~/.claude/settings.json or the repo's own queue files.
import json
import os
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

HOME = os.environ.setdefault("BASH_GUARD_HOME",
                             tempfile.mkdtemp(prefix="bash-guard-home-"))
STATE = os.environ.setdefault("BASH_GUARD_STATE_DIR",
                              tempfile.mkdtemp(prefix="bash-guard-state-"))

WATCH = os.path.join(REPO, "watch.py")
CONSOLE = os.path.join(REPO, "console.py")

# Seed a minimal settings.json with a few allow rules so whitelist-hit
# behavior can be exercised.
SEED_ALLOW = [
    "Bash(node:*)",
    "Bash(curl -s http://127.0.0.1:8642/api:*)",
    "Bash(cd /tmp:*)",
]


def ensure_settings(allow=None):
    """(Re)create the sandbox settings.json and return its path."""
    p = os.path.join(HOME, ".claude", "settings.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"permissions": {"allow": list(allow if allow is not None else SEED_ALLOW)}},
                  f, ensure_ascii=False, indent=2)
    return p


def reset_state():
    """Empty the sandbox pending queue."""
    with open(os.path.join(STATE, "pending.json"), "w", encoding="utf-8") as f:
        json.dump([], f)


ensure_settings()
reset_state()
