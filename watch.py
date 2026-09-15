#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bash-guard hook entry point — Claude Code PreToolUse (matcher: Bash)

Reads the hook JSON from stdin:
  {"tool_name": "Bash", "tool_input": {"command": ..., "description": ...},
   "session_id": ..., "cwd": ...}

Commands that miss the whitelist are recorded into pending.json (deduplicated
by command, with description/sessions/count) for review in the web console.
Every failure is swallowed silently — the hook must never break the normal
permission flow.
"""
import json
import os
import sys
import time

sys.dont_write_bytecode = True  # no pyc: stale bytecode would keep old policy alive
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

STATE_DIR = os.environ.get("BASH_GUARD_STATE_DIR") or os.path.dirname(os.path.abspath(__file__))
AUTO_LOG = os.path.join(STATE_DIR, "auto-approved.jsonl")
DENY_LOG = os.path.join(STATE_DIR, "denied.jsonl")


def _hook_decision(decision, reason):
    sys.stdout.write(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }, ensure_ascii=False))


def _audit(path, cmd, session):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                                "cmd": cmd, "session": session},
                               ensure_ascii=False) + "\n")
    except Exception:
        pass


def main():
    try:
        # Claude Code sends UTF-8 JSON; on Windows sys.stdin defaults to the
        # ANSI code page, so read raw bytes and decode explicitly.
        data = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
    except Exception:
        return
    if data.get("tool_name") != "Bash":
        return
    ti = data.get("tool_input") or {}
    cmd = (ti.get("command") or "").strip()
    if not cmd:
        return
    cwd = data.get("cwd") or os.path.expanduser("~")
    session = data.get("session_id") or ""
    try:
        if guard.command_allowed(cmd, cwd):
            return
        # hard policy: deletions / outbound data transfer → deny outright
        reason = guard.deny_reason(cmd)
        if reason:
            _hook_decision("deny", "bash-guard policy: " + reason)
            _audit(DENY_LOG, cmd, session)
            return
        # auto-allow: categories covered by policy pass without a prompt
        if guard.auto_allow(cmd):
            _hook_decision("allow", "bash-guard: every segment of this command "
                                    "is covered by the auto-allow policy")
            _audit(AUTO_LOG, cmd, session)
            return
        guard.append_pending(cmd, ti.get("description") or "", session, cwd)
    except Exception:
        pass  # a logging failure must never stall the permission flow


if __name__ == "__main__":
    main()
