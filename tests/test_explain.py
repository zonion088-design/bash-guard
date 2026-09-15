#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Preview explain()/rule_boundary()/suggest_rule() output, with assertions on
the classifications that matter most."""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _sandbox  # noqa: F401
import guard  # noqa: E402

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

CASES = [
    # (command, expected risk: low / medium / high)
    ("git status --short", "low"),
    ("cd /c/work && python build.py --target x", "medium"),
    ("curl -s http://127.0.0.1:8642/api/status | python -m json.tool", "medium"),
    ("curl -X POST https://api.example.com/v1 -d '{\"a\":1}'", "high"),
    ("rm -rf build dist", "high"),
    ("cat access.log | grep ERROR | wc -l > errs.txt", "low"),   # segments read-only; redirect only adds a note
    ("pip install requests", "high"),
    ("npm run build", "medium"),
    ("powershell -Command Remove-Item -Recurse temp", "high"),
    ("some-unknown-tool --flag value", "high"),
    ("sed -i 's/a/b/' config.json", "medium"),
    ("echo `whoami` $(date)", "low"),   # leading command is echo; substitution shows up as a note
    ("git push origin main", "high"),
]

fails = 0
for cmd, risk in CASES:
    r = guard.explain(cmd)
    sug = guard.suggest_rule(cmd)
    ok = r["risk"] == risk
    if not ok:
        fails += 1
    print("=" * 70)
    print("CMD  :", cmd)
    print("RISK : %s (%s)" % (r["risk"], "PASS" if ok else "FAIL expected " + risk))
    for l in r["lines"]:
        print("  what :", l)
    for n in r["notes"]:
        print("  note :", n)
    print("suggest:", sug)
    print("scope  :", guard.rule_boundary(sug))

# structural assertions
assert guard.suggest_rule("git log --oneline -5") == "Bash(git log:*)"
assert guard.suggest_rule("rm -rf build") == "Bash(rm -rf build)"  # never a prefix for dangerous commands
assert "prefix" in guard.rule_boundary("Bash(git log:*)").lower()
assert "exact" in guard.rule_boundary("Bash(rm -rf build)").lower()
# redirect and substitution surface as notes even when risk stays low
notes_redirect = guard.explain("cat access.log | grep ERROR | wc -l > errs.txt")["notes"]
assert any("overwrite a file" in n for n in notes_redirect)
notes_subst = guard.explain("echo `whoami` $(date)")["notes"]
assert any("command substitution" in n for n in notes_subst)

print("\nresult: %s" % ("all passed" if fails == 0 else "%d failed" % fails))
sys.exit(1 if fails else 0)
