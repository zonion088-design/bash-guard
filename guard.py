#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bash-guard core library — whitelist rule parsing/matching + pending queue + one-click approval.

Used by two entry points:
  watch.py    PreToolUse hook: Bash commands that miss the whitelist land in pending.json
  console.py  local web console: shows the queue, approvals write to ~/.claude/settings.json

Rule syntax (mirrors Claude Code permissions.allow Bash rules):
  Bash            allow all Bash
  Bash(cmd)       exact match (the full command text)
  Bash(prefix:*)  prefix match

Matching is deliberately approximate (it does not model deny/ask overrides,
`bash -c` wrapping and other corner cases) — better to over-queue than to let
a command silently stall on a permission prompt.
"""
import json
import os
import re
import time
from contextlib import contextmanager

BASE = os.path.dirname(os.path.abspath(__file__))
# State files live next to the library by default; override for tests/sandboxes.
STATE_DIR = os.environ.get("BASH_GUARD_STATE_DIR") or BASE
PENDING_PATH = os.path.join(STATE_DIR, "pending.json")
HISTORY_PATH = os.path.join(STATE_DIR, "history.json")
BACKUP_DIR = os.path.join(STATE_DIR, "backups")

MAX_PENDING = 500
MAX_SESSIONS = 5
MAX_HISTORY = 2000

# ── Policy: overridable via an optional policy.json next to this file ──
DEFAULT_POLICY = {
    # Categories that are hard-denied before anything else. These defaults are
    # a sane security baseline: destructive commands and outbound data transfer.
    "deny_categories": ["DEL", "NET_OUT"],
    # Categories auto-allowed by the hook when every segment falls into them.
    "auto_allow_categories": ["READ", "WRITE", "EXEC", "NET", "PKG"],
    # Appended to the deny reason shown to the model.
    "deny_note": (
        "Policy: deletion commands are always denied, and so is sending data "
        "outside this machine. If you genuinely need this, use an approved "
        "transfer channel (for example an email tool), or ask the user to run "
        "it manually."
    ),
}


def _home():
    """Home directory. BASH_GUARD_HOME lets tests point somewhere disposable."""
    return os.environ.get("BASH_GUARD_HOME") or os.path.expanduser("~")


def _user_settings():
    return os.path.join(_home(), ".claude", "settings.json")


def _user_local_settings():
    return os.path.join(_home(), ".claude", "settings.local.json")


def load_policy():
    p = dict(DEFAULT_POLICY)
    p.update(_load_json(os.path.join(BASE, "policy.json"), {}) or {})
    return p


# ── Rule suggestions: these commands are safe enough to suggest a prefix rule;
#    everything else gets an exact-match suggestion ──
SAFE_SINGLE = {
    "ls", "pwd", "cat", "head", "tail", "wc", "grep", "rg", "find", "which",
    "whoami", "date", "env", "df", "du", "uname", "hostname", "tree", "stat",
}
SAFE_PAIR = {
    # note: git branch / git tag are deliberately absent — their -d/-D forms
    # delete things, so they only ever get exact-match approvals
    "git status", "git diff", "git log", "git show", "git remote",
    "git stash list",
}
# localhost curl can be allowed as a (port-level) prefix rule
LOCAL_CURL_RE = re.compile(r'curl(?:\s+-[\w-]+)*\s+https?://127\.0\.0\.1:\d+')


# ── File lock: best-effort — if we can't get it, carry on anyway
#    (queue writes use atomic replace, concurrent writers can't corrupt) ──
@contextmanager
def _lock(path):
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "a+b") as f:
        locked = False
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                if os.name == "nt":
                    import msvcrt
                    f.seek(0)
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except OSError:
                time.sleep(0.05)
        try:
            yield
        finally:
            if locked:
                try:
                    if os.name == "nt":
                        import msvcrt
                        f.seek(0)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(f, fcntl.LOCK_UN)
                except OSError:
                    pass


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json_atomic(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    # Another Claude session may briefly hold a handle on settings.json —
    # a WinError 5 retry loop is all it takes.
    for i in range(6):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if i == 5:
                raise
            time.sleep(0.4)


# resolved after _load_json is defined (policy.json is optional)
POLICY = load_policy()


# ── Collecting and matching permission rules ──
def settings_files(cwd):
    """Collect settings files in Claude Code's effective order:
    user → user.local → project settings walking up from cwd.

    When BASH_GUARD_HOME is set, it acts as a sandbox ceiling: project
    settings are collected from it downward only, never from the real machine
    above it (used by the test suite)."""
    files = [_user_settings(), _user_local_settings()]
    d = os.path.abspath(cwd or _home())
    sandbox = os.environ.get("BASH_GUARD_HOME")
    while True:
        files.append(os.path.join(d, ".claude", "settings.json"))
        files.append(os.path.join(d, ".claude", "settings.local.json"))
        parent = os.path.dirname(d)
        if parent == d:
            break
        if sandbox:
            try:
                root = os.path.normcase(os.path.abspath(sandbox))
                under = os.path.commonpath([root, os.path.normcase(parent)]) == root
            except ValueError:
                under = False  # e.g. different drives on Windows
            if not under:
                break
        d = parent
    seen, out = set(), []
    for p in files:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def bash_rules(cwd=None):
    """Extract Bash rules from all allow lists; returns inner specs ('*' = allow all)."""
    specs = []
    for p in settings_files(cwd):
        s = _load_json(p, {})
        for r in ((s.get("permissions") or {}).get("allow") or []):
            r = str(r).strip()
            if r == "Bash":
                specs.append("*")
            elif r.startswith("Bash(") and r.endswith(")"):
                specs.append(r[5:-1])
    return specs


def split_segments(cmd):
    """Split a compound command on top-level && || ; | (quote-aware)."""
    segs, buf, q = [], [], None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if q:
            buf.append(c)
            if c == q:
                q = None
            i += 1
            continue
        if c in "\"'":
            q = c
            buf.append(c)
            i += 1
            continue
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            segs.append("".join(buf))
            buf = []
            i += 2
            continue
        if c in ";|":
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def seg_matches(spec, seg):
    if spec == "*":
        return True
    if spec.endswith(":*"):
        pre = spec[:-2]
        return seg == pre or seg.startswith(pre)
    return seg == spec


def command_allowed(cmd, cwd=None):
    """Predict whether the whitelist would allow this command
    (compound commands need every segment allowed)."""
    specs = bash_rules(cwd)
    if not specs:
        return False
    segs = split_segments(cmd)
    if not segs:
        return True
    return all(any(seg_matches(sp, s) for sp in specs) for s in segs)


# ── Pending queue ──
def load_pending():
    data = _load_json(PENDING_PATH, [])
    return data if isinstance(data, list) else []


def append_pending(cmd, desc="", session_id="", cwd=""):
    key = " ".join(cmd.split())
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _lock(PENDING_PATH):
        items = load_pending()
        for it in items:
            if it.get("key") == key:
                it["count"] = it.get("count", 0) + 1
                it["lastSeen"] = now
                if desc and not it.get("desc"):
                    it["desc"] = desc
                if session_id and session_id not in it.get("sessions", []):
                    it.setdefault("sessions", []).append(session_id)
                    it["sessions"] = it["sessions"][-MAX_SESSIONS:]
                _save_json_atomic(PENDING_PATH, items)
                return
        items.append({
            "key": key, "cmd": cmd, "desc": desc,
            "sessions": [session_id][:MAX_SESSIONS] if session_id else [],
            "count": 1, "firstSeen": now, "lastSeen": now, "cwd": cwd,
        })
        if len(items) > MAX_PENDING:
            items = items[-MAX_PENDING:]
        _save_json_atomic(PENDING_PATH, items)


def _remove_pending(key):
    with _lock(PENDING_PATH):
        items = load_pending()
        keep = [it for it in items if it.get("key") != key]
        _save_json_atomic(PENDING_PATH, keep)
        return len(items) - len(keep)


def _append_history(entry):
    with _lock(HISTORY_PATH):
        h = _load_json(HISTORY_PATH, [])
        if not isinstance(h, list):
            h = []
        h.append(entry)
        _save_json_atomic(HISTORY_PATH, h[-MAX_HISTORY:])


# ── Command classification (for the review console; purely local, no network) ──
# category → (risk, label)
CAT = {
    "READ":    ("low", "read-only"),
    "WRITE":   ("medium", "modifies files"),
    "EXEC":    ("medium", "executes code"),
    "NET":     ("medium", "network access"),
    "NET_OUT": ("high", "sends data out"),
    "PKG":     ("high", "installs third-party code"),
    "DEL":     ("high", "deletes"),
    "SYS":     ("high", "system-level operation"),
    "UNK":     ("high", "not in the knowledge base"),
}

# Two-word commands (subcommands of git/docker/npm/pip/…)
KB_PAIR = {
    ("git", "status"): ("show working-tree changes", "READ"),
    ("git", "diff"): ("show file diffs", "READ"),
    ("git", "log"): ("show commit history", "READ"),
    ("git", "show"): ("show a specific commit", "READ"),
    ("git", "branch"): ("list branches", "READ"),
    ("git", "tag"): ("list tags", "READ"),
    ("git", "remote"): ("view/manage remote URLs", "READ"),
    ("git", "add"): ("stage files (does not change file contents)", "WRITE"),
    ("git", "commit"): ("commit staged changes to the local repo", "WRITE"),
    ("git", "stash"): ("stash/restore current changes", "WRITE"),
    ("git", "checkout"): ("switch branches or restore files (may discard changes)", "WRITE"),
    ("git", "switch"): ("switch branches", "WRITE"),
    ("git", "restore"): ("restore files to an older version (may discard changes)", "WRITE"),
    ("git", "config"): ("read/write git configuration", "WRITE"),
    ("git", "init"): ("initialize a git repository", "WRITE"),
    ("git", "merge"): ("merge branches", "WRITE"),
    ("git", "rebase"): ("rebase (rewrites commit history)", "WRITE"),
    ("git", "cherry-pick"): ("apply a specific commit onto the current branch", "WRITE"),
    ("git", "mv"): ("move/rename files", "WRITE"),
    ("git", "reset"): ("reset HEAD/index (may discard changes)", "DEL"),
    ("git", "clean"): ("delete untracked files", "DEL"),
    ("git", "rm"): ("delete files from the repo and the working tree", "DEL"),
    ("git", "push"): ("push local commits to a remote repository", "NET_OUT"),
    ("git", "pull"): ("fetch remote updates and merge them", "NET"),
    ("git", "fetch"): ("fetch remote refs (does not change local files)", "NET"),
    ("git", "clone"): ("clone a remote repository", "NET"),
    ("docker", "ps"): ("list containers", "READ"),
    ("docker", "images"): ("list images", "READ"),
    ("docker", "logs"): ("show container logs", "READ"),
    ("docker", "rm"): ("remove a container", "DEL"),
    ("docker", "rmi"): ("remove an image", "DEL"),
    ("docker", "run"): ("start a container (can mount host dirs, open ports)", "SYS"),
    ("docker", "exec"): ("run a command inside a container", "SYS"),
    ("npm", "run"): ("run a script declared in package.json", "EXEC"),
    ("npm", "test"): ("run project tests", "EXEC"),
    ("npm", "start"): ("start the project", "EXEC"),
    ("npm", "install"): ("install third-party npm packages (downloads and runs install scripts)", "PKG"),
    ("npm", "i"): ("install third-party npm packages (downloads and runs install scripts)", "PKG"),
    ("npm", "publish"): ("publish a package to the npm registry (data leaves the machine)", "NET_OUT"),
    ("pip", "install"): ("install third-party Python packages (downloads and runs install scripts)", "PKG"),
    ("pip3", "install"): ("install third-party Python packages (downloads and runs install scripts)", "PKG"),
}

# Single-word commands
KB_SINGLE = {
    "ls": ("list directory contents", "READ"), "dir": ("list directory contents", "READ"),
    "pwd": ("print the current directory", "READ"),
    "cat": ("print file contents", "READ"), "type": ("print file contents", "READ"),
    "head": ("show the first lines of a file", "READ"), "tail": ("show the last lines of a file", "READ"),
    "grep": ("search text in files/input", "READ"), "rg": ("search text in files/input", "READ"),
    "findstr": ("search text in files", "READ"),
    "find": ("find files by criteria", "READ"),
    "wc": ("count lines/words", "READ"),
    "which": ("locate a command's path", "READ"), "where": ("locate a command's path", "READ"),
    "whoami": ("print the current user", "READ"), "hostname": ("print the hostname", "READ"),
    "uname": ("print system information", "READ"),
    "date": ("print date and time", "READ"),
    "env": ("show environment variables", "READ"), "printenv": ("show environment variables", "READ"),
    "df": ("show disk usage", "READ"), "du": ("show directory usage", "READ"),
    "tree": ("list a directory as a tree", "READ"),
    "stat": ("show file attributes", "READ"), "file": ("identify a file type", "READ"),
    "sort": ("sort lines of text", "READ"), "uniq": ("deduplicate lines of text", "READ"),
    "cut": ("extract text columns", "READ"), "tr": ("replace/delete characters", "READ"),
    "awk": ("process text (does not modify source files)", "READ"),
    "sed": ("stream-edit text (prints by default, does not write)", "READ"),
    "echo": ("print text", "READ"), "printf": ("print text", "READ"),
    "cd": ("change the current directory (no side effects)", "READ"),
    "sleep": ("wait for a while", "READ"), "timeout": ("bounded wait", "READ"),
    "tasklist": ("list running processes", "READ"),
    "netstat": ("show network connections/ports", "READ"),
    "ps": ("list running processes", "READ"),
    "wmic": ("query system/hardware information", "READ"),
    "od": ("dump a file byte by byte", "READ"), "xxd": ("dump a file byte by byte", "READ"),
    "ipconfig": ("show network configuration", "READ"),
    "less": ("page through a file", "READ"), "more": ("page through a file", "READ"),
    "test": ("evaluate a condition", "READ"),
    "true": ("always succeed", "READ"), "false": ("always fail", "READ"),
    "ping": ("probe network connectivity", "NET"),
    "nslookup": ("resolve a domain name", "NET"), "dig": ("resolve a domain name", "NET"),
    "curl": ("make HTTP requests / download content", "NET"),
    "wget": ("download a file", "NET"),
    "python": ("run Python scripts/code", "EXEC"),
    "python3": ("run Python scripts/code", "EXEC"),
    "py": ("run Python scripts/code", "EXEC"),
    "node": ("run Node.js scripts/code", "EXEC"),
    "ruby": ("run Ruby code", "EXEC"), "perl": ("run Perl code", "EXEC"),
    "java": ("run a Java program", "EXEC"),
    "claude": ("invoke the Claude Code CLI", "EXEC"),
    "make": ("build the project", "WRITE"), "cargo": ("build the Rust project", "WRITE"),
    "go": ("build the Go project", "WRITE"),
    "mv": ("move/rename files", "WRITE"), "rename": ("rename files", "WRITE"),
    "cp": ("copy files", "WRITE"), "copy": ("copy files", "WRITE"),
    "xcopy": ("copy a directory tree", "WRITE"), "robocopy": ("copy a directory tree", "WRITE"),
    "mkdir": ("create a directory", "WRITE"), "md": ("create a directory", "WRITE"),
    "touch": ("create an empty file / update timestamps", "WRITE"),
    "tee": ("write output to a file", "WRITE"),
    "tar": ("pack/unpack files", "WRITE"), "zip": ("compress files", "WRITE"),
    "unzip": ("decompress a file", "WRITE"), "gzip": ("compress/decompress files", "WRITE"),
    "ln": ("create a link", "WRITE"), "mklink": ("create a link", "WRITE"),
    "vim": ("open a text editor (interactive)", "WRITE"), "vi": ("open a text editor (interactive)", "WRITE"),
    "nano": ("open a text editor (interactive)", "WRITE"), "notepad": ("open Notepad (interactive)", "WRITE"),
    "code": ("open VS Code (interactive)", "WRITE"),
    "export": ("set an environment variable (current session only)", "WRITE"),
    "set": ("set/show environment variables", "WRITE"),
    "xargs": ("run a command on each input line (effect depends on the command)", "EXEC"),
    "rm": ("delete files", "DEL"), "rmdir": ("delete a directory", "DEL"),
    "del": ("delete files", "DEL"), "rd": ("delete a directory", "DEL"),
    "unlink": ("delete a file", "DEL"), "shred": ("irretrievably destroy a file", "DEL"),
    "kill": ("terminate a process", "SYS"), "taskkill": ("terminate a process", "SYS"),
    "pkill": ("terminate processes", "SYS"), "killall": ("terminate processes", "SYS"),
    "chmod": ("change file permissions", "SYS"), "chown": ("change file ownership", "SYS"),
    "icacls": ("change file permissions", "SYS"), "attrib": ("change file attributes", "SYS"),
    "sc": ("manage system services", "SYS"), "schtasks": ("manage scheduled tasks", "SYS"),
    "reg": ("read/write the registry", "SYS"), "regedit": ("edit the registry", "SYS"),
    "shutdown": ("shut down / reboot", "SYS"), "reboot": ("reboot", "SYS"),
    "bash": ("start a shell to run a command (can run anything)", "SYS"),
    "sh": ("start a shell to run a command (can run anything)", "SYS"),
    "zsh": ("start a shell to run a command (can run anything)", "SYS"),
    "powershell": ("start PowerShell to run a command (can run anything)", "SYS"),
    "pwsh": ("start PowerShell to run a command (can run anything)", "SYS"),
    "cmd": ("start cmd to run a command (can run anything)", "SYS"),
    "ssh": ("log into a remote machine and run commands", "NET_OUT"),
    "scp": ("copy files to a remote machine", "NET_OUT"),
    "npm": ("Node package manager", "PKG"), "npx": ("download and run an npm package", "PKG"),
    "pip": ("Python package manager", "PKG"), "pip3": ("Python package manager", "PKG"),
    "conda": ("Conda environment management", "PKG"), "yarn": ("Node package manager", "PKG"),
    "git": ("git version control", "WRITE"),
    "docker": ("Docker container operations", "SYS"),
}

_URL_RE = re.compile(r'https?://([^\s/\'"]+)')
_LOCAL_HOSTS = ("127.0.0.1", "localhost", "0.0.0.0", "[::1]")

# Wrapper commands: they only relay to the command behind them — classify and
# block by the real target, not the wrapper.
_WRAPPER_HEADS = {"env", "nice", "nohup", "time", "timeout", "watch", "exec", "xargs", "sudo"}


def _seg_head(seg):
    """Return a segment's leading command (skipping VAR=value prefixes,
    stripping paths and .exe; unwrapping env/timeout/xargs/sudo/… wrappers
    to get at the real command being run)."""
    toks = seg.split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if re.match(r"^[A-Za-z_]\w*=", t):  # environment variable prefix
            i += 1
            continue
        head = os.path.basename(t.replace("\\", "/").strip("\"'")).lower()
        if head.endswith(".exe"):
            head = head[:-4]
        if head in _WRAPPER_HEADS:
            i += 1
            if head == "timeout":  # skip timeout's own flags and duration (10 / 10s / 1.5m)
                while i < len(toks) and (toks[i].startswith("-")
                                         or re.match(r"^\d+(\.\d+)?[smh]?$", toks[i], re.I)):
                    i += 1
            continue
        return head, toks[i + 1:]
    return None, []


def _explain_segment(seg):
    head, rest = _seg_head(seg)
    if head is None:
        return ("(empty segment)", "READ")
    desc, cat = KB_PAIR.get((head, rest[0].lower() if rest else ""),
                            KB_SINGLE.get(head, ("command not in the knowledge base — review verbatim", "UNK")))
    # flag-driven corrections
    flags = [t for t in rest if t.startswith("-")]
    if head == "git" and rest and rest[0].lower() == "branch" and any(f in ("-d", "-D", "--delete") for f in flags):
        desc, cat = "delete a branch", "DEL"
    if head == "sed" and any(f.startswith("-i") for f in flags):
        desc, cat = "edit a file in place", "WRITE"
    if head == "find" and any(f in ("-delete",) for f in flags):
        desc, cat = "delete the files it finds", "DEL"
    if head == "find" and "-exec" in rest:
        desc, cat = "run an arbitrary command on the files it finds", "SYS"
    if head == "curl":
        m = _URL_RE.search(seg)
        if any(f in ("-X", "--request") for f in flags) or "-d" in rest or "--data" in rest or "-T" in rest:
            desc, cat = "send/upload data to a URL", "NET_OUT"
        elif m and not m.group(1).startswith(_LOCAL_HOSTS):
            desc, cat = "request an external host %s" % m.group(1), "NET_OUT"
        elif m:
            desc, cat = "request a local service (%s)" % m.group(1), "NET"
        if any(f in ("-o", "--output") for f in flags):
            desc += ", writes the result to a file"
    if head == "wget":
        m = _URL_RE.search(seg)
        if m and not m.group(1).startswith(_LOCAL_HOSTS):
            cat = "NET_OUT"
    if head in ("rm", "rmdir", "del", "rd") and any(f in ("-r", "-R", "-rf", "-fr", "/s", "-rf") for f in flags):
        desc = "recursively delete files/directories"
    return (desc, cat)


def explain(cmd):
    """Explain a whole command: one line per segment + overall risk +
    structural notes. Never raises."""
    try:
        segs = split_segments(cmd)
        lines, notes = [], []
        risks = []
        for i, seg in enumerate(segs, 1):
            desc, cat = _explain_segment(seg)
            risk, label = CAT[cat]
            risks.append(risk)
            prefix = "" if len(segs) == 1 else "Segment %d: " % i
            lines.append("%s`%s` — %s (%s)" % (prefix, seg, desc, label))
        if len(segs) > 1:
            notes.append("Compound command with %d segments (joined by && / ; / |); "
                         "Claude Code checks each segment against the whitelist — "
                         "every segment must be allowed" % len(segs))
        if ">" in cmd:
            if _only_null_redirects(cmd):
                notes.append("Redirects only point to /dev/null (output discarded) — writes nothing")
            elif ">>" in cmd:
                notes.append("Contains a >> redirect: output will be appended to a file")
            else:
                notes.append("Contains a > redirect: output will overwrite a file")
        if "$(" in cmd or "`" in cmd:
            notes.append("Contains command substitution $()/backticks: what actually runs "
                         "is only determined at runtime — review the nested parts")
        risk = "low"
        for r in risks:
            if r == "high" or (r == "medium" and risk == "low"):
                risk = r
        return {"lines": lines, "risk": risk, "notes": notes}
    except Exception as e:
        return {"lines": ["explain failed: %s" % e], "risk": "high", "notes": []}


# ── Plain-language summary: compress the machine explanation into one
#    human sentence + an approval recommendation, shown at the top of each
#    review card ──
_PLAIN_HEAD = {
    "taskkill": "force-kill a process", "kill": "kill a process", "tasklist": "list running processes",
    "ps": "list running processes", "wmic": "query system information",
    "reg": "read/write the registry", "powershell": "run a PowerShell command",
    "cmd": "run a command via cmd", "bash": "run a command via bash", "sh": "run a command via the shell",
    "schtasks": "manage scheduled tasks", "sc": "manage system services", "net": "manage network/users",
    "curl": "make an HTTP request", "wget": "download a file from the network", "scp": "copy files to a remote machine",
    "ssh": "connect to a remote machine", "netstat": "check network port usage",
    "pip": "install/manage Python packages", "npm": "install/manage Node packages",
    "od": "inspect a file's raw bytes", "xxd": "inspect a file's raw bytes",
    "tar": "pack/unpack files", "unzip": "unzip an archive", "zip": "compress files",
    "mkdir": "create a directory", "touch": "create an empty file",
    "cp": "copy files", "mv": "move/rename files", "rm": "delete files", "del": "delete files",
    "sleep": "wait", "cd": "change directory", "echo": "print text",
}
# inconsequential lead-in segments, skipped when synthesizing the summary
_PLAIN_SKIP = {"cd", "echo", "head", "tail", "wc", "sort", "cat", "ls", "grep", "findstr"}


def _plain_verb(seg):
    """Compress one segment into a verb phrase."""
    head, rest = _seg_head(seg)
    if head is None:
        return None
    if head == "sleep":
        return "wait"
    if head in ("python", "python3", "node"):
        r = " ".join(rest)
        if "<<" in seg:
            return "run a multi-line %s script (see raw command)" % ("Python" if head.startswith("py") else "JS")
        if r.startswith("-c") or r.startswith('"-c"'):
            return "run a piece of inline %s code (see raw command)" % ("Python" if head.startswith("py") else "JS")
        return "run a %s program" % ("Python" if head.startswith("py") else "Node")
    if seg.startswith("for ") or seg.startswith("for\t"):
        return "loop over a batch of files"
    if head in ("do", "done", "then", "fi", "if"):
        return None
    if head in ("bash", "sh") and rest and rest[0].endswith(".sh"):
        return "run the shell script %s" % rest[0]
    if head == "cmd" and rest and (rest[0].endswith("/c") or rest[0].endswith("//c")):
        bat = next((t for t in rest[1:] if t.lower().endswith((".bat", ".cmd"))), None)
        return ("run the batch file %s" % bat) if bat else "run a command via cmd (see raw command)"
    if head == "powershell" and any(t in ("-Command", "-c", "-File") for t in rest):
        return "run a PowerShell command (see raw command)"
    if head in _PLAIN_HEAD:
        v = _PLAIN_HEAD[head]
        if head == "reg":
            v = "query the registry (read-only)" if " query" in seg else "write to the registry"
        if head == "taskkill":
            m = re.search(r"P[Ii]D\s*[/=]?\s*(\d+)", seg)
            v = "force-kill a process" + (" (PID %s)" % m.group(1) if m else "")
        return v
    desc, _cat = _explain_segment(seg)
    if "not in the knowledge base" in desc:
        return "run a command called `%s`" % (seg.split()[0] if seg.split() else "?")
    return re.sub(r"\([^)]*\)", "", desc) or head


def plain(cmd):
    """Plain-language summary: one sentence on what the command does, plus an
    approval recommendation. Never raises.

    Returns {"headline": str, "advice": str, "tier": str} where tier is one of
    safe / normal / confirm / verify — the console batch-approves everything
    except "verify"."""
    try:
        segs = split_segments(cmd)
        steps = []
        for seg in segs:
            head, _ = _seg_head(seg)
            if head in _PLAIN_SKIP:
                continue
            v = _plain_verb(seg)
            if v and v not in steps:
                steps.append(v)
        ex = explain(cmd)
        risk = ex.get("risk", "high")
        if not steps:
            headline = "Could not parse this command — review the raw command verbatim"
        elif len(steps) == 1:
            headline = "This command will: " + steps[0]
        else:
            headline = "This command runs %d steps: %s" % (len(steps), " → ".join(steps))
        if "$(" in cmd or "`" in cmd:
            headline += " (contains command substitution — what runs is only decided at runtime)"
        if risk == "low":
            advice, tier = ("Read-only operation, changes nothing → safe to approve", "safe")
        elif risk == "medium":
            advice, tier = ("Routine operation (changes files / runs code / installs packages / "
                            "reaches a local service) → generally fine to approve", "normal")
        elif "system-level" in "".join(ex.get("lines", [])):
            advice, tier = ("System-level operation (processes / registry / services / scheduled tasks) "
                            "→ confirm it matches the current task before approving", "confirm")
        else:
            advice, tier = ("Contains commands or structures outside the knowledge base "
                            "→ review the raw command verbatim", "verify")
        return {"headline": headline, "advice": advice, "tier": tier}
    except Exception as e:
        return {"headline": "explain failed: %s" % e, "advice": "review manually",
                "tier": "verify"}


# ── Auto-allow: every segment's category is in the auto-allow set (and there
#    is no command substitution) → the hook allows it outright. SYS and UNK
#    still go to the queue; DEL/NET_OUT were already hard-denied before this. ──
_REDIRECT_RE = re.compile(r"\d*>>?\s*([^\s;|&]+)")
_NULL_TARGETS = ("/dev/null", "nul", "&1")  # discard output / merge streams, no real file write


def _only_null_redirects(cmd):
    """Every redirect only targets /dev/null/NUL or merges streams (2>&1)
    → no write capability."""
    for m in _REDIRECT_RE.finditer(cmd):
        tgt = m.group(1).strip("'\"").lower()
        if tgt not in _NULL_TARGETS:
            return False
    return True


def auto_allow(cmd):
    """True if every segment of the command falls into an auto-allow category
    and there is no command substitution."""
    try:
        if "$(" in cmd or "`" in cmd:
            return False  # command substitution: what runs is decided at runtime — human review
        segs = split_segments(cmd)
        if not segs:
            return False
        for seg in segs:
            head, rest = _seg_head(seg)
            if head is None:
                return False
            desc, cat = _explain_segment(seg)
            if cat not in POLICY["auto_allow_categories"]:
                return False
        return True
    except Exception:
        return False


def deny_reason(cmd):
    """Hard policy: deletions are always denied; outbound data transfer is
    always denied. Returns None, or a reason string (shown to the model in the
    PreToolUse deny decision)."""
    try:
        reasons = []
        for seg in split_segments(cmd):
            desc, cat = _explain_segment(seg)
            if cat in POLICY["deny_categories"]:
                reasons.append("`%s` %s (%s)" % (seg[:80], CAT[cat][1], desc))
        if not reasons:
            return None
        return "; ".join(reasons) + ". " + POLICY["deny_note"]
    except Exception:
        return None


def rule_boundary(rule):
    """Explain the boundary of what approving a rule allows."""
    try:
        if rule.startswith("Bash(") and rule.endswith(")"):
            inner = rule[5:-1]
            if inner.endswith(":*"):
                pre = inner[:-2]
                return ("Prefix rule: from now on, any single-segment command starting with `%s` passes "
                        "automatically. Compound commands (with && ; |) are still checked segment by "
                        "segment, so variants that append other commands will be caught and queued." % pre)
            return ("Exact rule: only this exact command passes; any variant (even one extra argument) "
                    "still requires approval.")
        return ""
    except Exception:
        return ""


# ── Rule suggestions ──
def suggest_rule(cmd):
    """Generate a suggested rule for a queued command: prefix rules for safe
    commands, exact match for everything else."""
    segs = split_segments(cmd)
    if len(segs) != 1:
        return "Bash(" + cmd + ")"
    tok = cmd.split()
    if len(tok) == 1 and tok[0] in SAFE_SINGLE:
        return "Bash(%s:*)" % tok[0]
    if len(tok) >= 2 and " ".join(tok[:2]) in SAFE_PAIR:
        return "Bash(%s:*)" % " ".join(tok[:2])
    m = LOCAL_CURL_RE.match(cmd)
    if m:
        return "Bash(%s:*)" % m.group(0)
    return "Bash(" + cmd + ")"


# ── Approval actions ──
def _valid_rule(rule):
    return (rule.startswith("Bash(") and rule.endswith(")")
            and len(rule) > 6 and "\n" not in rule and "\r" not in rule)


def approve(key, rule):
    """Approve: write the rule into the user settings whitelist and remove the
    item from the queue. Returns (ok, message)."""
    rule = (rule or "").strip()
    if not _valid_rule(rule):
        return False, "Rule format must be Bash(command) or Bash(prefix:*)"
    item = None
    for it in load_pending():
        if it.get("key") == key:
            item = it
            break
    if item is None:
        return False, "This command is no longer in the queue"

    settings = _user_settings()
    with _lock(settings):
        s = _load_json(settings, {})
        allow = ((s.get("permissions") or {}).get("allow"))
        if not isinstance(allow, list):
            s.setdefault("permissions", {})["allow"] = allow = []
        if rule in allow:
            msg = "Rule already in the whitelist: " + rule
        else:
            try:
                os.makedirs(BACKUP_DIR, exist_ok=True)
                bak = os.path.join(
                    BACKUP_DIR, "settings-" + time.strftime("%Y%m%d-%H%M%S") + ".json")
                with open(settings, encoding="utf-8") as f:
                    with open(bak, "w", encoding="utf-8") as g:
                        g.write(f.read())
                allow.append(rule)
                _save_json_atomic(settings, s)
                msg = "Added to whitelist: " + rule
            except Exception as e:
                return False, "Failed to write settings.json: %s" % e

    _remove_pending(key)
    _append_history({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                     "action": "approve", "cmd": item.get("cmd", ""),
                     "rule": rule})
    return True, msg


def reject(key):
    """Dismiss: remove from the queue (if the command reappears, it re-queues)."""
    removed = _remove_pending(key)
    if removed:
        _append_history({"ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                         "action": "reject", "cmd": key, "rule": ""})
    return removed > 0, ("Removed from the queue" if removed
                         else "This command is not in the queue")
