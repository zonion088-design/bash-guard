#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bash-guard review console — a local web UI for the pending-approval queue.

Endpoints:
  GET  /                      single-page review UI (web/index.html)
  GET  /api/bash/pending      queued commands + current Bash whitelist
  POST /api/bash/approve      {key, rule}  approve and write ~/.claude/settings.json
  POST /api/bash/approve_many {keys}       batch-approve (each with a backup)
  POST /api/bash/reject       {key}        dismiss from the queue

Run:  python console.py   →  http://127.0.0.1:8642
Port configurable via the BASH_GUARD_PORT environment variable.
Binds to 127.0.0.1 only — this is a local tool, never expose it.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guard  # noqa: E402

PORT = int(os.environ.get("BASH_GUARD_PORT", "8642"))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # keep the console process quiet

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            try:
                with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except FileNotFoundError:
                self._send(404, {"error": "web/index.html not found"})
        elif self.path == "/api/bash/pending":
            items = []
            for it in guard.load_pending():
                it = dict(it)
                it["suggest"] = guard.suggest_rule(it.get("cmd", ""))
                it["explain"] = guard.explain(it.get("cmd", ""))
                it["plain"] = guard.plain(it.get("cmd", ""))
                it["boundary"] = guard.rule_boundary(it["suggest"])
                items.append(it)
            self._send(200, {"pending": items,
                             "rules": guard.bash_rules(guard._home())})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            self._send(400, {"error": "request body is not valid JSON"})
            return
        if self.path == "/api/bash/approve":
            try:
                ok, msg = guard.approve(payload.get("key", ""),
                                        payload.get("rule", ""))
            except Exception as e:
                ok, msg = False, "backend error: %s" % e
            self._send(200, {"ok": ok, "message": msg})
        elif self.path == "/api/bash/approve_many":
            # batch approve: {keys: [key, ...]} — the frontend already filtered
            # out the "verify" tier
            done, failed = 0, []
            for k in payload.get("keys", []):
                try:
                    item = next((it for it in guard.load_pending()
                                 if it.get("key") == k), None)
                    if item is None:
                        continue
                    cmd = item.get("cmd", "")
                    rule = guard.suggest_rule(cmd)
                    if not guard._valid_rule(rule):
                        rule = "Bash(" + k + ")"  # heredocs etc. contain newlines: use the normalized key
                    ok, _msg = guard.approve(k, rule)
                    done += 1 if ok else 0
                    if not ok:
                        failed.append(k[:60])
                except Exception as e:
                    failed.append("%s (%s)" % (k[:40], e))
            self._send(200, {"ok": len(failed) == 0,
                             "message": "approved %d item(s)%s" % (
                                 done, "" if not failed else ", failed: " + "; ".join(failed[:3]))})
        elif self.path == "/api/bash/reject":
            try:
                ok, msg = guard.reject(payload.get("key", ""))
            except Exception as e:
                ok, msg = False, "backend error: %s" % e
            self._send(200, {"ok": ok, "message": msg})
        else:
            self._send(404, {"error": "not found"})


def serve(port=PORT):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("bash-guard console listening on http://127.0.0.1:%d" % port)
    httpd.serve_forever()


if __name__ == "__main__":
    serve()
