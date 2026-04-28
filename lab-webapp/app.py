"""Intentionally vulnerable web app for lab chain scenarios.

Exposes:
  GET /              — index, lists endpoints
  GET /healthz       — liveness
  GET /fetch?url=    — SSRF (no allowlist, accepts file://, http://, gopher://)
  GET /ping?host=    — command injection via shell=True
  GET /lookup?id=    — reflected/template-style SQL-like passthrough (returns query)
  GET /env           — leaks process environment (intentional info disclosure)

Deliberately unsafe — for the hakuna-lab compose only.
"""

import os
import subprocess
import urllib.request

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/")
def index():
    return (
        "lab-webapp — endpoints: /healthz /fetch?url= /ping?host= /lookup?id= /env\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.route("/healthz")
def health():
    return "ok"


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return "url required", 400
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "lab-webapp/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            body = r.read(16384)
        return body, 200, {"Content-Type": r.headers.get("Content-Type", "text/plain")}
    except Exception as exc:
        return f"error: {exc}", 500


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return "host required", 400
    proc = subprocess.run(
        f"ping -c 1 -W 2 {host}",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.stdout + proc.stderr, 200, {"Content-Type": "text/plain"}


@app.route("/lookup")
def lookup():
    item_id = request.args.get("id", "")
    return jsonify({"echo": item_id, "note": "reflective endpoint, no validation"})


@app.route("/env")
def env():
    return jsonify(dict(os.environ))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
