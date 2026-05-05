"""Intentionally vulnerable web app for hakuna-lab chain scenarios.

Original chains (kept):
  GET  /fetch?url=        SSRF, no allowlist             (Chain C)
  GET  /ping?host=        cmd injection via shell=True   (Chain E)
  GET  /lookup?id=        reflective passthrough
  GET  /env               leaks process environment

Advanced surfaces:
  GET  /log               Log4Shell-style: parses ${jndi:ldap://...} in UA
  POST /login_v2          Mongo NoSQL injection (raw JSON → find_one)
  GET  /auth/token        Issues HS256 JWT with weak/leaked secret
  GET  /admin             Accepts forged tokens (alg=none + signature off)
  GET  /preview?msg=      Jinja2 SSTI sink (render_template_string)
  POST /signup            Mass-assignment: JSON body splatted into user dict
  GET  /fetch_v2?url=     "Secured" SSRF — DNS rebinding TOCTOU bypass
  POST /reset             Cache poisoning via X-Forwarded-Host
  GET  /items?id=         SQL injection against lab-mysql (Chain G surface)

Deliberately unsafe — hakuna-lab compose only.
"""

import os
import socket
import subprocess
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

import jwt as pyjwt
import pymysql
from flask import Flask, jsonify, render_template_string, request
from pymongo import MongoClient

app = Flask(__name__)

# Same string lives in mongo://corp.secrets and mysql.secrets — cred reuse.
JWT_SECRET = "Summer2024!"

# In-memory user store for /signup (mass-assignment demo).
USERS: dict = {}


def _mongo():
    return MongoClient("mongodb://mongo:27017", serverSelectionTimeoutMS=2000)


def _mysql():
    return pymysql.connect(
        host="mysql", user="app", password="app123",
        database="appdb", connect_timeout=3, autocommit=True,
    )


@app.route("/")
def index():
    return (
        "lab-webapp v2 — /healthz /fetch /ping /lookup /env /log /login_v2 "
        "/auth/token /admin /preview /signup /fetch_v2 /reset /items\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.route("/healthz")
def health():
    return "ok"


# --- Original Chain C / E surfaces ------------------------------------------

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
        shell=True, capture_output=True, text=True, timeout=10,
    )
    return proc.stdout + proc.stderr, 200, {"Content-Type": "text/plain"}


@app.route("/lookup")
def lookup():
    return jsonify({"echo": request.args.get("id", ""), "note": "reflective"})


@app.route("/env")
def env():
    return jsonify(dict(os.environ))


# --- Advanced #1 — Log4Shell-style JNDI in logged headers --------------------

def _expand_jndi(value: str) -> None:
    """Mimic a vulnerable log shim. Real log4j fetches the LDAP referral and
    instantiates a Java class; here we just open the LDAP socket so the lookup
    is observable out-of-band against the lab's `ldap` service."""
    if "${jndi:" not in value:
        return
    inner = value.split("${jndi:", 1)[1].split("}", 1)[0]
    if not inner.startswith("ldap://"):
        return
    target = inner[len("ldap://"):]
    host, _, _ = target.partition("/")
    host_only, _, port = host.partition(":")
    try:
        sock = socket.create_connection((host_only, int(port or 389)), timeout=2)
        # Minimal LDAP BindRequest — enough to leave a server-side log entry.
        sock.sendall(b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00")
        sock.recv(1024)
        sock.close()
    except Exception:
        pass


@app.route("/log")
def log_endpoint():
    ua = request.headers.get("User-Agent", "")
    _expand_jndi(ua)
    return jsonify({"logged": ua})


# --- Advanced #3 — Mongo NoSQL injection -----------------------------------

@app.route("/login_v2", methods=["POST"])
def login_v2():
    """Naively unmarshalls JSON straight into a Mongo query.

    Auth bypass: {"username":"admin","password":{"$gt":""}}
    """
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return "bad json", 400
    try:
        user = _mongo().corp.users.find_one(body)
    except Exception as exc:
        return f"mongo error: {exc}", 500
    if user:
        user.pop("_id", None)
        return jsonify({"ok": True, "user": user})
    return jsonify({"ok": False}), 401


# --- Advanced #4 — JWT weak secret + alg-confusion ------------------------

@app.route("/auth/token")
def auth_token():
    user = request.args.get("user", "guest")
    payload = {
        "sub": user,
        "is_admin": False,
        "exp": datetime.utcnow() + timedelta(hours=1),
    }
    return jsonify({"token": pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")})


@app.route("/admin")
def admin():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return "missing token", 401
    token = auth.split(" ", 1)[1]
    try:
        # alg-confusion: signature verification is off and "none" accepted.
        claims = pyjwt.decode(
            token, JWT_SECRET,
            algorithms=["HS256", "none"],
            options={"verify_signature": False},
        )
    except Exception as exc:
        return f"bad token: {exc}", 401
    if not claims.get("is_admin"):
        return "not admin", 403
    return jsonify({"ok": True, "flag": "ADMIN-AREA-REACHED"})


# --- Advanced #5 — Jinja2 SSTI ---------------------------------------------

@app.route("/preview")
def preview():
    msg = request.args.get("msg", "hello")
    # Concatenation into render_template_string — classic SSTI sink.
    return render_template_string("<h1>Preview: " + msg + "</h1>")


# --- Advanced #6 — Mass-assignment privilege escalation ---------------------

@app.route("/signup", methods=["POST"])
def signup():
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return "bad json", 400
    email = body.get("email")
    if not email:
        return "email required", 400
    USERS[email] = dict(body)  # is_admin=true sneaks straight through
    return jsonify({"ok": True, "user": USERS[email]})


# --- Advanced #7 — DNS-rebinding SSRF allowlist bypass ----------------------

_PRIVATE_PREFIXES = ("10.", "127.", "169.254.", "172.16.", "192.168.")


@app.route("/fetch_v2")
def fetch_v2():
    """"Secure" SSRF guard: resolves host, rejects private IPs, then re-fetches
    by hostname. The double resolution is exploitable via DNS rebinding."""
    url = request.args.get("url", "")
    if not url:
        return "url required", 400
    parsed = urllib.parse.urlparse(url)
    if not parsed.hostname:
        return "bad url", 400
    try:
        ip = socket.gethostbyname(parsed.hostname)
    except Exception as exc:
        return f"resolve failed: {exc}", 400
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return f"refused: {ip} is private", 403
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read(16384), 200, {"Content-Type": r.headers.get("Content-Type", "text/plain")}
    except Exception as exc:
        return f"error: {exc}", 500


# --- Advanced #10 — Cache poisoning via X-Forwarded-Host -------------------

@app.route("/reset", methods=["POST"])
def reset():
    try:
        body = request.get_json(force=True) or {}
    except Exception:
        return "bad json", 400
    email = body.get("email", "")
    # Trusts X-Forwarded-Host blindly — cache key uses path+email but body
    # contains attacker-controlled host, poisoning shared caches.
    host = request.headers.get("X-Forwarded-Host") or request.host
    link = f"https://{host}/reset?token=ABC123&email={email}"
    return jsonify({"sent": True, "link": link})


# --- Chain G surface — SQLi against lab-mysql ------------------------------

@app.route("/items")
def items():
    item_id = request.args.get("id", "1")
    conn = _mysql()
    try:
        with conn.cursor() as cur:
            # f-string interpolation — textbook SQL injection.
            cur.execute(f"SELECT id, email, password FROM users WHERE id = {item_id}")
            rows = cur.fetchall()
        return jsonify(rows)
    except Exception as exc:
        return f"sql error: {exc}", 500
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
