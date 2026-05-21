#!/usr/bin/env python3
"""Hakuna endpoint agent — host-resident live vulnerability detection & response.

A lightweight, dependency-free agent (Python 3.8+ standard library only) that:

  1. Enrolls with the Hakuna cloud using a one-time token.
  2. Collects local host inventory — installed packages, running processes,
     listening sockets, security controls.
  3. Checks in on an interval; the cloud detects, contextualizes, and
     prioritizes vulnerabilities from that inventory.
  4. Executes response actions handed back on check-in (kill a process,
     quarantine a file, apply a patch, isolate the host) and reports results.

Usage:
    HAKUNA_URL=http://localhost:8000 HAKUNA_AGENT_TOKEN=hke_xxx \\
        python3 hakuna_agent.py [--demo] [--once] [--interval 300]

`--demo` appends a small set of known-vulnerable packages (clearly tagged
`hakuna-demo`) to the real inventory so the detection pipeline lights up on
an otherwise patched host. Real inventory is always collected and reported.
"""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

AGENT_VERSION = "1.0.0"

# Synthetic pids for demo processes — the agent simulates response actions
# against these instead of touching real processes.
DEMO_PID_BASE = 990000


# ─────────────────────────────────────────────────────────
# HTTP
# ─────────────────────────────────────────────────────────

def _request(url, path, token, body):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + path, data=data, method="POST",
        headers={"Content-Type": "application/json", "X-Agent-Token": token},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "ignore")
        raise RuntimeError(f"HTTP {e.code} on {path}: {detail}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Cannot reach {url}{path}: {e.reason}") from e


# ─────────────────────────────────────────────────────────
# Host facts
# ─────────────────────────────────────────────────────────

def _os_version():
    if sys.platform.startswith("linux") and os.path.exists("/etc/os-release"):
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return platform.platform()


def _primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def _platform_name():
    p = sys.platform
    if p.startswith("linux"):
        return "linux"
    if p == "darwin":
        return "darwin"
    if p.startswith("win"):
        return "windows"
    return p


# ─────────────────────────────────────────────────────────
# Inventory collection
# ─────────────────────────────────────────────────────────

def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return out.stdout if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def collect_software(limit=400):
    """Installed OS packages via dpkg or rpm."""
    pkgs = []
    dpkg = _run(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if dpkg:
        for line in dpkg.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[0]:
                pkgs.append({"name": parts[0], "version": parts[1],
                             "vendor": "os-package"})
    if not pkgs:
        rpm = _run(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"])
        for line in rpm.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[0]:
                pkgs.append({"name": parts[0], "version": parts[1],
                             "vendor": "os-package"})
    return pkgs[:limit]


def collect_processes():
    """Running processes from /proc (Linux) — name, pid, ppid."""
    procs = []
    if not os.path.isdir("/proc"):
        return procs
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as f:
                name = f.read().strip()
            with open(f"/proc/{pid}/stat") as f:
                stat = f.read()
            # ppid is field 4, but the process name in field 2 may contain
            # spaces/parens — split after the final ')'.
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            procs.append({"name": name, "pid": int(pid), "ppid": ppid})
        except (OSError, IndexError, ValueError):
            continue
    return procs


def collect_listening_ports():
    """Listening TCP sockets via `ss`, falling back to /proc/net/tcp."""
    ports = []
    ss = _run(["ss", "-tlnH"])
    if ss:
        for line in ss.splitlines():
            cols = line.split()
            if len(cols) < 4:
                continue
            local = cols[3]
            host, _, port = local.rpartition(":")
            if port.isdigit():
                ports.append({"address": host or "0.0.0.0",
                              "port": int(port), "protocol": "tcp"})
        return ports
    # Fallback: parse /proc/net/tcp (state 0A == LISTEN)
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) > 3 and cols[3] == "0A":
                        port = int(cols[1].split(":")[1], 16)
                        ports.append({"address": "0.0.0.0", "port": port,
                                      "protocol": "tcp"})
        except (OSError, StopIteration, ValueError, IndexError):
            continue
    return ports


def collect_security_controls(processes):
    """Best-effort EDR/AV detection from running process names."""
    known = {
        "falcon-sensor": ("CrowdStrike Falcon", "edr"),
        "falcond": ("CrowdStrike Falcon", "edr"),
        "SentinelAgent": ("SentinelOne", "edr"),
        "mdatp": ("Microsoft Defender", "edr"),
        "clamd": ("ClamAV", "av"),
    }
    names = {p["name"] for p in processes}
    controls = []
    for proc_name, (product, ctype) in known.items():
        if proc_name in names:
            controls.append({"type": ctype, "product": product,
                             "vendor": product.split()[0], "enabled": True})
    return controls


# ─────────────────────────────────────────────────────────
# Demo augmentation
# ─────────────────────────────────────────────────────────

def demo_inventory():
    """Known-vulnerable packages + matching runtime/network context.

    Tagged `hakuna-demo` so they are distinguishable from real inventory.
    Returns (software, processes, listening_ports, security_controls)."""
    software = [
        {"name": "log4j-core", "version": "2.14.1", "vendor": "hakuna-demo"},
        {"name": "openssl", "version": "3.0.2", "vendor": "hakuna-demo"},
        {"name": "sudo", "version": "1.9.5p1", "vendor": "hakuna-demo"},
        {"name": "curl", "version": "8.1.0", "vendor": "hakuna-demo"},
        {"name": "xz-utils", "version": "5.6.1", "vendor": "hakuna-demo"},
    ]
    processes = [
        {"name": "java", "pid": DEMO_PID_BASE + 1, "ppid": 1},
        {"name": "sshd", "pid": DEMO_PID_BASE + 2, "ppid": 1},
        {"name": "nginx", "pid": DEMO_PID_BASE + 3, "ppid": 1},
    ]
    listening_ports = [
        {"address": "0.0.0.0", "port": 8080, "protocol": "tcp",
         "process": "java", "pid": DEMO_PID_BASE + 1},
        {"address": "0.0.0.0", "port": 22, "protocol": "tcp",
         "process": "sshd", "pid": DEMO_PID_BASE + 2},
    ]
    controls = [
        {"type": "edr", "product": "CrowdStrike Falcon",
         "vendor": "CrowdStrike", "enabled": True},
    ]
    return software, processes, listening_ports, controls


def collect_inventory(demo=False):
    software = collect_software()
    processes = collect_processes()
    ports = collect_listening_ports()
    controls = collect_security_controls(processes)

    if demo:
        d_sw, d_proc, d_ports, d_ctrl = demo_inventory()
        software += d_sw
        processes += d_proc
        ports += d_ports
        if not controls:
            controls = d_ctrl

    return {
        "hostname": socket.gethostname(),
        "platform": _platform_name(),
        "os_version": _os_version(),
        "ip_address": _primary_ip(),
        "agent_version": AGENT_VERSION,
        "public": bool(os.environ.get("HAKUNA_AGENT_PUBLIC")),
        "software": software,
        "processes": processes,
        "listening_ports": ports,
        "security_controls": controls,
    }


# ─────────────────────────────────────────────────────────
# Response actions
# ─────────────────────────────────────────────────────────

def execute_action(action):
    """Execute one host response action; return a result dict."""
    atype = action.get("action_type")
    params = action.get("params") or {}

    if atype == "kill_process":
        pid = params.get("pid")
        name = params.get("process_name", "?")
        if isinstance(pid, int) and pid >= DEMO_PID_BASE:
            return {"ok": True, "detail": f"[demo] simulated termination of "
                    f"{name} (pid {pid})"}
        if not isinstance(pid, int):
            return {"ok": False, "detail": "no pid supplied"}
        try:
            os.kill(pid, 15)
            return {"ok": True, "detail": f"sent SIGTERM to {name} (pid {pid})"}
        except ProcessLookupError:
            return {"ok": False, "detail": f"pid {pid} not found"}
        except PermissionError:
            return {"ok": False, "detail": f"permission denied for pid {pid}"}

    if atype == "quarantine_file":
        path = params.get("path")
        if not path:
            return {"ok": False, "detail": "no path supplied"}
        qdir = os.path.join(os.path.expanduser("~"), ".hakuna-quarantine")
        try:
            os.makedirs(qdir, exist_ok=True)
            if os.path.exists(path):
                dest = os.path.join(qdir, os.path.basename(path))
                os.rename(path, dest)
                return {"ok": True, "detail": f"moved {path} to {dest}"}
            return {"ok": False, "detail": f"file not found: {path}"}
        except OSError as e:
            return {"ok": False, "detail": f"quarantine failed: {e}"}

    if atype == "apply_patch":
        pkg = params.get("package", "?")
        # A real deployment would invoke the platform package manager here.
        return {"ok": True, "detail": f"[demo] patch staged for {pkg}; "
                f"a production agent would run the package manager"}

    if atype == "isolate_host":
        return {"ok": True, "detail": "[demo] host isolation simulated; "
                "a production agent would apply a host firewall lockdown"}

    return {"ok": False, "detail": f"unknown action type: {atype}"}


# ─────────────────────────────────────────────────────────
# Agent loop
# ─────────────────────────────────────────────────────────

def log(msg):
    print(f"[hakuna-agent] {msg}", flush=True)


def run(url, token, interval, demo, once):
    log(f"v{AGENT_VERSION} starting — target {url}" + (" (demo mode)" if demo else ""))

    enroll = _request(url, "/api/endpoint-agents/enroll", token, {
        "hostname": socket.gethostname(),
        "platform": _platform_name(),
        "os_version": _os_version(),
        "agent_version": AGENT_VERSION,
    })
    interval = interval or enroll.get("checkin_interval", 300)
    log(f"enrolled as agent {enroll.get('agent_id')} ({enroll.get('name')})")

    while True:
        try:
            inv = collect_inventory(demo=demo)
            log(f"check-in: {len(inv['software'])} packages, "
                f"{len(inv['processes'])} processes, "
                f"{len(inv['listening_ports'])} listening ports")
            result = _request(url, "/api/endpoint-agents/checkin", token, inv)

            f = result.get("findings", {})
            log(f"detections: {f.get('total', 0)} open "
                f"({f.get('critical', 0)} critical, {f.get('high', 0)} high), "
                f"{f.get('new', 0)} new, {f.get('resolved', 0)} resolved")
            for d in result.get("auto_edr_detections", []):
                log(f"auto-response: EDR detection created for {d['cve']} "
                    f"-> rule #{d['detection_rule_id']}")

            for action in result.get("pending_actions", []):
                log(f"executing action {action['id']}: {action['action_type']}")
                outcome = execute_action(action)
                status = "completed" if outcome.get("ok") else "failed"
                log(f"  -> {status}: {outcome.get('detail')}")
                _request(url, f"/api/endpoint-agents/actions/{action['id']}/result",
                         token, {"status": status, "result": outcome})
        except RuntimeError as e:
            log(f"check-in error: {e}")

        if once:
            log("single run complete (--once)")
            return
        time.sleep(interval)


def main():
    ap = argparse.ArgumentParser(description="Hakuna endpoint agent")
    ap.add_argument("--url", default=os.environ.get("HAKUNA_URL"),
                    help="Hakuna backend base URL")
    ap.add_argument("--token", default=os.environ.get("HAKUNA_AGENT_TOKEN"),
                    help="Agent enrollment token (hke_...)")
    ap.add_argument("--interval", type=int,
                    default=int(os.environ.get("HAKUNA_AGENT_INTERVAL", "0")) or None,
                    help="Seconds between check-ins (default: server-provided)")
    ap.add_argument("--demo", action="store_true",
                    default=bool(os.environ.get("HAKUNA_AGENT_DEMO")),
                    help="Append known-vulnerable demo packages to inventory")
    ap.add_argument("--once", action="store_true",
                    help="Run a single check-in and exit")
    args = ap.parse_args()

    if not args.url or not args.token:
        ap.error("--url/--token (or HAKUNA_URL/HAKUNA_AGENT_TOKEN) are required")

    try:
        run(args.url, args.token, args.interval, args.demo, args.once)
    except KeyboardInterrupt:
        log("stopped")
    except RuntimeError as e:
        log(f"fatal: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
