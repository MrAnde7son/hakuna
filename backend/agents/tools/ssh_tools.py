"""SSH tool palette for the Linux Audit ReAct agent.

Three primitives:

  - ``ssh_run_command(command)`` — runs an arbitrary shell command. The
    backend classifier categorizes the command as read-only / write /
    network / privileged / unknown. Read-only auto-executes; everything
    else raises ``NeedsApproval`` so the user can sign off on each
    write/network/privileged action before the relay touches the host.
  - ``ssh_read_file(path)`` — reads any file the SSH user can access
    (subject to a 256 KB cap on the relay).
  - ``ssh_list_directory(path, all_files?)`` — directory listing.

The mission prompts carry the audit checklists (which commands to run
for kernel hardening, sshd config, sudoers, etc.).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import re
import shlex

from models.models import Asset
from agents.agent_tools import agent_tool, NeedsApproval
from agents.audit_registry import MissionTemplate, ProtocolAudit, register_audit
from agents.tools._target_utils import resolve_asset_target
from services.credential_manager import load_credentials
from services.relay_broker import get_relay_broker

logger = logging.getLogger(__name__)


_SSH_TIMEOUT_S = 60


# ── Dispatch helper ───────────────────────────────────────────────────


def _run_async(coro):
    # In-process RelayBroker futures live on the FastAPI main loop. If we
    # spin up a fresh loop here (asyncio.run from a worker thread), the
    # broker's `future.set_result` from the WS handler — running on the
    # main loop — never wakes our `wait_for`, and the caller hangs until
    # TASK_TIMEOUT (300s). Route to the main loop when one was captured.
    from core.event_loop import get_main_loop, is_on_main_loop
    main_loop = get_main_loop()
    if main_loop is not None and main_loop.is_running() and not is_on_main_loop():
        fut = asyncio.run_coroutine_threadsafe(coro, main_loop)
        return fut.result(timeout=_SSH_TIMEOUT_S + 15)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=_SSH_TIMEOUT_S + 15)
    return asyncio.run(coro)


async def _dispatch_ssh(
    db,
    org_id: int,
    asset_id: int,
    op: str,
    op_params: dict,
    relay_agent_id: str | None,
    credential_id: str | None,
) -> tuple[Asset, dict]:
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise ValueError(f"asset {asset_id} not found")
    target, target_port = resolve_asset_target(asset)
    if not target:
        raise ValueError(f"asset {asset_id} has no hostname or ip")
    if not relay_agent_id:
        raise ValueError("relay_agent_id missing from audit context")
    if not credential_id:
        raise ValueError("credential_id missing from audit context")

    broker = get_relay_broker()
    if not broker.is_connected(relay_agent_id):
        raise ConnectionError(f"relay agent {relay_agent_id} is not connected")

    raw_creds = await load_credentials(db, credential_id, org_id)
    if not raw_creds or not raw_creds.get("username"):
        raise ValueError(f"credential {credential_id} missing or has no username")

    ssh_creds = {
        "username": raw_creds.get("username", ""),
        "password": raw_creds.get("password", "") or "",
        "private_key": raw_creds.get("private_key", "") or "",
        "private_key_passphrase": raw_creds.get("private_key_passphrase", "") or "",
        "port": target_port or raw_creds.get("port") or 22,
    }

    result = await broker.send_task(
        agent_id=relay_agent_id,
        method="ssh_query",
        config={"target": target},
        credentials=ssh_creds,
        params={"op": op, "op_params": op_params, "timeout_s": _SSH_TIMEOUT_S},
    )
    return asset, (result or {})


def _ctx(params: dict) -> tuple[str | None, str | None]:
    relay = params.get("_relay_agent_id") or params.get("relay_agent_id")
    cred = params.get("_credential_id") or params.get("credential_id")
    return relay, cred


# ── Command classifier ───────────────────────────────────────────────
#
# Goal: decide whether a shell command is safely read-only or should
# require user approval. Any command we can't confidently call read-only
# is routed through NeedsApproval — false positives waste a click; false
# negatives hand the agent a write/network primitive without review.
#
# The classifier is conservative: when in doubt, it asks for approval.
# It is NOT a sandbox — the relay still runs whatever the user approves.

_READ_ONLY_HEADS = {
    # File / text inspection
    "cat", "head", "tail", "less", "more", "view", "bat",
    "grep", "egrep", "fgrep", "rg", "ack", "zgrep", "zcat", "zless",
    "wc", "sort", "uniq", "cut", "tr", "tac", "rev", "fold", "fmt",
    "xxd", "od", "hexdump", "strings", "file",
    "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum", "cksum",
    "cmp", "diff", "comm", "join", "paste",
    "awk", "gawk", "nawk",
    # Filesystem inspection
    "ls", "dir", "stat", "readlink", "realpath", "dirname", "basename",
    "pwd", "tree", "lsattr", "getfacl", "find", "locate", "which", "whereis",
    "df", "du", "lsblk", "mount", "lsof", "fuser",
    # System info
    "uname", "hostname", "hostnamectl", "uptime", "free", "vmstat", "iostat",
    "lscpu", "lspci", "lsusb", "lshw", "dmidecode", "lsmod", "modinfo",
    "getconf", "ulimit",
    # Process / service
    "ps", "pgrep", "pidof", "top", "htop", "btop", "iotop", "pstree",
    "systemctl", "service", "rc-status", "initctl", "chkconfig",
    "journalctl", "dmesg", "logger",  # journalctl -f is interactive but bounded by relay timeout
    # Identity
    "id", "whoami", "who", "w", "last", "lastlog", "groups", "getent",
    # Networking (read-only inspection)
    "ip", "ifconfig", "route", "ss", "netstat", "arp",
    "nslookup", "host", "dig", "drill", "getent",
    # Firewall (read paths only — modifying ones go through privileged classifier)
    "iptables-save", "ip6tables-save", "nft", "ufw", "firewall-cmd",
    # MAC / SELinux / AppArmor inspection
    "getenforce", "sestatus", "semanage", "seinfo", "aa-status", "aa-enabled",
    # Audit
    "auditctl", "ausearch", "aureport",
    # Cron
    "crontab",
    # Package managers (query subcommands handled by deeper inspection below)
    "dpkg", "dpkg-query", "dpkg-deb", "rpm", "apk", "pacman", "snap",
    "pip", "pip3", "npm", "gem", "cargo",
    # SSH inspection
    "ssh-keyscan", "ssh-keygen", "sshd",  # sshd -T tests config
    # Sysctl
    "sysctl",
    # Kerberos / time
    "klist", "date", "timedatectl", "ntpq", "chronyc",
    # Containers (read paths)
    "docker", "podman", "kubectl", "crictl", "ctr",  # most subcommands read; specific writes handled below
    "command", "type", "alias",
    # Misc
    "env", "printenv", "echo", "true", "false", "test",
}

_WRITE_HEADS = {
    "rm", "rmdir", "shred", "mv", "rename", "cp", "dd", "install",
    "touch", "mkdir", "mkfile",
    "chmod", "chown", "chgrp", "setfacl", "setcap", "chattr",
    "ln", "link", "unlink",
    "useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
    "passwd", "chpasswd", "gpasswd",
    "mkfs", "fsck", "fdisk", "parted", "gparted", "lvcreate", "lvremove",
    "vgcreate", "vgremove", "pvcreate", "pvremove",
    "umount", "swapon", "swapoff",
    "tee", "patch",
    "tar", "unzip", "gunzip",  # archive extraction can clobber files
    "git",  # git commit/push/checkout/reset are writes; let the user approve
}

_NETWORK_HEADS = {
    "curl", "wget", "fetch",
    "nc", "ncat", "netcat", "socat",
    "ping", "ping6", "traceroute", "tracepath", "mtr", "fping",
    "nmap", "masscan", "rustscan",
    "tcpdump", "tshark", "wireshark", "tcpflow",
    "ftp", "tftp", "sftp", "scp", "rsync",
    "ssh", "mosh", "telnet",
    "smbclient", "rpcclient",
    "ldapsearch", "ldapmodify",
    "openssl",  # s_client / s_server make connections
    "rclone",
    "aws", "gcloud", "az",
}

_PRIVILEGED_HEADS = {
    "sudo", "su", "doas", "pkexec", "runuser",
    "modprobe", "insmod", "rmmod",
    "kexec", "reboot", "shutdown", "halt", "poweroff",
    "mount",  # mount can change filesystem state
    "iptables", "ip6tables",  # modifying chains needs root
}

# Subcommand-aware allow/deny for binaries that have both read and write modes.
# Format: { command: { "read": {subcmd1, subcmd2, ...}, "default": "approval" } }
_SUBCOMMAND_RULES: dict[str, dict] = {
    "systemctl": {
        "read": {"status", "is-active", "is-enabled", "is-failed", "show",
                 "list-units", "list-unit-files", "list-sockets", "list-timers",
                 "list-jobs", "list-dependencies", "cat", "help", "--version"},
        "default_category": "privileged",
    },
    "service": {
        "read": {"status", "--status-all"},
        "default_category": "privileged",
    },
    "docker": {
        "read": {"ps", "images", "inspect", "logs", "version", "info", "diff",
                 "history", "port", "top", "stats", "events", "system", "network",
                 "volume", "context"},
        "default_category": "privileged",
    },
    "podman": {
        "read": {"ps", "images", "inspect", "logs", "version", "info", "diff",
                 "history", "port", "top", "stats", "events", "network", "volume"},
        "default_category": "privileged",
    },
    "kubectl": {
        "read": {"get", "describe", "logs", "explain", "version", "cluster-info",
                 "api-resources", "api-versions", "config", "diff", "top", "auth"},
        "default_category": "privileged",
    },
    "git": {
        "read": {"status", "log", "show", "diff", "blame", "branch", "tag",
                 "remote", "config", "rev-parse", "rev-list", "ls-files",
                 "ls-tree", "describe", "shortlog"},
        "default_category": "write",
    },
    "apt": {"read": {"list", "show", "search", "depends"}, "default_category": "privileged"},
    "apt-get": {"read": {}, "default_category": "privileged"},  # mostly write
    "dnf": {"read": {"list", "info", "search", "repolist", "history"}, "default_category": "privileged"},
    "yum": {"read": {"list", "info", "search", "repolist", "history"}, "default_category": "privileged"},
    "zypper": {"read": {"search", "info", "repos", "lr"}, "default_category": "privileged"},
    "pacman": {"read": {"-Q", "-Qi", "-Qs", "-Si", "-Ss"}, "default_category": "privileged"},
    "snap": {"read": {"list", "info", "find", "version"}, "default_category": "privileged"},
    "pip": {"read": {"list", "show", "freeze", "config"}, "default_category": "write"},
    "pip3": {"read": {"list", "show", "freeze", "config"}, "default_category": "write"},
    "npm": {"read": {"list", "ls", "view", "info", "config", "outdated"}, "default_category": "write"},
    "crontab": {"read": {"-l"}, "default_category": "write"},
    "iptables-save": {"read": {""}, "default_category": "read_only"},
    "ip6tables-save": {"read": {""}, "default_category": "read_only"},
    "iptables": {"read": {"-L", "-S", "-n", "--list", "--list-rules"}, "default_category": "privileged"},
    "ip6tables": {"read": {"-L", "-S", "-n", "--list", "--list-rules"}, "default_category": "privileged"},
    "nft": {"read": {"list"}, "default_category": "privileged"},
    "ufw": {"read": {"status"}, "default_category": "privileged"},
    "firewall-cmd": {
        "read": {"--state", "--list-all", "--list-all-zones", "--get-default-zone",
                 "--get-active-zones", "--get-zones"},
        "default_category": "privileged",
    },
    "auditctl": {"read": {"-l", "-s"}, "default_category": "privileged"},
    "sysctl": {"read": {"-a", "-n", "-N"}, "default_category": "privileged"},
    "ssh-keygen": {"read": {"-l", "-y", "-F"}, "default_category": "write"},
    "openssl": {"read": set(), "default_category": "network"},  # everything network/cert ops
}


def _classify_segment(seg: str) -> tuple[str, str]:
    """Classify one shell segment (between |, ;, &&, ||).

    Returns (category, reason). Category is one of:
      - "read_only" — auto-execute
      - "write"      — needs approval (modifies on-host state)
      - "network"    — needs approval (makes outbound connections)
      - "privileged" — needs approval (requires elevation)
      - "unknown"    — needs approval (we don't recognize the command)
    """
    try:
        tokens = shlex.split(seg, comments=False)
    except ValueError as e:
        return ("unknown", f"cannot parse: {e}")
    if not tokens:
        return ("read_only", "")

    # `command -v X` and `which X` style: keep the segment, look at the
    # first non-flag token.
    head = tokens[0]
    # Strip leading `time `, `nice `, `nohup `, `env VAR=VAL ` etc.
    while head in {"time", "nice", "nohup", "ionice", "stdbuf", "exec"} and len(tokens) > 1:
        tokens = tokens[1:]
        head = tokens[0]
    # `env VAR=VAL cmd ...` — env can prefix any command. We only allow read-only
    # uses (`env`/`printenv` alone) when env *is* the head.
    if head == "env" and len(tokens) > 1 and "=" in tokens[1]:
        # env VAR=VAL <real_cmd> ...
        idx = 1
        while idx < len(tokens) and "=" in tokens[idx]:
            idx += 1
        if idx < len(tokens):
            tokens = tokens[idx:]
            head = tokens[0]

    bare = head.rsplit("/", 1)[-1]

    # Subcommand rules apply first (e.g. `systemctl status` is read-only,
    # `systemctl start` is privileged).
    if bare in _SUBCOMMAND_RULES:
        rule = _SUBCOMMAND_RULES[bare]
        sub_args = [t for t in tokens[1:] if not t.startswith("-")] or [""]
        flag_args = [t for t in tokens[1:] if t.startswith("-")]
        first_sub = sub_args[0] if sub_args else ""
        # Read mode if either the first subcommand or any flag matches.
        if first_sub in rule["read"] or any(f in rule["read"] for f in flag_args):
            return ("read_only", "")
        return (rule["default_category"], f"{bare} {first_sub or (flag_args[0] if flag_args else '')} requires approval")

    if bare in _PRIVILEGED_HEADS:
        return ("privileged", f"requires elevation: {bare}")
    if bare in _NETWORK_HEADS:
        return ("network", f"makes network connections: {bare}")
    if bare in _WRITE_HEADS:
        return ("write", f"modifies system state: {bare}")
    if bare in _READ_ONLY_HEADS:
        return ("read_only", "")
    return ("unknown", f"unrecognized command: {bare}")


def _classify_command(command: str) -> tuple[str, str]:
    """Classify a full command line into (category, reason).

    Conservative: any sign of write redirects, command substitution, or
    unknown commands → escalates to non-read_only so the user approves.
    """
    if not command or not command.strip():
        return ("read_only", "")
    cmd = command.strip()

    # Strip quoted strings before scanning for shell metacharacters so we
    # don't false-positive on grep patterns containing `>` etc.
    scan = re.sub(r'"(?:\\.|[^"\\])*"', '""', cmd)
    scan = re.sub(r"'(?:\\.|[^'\\])*'", "''", scan)

    # Output redirection to file: `>`, `>>`, `&>`, `|& tee`, `>&-`. We allow
    # `2>&1` and `2>/dev/null` (stderr management is read-side).
    redir = re.compile(r"(?<![0-9&])>(?!\&)")
    for m in redir.finditer(scan):
        # Allow `>/dev/null` and `>>/dev/null`
        tail = scan[m.end():].lstrip()
        if tail.startswith("/dev/null"):
            continue
        return ("write", "shell redirect writes to a file")

    # Command substitution — could hide anything inside.
    if "$(" in scan or "`" in scan:
        return ("unknown", "command substitution requires manual review")
    # Process substitution with write side
    if "<(" in scan and "tee" in scan:
        return ("write", "process substitution writing via tee")

    # Split on shell separators. We split on `;`, `&&`, `||`, and `|`, and
    # classify each segment. Worst category wins.
    segments = re.split(r'(\|\||&&|;|\||(?<![0-9])\s&\s)', scan)
    # Drop the separator capture groups
    segments = [s for s in segments if s and not re.fullmatch(r'(\|\||&&|;|\||\s&\s)', s.strip())]

    worst = "read_only"
    reasons: list[str] = []
    severity = {"read_only": 0, "write": 2, "network": 2, "privileged": 2, "unknown": 1}
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        cat, reason = _classify_segment(seg)
        if severity[cat] > severity[worst] or (
            severity[cat] == severity[worst] and worst == "read_only" and cat != "read_only"
        ):
            worst = cat
            if reason:
                reasons.append(reason)
        elif cat != "read_only" and reason and reason not in reasons:
            reasons.append(reason)
    return (worst, "; ".join(reasons))


# ── Tools ─────────────────────────────────────────────────────────────


@agent_tool(
    "ssh_run_command",
    "Run a shell command on the target via SSH and return stdout, stderr, "
    "and exit code. The output is capped at 512 KB and the command at 60 s. "
    "BEHAVIOR DEPENDS ON THE COMMAND:\n"
    "  • Read-only commands (cat, ls, grep, find, ss, ps, systemctl status, "
    "sysctl -a, getenforce, sestatus, journalctl -n, dpkg -l, rpm -qa, etc.) "
    "execute immediately.\n"
    "  • Commands that write (rm, mv, chmod, useradd, package installs, "
    "service start/stop, etc.), make outbound network connections (curl, "
    "wget, ssh, scp, nmap, tcpdump, …), or require elevation (sudo, su, "
    "modprobe, mount, iptables -A, …) PAUSE the run for user approval. "
    "After approval, the command runs as written.\n"
    "  • Unknown commands also pause for approval — the classifier prefers "
    "false positives over false negatives.\n"
    "Shell redirects to files (`>`, `>>`) and command substitution `$(...)` "
    "always pause for approval. `2>/dev/null` / `2>&1` is fine.",
    {
        "asset_id": {"type": "integer"},
        "command": {
            "type": "string",
            "description": "Shell command to run (a /bin/sh -c string)",
        },
    },
)
def ssh_run_command_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    command = (params.get("command") or "").strip()
    if not command:
        return {"error": "command is required"}

    if not params.get("_approved"):
        category, reason = _classify_command(command)
        if category != "read_only":
            raise NeedsApproval(
                reason=(
                    f"Command requires approval ({category}): {reason or command}"
                ),
                category=f"ssh_{category}",
                details={"command": command, "category": category},
            )

    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(
        db, org_id, asset_id, "exec",
        {"command": command}, relay, cred,
    ))
    # Trim very large stdout for LLM consumption — full bytes are still on
    # the relay's side but token cost on the agent grows linearly.
    stdout = result.get("stdout") or ""
    stderr = result.get("stderr") or ""
    truncated = False
    if len(stdout) > 16000:
        stdout = stdout[:16000]
        truncated = True
    if len(stderr) > 4000:
        stderr = stderr[:4000]
        truncated = True
    return {
        "command": command,
        "exit_code": result.get("exit_code"),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_truncated": truncated,
        "error": result.get("error"),
    }


@agent_tool(
    "ssh_read_file",
    "Read a file from the target over SFTP. The relay enforces a 256 KB "
    "size cap. Returns content as text. Use for any config file the SSH "
    "user can read (sshd_config, /etc/passwd, /etc/sudoers, /etc/audit/*, "
    "/etc/security/*, /proc/* pseudo-files, etc.).",
    {
        "asset_id": {"type": "integer"},
        "path": {"type": "string", "description": "Absolute path to the file"},
    },
)
def ssh_read_file_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    path = (params.get("path") or "").strip()
    if not path:
        return {"error": "path is required"}
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(
        db, org_id, asset_id, "read_file",
        {"path": path}, relay, cred,
    ))
    return result


@agent_tool(
    "ssh_list_directory",
    "List entries of a directory on the target. Returns name, type "
    "(file/dir/link), mode (octal), owner, group, size for each entry. "
    "Equivalent to `ls -la` but structured. Set `all_files=true` to "
    "include dotfiles (default true).",
    {
        "asset_id": {"type": "integer"},
        "path": {"type": "string", "description": "Absolute directory path"},
        "all_files": {"type": "boolean", "description": "Include dotfiles (default true)"},
    },
)
def ssh_list_directory_tool(db, params: dict) -> dict:
    asset_id = params.get("asset_id")
    path = (params.get("path") or "").strip()
    if not path:
        return {"error": "path is required"}
    all_files = params.get("all_files")
    if all_files is None:
        all_files = True
    relay, cred = _ctx(params)
    org_id = params.get("_org_id")
    _, result = _run_async(_dispatch_ssh(
        db, org_id, asset_id, "list_dir",
        {"path": path, "all_files": bool(all_files)}, relay, cred,
    ))
    entries = result.get("entries") or []
    if len(entries) > 200:
        result["entries"] = entries[:200] + [{"_truncated": True, "_total": len(entries)}]
    return result


# ── Registry ──────────────────────────────────────────────────────────


_SSH_TOOL_NAMES = [
    "ssh_run_command",
    "ssh_read_file",
    "ssh_list_directory",
    # CVE correlation — deterministic inventory→CVE matching pass
    "correlate_software_to_cves",
    # Shared
    "emit_finding",
    "get_asset_profile",
    "read_scratchpad", "write_scratchpad",
    "request_clarification",
]


register_audit(ProtocolAudit(
    protocol="ssh",
    label="Linux Audit (SSH)",
    description=(
        "Credentialed Linux/Unix audit over SSH. The agent runs arbitrary "
        "shell commands via `ssh_run_command`, reads files via "
        "`ssh_read_file`, and lists directories via `ssh_list_directory`. "
        "Read-only commands execute immediately; writes / network access / "
        "privileged operations pause for user approval before the relay "
        "touches the host."
    ),
    supported_os=["linux", "unix", "macos"],
    auth_modes=["password", "key"],
    relay_method="ssh_query",
    credential_connector_ids=["linux_host", "linux-host"],
    tool_names=_SSH_TOOL_NAMES,
    required_ports=(22,),
    missions=[
        MissionTemplate(
            key="exposure_audit",
            label="Exposure Audit",
            description=(
                "End-to-end Linux/Unix exposure hunt: hardening (sshd_config, "
                "SUID/SGID, listening services, kernel age), identity (UID=0, "
                "shadow anomalies, sudoers, authorized_keys), software "
                "inventory + CVE triage via the correlator. Read-only commands "
                "auto-execute; writes / network / privileged operations pause "
                "for user approval."
            ),
            prompt_key="ssh_audit_exposure_audit",
            suggested_budget=50,
            cost_hint="high",
        ),
    ],
))
