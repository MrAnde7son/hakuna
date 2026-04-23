"""Extract a per-protocol coverage catalog from a local Nessus plugins tree.

Reads ``.nasl`` files, parses the ``if(description){...}`` metadata block, and
emits one JSON file per supported protocol under
``backend/data/nessus_coverage/{protocol}.json`` plus a ``summary.json`` with
counts and cluster breakdowns. ``.nbin`` files are skipped — they're compiled
and only their titles are available via Tenable's public plugin DB.

Usage:
    python backend/scripts/extract_nessus_coverage.py \
        --plugins /Library/Nessus/run/lib/nessus/plugins

The classifier deliberately keeps each plugin in every protocol bucket it
matches — SMB and WMI overlap heavily on Windows credentialed checks, and we
want both audit authors to see the relevant coverage.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# Read this many bytes from the head of each .nasl. The description block is
# always first and almost always under 20KB. Cap protects against pathological
# plugins (some .nasl files are >1MB of check logic after the header).
HEAD_BYTES = 40_000

# --- NASL header parsing ---------------------------------------------------

# script_set_attribute(attribute:"NAME", value:"VALUE") — VALUE is a
# double-quoted string, possibly multi-line, with backslash-escaped quotes.
RE_SET_ATTR = re.compile(
    r'script_set_attribute\s*\(\s*attribute\s*:\s*"([^"]+)"\s*,\s*value\s*:\s*"((?:[^"\\]|\\.)*)"\s*\)',
    re.DOTALL,
)

RE_SCRIPT_ID = re.compile(r"script_id\s*\(\s*(\d+)\s*\)")
RE_SCRIPT_NAME = re.compile(r'script_name\s*\(\s*english\s*:\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
RE_SCRIPT_FAMILY = re.compile(r'script_family\s*\(\s*english\s*:\s*"((?:[^"\\]|\\.)*)"', re.DOTALL)
RE_SCRIPT_CATEGORY = re.compile(r"script_category\s*\(\s*([A-Z_]+)\s*\)")
RE_SCRIPT_CVE = re.compile(r'script_cve_id\s*\(\s*(.*?)\)', re.DOTALL)
RE_SCRIPT_REQUIRE_KEYS = re.compile(r'script_require_keys\s*\(\s*(.*?)\)', re.DOTALL)
RE_SCRIPT_REQUIRE_PORTS = re.compile(r'script_require_ports\s*\(\s*(.*?)\)', re.DOTALL)
RE_SCRIPT_DEPENDENCIES = re.compile(r'script_dependencies\s*\(\s*(.*?)\)', re.DOTALL)
RE_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"', re.DOTALL)

# "if(description)" opens the metadata block. The block closes with a bare
# "exit(0);" at column 0-ish before any include() of the check logic. Slicing
# there gives us a clean window for the header regexes.
RE_DESCRIPTION_END = re.compile(r"\n\s*exit\s*\(\s*0\s*\)\s*;", re.MULTILINE)


def _unescape(s: str) -> str:
    return s.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")


def _extract_quoted_list(raw: str) -> list[str]:
    return [_unescape(m.group(1)) for m in RE_QUOTED.finditer(raw)]


def _extract_port_list(raw: str) -> list[str]:
    # script_require_ports mixes quoted service names and bare port numbers.
    out: list[str] = []
    for m in RE_QUOTED.finditer(raw):
        out.append(m.group(1))
    # Strip quoted segments before grabbing bare ints to avoid double-counting.
    bare = RE_QUOTED.sub("", raw)
    for n in re.findall(r"\b\d{2,5}\b", bare):
        out.append(n)
    return out


def _humanize_nbin(stem: str) -> str:
    """`wmi_enum_local_group_memberships` -> `WMI Enum Local Group Memberships`.

    Used only for .nbin files where we have no header to parse. The filename
    is the only signal we get (the bytecode and Nessus's plugin DBs are
    encrypted), so we surface it as-is with light prettification.
    """
    parts = stem.split("_")
    if not parts:
        return stem
    acros = {"wmi", "smb", "ldap", "snmp", "ssh", "iis", "tpm", "ntfs",
             "laps", "emet", "apt1", "dep", "sccm", "qfes", "esu", "md5s",
             "ssid", "dns", "usb", "amt", "intel"}
    out = []
    for p in parts:
        out.append(p.upper() if p.lower() in acros else p.capitalize())
    return " ".join(out)


def parse_nbin(filename: str) -> dict:
    """Build a minimal record for an encrypted .nbin plugin from its filename."""
    stem = filename[:-5] if filename.endswith(".nbin") else filename
    return {
        "plugin_id": None,
        "name": _humanize_nbin(stem),
        "family": "",
        "category": "",
        "synopsis": "",
        "description": "",
        "solution": "",
        "risk_factor": "",
        "cvss3_base_vector": "",
        "cvss_base_vector": "",
        "plugin_type": "",
        "cve_ids": [],
        "require_keys": [],
        "require_ports": [],
        "dependencies": [],
        "source": "nbin_filename",
    }


def parse_header(text: str) -> dict | None:
    """Return a dict of extracted fields, or None if this isn't a plugin."""
    end = RE_DESCRIPTION_END.search(text)
    header = text[: end.start()] if end else text

    sid_m = RE_SCRIPT_ID.search(header)
    if not sid_m:
        return None  # no plugin id = not a real check

    attrs: dict[str, str] = {}
    for m in RE_SET_ATTR.finditer(header):
        attrs[m.group(1)] = _unescape(m.group(2))

    name_m = RE_SCRIPT_NAME.search(header)
    family_m = RE_SCRIPT_FAMILY.search(header)
    cat_m = RE_SCRIPT_CATEGORY.search(header)

    cve_ids: list[str] = []
    cve_m = RE_SCRIPT_CVE.search(header)
    if cve_m:
        cve_ids = [c for c in _extract_quoted_list(cve_m.group(1)) if c.upper().startswith("CVE-")]

    require_keys: list[str] = []
    rk_m = RE_SCRIPT_REQUIRE_KEYS.search(header)
    if rk_m:
        require_keys = _extract_quoted_list(rk_m.group(1))

    require_ports: list[str] = []
    rp_m = RE_SCRIPT_REQUIRE_PORTS.search(header)
    if rp_m:
        require_ports = _extract_port_list(rp_m.group(1))

    dependencies: list[str] = []
    dep_m = RE_SCRIPT_DEPENDENCIES.search(header)
    if dep_m:
        dependencies = _extract_quoted_list(dep_m.group(1))

    return {
        "plugin_id": int(sid_m.group(1)),
        "source": "nasl_header",
        "name": _unescape(name_m.group(1)) if name_m else "",
        "family": _unescape(family_m.group(1)) if family_m else "",
        "category": cat_m.group(1) if cat_m else "",
        "synopsis": attrs.get("synopsis", "").strip(),
        "description": attrs.get("description", "").strip(),
        "solution": attrs.get("solution", "").strip(),
        "risk_factor": attrs.get("risk_factor", ""),
        "cvss3_base_vector": attrs.get("cvss3_base_vector", ""),
        "cvss_base_vector": attrs.get("cvss_base_vector", ""),
        "plugin_type": attrs.get("plugin_type", ""),
        "cve_ids": cve_ids,
        "require_keys": require_keys,
        "require_ports": require_ports,
        "dependencies": dependencies,
    }


# --- Protocol classification ----------------------------------------------

# (matcher, protocol) — runs against lowercased require_keys/ports/family/filename.
# A plugin can match multiple protocols and will appear in each bucket.
def classify_protocols(p: dict, filename: str) -> set[str]:
    keys = {k.lower() for k in p["require_keys"]}
    ports = {k.lower() for k in p["require_ports"]}
    family = p["family"].lower()
    fname = filename.lower()
    out: set[str] = set()

    def any_prefix(coll, prefixes):
        return any(any(x.startswith(pfx) for pfx in prefixes) for x in coll)

    # SNMP: explicit KB key, family, or 161 port requirement.
    if (
        "snmp/community" in keys
        or any_prefix(keys, ("snmp/",))
        or family == "snmp"
        or "services/snmp" in ports
        or "161" in ports
    ):
        out.add("snmp")

    # LDAP: service port or explicit LDAP KB key.
    if (
        "services/ldap" in ports
        or "389" in ports
        or "636" in ports
        or any_prefix(keys, ("ldap/",))
        or fname.startswith("ldap_")
    ):
        out.add("ldap")

    # SSH: credentialed Linux/BSD/Unix checks go through ssh_get_info.nasl,
    # which populates Host/Linux/*, Host/BSD/*, Host/MacOSX/*. Banner-only
    # SSH detection plugins don't require these but still touch port 22.
    ssh_key_prefixes = (
        "host/linux/",
        "host/bsd/",
        "host/macosx/",
        "host/solaris/",
        "host/aix/",
        "host/hpux/",
        "ssh/",
    )
    if (
        any_prefix(keys, ssh_key_prefixes)
        or "services/ssh" in ports
        or "22" in ports
        or family in {"ssh", "general"} and fname.startswith("ssh_")
    ):
        out.add("ssh")

    # SMB: any SMB KB key or SMB/NetBIOS port.
    smb_markers = ("smb/", "cifs/")
    if (
        any_prefix(keys, smb_markers)
        or "services/cifs" in ports
        or "139" in ports
        or "445" in ports
        or fname.startswith("smb_")
    ):
        out.add("smb")

    # WMI: WMI KB keys or filename. Most WMI-reached checks also set SMB keys
    # (since Nessus authenticates over SMB before querying WMI), so we keep WMI
    # narrower — explicit WMI markers only — to avoid drowning the bucket in
    # generic Windows checks.
    if any_prefix(keys, ("wmi/",)) or fname.startswith("wmi_"):
        out.add("wmi")

    return out


# --- Intent clustering -----------------------------------------------------

# Order matters — a plugin is assigned the first matching cluster when we want
# a single "primary" label, but we also emit the full set.
CLUSTER_RULES: list[tuple[str, re.Pattern]] = [
    ("patch_cve", re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)),  # overridden below by cve_ids check
    ("malware_detection", re.compile(
        r"\b(malware|malscan|apt\d+|bit9|authenticode|yara|trojan|backdoor|rootkit|"
        r"double[_ ]pulsar|known_good|unknown_running|fsecure|unwanted[_ ]software)\b",
        re.IGNORECASE)),
    ("authentication_weakness", re.compile(
        r"\b(null[_ ]bind|anonymous|blank[_ ]password|default[_ ](password|credential)|"
        r"weak[_ ]password|brute[_ -]?force|guess(able)?[_ ]password|no[_ ]authentication|"
        r"unauth(enticated)?[_ ]access|guest[_ ]account|password[_ ]policy)\b",
        re.IGNORECASE)),
    ("credential_material", re.compile(
        r"\b(password[_ ]hash|credential(s)?[_ ](stored|exposed|disclosed)|"
        r"cleartext[_ ]password|plaintext[_ ]credential|private[_ ]key|shared[_ ]secret|"
        r"kerberos[_ ]ticket|ntlm[_ ]hash|lsa[_ ]secret|cached[_ ]credential|"
        r"sam[_ ](database|check)|windows[_ ]laps|cred[_ ]guard|partial[_ ]product[_ ]key)\b",
        re.IGNORECASE)),
    ("privilege_and_acl", re.compile(
        r"\b(privilege|privileged|admin(istrator)?[_ ](access|rights|members)|"
        r"elevation|escalation|acl|permission(s)?[_ ]weak|dangerous[_ ]permission|"
        r"writ(e|able)[_ ]by[_ ]everyone|everyone[_ ]group|world[_ -]?writable|unsafe[_ ]acl|"
        r"local[_ ]group[_ ]membership|local[_ ]users|group[_ ]members|trusted[_ ]?domain)\b",
        re.IGNORECASE)),
    ("information_disclosure", re.compile(
        r"\b(disclos|enumerat|enum|information[_ ]disclosure|leak|expose(s|d)?|listing|"
        r"lists[_ ](the|all|user|share|account)|discover(s|ed)?[_ ](user|share|domain)|"
        r"netstat|list[_ ]interfaces|asset[_ ]info|system[_ ]hostname|"
        r"obtain[_ ]ssid|ntfs[_ ]drives|usb[_ ]drives)\b",
        re.IGNORECASE)),
    ("logging_and_audit", re.compile(
        r"\b(audit[_ ]policy|event[_ ]log|logging[_ ](disabled|not[_ ]enabled)|"
        r"log[_ ]retention|syslog|audit[_ ]trail|security[_ ]log)\b", re.IGNORECASE)),
    ("service_inventory", re.compile(
        r"\b(detection|detect(s|ed)?|version|installed|banner|fingerprint|"
        r"running[_ ](service|process)|last[_ ]reboot|available|not[_ ]available|"
        r"firewall|antivirus|antispyware|emet|tpm|bitlocker|"
        r"encryptable[_ ]volumes|bluetooth|kernel[_ ]drivers|display[_ ]drivers|"
        r"printer[_ ]drivers|modems|iis[_ ]components|server[_ ]features|"
        r"windows[_ ]app[_ ]store|computersystemproduct|sccm|"
        r"windows[_ ]not[_ ]activated)\b", re.IGNORECASE)),
    ("misconfiguration", re.compile(
        r"\b(misconfigur|insecure[_ ]config|not[_ ]configured|allows|permits|disabled|"
        r"enabled|signing[_ ]not[_ ]required|ssl/tls[_ ](weak|insecure)|weak[_ ]cipher|"
        r"weak[_ ]protocol|default[_ ]config|dep[_ ]off|disable[_ ]shares|"
        r"enable[_ ]shares|esu[_ ]status|not[_ ]activated)\b", re.IGNORECASE)),
]


RE_NBIN_PATCH = re.compile(r"(INTEL-SA-\d+|[_-]kb\d{6,}|MS\d{2}-\d{3})", re.IGNORECASE)
RE_NBIN_OPERATIONAL = re.compile(
    r"\b(process_on_port|start_\w+_svc|stop_\w+_svc|_running|known_good|unknown_running)\b",
    re.IGNORECASE,
)


def cluster(p: dict) -> list[str]:
    """Return all intent labels that apply. `patch_cve` is set iff cve_ids present."""
    labels: list[str] = []
    if p["cve_ids"]:
        labels.append("patch_cve")
    fname = p.get("filename", "")
    # For .nbin records, CVE lists aren't available; infer patch_cve from
    # vendor advisory IDs embedded in the filename (INTEL-SA-*, MS kb*).
    if "patch_cve" not in labels and RE_NBIN_PATCH.search(fname):
        labels.append("patch_cve")
    if RE_NBIN_OPERATIONAL.search(fname):
        labels.append("service_inventory")
    # Include filename so nbin records (which have no synopsis/solution) still
    # cluster on the verbs in the stem: enum, cred_guard, laps, etc.
    blob = f"{p['name']}\n{p['synopsis']}\n{p['solution']}\n{p.get('filename','')}"
    for label, pattern in CLUSTER_RULES:
        if label == "patch_cve":
            continue  # handled above
        if pattern.search(blob):
            labels.append(label)
    if not labels:
        labels.append("other")
    return labels


# --- Driver ----------------------------------------------------------------

PROTOCOLS = ("snmp", "ldap", "ssh", "smb", "wmi")


def run(plugins_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    per_proto: dict[str, list[dict]] = defaultdict(list)
    scanned = 0
    parsed = 0

    for nasl in plugins_dir.glob("*.nasl"):
        scanned += 1
        try:
            with nasl.open("rb") as f:
                raw = f.read(HEAD_BYTES)
            text = raw.decode("utf-8", errors="replace")
        except OSError:
            continue

        p = parse_header(text)
        if not p:
            continue
        parsed += 1

        p["filename"] = nasl.name
        protos = classify_protocols(p, nasl.name)
        if not protos:
            continue

        p["clusters"] = cluster(p)
        p["primary_cluster"] = p["clusters"][0]

        for proto in protos:
            per_proto[proto].append(p)

        if scanned % 10000 == 0:
            print(f"  scanned {scanned} / parsed {parsed} / matched {sum(len(v) for v in per_proto.values())}")

    # Second pass — .nbin files. These are encrypted bytecode; Nessus's own
    # plugins-desc.db is also encrypted. The filename is the only signal, but
    # it's surprisingly informative (e.g., `wmi_enum_local_group_memberships`,
    # `ldap_enum_trusteddomain`, `wmi_cred_guard`). We include them so the
    # coverage map reflects the full set of checks Nessus ships, with
    # `source: "nbin_filename"` marking the provenance.
    nbin_scanned = 0
    nbin_matched = 0
    for nbin in plugins_dir.glob("*.nbin"):
        nbin_scanned += 1
        p = parse_nbin(nbin.name)
        p["filename"] = nbin.name
        protos = classify_protocols(p, nbin.name)
        if not protos:
            continue
        p["clusters"] = cluster(p)
        p["primary_cluster"] = p["clusters"][0]
        nbin_matched += 1
        for proto in protos:
            per_proto[proto].append(p)
    print(f"  nbin scanned={nbin_scanned} matched={nbin_matched}")

    summary = {
        "scanned": scanned,
        "parsed": parsed,
        "nbin_scanned": nbin_scanned,
        "nbin_matched": nbin_matched,
        "protocols": {},
    }

    for proto in PROTOCOLS:
        # Sort by (has_id, plugin_id, filename) so nbin-only rows (id=None)
        # appear after .nasl rows in a deterministic order.
        plugins = sorted(
            per_proto.get(proto, []),
            key=lambda r: (r["plugin_id"] is None, r["plugin_id"] or 0, r["filename"]),
        )
        family_counts = Counter(r["family"] for r in plugins)
        cluster_counts = Counter()
        for r in plugins:
            for lbl in r["clusters"]:
                cluster_counts[lbl] += 1
        category_counts = Counter(r["category"] for r in plugins)
        cred_count = sum(
            1
            for r in plugins
            if any(
                k.lower().startswith(("smb/", "wmi/", "ldap/", "snmp/community", "host/linux/", "host/bsd/"))
                for k in r["require_keys"]
            )
        )
        cve_count = sum(1 for r in plugins if r["cve_ids"])
        nbin_count = sum(1 for r in plugins if r.get("source") == "nbin_filename")

        path = out_dir / f"{proto}.json"
        path.write_text(json.dumps({
            "protocol": proto,
            "total": len(plugins),
            "credentialed_total": cred_count,
            "cve_count": cve_count,
            "nbin_count": nbin_count,
            "family_counts": family_counts.most_common(),
            "cluster_counts": cluster_counts.most_common(),
            "category_counts": category_counts.most_common(),
            "plugins": plugins,
        }, indent=2))

        summary["protocols"][proto] = {
            "total": len(plugins),
            "credentialed_total": cred_count,
            "cve_count": cve_count,
            "nbin_count": nbin_count,
            "top_families": family_counts.most_common(10),
            "clusters": cluster_counts.most_common(),
        }

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nDone. scanned={scanned} parsed={parsed}")
    for proto, info in summary["protocols"].items():
        print(
            f"  {proto:6s}  total={info['total']:>6d}  "
            f"credentialed={info['credentialed_total']:>6d}  "
            f"cves={info['cve_count']:>6d}  nbin={info['nbin_count']:>4d}"
        )
    print(f"\nWrote {out_dir}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plugins", default="/Library/Nessus/run/lib/nessus/plugins")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "data" / "nessus_coverage"))
    args = ap.parse_args()
    run(Path(args.plugins), Path(args.out))


if __name__ == "__main__":
    main()
