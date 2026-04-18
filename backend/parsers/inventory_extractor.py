"""
Inventory extractor — parses plugin_output text from Info-level Nessus findings
into structured inventory records for attack path analysis.

Each extract_* function receives the raw plugin_output string and the asset_id/scan_id,
and returns a list of dicts ready to be inserted into the corresponding model.

Plugin IDs handled:
  69239  → AD users (domain users, groups memberships, SPNs)
  10860  → Local users via SID enumeration
  10902  → Local Administrators group members
  10908  → Domain Administrators group members
  38689  → Last logged-on user
  69238  → AD group memberships (full member lists)
  167251 → LDAP group JSON
  10456  → Running services (SMB enumeration)
  44401  → Service configuration details
  58651  → Netstat active connections (Windows + Linux format)
  64582  → Netstat connection info (structured tcp4/tcp6 blocks)
  70625  → Scheduled tasks (XML-like format)
  66334  → Patch report (missing KBs + CVEs)
  161502 → Currently logged-on users
  10863  → SSL certificate info (subject, issuer, validity, SANs, key info)
"""

from __future__ import annotations

import re
import json
import logging

logger = logging.getLogger(__name__)

# Groups that grant elevated privileges
PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "builtin\\administrators", "account operators",
    "backup operators", "print operators", "server operators",
    "group policy creator owners", "domain controllers",
    "read-only domain controllers", "cryptographic operators",
    "network configuration operators", "remote desktop users",
}


def _is_privileged_group(name: str) -> bool:
    return name.strip().lower() in PRIVILEGED_GROUPS


def _cn_from_dn(dn: str) -> str:
    """Extract the CN value from a Distinguished Name string."""
    m = re.match(r"CN=([^,]+)", dn, re.IGNORECASE)
    return m.group(1).strip() if m else dn.strip()


def _domain_from_dn(dn: str) -> str:
    """Extract domain name from DC= components of a DN."""
    dcs = re.findall(r"DC=([^,]+)", dn, re.IGNORECASE)
    return ".".join(dcs) if dcs else ""


def _rid_from_sid(sid: str):
    """Return the Relative ID (last component) of a SID string."""
    if not sid:
        return None
    parts = sid.rsplit("-", 1)
    try:
        return int(parts[-1])
    except ValueError:
        return None


# ─────────────────────────────────────────────────────────
# Identity type classification
# ─────────────────────────────────────────────────────────

# Patterns that indicate non-human identities
_NHI_USERNAME_PATTERNS = re.compile(
    r"(?i)"
    r"^svc[-_]|[-_]svc$|"               # svc-backup, backup-svc
    r"^sa[-_]|[-_]sa$|"                  # sa-sql, sql-sa
    r"^bot[-_]|[-_]bot$|\[bot\]|"        # bot-deploy, [bot]
    r"^sys[-_]|^system$|"                # sys-monitor, SYSTEM
    r"^api[-_]|[-_]api$|"                # api-gateway
    r"^task[-_]|^sched[-_]|"             # task-runner, sched-backup
    r"^msa[-_]|^gmsa[-_]|"              # Managed Service Accounts
    r"^health[-_]?check|"               # healthcheck
    r"\$$"                               # computer accounts: HOST$
)

_NHI_WELLKNOWN = {
    "system", "local service", "network service",
    "defaultaccount", "guest", "wdagutilityaccount",
    "krbtgt", "defaultapppool",
}

_SOURCE_FROM_PLUGIN = {
    "69239": "Active Directory",
    "167250": "Active Directory",
    "10860": "Windows",
    "10902": "Windows",
    "10908": "Windows",
    "38689": "Windows",
}


def classify_identity(user: dict) -> dict:
    """Classify a user dict as human / non_human and set source_systems.

    Mutates and returns the dict.
    """
    username = (user.get("username") or "").strip()
    user_type = user.get("user_type", "")
    uname_lower = username.lower()

    # Determine source system from plugin
    source = _SOURCE_FROM_PLUGIN.get(user.get("source_plugin", ""), "Other")
    user["source_systems"] = [source]

    # ── Non-human checks ──
    is_nhi = False
    subtype = None

    if user_type == "computer_account" or uname_lower.endswith("$"):
        is_nhi, subtype = True, "machine_identity"
    elif user_type == "service_account":
        is_nhi, subtype = True, "service_account"
    elif uname_lower in _NHI_WELLKNOWN:
        is_nhi, subtype = True, "machine_identity"
    elif _NHI_USERNAME_PATTERNS.search(uname_lower):
        is_nhi, subtype = True, "service_account"
    elif user.get("spns"):
        is_nhi, subtype = True, "service_account"

    if is_nhi:
        user["identity_type"] = "non_human"
        user["identity_subtype"] = subtype
    else:
        # Positive human signals or default to human for real accounts
        rid = user.get("rid")
        if rid is not None and rid >= 1000:
            user["identity_type"] = "human"
        elif user.get("dn") or user.get("department") or user.get("manager_dn"):
            user["identity_type"] = "human"
        elif user_type in ("domain_user", "local_user") and rid is None:
            user["identity_type"] = "human"
        else:
            user["identity_type"] = "unknown"
        user["identity_subtype"] = None

    return user


# ─────────────────────────────────────────────────────────
# Plugin 69239 — AD Users and Groups
# ─────────────────────────────────────────────────────────

def extract_ad_users(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse AD user blocks from plugin 69239 output."""
    if not plugin_output:
        return []

    users = []
    # Split into user blocks — each starts with "User" followed by spaces then ":"
    # Negative lookahead excludes "User Account Control" lines
    blocks = re.split(r"\n(?=User\s+(?!Account):)", plugin_output)

    for block in blocks:
        block = block.strip()
        if not block.startswith("User"):
            continue

        user = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "69239",
            "user_type": "domain_user",
            "username": None,
            "domain": None,
            "sid": None,
            "rid": None,
            "dn": None,
            "uac": None,
            "spns": [],
            "member_of": [],
            "password_last_set": None,
            "date_joined": None,
            "is_local_admin": False,
            "is_domain_admin": False,
            "is_privileged": False,
            "is_disabled": False,
            "password_never_expires": False,
            "never_logged_in": False,
            "never_changed_password": False,
            "last_logon_host": None,
            "department": None,
            "job_title": None,
            "manager_dn": None,
            "manager_username": None,
        }

        lines = block.split("\n")
        in_member_of = False
        in_spn = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                in_member_of = False
                in_spn = False
                continue

            if line.startswith("User") and ":" in line and "Account" not in line:
                dn = line.split(":", 1)[1].strip()
                user["dn"] = dn
                user["username"] = _cn_from_dn(dn)
                user["domain"] = _domain_from_dn(dn)
                in_member_of = False
                in_spn = False
            elif "Date Joined" in line:
                user["date_joined"] = line.split(":", 1)[1].strip()
                in_member_of = False
                in_spn = False
            elif "Service Principle Name" in line or "Service Principal Name" in line:
                spn_val = line.split(":", 1)[1].strip()
                if spn_val:
                    user["spns"] = [s.strip() for s in spn_val.split(",") if s.strip()]
                in_member_of = False
                in_spn = True
            elif "User Account Control" in line:
                try:
                    user["uac"] = int(line.split(":", 1)[1].strip())
                    # UAC flag 2 = ACCOUNTDISABLE
                    if user["uac"] & 2:
                        user["is_disabled"] = True
                    # UAC flag 65536 = DONT_EXPIRE_PASSWORD
                    if user["uac"] & 65536:
                        user["password_never_expires"] = True
                except (ValueError, IndexError):
                    pass
                in_member_of = False
                in_spn = False
            elif "Object SID" in line:
                user["sid"] = line.split(":", 1)[1].strip()
                user["rid"] = _rid_from_sid(user["sid"])
                in_member_of = False
                in_spn = False
            elif "Password Last Set" in line:
                user["password_last_set"] = line.split(":", 1)[1].strip()
                in_member_of = False
                in_spn = False
            elif "Member Of" in line:
                in_member_of = True
                in_spn = False
            elif in_member_of and stripped.startswith("CN="):
                user["member_of"].append(stripped)
                group_cn = _cn_from_dn(stripped).lower()
                if group_cn in ("domain admins", "enterprise admins", "schema admins"):
                    user["is_domain_admin"] = True
                    user["is_privileged"] = True
                elif _is_privileged_group(group_cn):
                    user["is_privileged"] = True
            elif in_spn and stripped and not any(k in line for k in ("Date", "Modified", "User Account", "Object SID", "Password", "Primary", "Member")):
                user["spns"].append(stripped)
            # AD organizational attributes
            elif "Department" in line and ":" in line:
                user["department"] = line.split(":", 1)[1].strip() or None
                in_member_of = False
                in_spn = False
            elif "Title" in line and ":" in line and "Account" not in line:
                user["job_title"] = line.split(":", 1)[1].strip() or None
                in_member_of = False
                in_spn = False
            elif "Manager" in line and ":" in line:
                mgr_dn = line.split(":", 1)[1].strip()
                if mgr_dn:
                    user["manager_dn"] = mgr_dn
                    user["manager_username"] = _cn_from_dn(mgr_dn)
                in_member_of = False
                in_spn = False

        # Computer accounts (hostname$)
        if user["username"] and user["username"].endswith("$"):
            user["user_type"] = "computer_account"
        # Service accounts often have SPNs
        elif user["spns"]:
            user["user_type"] = "service_account"

        if user["username"]:
            classify_identity(user)
            users.append(user)

    return users


# ─────────────────────────────────────────────────────────
# Plugin 10860 — Local Users (SID enumeration)
# ─────────────────────────────────────────────────────────

def extract_local_users(plugin_output: str, asset_id: int, scan_id: int, asset_hostname: str = "") -> list[dict]:
    """Parse local user list from plugin 10860."""
    if not plugin_output:
        return []

    users = []
    # Lines like:   - Administrator (id 500, Administrator account)
    #               - cymptom (id 1002)
    pattern = re.compile(r"-\s+(\S+)\s+\(id\s+(\d+)(?:,\s*([^)]*))?\)")
    for m in pattern.finditer(plugin_output):
        username = m.group(1).strip()
        rid = int(m.group(2))
        desc = (m.group(3) or "").strip()

        user_type = "local_user"
        if username.endswith("$"):
            user_type = "computer_account"
        elif "kerberos" in desc.lower():
            user_type = "service_account"

        rec = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "10860",
            "user_type": user_type,
            "username": username,
            "domain": asset_hostname or "",
            "sid": None,
            "rid": rid,
            "dn": None,
            "uac": None,
            "spns": [],
            "member_of": [],
            "password_last_set": None,
            "date_joined": None,
            "is_local_admin": rid == 500,  # Built-in Administrator
            "is_domain_admin": False,
            "is_privileged": rid == 500,
            "is_disabled": False,
            "password_never_expires": False,
            "never_logged_in": False,
            "never_changed_password": False,
            "last_logon_host": asset_hostname or None,
        }
        classify_identity(rec)
        users.append(rec)

    return users


# ─────────────────────────────────────────────────────────
# Plugin 10902 — Local Administrators Group
# ─────────────────────────────────────────────────────────

def extract_admins_group(plugin_output: str, asset_id: int, scan_id: int, asset_hostname: str = "") -> list[dict]:
    """Parse Administrators group members from plugin 10902."""
    if not plugin_output:
        return []

    users = []
    # Lines like:   - DOMAIN\username (User)
    #               - DOMAIN\Group Name (Group)
    pattern = re.compile(r"-\s+([^\\(]+)\\([^(]+)\s+\((\w+)\)")
    for m in pattern.finditer(plugin_output):
        domain = m.group(1).strip()
        name = m.group(2).strip()
        member_type = m.group(3).strip()  # User or Group

        if member_type == "Group":
            continue  # Groups handled separately

        is_domain_admin = False
        is_privileged = True  # All local admins are privileged

        rec = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "10902",
            "user_type": "domain_user" if domain.upper() != asset_hostname.upper() else "local_user",
            "username": name,
            "domain": domain,
            "sid": None,
            "rid": None,
            "dn": None,
            "uac": None,
            "spns": [],
            "member_of": ["Administrators"],
            "password_last_set": None,
            "date_joined": None,
            "is_local_admin": True,
            "is_domain_admin": is_domain_admin,
            "is_privileged": is_privileged,
            "is_disabled": False,
            "password_never_expires": False,
            "never_logged_in": False,
            "never_changed_password": False,
            "last_logon_host": asset_hostname or None,
        }
        classify_identity(rec)
        users.append(rec)

    return users


# ─────────────────────────────────────────────────────────
# Plugin 38689 — Last Logged-On User
# ─────────────────────────────────────────────────────────

def extract_last_logon(plugin_output: str, asset_id: int, scan_id: int, asset_hostname: str = "") -> list[dict]:
    """Parse last successful logon from plugin 38689."""
    if not plugin_output:
        return []

    m = re.search(r"Last Successful logon\s*:\s*(.+)", plugin_output)
    if not m:
        return []

    raw = m.group(1).strip()
    # Format: DOMAIN\username or .\username
    if "\\" in raw:
        parts = raw.split("\\", 1)
        domain = parts[0].strip()
        username = parts[1].strip()
        if domain == ".":
            domain = asset_hostname or "local"
    else:
        domain = asset_hostname or "local"
        username = raw

    rec = {
        "scan_id": scan_id,
        "asset_id": asset_id,
        "source_plugin": "38689",
        "user_type": "local_user" if domain in (".", asset_hostname) else "domain_user",
        "username": username,
        "domain": domain,
        "sid": None,
        "rid": None,
        "dn": None,
        "uac": None,
        "spns": [],
        "member_of": [],
        "password_last_set": None,
        "date_joined": None,
        "is_local_admin": False,
        "is_domain_admin": False,
        "is_privileged": False,
        "is_disabled": False,
        "password_never_expires": False,
        "never_logged_in": False,
        "never_changed_password": False,
        "last_logon_host": asset_hostname or None,
    }
    classify_identity(rec)
    return [rec]


# ─────────────────────────────────────────────────────────
# Plugin 69238 — AD Group Memberships
# ─────────────────────────────────────────────────────────

def extract_ad_groups(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse AD group blocks from plugin 69238."""
    if not plugin_output:
        return []

    groups = []
    # Split into group blocks — each starts with "Group         :"
    blocks = re.split(r"\n(?=Group\s+:)", plugin_output)

    for block in blocks:
        block = block.strip()
        if not block.startswith("Group"):
            continue

        group = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "69238",
            "group_name": None,
            "domain": None,
            "sid": None,
            "dn": None,
            "description": None,
            "members": [],
            "is_privileged": False,
        }

        lines = block.split("\n")
        in_members = False

        for line in lines:
            stripped = line.strip()
            if not stripped:
                in_members = False
                continue

            if line.startswith("Group") and ":" in line:
                dn = line.split(":", 1)[1].strip()
                group["dn"] = dn
                group["group_name"] = _cn_from_dn(dn)
                group["domain"] = _domain_from_dn(dn)
            elif "Object SID" in line:
                group["sid"] = line.split(":", 1)[1].strip()
            elif line.strip().startswith("CN ") and ":" in line:
                # "CN            : Domain Admins"
                group["group_name"] = line.split(":", 1)[1].strip()
            elif "Members" in line and ":" in line:
                in_members = True
            elif in_members and stripped.startswith("CN="):
                group["members"].append(stripped)

        if group["group_name"]:
            group["is_privileged"] = _is_privileged_group(group["group_name"])
            groups.append(group)

    return groups


# ─────────────────────────────────────────────────────────
# Plugin 167250 — LDAP Users (JSON format, full AD attributes)
# ─────────────────────────────────────────────────────────

def extract_ldap_users(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse LDAP user JSON from plugin 167250.

    Each line is a JSON array of [attr, [values]] pairs representing one AD object.
    This plugin provides richer data than 69239, including department, title, manager.
    """
    if not plugin_output:
        return []

    users = []
    for line in plugin_output.strip().split("\n"):
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            pairs = json.loads(line)
            attrs = {p[0]: p[1] for p in pairs if len(p) == 2}
        except (json.JSONDecodeError, Exception):
            continue

        def first(key):
            vals = attrs.get(key, [])
            return vals[0] if vals else None

        # Skip non-user objects (computers have objectClass "computer")
        obj_classes = [c.lower() for c in attrs.get("objectClass", [])]
        if "computer" in obj_classes:
            continue
        if "user" not in obj_classes and "person" not in obj_classes:
            continue

        username = first("sAMAccountName") or first("cn") or first("name")
        if not username:
            continue

        dn = first("distinguishedName") or ""
        sid = first("objectSid") or None
        uac_str = first("userAccountControl")
        uac = int(uac_str) if uac_str and uac_str.isdigit() else None

        member_of = attrs.get("memberOf", [])
        spns = attrs.get("servicePrincipalName", [])

        # Manager / department / title
        manager_dn_val = first("manager")
        manager_username = _cn_from_dn(manager_dn_val) if manager_dn_val else None
        department = first("department")
        job_title = first("title")

        # Privilege detection
        is_domain_admin = False
        is_privileged = False
        for g in member_of:
            gcn = _cn_from_dn(g).lower()
            if gcn in ("domain admins", "enterprise admins", "schema admins"):
                is_domain_admin = True
                is_privileged = True
            elif _is_privileged_group(gcn):
                is_privileged = True

        # Computer account check
        user_type = "domain_user"
        if username.endswith("$"):
            user_type = "computer_account"
        elif spns:
            user_type = "service_account"

        # UAC flags
        is_disabled = bool(uac and uac & 2)
        password_never_expires = bool(uac and uac & 65536)

        # Password last set
        pwd_last_set = first("pwdLastSet")

        # When created → date_joined
        date_joined = first("whenCreated")

        user = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "167250",
            "user_type": user_type,
            "username": username,
            "domain": _domain_from_dn(dn),
            "sid": sid,
            "rid": _rid_from_sid(sid) if sid else None,
            "dn": dn,
            "uac": uac,
            "spns": spns,
            "member_of": member_of,
            "password_last_set": pwd_last_set,
            "date_joined": date_joined,
            "is_local_admin": False,
            "is_domain_admin": is_domain_admin,
            "is_privileged": is_privileged or bool(first("adminCount")),
            "is_disabled": is_disabled,
            "password_never_expires": password_never_expires,
            "never_logged_in": first("logonCount") in (None, "0"),
            "never_changed_password": pwd_last_set in (None, "0"),
            "last_logon_host": None,
            "department": department,
            "job_title": job_title,
            "manager_dn": manager_dn_val,
            "manager_username": manager_username,
        }
        classify_identity(user)
        users.append(user)

    return users


# ─────────────────────────────────────────────────────────
# Plugin 168912 — Domain Trust Relationships (LDAP JSON)
# ─────────────────────────────────────────────────────────

_TRUST_DIRECTION = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
_TRUST_TYPE = {1: "downlevel", 2: "uplevel", 3: "mit_kerberos", 4: "dce"}


def extract_domain_trusts(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse domain trust objects from plugin 168912 (LDAP trustedDomain objects)."""
    if not plugin_output:
        return []

    trusts = []
    for line in plugin_output.strip().split("\n"):
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            pairs = json.loads(line)
            attrs = {p[0]: p[1] for p in pairs if len(p) == 2}
        except (json.JSONDecodeError, Exception):
            continue

        def first(key):
            vals = attrs.get(key, [])
            return vals[0] if vals else None

        obj_classes = [c.lower() for c in attrs.get("objectClass", [])]
        if "trusteddomain" not in obj_classes:
            continue

        trusted_domain = first("trustPartner") or first("cn") or first("name")
        if not trusted_domain:
            continue

        dn = first("distinguishedName") or ""
        direction_raw = first("trustDirection")
        direction = _TRUST_DIRECTION.get(int(direction_raw), "unknown") if direction_raw and direction_raw.isdigit() else "unknown"
        type_raw = first("trustType")
        trust_type = _TRUST_TYPE.get(int(type_raw), "unknown") if type_raw and type_raw.isdigit() else "unknown"
        attrs_raw = first("trustAttributes")
        trust_attrs = int(attrs_raw) if attrs_raw and attrs_raw.isdigit() else 0

        # trustAttributes flags:
        #   0x01 = non-transitive, 0x02 = uplevel_only, 0x04 = quarantined (SID filtering),
        #   0x08 = forest_transitive, 0x20 = within_forest
        is_transitive = bool(trust_attrs & 0x08) or bool(trust_attrs & 0x20) or not bool(trust_attrs & 0x01)
        is_sid_filtering = bool(trust_attrs & 0x04) or not bool(trust_attrs & 0x20)

        trusts.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "168912",
            "trusted_domain": trusted_domain,
            "flat_name": first("flatName"),
            "sid": first("securityIdentifier"),
            "dn": dn,
            "trust_direction": direction,
            "trust_type": trust_type,
            "trust_attributes": trust_attrs,
            "is_transitive": is_transitive,
            "is_sid_filtering_enabled": is_sid_filtering,
            "source_domain": _domain_from_dn(dn),
            "when_created": first("whenCreated"),
        })

    return trusts


# ─────────────────────────────────────────────────────────
# Plugin 167251 — LDAP Groups (JSON format)
# ─────────────────────────────────────────────────────────

def extract_ldap_groups(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse LDAP group JSON from plugin 167251."""
    if not plugin_output:
        return []

    groups = []
    # Each line is a JSON array of [attr, [values]] pairs
    for line in plugin_output.strip().split("\n"):
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            pairs = json.loads(line)
            attrs = {p[0]: p[1] for p in pairs if len(p) == 2}
        except (json.JSONDecodeError, Exception):
            continue

        def first(key):
            vals = attrs.get(key, [])
            return vals[0] if vals else None

        group_name = first("cn") or first("sAMAccountName") or first("name")
        if not group_name:
            continue

        dn = first("distinguishedName") or ""
        members = attrs.get("member", [])
        description = first("description") or None
        sid = first("objectSid") or None

        groups.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "167251",
            "group_name": group_name,
            "domain": _domain_from_dn(dn),
            "sid": sid,
            "dn": dn,
            "description": description,
            "members": members,
            "is_privileged": _is_privileged_group(group_name),
        })

    return groups


# ─────────────────────────────────────────────────────────
# Plugin 10456 — Running Services (SMB)
# ─────────────────────────────────────────────────────────

def extract_services(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse active services from plugin 10456."""
    if not plugin_output:
        return []

    services = []
    # Format: "Display Name [ ServiceName ]"  or  "ServiceName [ ServiceName ]"
    # Each service is on its own line: constrain match to a single line
    pattern = re.compile(r"^([^\[\n]+)\[\s*(\w+)\s*\]", re.MULTILINE)
    for m in pattern.finditer(plugin_output):
        display_name = m.group(1).strip().rstrip()
        service_name = m.group(2).strip()
        if service_name and display_name:
            services.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "source_plugin": "10456",
                "service_name": service_name,
                "display_name": display_name,
                "is_running": True,
            })

    return services


# ─────────────────────────────────────────────────────────
# Plugin 44401 — Service Configuration Details (SMB)
# ─────────────────────────────────────────────────────────

def extract_service_config(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse service startup type and run-as user from plugin 44401.

    Typical block format (one blank line between services):
        Display Name : Windows Update
        Short Name   : wuauserv
        Startup Type : Automatic
        Log On As    : Local System
        State        : Running
    """
    if not plugin_output:
        return []

    _STATE_MAP = {"running": True, "started": True, "stopped": False, "disabled": False}

    services = []
    # Split on blank lines to get per-service blocks
    blocks = re.split(r"\n\s*\n", plugin_output.strip())
    for block in blocks:
        if not block.strip():
            continue

        def _field(pattern: str) -> str | None:
            m = re.search(pattern, block, re.IGNORECASE)
            return m.group(1).strip() if m else None

        # Accept both "Short Name" and "Service Name" / "Service" labels
        service_name = (
            _field(r"Short\s+Name\s*[:\-]\s*(.+)") or
            _field(r"Service\s+Name\s*[:\-]\s*(.+)") or
            _field(r"^Service\s*[:\-]\s*(.+)")
        )
        display_name = _field(r"Display\s+Name\s*[:\-]\s*(.+)")
        startup_type = (
            _field(r"Startup\s+Type\s*[:\-]\s*(.+)") or
            _field(r"Start\s+Type\s*[:\-]\s*(.+)") or
            _field(r"Startup\s*[:\-]\s*(.+)")
        )
        run_as_user = (
            _field(r"Log\s+On\s+As\s*[:\-]\s*(.+)") or
            _field(r"Login\s+As\s*[:\-]\s*(.+)") or
            _field(r"Run\s+As\s*[:\-]\s*(.+)")
        )
        state_raw = _field(r"State\s*[:\-]\s*(.+)")
        is_running = _STATE_MAP.get((state_raw or "").lower().strip(), True)

        if not service_name:
            continue

        rec: dict = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "44401",
            "service_name": service_name,
            "is_running": is_running,
        }
        if display_name:
            rec["display_name"] = display_name
        if startup_type:
            rec["startup_type"] = startup_type
        if run_as_user:
            rec["run_as_user"] = run_as_user

        services.append(rec)

    return services


# ─────────────────────────────────────────────────────────
# Plugin 64582 — Netstat Connection Info (structured)
# ─────────────────────────────────────────────────────────

# Canonical TCP/UDP states — anything else (e.g. a stray PID from a Linux
# `netstat -p` line that omits the State column for UDP) is dropped so the
# column doesn't end up with values like "3892" side-by-side with "listen".
_VALID_NET_STATES = {
    "listen", "established", "syn_sent", "syn_received",
    "fin_wait_1", "fin_wait_2", "time_wait", "close", "close_wait",
    "last_ack", "closing",
}
_NET_STATE_ALIASES = {
    "listening": "listen",
    "syn-sent": "syn_sent",
    "syn_recv": "syn_received",
    "syn-received": "syn_received",
    "closed": "close",
    "close-wait": "close_wait",
    "last-ack": "last_ack",
    "fin-wait-1": "fin_wait_1",
    "fin-wait-2": "fin_wait_2",
    "time-wait": "time_wait",
}


def _normalize_net_state(raw):
    if not raw:
        return None
    s = str(raw).strip().lower()
    s = _NET_STATE_ALIASES.get(s, s)
    return s if s in _VALID_NET_STATES else None


def extract_netstat_info(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse structured netstat blocks from plugin 64582."""
    if not plugin_output:
        return []

    conns = []
    # Block format:
    # tcp4 (listen)
    #   src: [host=0.0.0.0, port=88]
    #   dst: [host=0.0.0.0, port=0]
    block_pattern = re.compile(
        r"(tcp4|tcp6|udp4|udp6)\s+\((\w+)\)\s+"
        r"src:\s+\[host=([^\]]*),\s+port=([^\]]*)\]\s+"
        r"dst:\s+\[host=([^\]]*),\s+port=([^\]]*)\]",
        re.IGNORECASE
    )
    for m in block_pattern.finditer(plugin_output):
        proto = m.group(1).lower()
        state = _normalize_net_state(m.group(2))
        local_addr = m.group(3).strip()
        local_port_str = m.group(4).strip()
        remote_addr = m.group(5).strip()
        remote_port_str = m.group(6).strip()

        try:
            local_port = int(local_port_str) if local_port_str not in ("*", "0") else 0
        except ValueError:
            local_port = 0
        try:
            remote_port = int(remote_port_str) if remote_port_str not in ("*", "0") else 0
        except ValueError:
            remote_port = 0

        conns.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "64582",
            "proto": proto,
            "state": state,
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "pid": None,
        })

    return conns


# ─────────────────────────────────────────────────────────
# Plugin 58651 — Netstat Active Connections (raw)
# ─────────────────────────────────────────────────────────

def extract_netstat_active(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse raw netstat output from plugin 58651 (Windows and Linux formats)."""
    if not plugin_output:
        return []

    conns = []

    # Windows format: Proto  Local Address  Foreign Address  State  [PID]
    # TCP    0.0.0.0:88    0.0.0.0:0    LISTENING    752
    win_pattern = re.compile(
        r"^\s*(TCP|UDP)\s+(\S+):(\S+)\s+(\S+):(\S+)\s+(\w+)(?:\s+(\d+))?",
        re.IGNORECASE | re.MULTILINE,
    )
    win_matches = list(win_pattern.finditer(plugin_output))

    if win_matches:
        for m in win_matches:
            proto = "tcp4" if m.group(1).upper() == "TCP" else "udp4"
            local_addr = m.group(2)
            local_port_str = m.group(3)
            remote_addr = m.group(4)
            remote_port_str = m.group(5)
            state = _normalize_net_state(m.group(6))
            pid_str = m.group(7)

            try:
                local_port = int(local_port_str)
            except ValueError:
                local_port = 0
            try:
                remote_port = int(remote_port_str)
            except ValueError:
                remote_port = 0

            conns.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "source_plugin": "58651",
                "proto": proto,
                "state": state,
                "local_addr": local_addr,
                "local_port": local_port,
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "pid": int(pid_str) if pid_str else None,
            })
        return conns

    # Linux format: Proto Recv-Q Send-Q Local-Address Foreign-Address State
    # tcp   0  0  0.0.0.0:80  0.0.0.0:*  LISTEN
    lin_pattern = re.compile(
        r"^\s*(tcp6?|udp6?)\s+\d+\s+\d+\s+(\S+):(\S+)\s+(\S+):(\S+)\s+(\w+)",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in lin_pattern.finditer(plugin_output):
        proto_raw = m.group(1).lower()
        proto = "tcp6" if proto_raw == "tcp6" else ("udp6" if proto_raw == "udp6" else
                "tcp4" if "tcp" in proto_raw else "udp4")
        local_addr = m.group(2)
        local_port_str = m.group(3)
        remote_addr = m.group(4)
        remote_port_str = m.group(5)
        state = _normalize_net_state(m.group(6))

        try:
            local_port = int(local_port_str)
        except ValueError:
            local_port = 0
        try:
            remote_port = int(remote_port_str) if remote_port_str != "*" else 0
        except ValueError:
            remote_port = 0

        conns.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "58651",
            "proto": proto,
            "state": state,
            "local_addr": local_addr,
            "local_port": local_port,
            "remote_addr": remote_addr,
            "remote_port": remote_port,
            "pid": None,
        })

    return conns


# ─────────────────────────────────────────────────────────
# Plugin 70625 — Scheduled Tasks
# ─────────────────────────────────────────────────────────

def extract_scheduled_tasks(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse scheduled task blocks from plugin 70625."""
    if not plugin_output:
        return []

    tasks = []
    # Split on top-level "+ Task" blocks
    task_blocks = re.split(r"\n\s+\+\s+Task\b", plugin_output)

    for block in task_blocks[1:]:  # skip header before first Task
        task = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "70625",
            "task_uri": None,
            "author": None,
            "run_as_sid": None,
            "run_as_user": None,
            "command": None,
            "arguments": None,
            "trigger_type": None,
            "logon_type": None,
            "is_enabled": True,
        }

        def _val(pattern):
            m = re.search(pattern, block)
            return m.group(1).strip() if m else None

        task["author"] = _val(r"- Author\s*:\s*(.+)")
        task["task_uri"] = _val(r"- URI\s*:\s*(.+)")
        task["run_as_sid"] = _val(r"- UserId\s*:\s*(S-1-\S+)")
        task["logon_type"] = _val(r"- LogonType\s*:\s*(.+)")
        task["command"] = _val(r"- Command\s*:\s*(.+)")
        task["arguments"] = _val(r"- Arguments\s*:\s*(.+)")

        # Trigger type — look for the trigger element name
        tm = re.search(r"\+\s+([\w]+Trigger)\b", block)
        if tm:
            task["trigger_type"] = tm.group(1)

        if task["task_uri"] or task["command"]:
            tasks.append(task)

    return tasks


# ─────────────────────────────────────────────────────────
# Plugin 66334 — Patch Report
# ─────────────────────────────────────────────────────────

def extract_patch_report(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse missing KB patches from plugin 66334."""
    if not plugin_output:
        return []

    patches = []

    # Match KB lines: "- KB5046615 (41 vulnerabilities)" or "- KB5046615"
    kb_pattern = re.compile(r"-\s+(KB\d+)(?:\s+\((\d+)\s+vulnerabilit\w+\))?")
    # Match CVE lists after "Impact" sections
    cve_pattern = re.compile(r"CVE-\d{4}-\d+")

    # Also match advisory-style patches with descriptions
    # "[ Advisory title ]" followed by action text
    advisory_pattern = re.compile(
        r"\[\s*([^\]]+)\s*\]\s*\n\s*\+\s*Action to take\s*:\s*([^\n]+)",
        re.IGNORECASE
    )

    # First pass: KB-style patches (Microsoft)
    for m in kb_pattern.finditer(plugin_output):
        kb_id = m.group(1)
        vuln_count = int(m.group(2)) if m.group(2) else 0

        # Find CVEs in the vicinity (within ~500 chars after this KB mention)
        start = m.end()
        snippet = plugin_output[start:start + 600]
        cves = list(dict.fromkeys(cve_pattern.findall(snippet)))

        patches.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "66334",
            "kb_id": kb_id,
            "vuln_count": vuln_count,
            "description": None,
            "cves": cves,
        })

    # Second pass: advisory-style patches (Linux, third-party)
    for m in advisory_pattern.finditer(plugin_output):
        title = m.group(1).strip()
        action = m.group(2).strip()

        # Find CVEs in the vicinity
        start = m.end()
        snippet = plugin_output[start:start + 400]
        cves = list(dict.fromkeys(cve_pattern.findall(snippet)))

        patches.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "66334",
            "kb_id": title[:120],   # Use title as pseudo-ID
            "vuln_count": len(cves),
            "description": action,
            "cves": cves,
        })

    return patches


# ─────────────────────────────────────────────────────────
# Plugin 161502 — Logged On Users
# ─────────────────────────────────────────────────────────

def extract_logged_on(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse currently logged-on users from plugin 161502."""
    if not plugin_output:
        return []

    logged = []
    # Block format:
    #   - S-1-5-21-...-500
    #     Domain   : DOMAIN
    #     Username : Administrator
    sid_blocks = re.split(r"\n\s+-\s+(S-1-\S+)", plugin_output)

    i = 1
    while i < len(sid_blocks):
        sid = sid_blocks[i].strip()
        block = sid_blocks[i + 1] if i + 1 < len(sid_blocks) else ""

        domain_m = re.search(r"Domain\s*:[ \t]*(.+)", block)
        user_m = re.search(r"Username\s*:[ \t]*(.+)", block)

        logged.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "161502",
            "sid": sid,
            "domain": (domain_m.group(1).strip() or None) if domain_m else None,
            "username": (user_m.group(1).strip() or None) if user_m else None,
        })
        i += 2

    return logged


# ─────────────────────────────────────────────────────────
# Plugin 10395 — SMB Shares enumerated
# ─────────────────────────────────────────────────────────

_DEFAULT_SHARES = {"admin$", "c$", "d$", "e$", "ipc$", "print$", "netlogon", "sysvol"}

def extract_smb_shares(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse SMB share list from plugin 10395."""
    if not plugin_output:
        return []

    shares = []
    # Format:  - ADMIN$ : Remote Admin
    #          - C$     : Default share
    pattern = re.compile(r"-\s+(\S+)\s*(?::\s*(.*))?", re.MULTILINE)
    for m in pattern.finditer(plugin_output):
        share_name = m.group(1).strip()
        comment = (m.group(2) or "").strip()
        if not share_name:
            continue
        shares.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "10395",
            "share_name": share_name,
            "share_type": "Disk",
            "comment": comment or None,
            "path": None,
            "max_users": None,
            "acl": [],
            "is_writeable": False,
            "is_default_share": share_name.lower() in _DEFAULT_SHARES,
        })
    return shares


# ─────────────────────────────────────────────────────────
# Plugin 60119 — SMB Share Permissions
# ─────────────────────────────────────────────────────────

def extract_share_permissions(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse SMB share ACL from plugin 60119.

    Handles the common Nessus format:
        - SHARE_NAME - (readable,writable)
          + Type: DISK
          + Path: C:\\path
          + Access control:
            - Account [0x1f01ff] : Full Control

    Also handles the older Path:-first format as a fallback.
    """
    if not plugin_output:
        return []

    shares = []

    # Primary format: blocks start with "- SHARENAME - (readable,...)"
    # e.g.  "- Users - (readable,writable)"  or  "- ADMIN$ - (readable,not writable)"
    block_pattern = re.compile(
        r"^-\s+(\S+)\s*-\s*\(([^)]+)\)",
        re.MULTILINE,
    )
    ace_pattern = re.compile(r"-\s+([^\[]+)\[([^\]]+)\]\s*:\s*(.+)")

    block_starts = [(m.start(), m.group(1), m.group(2)) for m in block_pattern.finditer(plugin_output)]

    if block_starts:
        for idx, (start, share_name, access_flags) in enumerate(block_starts):
            end = block_starts[idx + 1][0] if idx + 1 < len(block_starts) else len(plugin_output)
            block = plugin_output[start:end]

            path_m = re.search(r"\+\s*Path\s*:\s*(.+)", block, re.IGNORECASE)
            path = path_m.group(1).strip() if path_m else None

            # Writability from header "(readable,writable)" or "(readable,not writable)"
            flags_lower = access_flags.lower()
            is_writeable = "writable" in flags_lower and "not writable" not in flags_lower

            acl = []
            for ace in ace_pattern.finditer(block):
                account = ace.group(1).strip()
                ace_type = ace.group(2).strip()
                permissions = ace.group(3).strip()
                if not is_writeable and (
                    "write" in permissions.lower()
                    or "full" in permissions.lower()
                    or "change" in permissions.lower()
                ):
                    is_writeable = True
                acl.append({"account": account, "type": ace_type, "permissions": permissions})

            shares.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "source_plugin": "60119",
                "share_name": share_name,
                "share_type": "Disk",
                "comment": None,
                "path": path,
                "max_users": None,
                "acl": acl,
                "is_writeable": is_writeable,
                "is_default_share": share_name.lower() in _DEFAULT_SHARES,
            })
        return shares

    # Fallback: older format where each block starts with "Path:"
    blocks = re.split(r"\n(?=Path\s*:)", plugin_output, flags=re.IGNORECASE)
    for block in blocks:
        block = block.strip()
        if not block:
            continue

        path_m = re.search(r"Path\s*:\s*(.+)", block, re.IGNORECASE)
        name_m = re.search(r"Share\s+[Nn]ame\s*:\s*(.+)", block, re.IGNORECASE)
        share_name = name_m.group(1).strip() if name_m else None
        path = path_m.group(1).strip() if path_m else None
        if not share_name and not path:
            continue

        acl = []
        is_writeable = False
        for ace in ace_pattern.finditer(block):
            account = ace.group(1).strip()
            ace_type = ace.group(2).strip()
            permissions = ace.group(3).strip()
            if "write" in permissions.lower() or "full" in permissions.lower() or "change" in permissions.lower():
                is_writeable = True
            acl.append({"account": account, "type": ace_type, "permissions": permissions})

        shares.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "60119",
            "share_name": share_name or (path or "").split("\\")[-1],
            "share_type": "Disk",
            "comment": None,
            "path": path,
            "max_users": None,
            "acl": acl,
            "is_writeable": is_writeable,
            "is_default_share": (share_name or "").lower() in _DEFAULT_SHARES,
        })
    return shares


# ─────────────────────────────────────────────────────────
# Plugin 20811 / 22869 — Installed Software
# ─────────────────────────────────────────────────────────

_VENDOR_KEYWORDS = [
    ("Microsoft",            ["microsoft", "windows", "office", "visual studio", "ms ", ".net", "sysinternals", "xbox", "skype", "teams"]),
    ("Google",               ["google", "chrome", "picasa"]),
    ("Mozilla",              ["mozilla", "firefox", "thunderbird"]),
    ("Adobe",                ["adobe", "acrobat", "reader", "photoshop", "flash"]),
    ("Oracle",               ["oracle", "java", "jdk", "jre", "virtualbox", "mysql"]),
    ("Apple",                ["apple", "itunes", "icloud", "bonjour", "safari"]),
    ("Cisco",                ["cisco", "webex", "anyconnect"]),
    ("VMware",               ["vmware"]),
    ("Citrix",               ["citrix"]),
    ("Slack",                ["slack"]),
    ("Zoom",                 ["zoom"]),
    ("Amazon",               ["amazon", "aws", "kindle"]),
    ("Dropbox",              ["dropbox"]),
    ("7-Zip",                ["7-zip"]),
    ("WinRAR",               ["winrar"]),
    ("PuTTY",                ["putty"]),
    ("OpenSSH",              ["openssh"]),
    ("Python Software Foundation", ["python "]),
    ("Node.js",              ["node.js", "nodejs"]),
    ("Git",                  ["git "]),
    ("CrowdStrike",          ["crowdstrike", "falcon"]),
    ("SentinelOne",          ["sentinelone"]),
    ("Sophos",               ["sophos"]),
    ("Kaspersky",            ["kaspersky"]),
    ("Broadcom / Symantec",  ["symantec", "norton"]),
    ("Trellix",              ["mcafee", "trellix"]),
    ("Trend Micro",          ["trend micro"]),
    ("ESET",                 ["eset"]),
    ("Bitdefender",          ["bitdefender"]),
]


_SOFTWARE_CATEGORIES = [
    ("Security",       ["crowdstrike", "falcon", "sentinelone", "sophos", "kaspersky", "symantec",
                        "norton", "mcafee", "trellix", "trend micro", "eset", "bitdefender",
                        "malwarebytes", "defender", "webroot", "cylance", "carbon black",
                        "palo alto", "fortinet", "forticlient", "checkpoint", "cybereason",
                        "deep instinct", "avast", "avg ", "comodo", "f-secure"]),
    ("Dev Tools",      ["visual studio", "vscode", "intellij", "pycharm", "eclipse", "xcode",
                        "android studio", "sublime", "notepad++", "atom ", "git ", "github",
                        "python ", "node.js", "nodejs", "ruby", "perl ", "php ", "golang",
                        "rust ", "cmake", "gradle", "maven", "docker", "kubernetes",
                        "vagrant", "terraform", "ansible", "jenkins", "jdk", "jre",
                        "sdk", "compiler", "debugger", "postman", "insomnia", "fiddler",
                        "wireshark", "wsl", "mingw", "cygwin", "powershell", "windbg",
                        ".net framework", ".net runtime", ".net sdk", "nuget"]),
    ("Collaboration",  ["teams", "slack", "zoom", "webex", "skype", "discord", "telegram",
                        "signal", "mattermost", "google chat", "google meet", "gotomeeting",
                        "ringcentral", "bluejeans", "jitsi"]),
    ("Productivity",   ["office", "microsoft 365", "libreoffice", "openoffice", "word",
                        "excel", "powerpoint", "outlook", "onenote", "acrobat", "reader",
                        "foxit", "notepad", "evernote", "notion", "obsidian", "confluence"]),
    ("Browser",        ["chrome", "firefox", "edge", "safari", "opera", "brave", "vivaldi",
                        "internet explorer", "chromium", "tor browser"]),
    ("Remote Access",  ["putty", "openssh", "winscp", "filezilla", "mremoteng", "realvnc",
                        "tightvnc", "teamviewer", "anydesk", "citrix receiver", "citrix workspace",
                        "vmware horizon", "rdp", "rdesktop", "mstsc", "royal ts",
                        "anyconnect", "globalprotect", "openvpn", "wireguard"]),
    ("Virtualization", ["vmware", "virtualbox", "hyper-v", "parallels", "qemu", "kvm",
                        "proxmox", "vagrant", "docker desktop"]),
    ("Cloud & Storage",["onedrive", "dropbox", "google drive", "box sync", "icloud",
                        "aws cli", "azure cli", "gcloud", "s3 browser", "nextcloud",
                        "owncloud", "sharefile", "carbonite"]),
    ("Database",       ["mysql", "postgresql", "sql server", "sqlite", "mongodb", "oracle db",
                        "mariadb", "redis", "elasticsearch", "ssms", "pgadmin",
                        "dbeaver", "datagrip", "toad "]),
    ("Media",          ["vlc", "itunes", "spotify", "audacity", "obs studio", "handbrake",
                        "photoshop", "gimp", "illustrator", "inkscape", "blender",
                        "premiere", "after effects", "davinci", "picasa", "irfanview",
                        "media player", "quicktime", "foobar"]),
    ("Utilities",      ["7-zip", "winrar", "winzip", "ccleaner", "everything search",
                        "sysinternals", "autoruns", "procmon", "process explorer",
                        "treesizefree", "rufus", "etcher", "crystaldiskinfo",
                        "hwinfo", "cpu-z", "gpu-z", "speccy"]),
    ("Networking",     ["nmap", "wireshark", "npcap", "winpcap", "tcpdump", "netcat",
                        "traceroute", "angry ip", "advanced ip scanner", "lansweeper",
                        "solarwinds", "snmp", "dns ", "dhcp"]),
]


def _classify_software(name: str) -> str | None:
    if not name:
        return None
    n = name.lower()
    for category, keywords in _SOFTWARE_CATEGORIES:
        if any(kw in n for kw in keywords):
            return category
    return None


def _infer_vendor(name: str) -> str | None:
    if not name:
        return None
    n = name.lower()
    for vendor, keywords in _VENDOR_KEYWORDS:
        if any(kw in n for kw in keywords):
            return vendor
    return None


def extract_installed_software(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse installed software list from plugins 20811 / 22869."""
    if not plugin_output:
        return []

    software = []
    # Format: "Name [version X] [installed on date]"
    # or just: "  ProductName\n"
    line_pattern = re.compile(
        r"^\s+(.+?)\s+\[(?:version\s+)?([^\]]+)\](?:\s+\[installed on ([^\]]+)\])?",
        re.MULTILINE | re.IGNORECASE,
    )

    matched = False
    for m in line_pattern.finditer(plugin_output):
        name = m.group(1).strip()
        version = (m.group(2) or "").strip()
        installed_on = (m.group(3) or "").strip() or None
        if name:
            matched = True
            software.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "source_plugin": "20811",
                "name": name,
                "version": version or None,
                "installed_on": installed_on,
                "vendor": _infer_vendor(name),
                "category": _classify_software(name),
            })

    # Fallback: plain indented list (one entry per line)
    if not matched:
        for line in plugin_output.splitlines():
            line = line.strip()
            if line and not line.startswith(("The following", "This plugin")):
                software.append({
                    "scan_id": scan_id,
                    "asset_id": asset_id,
                    "source_plugin": "20811",
                    "name": line,
                    "version": None,
                    "installed_on": None,
                    "vendor": _infer_vendor(line),
                    "category": _classify_software(line),
                })

    return software


# ─────────────────────────────────────────────────────────
# Auto-update status enrichment (correlates services ↔ software)
# ─────────────────────────────────────────────────────────

# Maps service name patterns → (software name keywords, vendor).
# If the service exists and is automatic → "enabled"; disabled → "disabled".
_UPDATER_SERVICE_MAP = [
    # Google Chrome / Google products
    (["googleupdater", "googleupdate", "gupdate", "gupdatem"],
     ["chrome", "google earth", "google drive"],
     "Google"),
    # Mozilla Firefox
    (["mozillamaintenance"],
     ["firefox", "thunderbird"],
     "Mozilla"),
    # Windows Update (wuauserv) — covers OS-level patching
    (["wuauserv", "waasmedicsvc", "usosvc"],
     ["windows"],
     "Microsoft"),
    # Adobe updater
    (["adobearmservice", "adobeupdateservice", "armsvc"],
     ["acrobat", "adobe reader", "adobe creative", "photoshop", "illustrator"],
     "Adobe"),
    # Brave browser
    (["brave update service", "braveupdateservice"],
     ["brave"],
     "Brave"),
    # Microsoft Edge
    (["edgeupdate", "microsoftedgeupdate"],
     ["edge"],
     "Microsoft"),
    # Zoom
    (["zoomupdater"],
     ["zoom"],
     "Zoom"),
    # TeamViewer
    (["teamviewerupdater"],
     ["teamviewer"],
     "TeamViewer"),
]


def enrich_software_auto_update(
    software_records: list[dict],
    service_records: list[dict],
) -> list[dict]:
    """Correlate updater services with installed software to set auto_update_status.

    For each asset, checks whether known updater services are present and
    what their startup_type is:
      - Service present + automatic → "enabled"
      - Service present + disabled/manual → "disabled"
      - No matching service found → left as None (unknown)

    Mutates software_records in place and returns them.
    """
    if not software_records or not service_records:
        return software_records

    # Build per-asset service index: {asset_id: {service_name_lower: startup_type}}
    asset_services: dict[int, dict[str, str]] = {}
    for svc in service_records:
        aid = svc.get("asset_id")
        if aid is None:
            continue
        svc_name = (svc.get("service_name") or "").lower()
        if not svc_name:
            continue
        if aid not in asset_services:
            asset_services[aid] = {}
        # Prefer records with startup_type set (from plugin 44401 over 10456)
        existing = asset_services[aid].get(svc_name)
        startup = (svc.get("startup_type") or "").lower()
        if existing is None or startup:
            asset_services[aid][svc_name] = startup

    _AUTO_TYPES = {"automatic", "auto_start", "auto", "delayed-start", "automatic (delayed start)"}
    _DISABLED_TYPES = {"disabled", "manual", "demand_start"}

    for sw in software_records:
        aid = sw.get("asset_id")
        if aid not in asset_services:
            continue

        svcs = asset_services[aid]
        sw_name_lower = (sw.get("name") or "").lower()
        if not sw_name_lower:
            continue

        for svc_patterns, sw_keywords, _vendor in _UPDATER_SERVICE_MAP:
            # Does this software match any keyword for this updater?
            if not any(kw in sw_name_lower for kw in sw_keywords):
                continue

            # Check if any of the updater services exist for this asset
            for svc_pattern in svc_patterns:
                # Match by substring since service names may have version suffixes
                matched_startup = None
                for svc_name, startup in svcs.items():
                    if svc_pattern in svc_name:
                        matched_startup = startup
                        break

                if matched_startup is not None:
                    if matched_startup in _AUTO_TYPES or not matched_startup:
                        # Running or automatic = enabled (no startup_type often
                        # means it was found running via plugin 10456)
                        sw["auto_update_status"] = "enabled"
                    elif matched_startup in _DISABLED_TYPES:
                        sw["auto_update_status"] = "disabled"
                    else:
                        sw["auto_update_status"] = "unknown"
                    break
            else:
                continue
            break  # Found a match for this software, move to next

    return software_records


# ─────────────────────────────────────────────────────────
# Plugin 131023 / 16193 — Windows Defender / AV
# ─────────────────────────────────────────────────────────

def extract_av_info(plugin_output: str, asset_id: int, scan_id: int, plugin_id: str = "131023") -> list[dict]:
    """Parse AV product info from plugins 131023 (Defender) and 16193 (AV check)."""
    if not plugin_output:
        return []

    controls = []
    product_m = re.search(r"(?:Product|Antivirus)\s*:\s*(.+)", plugin_output, re.IGNORECASE)
    version_m = re.search(r"(?:Engine\s+)?[Vv]ersion\s*:\s*(.+)", plugin_output, re.IGNORECASE)
    sig_m = re.search(r"(?:Signature|Definition)\s+[Dd]ate\s*:\s*(.+)", plugin_output, re.IGNORECASE)
    enabled_m = re.search(r"(?:Real[- ]time|On[- ]access|Status)\s*:\s*(\w+)", plugin_output, re.IGNORECASE)
    up_to_date_m = re.search(r"(?:Up-?to-?date|Signatures?\s+up-?to-?date)\s*:\s*(\w+)", plugin_output, re.IGNORECASE)

    product_name = product_m.group(1).strip() if product_m else None

    # If no explicit product field, try to find it from context
    if not product_name:
        for line in plugin_output.splitlines():
            line = line.strip()
            if line and not any(c in line for c in (":", "=")):
                product_name = line
                break

    # Last resort: use known product names per plugin
    if not product_name:
        _PLUGIN_DEFAULT_PRODUCT = {
            "131023": "Windows Defender Antivirus",
            "16193":  "Antivirus (Generic)",
        }
        product_name = _PLUGIN_DEFAULT_PRODUCT.get(plugin_id)

    is_enabled = True
    if enabled_m:
        is_enabled = enabled_m.group(1).strip().lower() in ("enabled", "active", "running", "true", "yes", "on")

    is_up_to_date = None
    if up_to_date_m:
        is_up_to_date = up_to_date_m.group(1).strip().lower() in ("yes", "true", "current", "ok")

    # Infer vendor from product name
    vendor = None
    if product_name:
        pn_lower = product_name.lower()
        if "defender" in pn_lower or "windows" in pn_lower:
            vendor = "Microsoft"
        elif "crowdstrike" in pn_lower or "falcon" in pn_lower:
            vendor = "CrowdStrike"
        elif "sentinelone" in pn_lower or "sentinel" in pn_lower:
            vendor = "SentinelOne"
        elif "sophos" in pn_lower:
            vendor = "Sophos"
        elif "kaspersky" in pn_lower:
            vendor = "Kaspersky"
        elif "symantec" in pn_lower or "sep" == pn_lower:
            vendor = "Broadcom / Symantec"
        elif "mcafee" in pn_lower or "trellix" in pn_lower:
            vendor = "Trellix"
        elif "trend micro" in pn_lower:
            vendor = "Trend Micro"
        elif "eset" in pn_lower:
            vendor = "ESET"
        elif "bitdefender" in pn_lower:
            vendor = "Bitdefender"

    controls.append({
        "scan_id": scan_id,
        "asset_id": asset_id,
        "source_plugin": plugin_id,
        "control_type": "av",
        "product_name": product_name,
        "vendor": vendor,
        "version": version_m.group(1).strip() if version_m else None,
        "is_enabled": is_enabled,
        "is_up_to_date": is_up_to_date,
        "signature_date": sig_m.group(1).strip() if sig_m else None,
        "details": {},
    })
    return controls


# ─────────────────────────────────────────────────────────
# Plugin 56310 — Windows Firewall
# ─────────────────────────────────────────────────────────

def extract_firewall_info(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse Windows Firewall status from plugin 56310."""
    if not plugin_output:
        return []

    # Profiles: Domain, Private, Public — look for enabled/disabled per profile
    details = {}
    is_enabled = False
    for m in re.finditer(r"(Domain|Private|Public)\s+Profile\s*:?\s*(Enabled|Disabled)", plugin_output, re.IGNORECASE):
        profile = m.group(1)
        state = m.group(2)
        details[profile] = state
        if state.lower() == "enabled":
            is_enabled = True

    # Fallback: look for any "enabled" mention
    if not details:
        is_enabled = bool(re.search(r"\benabled\b", plugin_output, re.IGNORECASE))

    return [{
        "scan_id": scan_id,
        "asset_id": asset_id,
        "source_plugin": "56310",
        "control_type": "firewall",
        "product_name": "Windows Firewall",
        "vendor": "Microsoft",
        "version": None,
        "is_enabled": is_enabled,
        "is_up_to_date": None,
        "signature_date": None,
        "details": details,
    }]


# ─────────────────────────────────────────────────────────
# Plugin 69236 — AD Computer Objects
# ─────────────────────────────────────────────────────────

def extract_ad_computers(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse AD computer objects from plugin 69236."""
    if not plugin_output:
        return []

    computers = []
    # Split into computer blocks — each starts with "Computer      :"
    blocks = re.split(r"\n(?=Computer\s+:)", plugin_output)

    for block in blocks:
        block = block.strip()
        if not block.startswith("Computer"):
            continue

        comp = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "69236",
            "computer_name": None,
            "dns_hostname": None,
            "os": None,
            "os_version": None,
            "sid": None,
            "dn": None,
            "is_domain_controller": False,
            "is_disabled": False,
            "uac": None,
            "date_joined": None,
        }

        for line in block.splitlines():
            stripped = line.strip()
            if line.startswith("Computer") and ":" in line:
                dn = line.split(":", 1)[1].strip()
                comp["dn"] = dn
                comp["computer_name"] = _cn_from_dn(dn).rstrip("$")
            elif "DNS Host Name" in line or "dNSHostName" in line:
                comp["dns_hostname"] = line.split(":", 1)[1].strip()
            elif "Operating System Version" in line:
                comp["os_version"] = line.split(":", 1)[1].strip()
            elif "Operating System" in line and "Version" not in line:
                comp["os"] = line.split(":", 1)[1].strip()
            elif "Object SID" in line:
                comp["sid"] = line.split(":", 1)[1].strip()
            elif "User Account Control" in line:
                try:
                    uac = int(line.split(":", 1)[1].strip())
                    comp["uac"] = uac
                    if uac & 2:
                        comp["is_disabled"] = True
                    # UAC 8192 = SERVER_TRUST_ACCOUNT (domain controller)
                    if uac & 8192:
                        comp["is_domain_controller"] = True
                except (ValueError, IndexError):
                    pass
            elif "Date Joined" in line:
                comp["date_joined"] = line.split(":", 1)[1].strip()

        if comp["computer_name"]:
            computers.append(comp)

    return computers


# ─────────────────────────────────────────────────────────
# Plugin 167252 — LDAP Computers (JSON format)
# ─────────────────────────────────────────────────────────

def extract_ldap_computers(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse LDAP computer JSON from plugin 167252."""
    if not plugin_output:
        return []

    computers = []
    for line in plugin_output.strip().split("\n"):
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            pairs = json.loads(line)
            attrs = {p[0]: p[1] for p in pairs if len(p) == 2}
        except (json.JSONDecodeError, Exception):
            continue

        def first(key):
            vals = attrs.get(key, [])
            return vals[0] if vals else None

        computer_name = first("cn") or first("sAMAccountName") or first("name")
        if not computer_name:
            continue

        dn = first("distinguishedName") or ""
        uac_raw = first("userAccountControl")
        try:
            uac = int(uac_raw) if uac_raw else None
        except (ValueError, TypeError):
            uac = None

        is_disabled = bool(uac and uac & 2)
        is_dc = bool(uac and uac & 8192)

        computers.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "source_plugin": "167252",
            "computer_name": computer_name.rstrip("$"),
            "dns_hostname": first("dNSHostName"),
            "os": first("operatingSystem"),
            "os_version": first("operatingSystemVersion"),
            "sid": first("objectSid"),
            "dn": dn,
            "is_domain_controller": is_dc,
            "is_disabled": is_disabled,
            "uac": uac,
            "date_joined": first("whenCreated"),
        })

    return computers


# ─────────────────────────────────────────────────────────
# Plugin 17651 — Password Policy
# ─────────────────────────────────────────────────────────

def extract_password_policy(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse domain password policy from plugin 17651."""
    if not plugin_output:
        return []

    def _int(pattern):
        m = re.search(pattern, plugin_output, re.IGNORECASE)
        if not m:
            return None
        try:
            return int(m.group(1).strip())
        except (ValueError, AttributeError):
            return None

    def _bool_flag(pattern):
        m = re.search(pattern, plugin_output, re.IGNORECASE)
        if not m:
            return None
        val = m.group(1).strip().lower()
        return val in ("enabled", "yes", "true", "1", "on")

    # Domain
    domain_m = re.search(r"(?:Domain|Domaine)\s*:\s*(.+)", plugin_output, re.IGNORECASE)
    domain = domain_m.group(1).strip() if domain_m else None

    # Support both verbose ("Minimum Password Length") and short ("Minimum password len") forms
    min_length = _int(r"[Mm]inimum\s+[Pp]assword\s+(?:[Ll]ength|[Ll]en)\s*:\s*(\d+)")
    history = _int(r"[Pp]assword\s+[Hh]istory\s+(?:[Ss]ize|[Ll]en)\s*:\s*(\d+)")
    max_age = _int(r"[Mm]aximum\s+[Pp]assword\s+[Aa]ge\s*(?:\([^)]*\))?\s*:\s*(\d+)")
    min_age = _int(r"[Mm]inimum\s+[Pp]assword\s+[Aa]ge\s*(?:\([^)]*\))?\s*:\s*(\d+)")
    # "Password must meet complexity requirements: Enabled" or "Password Complexity: Enabled"
    complexity = _bool_flag(r"[Pp]assword\s+(?:[Cc]omplexity|must\s+meet\s+complexity\s+requirements)\s*:\s*(\w+)")
    reversible = _bool_flag(r"[Rr]eversible\s+[Ee]ncryption\s*:\s*(\w+)")
    # "Number of invalid logon before locked out (s): 0" or "Lockout Threshold: 0"
    lockout_threshold = _int(r"(?:[Ll]ockout\s+[Tt]hreshold|[Nn]umber\s+of\s+invalid\s+logon\s+before\s+locked\s+out\s*(?:\([^)]*\))?)\s*:\s*(\d+)")
    # "Locked account time (s): 1800" or "Lockout Duration (mins): 30"
    lockout_duration_raw = _int(r"(?:[Ll]ockout\s+[Dd]uration|[Ll]ocked\s+account\s+time)\s*(?:\([^)]*\))?\s*:\s*(\d+)")
    lockout_window_raw = _int(r"(?:[Ll]ockout\s+(?:[Oo]bservation\s+[Ww]indow|[Ww]indow)|[Tt]ime\s+between\s+failed\s+logon)\s*(?:\([^)]*\))?\s*:\s*(\d+)")

    # Detect if values are in seconds (plugin uses "(s)") and convert to minutes
    _in_seconds = bool(re.search(r"[Ll]ocked\s+account\s+time\s*\(s\)", plugin_output))
    if _in_seconds:
        lockout_duration = lockout_duration_raw // 60 if lockout_duration_raw is not None else None
        lockout_window = lockout_window_raw // 60 if lockout_window_raw is not None else None
    else:
        lockout_duration = lockout_duration_raw
        lockout_window = lockout_window_raw

    is_weak = (
        (min_length is not None and min_length < 8) or
        (complexity is False) or
        (lockout_threshold == 0)
    )

    return [{
        "scan_id": scan_id,
        "asset_id": asset_id,
        "source_plugin": "17651",
        "domain": domain,
        "min_length": min_length,
        "history_count": history,
        "max_age_days": max_age,
        "min_age_days": min_age,
        "complexity_enabled": complexity,
        "reversible_encryption": reversible,
        "lockout_threshold": lockout_threshold,
        "lockout_duration_mins": lockout_duration,
        "lockout_window_mins": lockout_window,
        "is_weak": is_weak,
    }]


# ─────────────────────────────────────────────────────────
# Plugin 92364 — Windows Environment Variables
# ─────────────────────────────────────────────────────────

_SENSITIVE_ENV_PATTERNS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "token", "credential", "private", "symmetric_key", "encrypted",
    "access_key", "access_token", "certpassword", "privatekey",
}


def _is_sensitive_env_var(name: str) -> bool:
    n = name.lower()
    return any(p in n for p in _SENSITIVE_ENV_PATTERNS)


def extract_ssl_certificate(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """
    Plugin 10863 — SSL Certificate Information.
    Parses one certificate per finding (each finding = one cert on one port).
    """
    from datetime import datetime

    def _parse_dn_block(text: str) -> dict:
        result = {}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r'Country\s*:\s*(.+)', line)
            if m:
                result['c'] = m.group(1).strip()
                continue
            m = re.match(r'Organization\s*:\s*(.+)', line)
            if m and 'Unit' not in line:
                result['o'] = m.group(1).strip()
                continue
            m = re.match(r'Organ(?:izational|ization)\s*Unit\s*:\s*(.+)', line, re.IGNORECASE)
            if m:
                result['ou'] = m.group(1).strip()
                continue
            m = re.match(r'Common Name\s*:\s*(.+)', line, re.IGNORECASE)
            if m:
                result['cn'] = m.group(1).strip()
                continue
            m = re.match(r'Email Address\s*:\s*(.+)', line, re.IGNORECASE)
            if m:
                result['email'] = m.group(1).strip()
        return result

    def _parse_date(raw: str):
        raw = re.sub(r'\s+', ' ', raw.strip()).replace(' GMT', '').strip()
        for fmt in ("%b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                pass
        return None

    cert: dict = {
        "asset_id": asset_id, "scan_id": scan_id, "source_plugin": "10863",
        "subject_cn": None, "subject_o": None, "subject_ou": None,
        "subject_c": None, "subject_email": None,
        "issuer_cn": None, "issuer_o": None, "issuer_ou": None, "issuer_c": None,
        "serial_number": None, "not_before": None, "not_after": None,
        "is_expired": False, "days_until_expiry": None,
        "signature_algorithm": None, "key_algorithm": None, "key_bits": None,
        "subject_alt_names": [], "is_ca": False, "is_self_signed": False,
        "port": None, "protocol": None,
    }

    # Split into top-level sections by finding section headers
    # We'll detect Subject Name / Issuer Name blocks and other fields
    lines = plugin_output.splitlines()
    section = None
    section_lines: list[str] = []

    def _flush_section():
        if section and section_lines:
            dn = _parse_dn_block("\n".join(section_lines))
            if section == "subject":
                cert.update({
                    "subject_cn": dn.get("cn"), "subject_o": dn.get("o"),
                    "subject_ou": dn.get("ou"), "subject_c": dn.get("c"),
                    "subject_email": dn.get("email"),
                })
            elif section == "issuer":
                cert.update({
                    "issuer_cn": dn.get("cn"), "issuer_o": dn.get("o"),
                    "issuer_ou": dn.get("ou"), "issuer_c": dn.get("c"),
                })

    TOP_LEVEL = re.compile(
        r'^(Serial Number|Version|Signature Algorithm|Not Valid Before|Not Valid After'
        r'|Public Key Info|Subject Alternative Name|Basic Constraints|Key Usage'
        r'|Extended Key Usage|Fingerprints|Thumbprint|Certificate)\s*:',
        re.IGNORECASE,
    )
    in_pubkey = False

    for line in lines:
        stripped = line.strip()

        # Detect start of Subject / Issuer blocks
        if re.match(r'^Subject Name\s*:', stripped, re.IGNORECASE):
            _flush_section()
            section = "subject"
            section_lines = []
            continue
        if re.match(r'^Issuer Name\s*:', stripped, re.IGNORECASE):
            _flush_section()
            section = "issuer"
            section_lines = []
            continue

        # Detect start of a top-level field → close current section
        if TOP_LEVEL.match(stripped):
            _flush_section()
            section = None
            section_lines = []
            in_pubkey = re.match(r'^Public Key Info\s*:', stripped, re.IGNORECASE) is not None

        if section in ("subject", "issuer"):
            section_lines.append(line)
            continue

        # Serial Number
        m = re.match(r'Serial Number\s*:\s*(.+)', stripped, re.IGNORECASE)
        if m:
            cert["serial_number"] = m.group(1).strip()
            continue

        # Signature Algorithm
        m = re.match(r'Signature Algorithm\s*:\s*(.+)', stripped, re.IGNORECASE)
        if m:
            cert["signature_algorithm"] = m.group(1).strip()
            continue

        # Validity dates
        m = re.match(r'Not Valid Before\s*:\s*(.+)', stripped, re.IGNORECASE)
        if m:
            cert["not_before"] = m.group(1).strip()
            continue
        m = re.match(r'Not Valid After\s*:\s*(.+)', stripped, re.IGNORECASE)
        if m:
            cert["not_after"] = m.group(1).strip()
            continue

        # Public Key Info sub-fields
        if in_pubkey:
            m = re.match(r'\s+Algorithm\s*:\s*(.+)', line)
            if m and not cert.get("key_algorithm"):
                cert["key_algorithm"] = m.group(1).strip()
                continue
            m = re.match(r'\s+Key (?:Length|Size)\s*:\s*(\d+)', line, re.IGNORECASE)
            if m:
                cert["key_bits"] = int(m.group(1))
                continue

        # Subject Alternative Names
        m = re.match(r'Subject Alternative Name\s*:\s*(.+)', stripped, re.IGNORECASE)
        if m:
            san_raw = m.group(1).strip()
            cert["subject_alt_names"] = [s.strip() for s in san_raw.split(',') if s.strip()]
            continue

        # Is CA
        m = re.match(r'\s+Is a CA certificate\s*:\s*(.+)', line, re.IGNORECASE)
        if m:
            cert["is_ca"] = m.group(1).strip().upper() in ('TRUE', 'YES', '1')
            continue

    _flush_section()

    # is_self_signed: subject CN == issuer CN (or full O/CN match)
    scn = (cert.get("subject_cn") or "").lower().strip()
    icn = (cert.get("issuer_cn") or "").lower().strip()
    so  = (cert.get("subject_o")  or "").lower().strip()
    io  = (cert.get("issuer_o")   or "").lower().strip()
    if scn and icn:
        cert["is_self_signed"] = (scn == icn) and (not so or so == io)

    # Compute expiry
    if cert.get("not_after"):
        dt = _parse_date(cert["not_after"])
        if dt:
            delta = (dt - datetime.utcnow()).days
            cert["days_until_expiry"] = delta
            cert["is_expired"] = delta < 0

    return [cert]


def extract_env_vars(output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Plugin 92364 — Windows Environment Variables (global + active user scope)."""
    records = []
    scope = "global"
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "Global Environment Variables" in line:
            scope = "global"
            continue
        if "Active User Environment Variables" in line:
            scope = "user"
            continue
        if " : " in line:
            name, _, value = line.partition(" : ")
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            records.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "name": name.lower(),
                "value": value,
                "scope": scope,
                "is_sensitive": _is_sensitive_env_var(name),
                "source_plugin": "92364",
            })
    return records


# ─────────────────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────────────────

def extract_ai_tools(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """
    Plugin 196906 — AI/LLM Software Report.
    Output format:
        The following Artificial Intelligence/Large Language Model <CATEGORY> were observed...:
          Tool Name 1
          Tool Name 2
    """
    results = []
    current_category = "other"
    # Map section header keywords → normalized category
    CATEGORY_MAP = {
        "browser extension": "browser_extension",
        "application": "application",
        "cloud service": "cloud_service",
        "model": "model",
        "tool": "tool",
    }

    for line in plugin_output.splitlines():
        stripped = line.strip()
        lower = stripped.lower()

        # Section header: "The following ... were observed..."
        if lower.startswith("the following artificial intelligence") or lower.startswith("the following ai"):
            current_category = "other"
            for kw, cat in CATEGORY_MAP.items():
                if kw in lower:
                    current_category = cat
                    break
            continue

        # Skip blank lines, "Refer to plugins" lines, and other prose
        if not stripped or stripped.lower().startswith("refer to plugin") \
                or stripped.lower().startswith("for each of the software") \
                or stripped.lower().startswith("note that") \
                or stripped.startswith("http"):
            continue

        # Tool entries are indented (at least 2 spaces) in raw output;
        # after strip() they're non-empty names not matching prose patterns
        if len(line) > len(stripped) and stripped:  # was indented
            results.append({
                "scan_id": scan_id,
                "asset_id": asset_id,
                "tool_name": stripped,
                "category": current_category,
                "source_plugin": "196906",
            })

    return results


# ─── Plugin 70329 — Microsoft Windows Process Information ──────────
def extract_processes_70329(plugin_output: str, asset_id: int, scan_id: int) -> list[dict]:
    """Parse WMI process tree output from plugin 70329.

    Format:
        SID: Process (PID)
         0 : System Idle Process (0)
         0 : |- System (4)
         0 :    |- smss.exe (400)
    """
    results = []
    # Stack of (depth, pid, name) for parent tracking
    stack = []

    for line in plugin_output.splitlines():
        # Match:  " <sid> : <rest>" — capture everything after " : " literally
        m = re.match(r"^\s*(\d+)\s*: (.*)$", line)
        if not m:
            continue

        session_id = int(m.group(1))
        rest = m.group(2)       # e.g. "   |- smss.exe (400) "

        # Extract PID from trailing "(digits)"
        pid_m = re.search(r"\((\d+)\)\s*$", rest)
        if not pid_m:
            continue
        pid = int(pid_m.group(1))
        rest_no_pid = rest[:pid_m.start()]  # e.g. "   |- smss.exe "

        # Separate indent from process name
        # rest_no_pid: "System Idle Process " or "|- System " or "   |- smss.exe "
        proc_name = rest_no_pid.lstrip(" |─-").strip()
        if not proc_name:
            continue

        # Depth from leading whitespace/tree chars
        # root: "System Idle Process"  → 0 leading chars → depth 0
        # child: "|- System"           → 3 chars ("|- ")  → depth 1
        # grandchild: "   |- smss.exe" → 6 chars          → depth 2
        indent_len = len(rest_no_pid) - len(rest_no_pid.lstrip(" |-"))
        depth = indent_len // 3

        # Update the stack to find parent
        # Pop entries at same depth or deeper
        while stack and stack[-1][0] >= depth:
            stack.pop()

        ppid = stack[-1][1] if stack else None
        parent_name = stack[-1][2] if stack else None

        stack.append((depth, pid, proc_name))

        results.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "process_name": proc_name,
            "pid": pid,
            "ppid": ppid,
            "session_id": session_id,
            "parent_name": parent_name,
            "depth": depth,
            "source_plugin": "70329",
        })

    return results


# ─────────────────────────────────────────────────────────
# Database Instance Detection Extractors
# ─────────────────────────────────────────────────────────

def extract_mssql_instances(output: str, asset_id, scan_id) -> list[dict]:
    """Extract MSSQL instances from plugin 10144 / 34252 output."""
    results = []
    current = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current.get("instance_name") or current.get("version"):
                results.append({
                    "scan_id": scan_id, "asset_id": asset_id,
                    "db_type": "mssql",
                    "instance_name": current.get("instance_name"),
                    "version": current.get("version"),
                    "port": current.get("port"),
                    "named_pipes": current.get("named_pipes", []),
                    "is_running": current.get("state", "running").lower() == "running",
                    "source_plugin": "10144",
                })
                current = {}
            continue
        lower = line.lower()
        if lower.startswith("instance") and ":" in line:
            current["instance_name"] = line.split(":", 1)[1].strip()
        elif lower.startswith("version") and ":" in line:
            current["version"] = line.split(":", 1)[1].strip()
        elif lower.startswith("port") and ":" in line:
            port_str = line.split(":", 1)[1].strip().split("/")[0]
            try:
                current["port"] = int(port_str)
            except ValueError:
                pass
        elif lower.startswith("state") and ":" in line:
            current["state"] = line.split(":", 1)[1].strip()
        elif lower.startswith("named pipe") and ":" in line:
            pipe = line.split(":", 1)[1].strip()
            current.setdefault("named_pipes", []).append(pipe)
    # Flush last record
    if current.get("instance_name") or current.get("version"):
        results.append({
            "scan_id": scan_id, "asset_id": asset_id,
            "db_type": "mssql",
            "instance_name": current.get("instance_name"),
            "version": current.get("version"),
            "port": current.get("port"),
            "named_pipes": current.get("named_pipes", []),
            "is_running": current.get("state", "running").lower() == "running",
            "source_plugin": "10144",
        })
    if not results:
        # Fallback: store a minimal record for any MSSQL detection
        results.append({
            "scan_id": scan_id, "asset_id": asset_id,
            "db_type": "mssql",
            "instance_name": None,
            "version": None,
            "port": 1433,
            "named_pipes": [],
            "is_running": True,
            "source_plugin": "10144",
        })
    return results


def extract_mysql_instances(output: str, asset_id, scan_id) -> list[dict]:
    """Extract MySQL instances from plugin 10719 / 26024 output."""
    version = None
    port = 3306
    for line in output.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("version") and ":" in line:
            version = line.split(":", 1)[1].strip()
        elif lower.startswith("port") and ":" in line:
            port_str = line.split(":", 1)[1].strip().split("/")[0]
            try:
                port = int(port_str)
            except ValueError:
                pass
    return [{
        "scan_id": scan_id, "asset_id": asset_id,
        "db_type": "mysql",
        "instance_name": None,
        "version": version,
        "port": port,
        "named_pipes": [],
        "is_running": True,
        "source_plugin": "10719",
    }]


def extract_postgresql_instances(output: str, asset_id, scan_id) -> list[dict]:
    """Extract PostgreSQL instances from plugin 26028 output."""
    version = None
    port = 5432
    for line in output.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("version") and ":" in line:
            version = line.split(":", 1)[1].strip()
        elif lower.startswith("port") and ":" in line:
            port_str = line.split(":", 1)[1].strip().split("/")[0]
            try:
                port = int(port_str)
            except ValueError:
                pass
    return [{
        "scan_id": scan_id, "asset_id": asset_id,
        "db_type": "postgresql",
        "instance_name": None,
        "version": version,
        "port": port,
        "named_pipes": [],
        "is_running": True,
        "source_plugin": "26028",
    }]


def extract_oracle_instances(output: str, asset_id, scan_id) -> list[dict]:
    """Extract Oracle instances from plugin 22689 / 57474 output."""
    version = None
    port = 1521
    for line in output.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("version") and ":" in line:
            version = line.split(":", 1)[1].strip()
        elif "oracle" in lower and "release" in lower:
            # e.g. "Oracle Database 11g Enterprise Edition Release 11.2.0.4.0"
            version = line.strip()
        elif lower.startswith("port") and ":" in line:
            port_str = line.split(":", 1)[1].strip().split("/")[0]
            try:
                port = int(port_str)
            except ValueError:
                pass
    return [{
        "scan_id": scan_id, "asset_id": asset_id,
        "db_type": "oracle",
        "instance_name": None,
        "version": version,
        "port": port,
        "named_pipes": [],
        "is_running": True,
        "source_plugin": "22689",
    }]


# Maps plugin_id → (extractor_fn, target_table_key)
# target_table_key matches keys in the result dict returned by extract_all_inventory
PLUGIN_DISPATCH = {
    "69239": ("ad_users", extract_ad_users),
    "10860": ("local_users", extract_local_users),
    "10902": ("admins_group", extract_admins_group),
    "38689": ("last_logon", extract_last_logon),
    "69238": ("ad_groups", extract_ad_groups),
    "167250": ("ldap_users", extract_ldap_users),
    "167251": ("ldap_groups", extract_ldap_groups),
    "168912": ("domain_trusts", extract_domain_trusts),
    "10456": ("services", extract_services),
    "44401": ("services", extract_service_config),
    "64582": ("netconns", extract_netstat_info),
    "58651": ("netconns", extract_netstat_active),
    "70625": ("scheduled_tasks", extract_scheduled_tasks),
    "66334": ("patches", extract_patch_report),
    "161502": ("logged_on", extract_logged_on),
    # New entity types
    "10395": ("shares", extract_smb_shares),
    "60119": ("shares", extract_share_permissions),
    "20811": ("software", extract_installed_software),
    "22869": ("software", extract_installed_software),
    "131023": ("security_controls", lambda o, a, s: extract_av_info(o, a, s, "131023")),
    "16193":  ("security_controls", lambda o, a, s: extract_av_info(o, a, s, "16193")),
    "56310": ("security_controls", extract_firewall_info),
    "69236": ("computers", extract_ad_computers),
    "167252": ("computers", extract_ldap_computers),
    "17651": ("password_policies", extract_password_policy),
    "92364": ("env_vars", extract_env_vars),
    "10863": ("certificates", extract_ssl_certificate),
    "196906": ("ai_tools", extract_ai_tools),
    "70329": ("processes", extract_processes_70329),
    # Database instance detection
    "10144": ("database_instances", extract_mssql_instances),
    "34252": ("database_instances", extract_mssql_instances),
    "10719": ("database_instances", extract_mysql_instances),
    "26024": ("database_instances", extract_mysql_instances),
    "26028": ("database_instances", extract_postgresql_instances),
    "22689": ("database_instances", extract_oracle_instances),
    "57474": ("database_instances", extract_oracle_instances),
}

# User-producing plugins (their records go into InventoryUser)
USER_PLUGINS = {"ad_users", "ldap_users", "local_users", "admins_group", "last_logon"}
# Group-producing plugins → InventoryGroup
GROUP_PLUGINS = {"ad_groups", "ldap_groups"}


# ─── Credential Exposure Extraction ─────────────────────────────
CREDENTIAL_FAMILIES = {
    "Default Unix Accounts": "default_account",
    "Brute force attacks": "brute_forceable",
}

CREDENTIAL_PLUGIN_PATTERNS = {
    # cleartext / anonymous access
    "10079": ("cleartext", "ftp"),         # Anonymous FTP
    "42263": ("cleartext", "ftp"),         # FTP Cleartext Authentication
    "42880": ("cleartext", "ssl"),         # SSL/TLS - various
    "26928": ("cleartext", "http"),        # SSL Weak Cipher
    "10263": ("cleartext", "smtp"),        # SMTP Open Relay
    "10205": ("cleartext", "snmp"),        # SNMP Default Community
    "41028": ("cleartext", "snmp"),        # SNMP Agent Default Community Name (public)
    "10264": ("cleartext", "telnet"),      # Telnet Server Detection (cleartext protocol)
    # Weak/default credentials
    "10407": ("default_account", "x11"),   # X Server Unauthenticated Access
    "17208": ("default_account", "vnc"),   # VNC Server Unauthenticated Access
    "10245": ("default_account", "http"),  # Web Server Default Page
    "87895": ("weak_config", "ssh"),       # SSH Weak Algorithms
    "70658": ("weak_config", "ssh"),       # SSH Server CBC Mode Ciphers
    "153953": ("weak_config", "rdp"),      # RDP not using NLA
}


def extract_credentials_from_findings(findings: list[dict], scan_id: int) -> list[dict]:
    """
    Extract credential exposure records from findings based on plugin family and specific plugin IDs.
    Unlike other extractors, this works on families not individual plugin outputs.
    """
    records = []
    seen = set()  # (asset_id, source_plugin, username) dedup

    for f in findings:
        plugin_id = str(f.get("plugin_id", ""))
        plugin_family = f.get("plugin_family", "") or ""
        plugin_name = f.get("plugin_name", "") or ""
        plugin_output = f.get("plugin_output", "") or ""
        asset_id = f.get("asset_id")
        severity_int = f.get("severity", 0)
        port = f.get("port")
        protocol = f.get("protocol", "")
        solution = f.get("solution", "") or ""

        severity_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        severity = severity_map.get(severity_int, "info")

        cred_type = None
        proto = protocol or ""
        username = None

        # Check by plugin family
        if plugin_family in CREDENTIAL_FAMILIES:
            cred_type = CREDENTIAL_FAMILIES[plugin_family]
            # Try to extract username from output
            username = _extract_username_from_output(plugin_output, plugin_name)
            # Infer protocol from port
            proto = _infer_protocol(port, protocol, plugin_name)

        # Check by specific plugin ID
        elif plugin_id in CREDENTIAL_PLUGIN_PATTERNS:
            cred_type, proto = CREDENTIAL_PLUGIN_PATTERNS[plugin_id]

        # Check by plugin name keywords (catch-all for credential family)
        elif any(kw in plugin_name.lower() for kw in [
            "default password", "default credential", "cleartext password",
            "plaintext password", "password in clear", "unencrypted password",
            "anonymous access", "no password", "blank password",
            "weak password", "password transmitted in clear",
        ]):
            cred_type = "cleartext" if "clear" in plugin_name.lower() or "plain" in plugin_name.lower() else "default_account"
            proto = _infer_protocol(port, protocol, plugin_name)

        if not cred_type or not asset_id:
            continue

        dedup_key = (asset_id, plugin_id, username or "")
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        records.append({
            "scan_id": scan_id,
            "asset_id": asset_id,
            "credential_type": cred_type,
            "protocol": proto,
            "username": username,
            "severity": severity,
            "port": port,
            "description": (f.get("synopsis") or plugin_name or "")[:500],
            "plugin_name": plugin_name,
            "source_plugin": plugin_id,
            "remediation": (solution)[:500] if solution else None,
        })

    return records


def _extract_username_from_output(output: str, plugin_name: str) -> str | None:
    """Try to extract username from plugin output."""
    if not output:
        return None
    # Common patterns: "account 'root'", "user 'admin'", "login: admin"
    import re
    patterns = [
        r"account\s+['\"]([^'\"]+)['\"]",
        r"user(?:name)?\s*[:=]\s*['\"]?(\S+)",
        r"login\s*[:=]\s*['\"]?(\S+)",
        r"The\s+(\w+)\s+account",
    ]
    for pat in patterns:
        m = re.search(pat, output, re.I)
        if m:
            return m.group(1).strip("'\"")
    return None


def _infer_protocol(port: int | None, protocol: str, plugin_name: str) -> str:
    """Infer the protocol from port number or plugin name."""
    if port:
        port_map = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
            110: "pop3", 143: "imap", 161: "snmp", 443: "https", 445: "smb",
            993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
            3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
            5901: "vnc", 6379: "redis", 8080: "http", 8443: "https",
            27017: "mongodb",
        }
        if port in port_map:
            return port_map[port]

    # Infer from plugin name
    name_lower = plugin_name.lower()
    for proto in ["ssh", "ftp", "telnet", "snmp", "vnc", "rdp", "smb", "http", "smtp", "ldap", "mysql", "mssql", "redis", "mongodb"]:
        if proto in name_lower:
            return proto

    return protocol or "unknown"


def extract_inventory_from_findings(findings: list[dict], dispatch: dict = None) -> dict:
    """
    Given a list of finding dicts (each with plugin_id, plugin_output,
    asset_id, scan_id, asset_hostname), extract all inventory records.

    Args:
        findings: list of finding dicts from a scan
        dispatch: optional plugin_id -> (table_key, extract_fn) mapping.
                  Defaults to the built-in PLUGIN_DISPATCH for Nessus.
                  Pass a custom dispatch for non-Nessus sources.

    Returns a dict keyed by entity type, each holding a list of record dicts.
    """
    if dispatch is None:
        dispatch = PLUGIN_DISPATCH

    result = {
        "users": [],
        "groups": [],
        "services": [],
        "netconns": [],
        "scheduled_tasks": [],
        "patches": [],
        "logged_on": [],
        "shares": [],
        "software": [],
        "security_controls": [],
        "computers": [],
        "password_policies": [],
        "env_vars": [],
        "certificates": [],
        "ai_tools": [],
        "processes": [],
        "database_instances": [],
        "domain_trusts": [],
        "credentials": [],
    }

    for finding in findings:
        plugin_id = str(finding.get("plugin_id", ""))
        if plugin_id not in dispatch:
            continue

        output = finding.get("plugin_output") or ""
        if not output.strip():
            continue

        asset_id = finding.get("asset_id")
        scan_id = finding.get("scan_id")
        asset_hostname = finding.get("asset_hostname", "") or finding.get("host_name", "") or ""

        table_key, fn = dispatch[plugin_id]

        try:
            import inspect
            sig = inspect.signature(fn)
            if "asset_hostname" in sig.parameters:
                records = fn(output, asset_id, scan_id, asset_hostname)
            else:
                records = fn(output, asset_id, scan_id)
        except Exception as e:
            logger.warning(f"Inventory extract failed for plugin {plugin_id} on asset {asset_id}: {e}")
            records = []

        # Inject port/protocol into certificate records
        if table_key == "certificates":
            port = finding.get("port")
            proto = finding.get("protocol")
            for r in records:
                if port is not None:
                    r["port"] = port
                if proto is not None:
                    r["protocol"] = proto

        # Route to correct bucket
        if table_key in USER_PLUGINS:
            result["users"].extend(records)
        elif table_key in GROUP_PLUGINS:
            result["groups"].extend(records)
        elif table_key in result:
            result[table_key].extend(records)

    # Deduplicate users: same (username, domain, scan_id) → merge, prefer richer record
    result["users"] = _dedup_users(result["users"])

    # Credential extraction works on families + keywords, not individual plugin dispatches
    try:
        result["credentials"] = extract_credentials_from_findings(
            findings, findings[0].get("scan_id") if findings else 0)
    except Exception as e:
        logger.warning(f"Credential extraction failed: {e}")

    # Enrich software with auto-update status from correlated services
    if result["software"] and result["services"]:
        try:
            enrich_software_auto_update(result["software"], result["services"])
        except Exception as e:
            logger.warning(f"Auto-update enrichment failed: {e}")

    return result


# Priority: higher number = richer data source (preferred when merging)
_PLUGIN_PRIORITY = {"167250": 3, "69239": 2, "10902": 1, "10860": 1, "38689": 0}


def _dedup_users(users: list[dict]) -> list[dict]:
    """Merge duplicate user records by (username_lower, domain_lower, scan_id).

    When two plugins produce the same user, keep the higher-priority record
    and merge source_systems + privilege flags from the lower-priority one.
    """
    seen: dict[tuple, dict] = {}
    for u in users:
        key = (
            (u.get("username") or "").lower(),
            (u.get("domain") or "").lower(),
            u.get("scan_id"),
        )
        if key not in seen:
            seen[key] = u
        else:
            existing = seen[key]
            existing_pri = _PLUGIN_PRIORITY.get(existing.get("source_plugin", ""), 0)
            new_pri = _PLUGIN_PRIORITY.get(u.get("source_plugin", ""), 0)

            # Keep the higher-priority record as base
            if new_pri > existing_pri:
                base, donor = u, existing
            else:
                base, donor = existing, u

            # Merge source_systems
            sources = list(base.get("source_systems") or [])
            for s in (donor.get("source_systems") or []):
                if s not in sources:
                    sources.append(s)
            base["source_systems"] = sources

            # Merge privilege flags (OR logic — if either says admin, keep it)
            for flag in ("is_local_admin", "is_domain_admin", "is_privileged"):
                if donor.get(flag):
                    base[flag] = True

            # Merge member_of lists
            existing_groups = set(base.get("member_of") or [])
            for g in (donor.get("member_of") or []):
                if g not in existing_groups:
                    base.setdefault("member_of", []).append(g)

            # Fill empty fields from donor
            for field in ("department", "job_title", "manager_dn", "manager_username",
                          "sid", "dn", "uac", "password_last_set", "date_joined",
                          "last_logon_host", "identity_type", "identity_subtype"):
                if not base.get(field) and donor.get(field):
                    base[field] = donor[field]

            # Prefer non-"unknown" identity_type
            if base.get("identity_type") == "unknown" and donor.get("identity_type") not in (None, "unknown"):
                base["identity_type"] = donor["identity_type"]
                if donor.get("identity_subtype"):
                    base["identity_subtype"] = donor["identity_subtype"]

            seen[key] = base

    return list(seen.values())


# ─────────────────────────────────────────────────────────────────────────────
# Security control detection from services + software
# ─────────────────────────────────────────────────────────────────────────────

def detect_security_controls_from_inventory(db, scan_id: int) -> int:
    """
    Query existing InventoryService and InventorySoftware rows for this scan,
    match them against the SECURITY_TOOL_CATALOG, and upsert
    InventorySecurityControl records.

    Returns the number of new controls persisted.
    """
    from models.models import InventoryService, InventorySoftware, InventorySecurityControl
    from threat_intel.security_tool_catalog import match_service, match_software

    # Key: (asset_id, product) → already inserted this session, skip duplicates
    seen: set[tuple[int, str]] = set()

    # Load existing catalog-detected controls so we never double-insert
    existing = (
        db.query(
            InventorySecurityControl.asset_id,
            InventorySecurityControl.product_name,
        )
        .filter(
            InventorySecurityControl.scan_id == scan_id,
            InventorySecurityControl.source_plugin == "catalog",
        )
        .all()
    )
    for row in existing:
        seen.add((row.asset_id, row.product_name))

    new_controls = []

    # ── Match services ────────────────────────────────────────────────────────
    services = (
        db.query(InventoryService)
        .filter(InventoryService.scan_id == scan_id)
        .all()
    )
    for svc in services:
        entry = match_service(svc.service_name or "", svc.display_name or "")
        if not entry:
            continue
        key = (svc.asset_id, entry["product"])
        if key in seen:
            continue
        seen.add(key)
        new_controls.append(
            InventorySecurityControl(
                scan_id=scan_id,
                asset_id=svc.asset_id,
                control_type=entry["control_type"],
                product_name=entry["product"],
                vendor=entry["vendor"],
                is_enabled=svc.is_running,
                details={
                    "category": entry["category"],
                    "description": entry["description"],
                    "matched_service": svc.service_name,
                    "display_name": svc.display_name,
                    "detection_method": "service",
                },
                source_plugin="catalog",
            )
        )

    # ── Match installed software ──────────────────────────────────────────────
    software = (
        db.query(InventorySoftware)
        .filter(InventorySoftware.scan_id == scan_id)
        .all()
    )
    for sw in software:
        entry = match_software(sw.name or "")
        if not entry:
            continue
        key = (sw.asset_id, entry["product"])
        if key in seen:
            continue
        seen.add(key)
        new_controls.append(
            InventorySecurityControl(
                scan_id=scan_id,
                asset_id=sw.asset_id,
                control_type=entry["control_type"],
                product_name=entry["product"],
                vendor=entry["vendor"],
                is_enabled=True,
                details={
                    "category": entry["category"],
                    "description": entry["description"],
                    "matched_software": sw.name,
                    "version": sw.version,
                    "detection_method": "software",
                },
                source_plugin="catalog",
            )
        )

    if new_controls:
        db.bulk_save_objects(new_controls)
        db.commit()

    logger.info(
        f"Security catalog detection: scan {scan_id} → {len(new_controls)} "
        f"new controls from {len(services)} services + {len(software)} software entries"
    )
    return len(new_controls)
