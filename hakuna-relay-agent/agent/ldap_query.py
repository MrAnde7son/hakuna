"""impacket LDAP query executor for the Hakuna relay agent.

Runs read-only LDAP queries against an Active Directory domain controller
using impacket's LDAP client. The backend's LDAP Audit agent dispatches
`method=ldap_query` tasks; this handler routes them based on `params.op`.

Design notes
------------
- Impacket's `impacket.ldap.ldap` is synchronous; every query runs inside
  `asyncio.to_thread` so the WebSocket loop stays responsive.
- We SEARCH only. `ldap.ldapConnection.add()` / `modify()` / `delete()` are
  deliberately not invoked from here; any op that would need them returns
  an error.
- Auth flow mirrors WMI's credential shape `{username, password, domain}`
  plus optional `lmhash`/`nthash` for pass-the-hash. We try NTLM bind first
  (works even on a domain controller that doesn't accept simple bind).
- Binary attributes (objectSid, objectGUID, nTSecurityDescriptor) are
  returned base64-encoded; the backend decoder handles them.

Result shape (every op returns the same envelope):
    { "entries": [...], "base_dn": "...", "domain": "...", "_errors": {...} }
"""

from __future__ import annotations

import asyncio
import base64
import logging
import struct
import uuid
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


class LDAPError(Exception):
    """Any LDAP connection / query failure surfaced back to the backend."""


# Lazy import so relays not running LDAP audits don't pay the import cost.
def _impacket():
    from impacket.ldap import ldap, ldapasn1
    return ldap, ldapasn1


@register_method("ldap_query")
async def ldap_query_handler(ws, task, transport_config, credentials, params) -> dict:
    """Dispatch an LDAP op to its impacket implementation."""
    target = (transport_config or {}).get("target")
    if not target:
        raise LDAPError("transport_config.target is required")
    port = (transport_config or {}).get("port")

    op = (params or {}).get("op") or "search"
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or 60)

    if not credentials or not credentials.get("username"):
        raise LDAPError("credentials with 'username' are required")

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, port, credentials, op, op_params),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise LDAPError(f"LDAP op '{op}' timed out after {timeout_s}s for {target}")


def _run_sync(target: str, port: int | None, creds: dict, op: str, op_params: dict) -> dict:
    ldap, _ = _impacket()

    username = creds.get("username", "")
    password = creds.get("password", "")
    domain = creds.get("domain", "") or ""
    lmhash = creds.get("lmhash", "") or ""
    nthash = creds.get("nthash", "") or ""

    # Build the LDAP URL. Prefer ldaps (636) for security; fall back to ldap (389)
    # if ldaps fails (self-signed certs are common on internal DCs). When the
    # caller pinned a port, skip the scheme we know won't answer on it.
    attempts = _build_bind_attempts(username, password, domain, lmhash, nthash)
    conn = None
    errors: list[str] = []
    if port:
        host_port = f"{target}:{port}"
        urls = (f"ldap://{host_port}",) if port == 389 else (
            (f"ldaps://{host_port}",) if port == 636 else (
                f"ldaps://{host_port}", f"ldap://{host_port}"
            )
        )
    else:
        urls = (f"ldaps://{target}", f"ldap://{target}")
    for url in urls:
        for label, bind in attempts:
            # Every bind needs a fresh connection — impacket keeps bind state
            # on the socket and won't let us retry a different auth on the
            # same LDAPConnection.
            try:
                c = ldap.LDAPConnection(url)
            except Exception as e:
                errors.append(f"{url}: connect: {e}")
                break  # URL unreachable; skip remaining auth attempts on it
            try:
                bind(c)
                conn = c
                break
            except Exception as e:
                errors.append(f"{url} {label}: {e}")
                try:
                    c.close()
                except Exception:
                    pass
        if conn is not None:
            break
    if conn is None:
        raise LDAPError(f"LDAP bind failed: {'; '.join(errors) or 'no attempts succeeded'}")

    try:
        if op == "domain_info":
            return _op_domain_info(conn)
        if op == "password_policy":
            return _op_password_policy(conn)
        if op == "search":
            return _op_search(conn, op_params)
        if op == "acl":
            return _op_acl(conn, op_params)
        if op == "resolve_sids":
            return _op_resolve_sids(conn, op_params)
        # Write ops use ldap3 (impacket's LDAP stack is read-only by design).
        if op in ("add", "modify", "delete"):
            return _op_write(target, port, creds, op, op_params)
        return {"_errors": {op: f"unknown op: {op}"}}
    finally:
        try:
            conn.close()
        except Exception:
            pass


# ── Bind strategy ────────────────────────────────────────────────────
#
# AD domain controllers accept NTLM (SASL sicilyNegotiate). OpenLDAP and many
# hardened AD setups only accept simple bind, which needs a full bind DN — so
# we try NTLM first, then simple bind against a short list of DN shapes built
# from whatever the user entered in the credential form.
#
# The credential form asks for "domain", and users give us anything: a UPN
# suffix (`lab.local`), a NetBIOS name (`LAB`), or a DN (`dc=lab,dc=local`).
# `_domain_to_dn` normalizes all three to a DN suffix we can concatenate onto
# the username. If the username already looks like a DN (contains `=`), we
# use it verbatim and skip DN construction.


def _domain_to_dn(domain: str) -> str:
    """Accept `lab.local` | `dc=lab,dc=local` | `LAB` and return a DN suffix.

    Empty input → empty string (caller skips DN-based attempts).
    """
    d = (domain or "").strip()
    if not d:
        return ""
    if "=" in d:
        return d  # already a DN
    if "." in d:
        parts = [p for p in d.split(".") if p]
        return ",".join(f"dc={p}" for p in parts)
    # Bare NetBIOS-ish name — not enough to build a real DN. Return empty
    # so we don't fabricate something misleading; NTLM will still be tried.
    return ""


def _build_bind_attempts(username: str, password: str, domain: str,
                         lmhash: str, nthash: str) -> list:
    """Ordered list of (label, bind_fn) to try against each LDAP URL.

    1. NTLM — works for real AD.
    2. Simple bind with a full DN — works for OpenLDAP and for AD when the
       user supplied creds as a DN already. Covers the common OpenLDAP
       layouts (`cn=admin,<dn>`, `uid=user,ou=users,<dn>`).

    Every lambda binds its own `c` (connection) so the caller can create a
    fresh LDAPConnection per attempt.
    """
    attempts: list = []

    # NTLM first. Impacket's default is sicilyNegotiate.
    attempts.append((
        "ntlm",
        lambda c: c.login(username, password, domain, lmhash, nthash),
    ))

    # Simple-bind variants. If the username is already a DN, trust it verbatim.
    # Otherwise, derive a DN suffix from whatever shape of "domain" we got and
    # try the common RDNs. Pass domain='' so impacket doesn't prepend
    # `user@domain` or `DOMAIN\user` — we want the bind DN sent as-is.
    simple_dns: list[str] = []
    if "=" in username:
        simple_dns.append(username)
    else:
        dn_suffix = _domain_to_dn(domain)
        if dn_suffix:
            simple_dns.append(f"cn={username},{dn_suffix}")
            simple_dns.append(f"uid={username},ou=users,{dn_suffix}")
            simple_dns.append(f"uid={username},{dn_suffix}")

    for dn in simple_dns:
        attempts.append((
            f"simple({dn})",
            lambda c, _dn=dn: c.login(_dn, password, "", "", "", authenticationChoice="simple"),
        ))

    return attempts


# ── Ops ──────────────────────────────────────────────────────────────


def _op_domain_info(conn) -> dict:
    """Read RootDSE + domain object for functional levels and base DN."""
    # RootDSE. Per RFC 4511 §5.1, RootDSE lookup requires scope=baseObject on
    # an empty search base. AD tolerates wholeSubtree here, but OpenLDAP (and
    # other RFC-strict servers) return noSuchObject for subtree searches on
    # an empty base, so we must ask for baseObject explicitly.
    root = _rootdse_search(
        conn,
        attributes=[
            "defaultNamingContext", "namingContexts",
            "rootDomainNamingContext",
            "configurationNamingContext", "schemaNamingContext",
            "domainFunctionality", "forestFunctionality",
            "domainControllerFunctionality", "dnsHostName",
        ],
    )
    base_dn = ""
    forest_dn = ""
    info: dict[str, Any] = {}
    for r in root:
        d = _entry_to_dict(r)
        if d.get("defaultNamingContext"):
            base_dn = _as_str(d["defaultNamingContext"])
        elif d.get("namingContexts"):
            # OpenLDAP / RFC LDAP servers don't have defaultNamingContext; fall
            # back to the first namingContexts entry (it's multi-valued).
            nc = d["namingContexts"]
            base_dn = _as_str(nc[0] if isinstance(nc, list) else nc) or ""
        if d.get("rootDomainNamingContext"):
            forest_dn = _as_str(d["rootDomainNamingContext"])
        info.update({
            "domain_functionality": _as_str(d.get("domainFunctionality")),
            "forest_functionality": _as_str(d.get("forestFunctionality")),
            "dc_functionality": _as_str(d.get("domainControllerFunctionality")),
            "dns_host_name": _as_str(d.get("dnsHostName")),
        })

    # Domain object for NetBIOS + additional attrs
    if base_dn:
        entries = conn.search(
            searchBase=base_dn,
            searchFilter="(objectClass=domain)",
            attributes=["name", "objectSid", "ms-DS-MachineAccountQuota"],
        )
        for e in entries:
            d = _entry_to_dict(e)
            info["domain_netbios"] = _as_str(d.get("name"))
            info["machine_account_quota"] = _as_int(d.get("ms-DS-MachineAccountQuota"))
            break

    info["base_dn"] = base_dn
    info["forest_dn"] = forest_dn
    return info


def _op_password_policy(conn) -> dict:
    base_dn = _base_dn(conn)
    entries = conn.search(
        searchBase=base_dn,
        searchFilter="(objectClass=domain)",
        attributes=[
            "minPwdLength", "pwdHistoryLength", "pwdProperties",
            "maxPwdAge", "minPwdAge",
            "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
        ],
    )
    for e in entries:
        d = _entry_to_dict(e)
        # pwdProperties bit 0 = DOMAIN_PASSWORD_COMPLEX
        pwd_props = _as_int(d.get("pwdProperties")) or 0
        return {
            "min_length": _as_int(d.get("minPwdLength")),
            "history_length": _as_int(d.get("pwdHistoryLength")),
            "complexity_enabled": bool(pwd_props & 0x1),
            "max_age_100ns": _as_int(d.get("maxPwdAge")),
            "min_age_100ns": _as_int(d.get("minPwdAge")),
            "lockout_threshold": _as_int(d.get("lockoutThreshold")),
            "lockout_duration_100ns": _as_int(d.get("lockoutDuration")),
            "lockout_observation_100ns": _as_int(d.get("lockOutObservationWindow")),
        }
    return {"_errors": {"password_policy": "domain object not found"}}


def _op_search(conn, op_params: dict) -> dict:
    base_dn = op_params.get("base_dn") or _base_dn(conn)
    ldap_filter = op_params.get("filter") or "(objectClass=*)"
    attributes = op_params.get("attributes") or []

    try:
        raw = conn.search(
            searchBase=base_dn,
            searchFilter=ldap_filter,
            attributes=attributes,
            sizeLimit=int(op_params.get("size_limit") or 500),
        )
    except Exception as e:
        # impacket raises LDAPSearchError with the code on the object.
        return {"_errors": {"search": f"{type(e).__name__}: {e}"}, "entries": []}

    entries = [_entry_to_dict(r) for r in raw if _is_search_result(r)]
    return {"entries": entries, "base_dn": base_dn}


def _op_acl(conn, op_params: dict) -> dict:
    dn = op_params.get("dn")
    if not dn:
        return {"_errors": {"acl": "dn is required"}}

    raw = conn.search(
        searchBase=dn,
        searchFilter="(objectClass=*)",
        attributes=["distinguishedName", "nTSecurityDescriptor", "objectClass"],
    )
    for r in raw:
        if not _is_search_result(r):
            continue
        d = _entry_to_dict(r)
        sd_b64 = d.get("nTSecurityDescriptor")
        if not sd_b64:
            return {"dn": dn, "_errors": {"acl": "nTSecurityDescriptor missing (SACL requires SYSTEM; DACL requires read permission)"}}

        sd_b64_str = sd_b64 if isinstance(sd_b64, str) else _coerce_bin(sd_b64)
        try:
            sd_bytes = base64.b64decode(sd_b64_str)
        except Exception as e:
            return {"dn": dn, "security_descriptor_b64": sd_b64_str,
                    "_errors": {"acl": f"could not base64-decode SD: {e}"}}

        try:
            decoded = _decode_security_descriptor(sd_bytes)
        except Exception as e:
            return {"dn": dn, "security_descriptor_b64": sd_b64_str,
                    "_errors": {"acl": f"SD parse failed: {type(e).__name__}: {e}"}}

        # Resolve trustee SIDs → names in one batch query so the LLM can reason
        # about who actually holds these rights.
        sid_set = {ace["trustee_sid"] for ace in decoded["aces"] if ace.get("trustee_sid")}
        if decoded.get("owner_sid"):
            sid_set.add(decoded["owner_sid"])
        if decoded.get("group_sid"):
            sid_set.add(decoded["group_sid"])
        name_map = _resolve_sids(conn, sid_set)

        for ace in decoded["aces"]:
            sid = ace.get("trustee_sid")
            if sid:
                ace["trustee"] = name_map.get(sid) or _WELL_KNOWN_SIDS.get(sid) or sid

        return {
            "dn": dn,
            "object_class": d.get("objectClass"),
            "owner_sid": decoded.get("owner_sid"),
            "owner": name_map.get(decoded.get("owner_sid")) or _WELL_KNOWN_SIDS.get(decoded.get("owner_sid")) or decoded.get("owner_sid"),
            "group_sid": decoded.get("group_sid"),
            "control_flags": decoded.get("control_flags"),
            "aces": decoded["aces"],
            "ace_count": len(decoded["aces"]),
            "dangerous_ace_count": sum(1 for a in decoded["aces"] if a.get("dangerous")),
            "security_descriptor_b64": sd_b64_str,
        }
    return {"dn": dn, "_errors": {"acl": "object not found"}}


def _op_resolve_sids(conn, op_params: dict) -> dict:
    sids = op_params.get("sids") or []
    if not isinstance(sids, list) or not sids:
        return {"_errors": {"resolve_sids": "sids (list[str]) is required"}}
    resolved = _resolve_sids(conn, set(sids))
    return {"resolved": resolved, "unresolved": [s for s in sids if s not in resolved]}


# ── ACL decoder ──────────────────────────────────────────────────────
#
# Layout we depend on:
#   impacket.ldap.ldaptypes.SR_SECURITY_DESCRIPTOR — wraps the raw bytes into
#   OwnerSid / GroupSid / Dacl / Sacl. The Dacl has ['Data'], a list of ACE
#   structures whose type determines what shape ['Ace'] is:
#     - ACCESS_ALLOWED_ACE (type 0x00)  — plain SID + Mask
#     - ACCESS_DENIED_ACE  (type 0x01)
#     - ACCESS_ALLOWED_OBJECT_ACE (type 0x05) — SID + Mask + ObjectType GUID
#     - ACCESS_DENIED_OBJECT_ACE  (type 0x06)
# Our LLM cares about "who has which dangerous right on this object", so we
# flatten every ACE to {type, trustee_sid, mask, rights[], object_guid,
# object_right, dangerous} and skip inherited SYSTEM-only entries when
# computing the dangerous count.

_ACE_TYPES = {
    0x00: "ALLOWED",
    0x01: "DENIED",
    0x02: "AUDIT",
    0x05: "ALLOWED_OBJECT",
    0x06: "DENIED_OBJECT",
    0x07: "AUDIT_OBJECT",
}

# Access-mask bits that matter for AD takeover. Source: MS-ADTS §5.1.3.2.
_RIGHTS_MASK = [
    (0x10000000, "GENERIC_ALL"),
    (0x40000000, "GENERIC_WRITE"),
    (0x20000000, "GENERIC_READ"),
    (0x80000000, "GENERIC_EXECUTE"),
    (0x00040000, "WRITE_DAC"),
    (0x00080000, "WRITE_OWNER"),
    (0x00020000, "READ_CONTROL"),
    (0x00010000, "DELETE"),
    (0x00000100, "CONTROL_ACCESS"),       # extended right (use with ObjectType)
    (0x00000020, "WRITE_PROP"),           # write specific property (ObjectType)
    (0x00000010, "READ_PROP"),
    (0x00000008, "SELF"),                 # validated write
    (0x00000004, "LIST_OBJECT"),
    (0x00000002, "DELETE_CHILD"),
    (0x00000001, "CREATE_CHILD"),
]

# Dangerous control-access (extended right) GUIDs. Lowercase, no braces.
_EXTENDED_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "All-Extended-Rights-User",
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
}

# Trustee SIDs we do NOT flag as suspicious even on privileged objects —
# these are the baseline holders of admin rights in any domain.
_EXPECTED_PRIVILEGED_SIDS = {
    "S-1-5-18": "SYSTEM",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "NT AUTHORITY\\SELF",
}

_WELL_KNOWN_SIDS = {
    "S-1-0-0": "NULL SID",
    "S-1-1-0": "Everyone",
    "S-1-2-0": "LOCAL",
    "S-1-3-0": "CREATOR OWNER",
    "S-1-3-1": "CREATOR GROUP",
    "S-1-5-2": "NETWORK",
    "S-1-5-4": "INTERACTIVE",
    "S-1-5-6": "SERVICE",
    "S-1-5-7": "ANONYMOUS",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-10": "NT AUTHORITY\\SELF",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
    "S-1-5-32-544": "BUILTIN\\Administrators",
    "S-1-5-32-545": "BUILTIN\\Users",
    "S-1-5-32-546": "BUILTIN\\Guests",
    "S-1-5-32-548": "BUILTIN\\Account Operators",
    "S-1-5-32-549": "BUILTIN\\Server Operators",
    "S-1-5-32-550": "BUILTIN\\Print Operators",
    "S-1-5-32-551": "BUILTIN\\Backup Operators",
    "S-1-5-32-554": "BUILTIN\\Pre-Windows 2000 Compatible Access",
}


def _decode_security_descriptor(sd_bytes: bytes) -> dict:
    from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    out: dict[str, Any] = {
        "control_flags": int(sd["Control"]),
        "owner_sid": None,
        "group_sid": None,
        "aces": [],
    }
    owner = sd["OwnerSid"]
    if owner:
        try:
            out["owner_sid"] = owner.formatCanonical()
        except Exception:
            pass
    group = sd["GroupSid"]
    if group:
        try:
            out["group_sid"] = group.formatCanonical()
        except Exception:
            pass

    dacl = sd["Dacl"]
    if dacl is None:
        return out

    for ace in dacl["Data"]:
        try:
            out["aces"].append(_decode_ace(ace))
        except Exception as e:
            out["aces"].append({"_error": f"ace decode failed: {e}"})
    return out


def _decode_ace(ace) -> dict:
    ace_type_int = int(ace["AceType"])
    ace_type = _ACE_TYPES.get(ace_type_int, f"TYPE_0x{ace_type_int:02x}")
    inner = ace["Ace"]

    try:
        mask = int(inner["Mask"]["Mask"])
    except Exception:
        mask = 0

    try:
        sid = inner["Sid"].formatCanonical()
    except Exception:
        sid = None

    rights = [name for bit, name in _RIGHTS_MASK if mask & bit]

    object_guid = None
    object_right = None
    # Object ACEs (types 5/6/7) carry an ObjectType GUID identifying which
    # property/extended right the mask applies to. Flags bit 0x1 indicates
    # ObjectType is present.
    if ace_type_int in (0x05, 0x06, 0x07):
        try:
            flags = int(inner["Flags"])
        except Exception:
            flags = 0
        if flags & 0x01:
            try:
                guid_bytes = bytes(inner["ObjectType"])
                guid_str = str(uuid.UUID(bytes_le=guid_bytes)).lower()
                object_guid = guid_str
                object_right = _EXTENDED_RIGHTS.get(guid_str)
            except Exception:
                pass

    dangerous = _is_dangerous_ace(ace_type_int, mask, sid, object_right)

    return {
        "type": ace_type,
        "trustee_sid": sid,
        "mask": mask,
        "rights": rights,
        "object_guid": object_guid,
        "object_right": object_right,
        "dangerous": dangerous,
    }


def _is_dangerous_ace(ace_type_int: int, mask: int, sid: str | None, object_right: str | None) -> bool:
    # Only ALLOWED (+ALLOWED_OBJECT) ACEs grant access. DENY ACEs aren't dangerous.
    if ace_type_int not in (0x00, 0x05):
        return False
    if sid in _EXPECTED_PRIVILEGED_SIDS:
        return False
    # Direct dangerous bits on the object.
    if mask & 0x10000000:  # GENERIC_ALL
        return True
    if mask & 0x40000000:  # GENERIC_WRITE
        return True
    if mask & 0x00040000:  # WRITE_DAC
        return True
    if mask & 0x00080000:  # WRITE_OWNER
        return True
    # Extended right — only dangerous if tied to a known-sensitive GUID
    # (DCSync, force password reset, etc.).
    if mask & 0x00000100 and object_right in {
        "DS-Replication-Get-Changes",
        "DS-Replication-Get-Changes-All",
        "DS-Replication-Get-Changes-In-Filtered-Set",
        "User-Force-Change-Password",
    }:
        return True
    return False


# ── SID resolution ───────────────────────────────────────────────────


def _resolve_sids(conn, sids: set[str]) -> dict[str, str]:
    """Bulk-resolve SIDs to sAMAccountName via a single OR filter."""
    resolved: dict[str, str] = {}
    unknown = [s for s in sids if s and s not in _WELL_KNOWN_SIDS]
    # Well-known entries fill in immediately.
    for s in sids:
        if s in _WELL_KNOWN_SIDS:
            resolved[s] = _WELL_KNOWN_SIDS[s]

    if not unknown:
        return resolved

    base_dn = _base_dn(conn)
    if not base_dn:
        return resolved

    # Build (|(objectSid=<hex>)(objectSid=<hex>)...). Impacket filter parsing
    # accepts \xx byte escapes for binary values.
    terms: list[str] = []
    for sid_str in unknown:
        try:
            filter_bytes = _sid_to_filter_bytes(sid_str)
        except Exception:
            continue
        terms.append(f"(objectSid={filter_bytes})")
    if not terms:
        return resolved

    # AD caps OR-filter elements around ~1000; chunk defensively at 100.
    for i in range(0, len(terms), 100):
        chunk = terms[i:i + 100]
        flt = f"(|{''.join(chunk)})" if len(chunk) > 1 else chunk[0]
        try:
            raw = conn.search(
                searchBase=base_dn,
                searchFilter=flt,
                attributes=["sAMAccountName", "objectSid", "distinguishedName"],
                sizeLimit=1000,
            )
        except Exception as e:
            logger.warning("SID resolve chunk failed: %s", e)
            continue
        for r in raw:
            if not _is_search_result(r):
                continue
            d = _entry_to_dict(r)
            sid = d.get("objectSid")
            sam = d.get("sAMAccountName") or d.get("distinguishedName")
            # objectSid was returned base64 (binary attr); decode to canonical.
            if isinstance(sid, str) and sid:
                try:
                    sid_canon = _sid_bytes_to_str(base64.b64decode(sid))
                    if sid_canon:
                        resolved[sid_canon] = _as_str(sam) or sid_canon
                except Exception:
                    pass
    return resolved


def _sid_to_filter_bytes(sid_str: str) -> str:
    """Convert 'S-1-5-21-...-512' to the '\\xx\\xx...' form LDAP filters need."""
    parts = sid_str.strip().split("-")
    if len(parts) < 3 or parts[0] != "S":
        raise ValueError(f"malformed SID: {sid_str}")
    revision = int(parts[1])
    identifier_authority = int(parts[2])
    sub_auths = [int(p) for p in parts[3:]]

    packed = struct.pack("BB", revision, len(sub_auths))
    # 6-byte big-endian identifier authority.
    packed += struct.pack(">Q", identifier_authority)[2:]
    for sa in sub_auths:
        packed += struct.pack("<I", sa & 0xFFFFFFFF)
    return "".join(f"\\{b:02x}" for b in packed)


def _sid_bytes_to_str(data: bytes) -> str | None:
    if not data or len(data) < 8:
        return None
    revision = data[0]
    sub_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], "big")
    if len(data) < 8 + 4 * sub_count:
        return None
    subs = [int.from_bytes(data[8 + 4 * i:12 + 4 * i], "little") for i in range(sub_count)]
    return "S-" + "-".join([str(revision), str(identifier_authority)] + [str(s) for s in subs])


# ── impacket entry → plain dict ──────────────────────────────────────


def _is_search_result(r) -> bool:
    """impacket yields both SearchResultEntry and SearchResultReference/Done."""
    cls_name = type(r).__name__
    return "SearchResultEntry" in cls_name


def _entry_to_dict(entry) -> dict:
    """Convert impacket's SearchResultEntry into a flat dict we can JSON-ship."""
    from impacket.ldap import ldapasn1

    out: dict[str, Any] = {}
    try:
        out["distinguishedName"] = str(entry["objectName"])
    except Exception:
        pass

    try:
        attrs = entry["attributes"]
    except Exception:
        attrs = []

    for attr in attrs:
        try:
            name = str(attr["type"])
            values = list(attr["vals"])
        except Exception:
            continue
        decoded = [_decode_value(name, v) for v in values]
        out[name] = decoded[0] if len(decoded) == 1 else decoded
    return out


# Attributes that are always binary — return base64.
_BINARY_ATTRS = {
    "objectSid", "objectGUID", "nTSecurityDescriptor",
    "msDS-AllowedToActOnBehalfOfOtherIdentity",
    "securityIdentifier",
}

# Attributes commonly returned as ints — parse where safe.
_INT_ATTRS = {
    "userAccountControl", "pwdLastSet", "lastLogon", "lastLogonTimestamp",
    "accountExpires", "primaryGroupID", "adminCount",
    "minPwdLength", "pwdHistoryLength", "pwdProperties",
    "maxPwdAge", "minPwdAge",
    "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
    "trustDirection", "trustType", "trustAttributes",
    "ms-DS-MachineAccountQuota",
    "domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
}


def _decode_value(attr_name: str, raw) -> Any:
    if attr_name in _BINARY_ATTRS:
        return _coerce_bin(raw)
    s = _as_str(raw)
    if attr_name in _INT_ATTRS:
        try:
            return int(s) if s else None
        except (ValueError, TypeError):
            return s
    return s


def _as_str(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        return v
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return repr(v)
    # impacket asn1 values have __str__
    try:
        return str(v)
    except Exception:
        return None


def _as_int(v) -> int | None:
    s = _as_str(v)
    if s is None:
        return None
    try:
        return int(s)
    except (ValueError, TypeError):
        return None


def _coerce_bin(v) -> str:
    """Return bytes as base64; strings as-is (some impacket paths pre-decode)."""
    if v is None:
        return ""
    if isinstance(v, bytes):
        return base64.b64encode(v).decode("ascii")
    if isinstance(v, str):
        # Could already be a utf-8 string (impacket sometimes pre-decodes). If it
        # doesn't look like valid base64 OR the value ends up being binary,
        # re-encode from latin1 (which preserves bytes) → base64.
        try:
            return base64.b64encode(v.encode("latin1")).decode("ascii")
        except Exception:
            return v
    return base64.b64encode(str(v).encode("utf-8", errors="replace")).decode("ascii")


def _base_dn(conn) -> str:
    """Pull base DN from RootDSE.

    AD exposes `defaultNamingContext`; OpenLDAP / RFC servers only publish
    `namingContexts` (multi-valued). Query both and prefer the AD attribute
    when present so multi-domain ADs still point at the right NC.
    """
    root = _rootdse_search(
        conn,
        attributes=["defaultNamingContext", "namingContexts"],
    )
    for r in root:
        d = _entry_to_dict(r)
        v = d.get("defaultNamingContext")
        if v:
            return _as_str(v) or ""
        nc = d.get("namingContexts")
        if nc:
            first = nc[0] if isinstance(nc, list) else nc
            return _as_str(first) or ""
    return ""


def _rootdse_search(conn, attributes: list[str]) -> list:
    """Issue a RootDSE-compliant LDAP search (empty base, scope=baseObject)."""
    _, ldapasn1 = _impacket()
    return conn.search(
        searchBase="",
        scope=ldapasn1.Scope("baseObject"),
        searchFilter="(objectClass=*)",
        attributes=attributes,
    )


# ── Write ops via ldap3 ──────────────────────────────────────────────
#
# impacket's LDAP stack is read-only by design (no add/modify/delete in the
# public surface). For the gated write tools the backend exposes we use
# ldap3, which has clean APIs for those operations. Each call opens its own
# connection — write traffic is rare (every call is user-approved) so the
# extra bind cost is negligible.


def _ldap3():
    import ldap3
    return ldap3


def _op_write(target: str, port: int | None, creds: dict, op: str, op_params: dict) -> dict:
    """Run an add/modify/delete via ldap3.

    op_params shape:
      - add:    {dn, object_class: [str], attributes: {name: value | [values]}}
      - modify: {dn, changes: {attr: [{action: 'replace'|'add'|'delete', values: [...]}]}}
      - delete: {dn}
    Returns: {result: 'success'|'failure', op, dn, message?, raw?}
    """
    ldap3 = _ldap3()
    dn = (op_params.get("dn") or "").strip()
    if not dn:
        return {"_errors": {op: "dn is required"}}

    username = creds.get("username", "")
    password = creds.get("password", "")
    domain = creds.get("domain", "") or ""
    user_dn = f"{domain}\\{username}" if domain and "\\" not in username else username

    use_ssl = bool(port) and int(port) in (636, 3269)
    server_port = int(port) if port else 636 if use_ssl else 389
    server = ldap3.Server(target, port=server_port, use_ssl=use_ssl, get_info=ldap3.NONE)
    try:
        conn = ldap3.Connection(
            server, user=user_dn, password=password,
            authentication=ldap3.NTLM, auto_bind=True, raise_exceptions=False,
        )
    except Exception as e:
        # Fall back to simple bind if NTLM fails (OpenLDAP / hardened DCs).
        try:
            conn = ldap3.Connection(
                server, user=user_dn, password=password,
                authentication=ldap3.SIMPLE, auto_bind=True, raise_exceptions=False,
            )
        except Exception as e2:
            return {"_errors": {op: f"bind failed: NTLM={e}; SIMPLE={e2}"}}

    try:
        if op == "add":
            object_class = op_params.get("object_class") or []
            attributes = op_params.get("attributes") or {}
            ok = conn.add(dn, object_class=object_class or None, attributes=attributes)
        elif op == "modify":
            action_map = {
                "replace": ldap3.MODIFY_REPLACE,
                "add": ldap3.MODIFY_ADD,
                "delete": ldap3.MODIFY_DELETE,
            }
            changes_in = op_params.get("changes") or {}
            changes: dict[str, list] = {}
            for attr, ops in changes_in.items():
                changes[attr] = []
                for entry in ops:
                    action = (entry.get("action") or "replace").lower()
                    values = entry.get("values") or []
                    code = action_map.get(action)
                    if code is None:
                        return {"_errors": {op: f"unknown change action: {action}"}}
                    changes[attr].append((code, values))
            ok = conn.modify(dn, changes)
        elif op == "delete":
            ok = conn.delete(dn)
        else:
            return {"_errors": {op: f"unsupported write op: {op}"}}

        return {
            "op": op,
            "dn": dn,
            "result": "success" if ok else "failure",
            "message": (conn.result or {}).get("description"),
            "raw": conn.result,
        }
    finally:
        try:
            conn.unbind()
        except Exception:
            pass
