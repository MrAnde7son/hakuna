"""pysnmp SNMP query executor for the Hakuna relay agent.

Runs read-only SNMP probes (GET / GETNEXT walks) against network devices and
legacy systems. Dispatched via `method=snmp_query` from the backend SNMP Audit
agent's tool palette.

Design notes
------------
- pysnmp's hlapi sync API is wrapped in `asyncio.to_thread` so the WebSocket
  loop stays responsive.
- NEVER writes. We use `getCmd` and `nextCmd` only. No `setCmd` is ever
  invoked by any op here.
- v1/v2c auth is the community string; v3 uses USM (user + auth + priv).
- `community_probe` tries a short list of common default community strings
  (public, private, cisco, manager) to flag weak-community exposure — no
  brute-forcing beyond that hardcoded list.
- Results are shaped: counts + rows. Raw varBinds stay on the relay.

Result shape (per op):
    { <op-specific fields>, "_errors": { <op>: "..." } }
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from .method_registry import register_method

logger = logging.getLogger(__name__)


class SNMPError(Exception):
    """Any SNMP failure surfaced back to the backend."""


# Canonical MIB-2 OIDs — hardcoded to avoid pysnmp MIB-compile overhead.
_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
_OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
_OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
_OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
_OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

_OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
_OID_IF_TYPE = "1.3.6.1.2.1.2.2.1.3"
_OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
_OID_IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
_OID_IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
_OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

_OID_IP_ADDR_TABLE = "1.3.6.1.2.1.4.20.1"
_OID_IP_NET_TO_MEDIA = "1.3.6.1.2.1.4.22.1"
_OID_IP_ROUTE_DEST = "1.3.6.1.2.1.4.21.1.1"
_OID_IP_ROUTE_NEXTHOP = "1.3.6.1.2.1.4.21.1.7"
_OID_IP_ROUTE_MASK = "1.3.6.1.2.1.4.21.1.11"

_DEFAULT_COMMUNITIES = [
    "public", "private", "community", "manager",
    "cisco", "admin", "monitor", "default",
]

_MAX_WALK_ROWS = 500


def _pysnmp():
    from pysnmp.hlapi import (
        SnmpEngine, CommunityData, UsmUserData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity,
        getCmd, nextCmd,
        usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
        usmHMAC128SHA224AuthProtocol, usmHMAC192SHA256AuthProtocol,
        usmHMAC256SHA384AuthProtocol, usmHMAC384SHA512AuthProtocol,
        usmNoAuthProtocol,
        usmDESPrivProtocol, usm3DESEDEPrivProtocol,
        usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
        usmNoPrivProtocol,
    )
    return {
        "SnmpEngine": SnmpEngine,
        "CommunityData": CommunityData,
        "UsmUserData": UsmUserData,
        "UdpTransportTarget": UdpTransportTarget,
        "ContextData": ContextData,
        "ObjectType": ObjectType,
        "ObjectIdentity": ObjectIdentity,
        "getCmd": getCmd,
        "nextCmd": nextCmd,
        "auth": {
            "none": usmNoAuthProtocol,
            "MD5": usmHMACMD5AuthProtocol,
            "SHA": usmHMACSHAAuthProtocol,
            "SHA224": usmHMAC128SHA224AuthProtocol,
            "SHA256": usmHMAC192SHA256AuthProtocol,
            "SHA384": usmHMAC256SHA384AuthProtocol,
            "SHA512": usmHMAC384SHA512AuthProtocol,
        },
        "priv": {
            "none": usmNoPrivProtocol,
            "DES": usmDESPrivProtocol,
            "3DES": usm3DESEDEPrivProtocol,
            "AES": usmAesCfb128Protocol,
            "AES192": usmAesCfb192Protocol,
            "AES256": usmAesCfb256Protocol,
        },
    }


@register_method("snmp_query")
async def snmp_query_handler(ws, task, transport_config, credentials, params) -> dict:
    target = (transport_config or {}).get("target")
    if not target:
        raise SNMPError("transport_config.target is required")

    op = (params or {}).get("op") or "sys_info"
    op_params = (params or {}).get("op_params") or {}
    timeout_s = int((params or {}).get("timeout_s") or 30)
    port = int((transport_config or {}).get("port") or 161)

    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_run_sync, target, port, credentials or {}, op, op_params),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        raise SNMPError(f"SNMP op '{op}' timed out after {timeout_s}s for {target}")


def _run_sync(target: str, port: int, creds: dict, op: str, op_params: dict) -> dict:
    mods = _pysnmp()

    if op == "community_probe":
        return _op_community_probe(mods, target, port)

    auth = _build_auth_data(mods, creds)
    if auth is None:
        return {"_errors": {op: "no SNMP credentials configured (need community or v3 user)"}}

    if op == "sys_info":
        return _op_sys_info(mods, target, port, auth)
    if op == "interfaces":
        return _op_interfaces(mods, target, port, auth)
    if op == "arp_table":
        return _op_arp_table(mods, target, port, auth)
    if op == "ip_addrs":
        return _op_ip_addrs(mods, target, port, auth)
    if op == "routing_table":
        return _op_routing_table(mods, target, port, auth)
    if op == "get":
        return _op_get(mods, target, port, auth, op_params)
    if op == "walk":
        return _op_walk(mods, target, port, auth, op_params)
    return {"_errors": {op: f"unknown op: {op}"}}


# ── Auth builders ────────────────────────────────────────────────────


def _build_auth_data(mods: dict, creds: dict):
    version = (creds.get("version") or "v2c").lower()
    if version in ("v1", "1"):
        community = creds.get("community") or ""
        if not community:
            return None
        return mods["CommunityData"](community, mpModel=0)
    if version in ("v2c", "v2", "2c", "2"):
        community = creds.get("community") or ""
        if not community:
            return None
        return mods["CommunityData"](community, mpModel=1)
    if version in ("v3", "3"):
        username = creds.get("username") or ""
        if not username:
            return None
        auth_proto = mods["auth"].get(creds.get("auth_protocol") or "none", mods["auth"]["none"])
        priv_proto = mods["priv"].get(creds.get("priv_protocol") or "none", mods["priv"]["none"])
        return mods["UsmUserData"](
            username,
            creds.get("auth_key") or None,
            creds.get("priv_key") or None,
            authProtocol=auth_proto,
            privProtocol=priv_proto,
        )
    return None


# ── Ops ──────────────────────────────────────────────────────────────


def _op_sys_info(mods: dict, target: str, port: int, auth) -> dict:
    oids = {
        "sys_descr": _OID_SYS_DESCR,
        "sys_object_id": _OID_SYS_OBJECT_ID,
        "sys_uptime_ticks": _OID_SYS_UPTIME,
        "sys_contact": _OID_SYS_CONTACT,
        "sys_name": _OID_SYS_NAME,
        "sys_location": _OID_SYS_LOCATION,
        "sys_services": _OID_SYS_SERVICES,
    }
    out: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for field, oid in oids.items():
        try:
            value = _snmp_get_one(mods, target, port, auth, oid)
            out[field] = value
        except Exception as e:
            errors[field] = f"{type(e).__name__}: {e}"
    if errors:
        out["_errors"] = errors
    return out


def _op_interfaces(mods: dict, target: str, port: int, auth) -> dict:
    rows = _walk_columns(mods, target, port, auth, {
        "descr": _OID_IF_DESCR,
        "type": _OID_IF_TYPE,
        "speed": _OID_IF_SPEED,
        "phys_addr": _OID_IF_PHYS_ADDRESS,
        "admin_status": _OID_IF_ADMIN_STATUS,
        "oper_status": _OID_IF_OPER_STATUS,
    })
    # Normalize admin/oper status codes to human labels.
    for r in rows.values():
        r["admin"] = _if_status(r.get("admin_status"))
        r["oper"] = _if_status(r.get("oper_status"))
        r["phys_addr"] = _format_mac(r.get("phys_addr"))
    return {"total": len(rows), "interfaces": list(rows.values())[:_MAX_WALK_ROWS]}


def _op_arp_table(mods: dict, target: str, port: int, auth) -> dict:
    rows = _walk_flat(mods, target, port, auth, _OID_IP_NET_TO_MEDIA)
    # ARP entries are in columns 2 (phys), 3 (net), 4 (type). Group by index tail.
    grouped: dict[str, dict] = {}
    for oid, value in rows:
        # oid shape: ...1.4.22.1.<col>.<ifIndex>.<ip-octets>
        tail = oid[len(_OID_IP_NET_TO_MEDIA) + 1:]
        parts = tail.split(".", 1)
        if len(parts) != 2:
            continue
        col, key = parts
        entry = grouped.setdefault(key, {})
        if col == "2":
            entry["mac"] = _format_mac(value)
        elif col == "3":
            entry["ip"] = str(value)
        elif col == "4":
            entry["type"] = _arp_type(value)
    entries = [e for e in grouped.values() if e.get("ip") or e.get("mac")]
    return {"total": len(entries), "entries": entries[:_MAX_WALK_ROWS]}


def _op_ip_addrs(mods: dict, target: str, port: int, auth) -> dict:
    rows = _walk_flat(mods, target, port, auth, _OID_IP_ADDR_TABLE)
    grouped: dict[str, dict] = {}
    for oid, value in rows:
        tail = oid[len(_OID_IP_ADDR_TABLE) + 1:]
        parts = tail.split(".", 1)
        if len(parts) != 2:
            continue
        col, key = parts
        entry = grouped.setdefault(key, {})
        if col == "1":
            entry["addr"] = str(value)
        elif col == "2":
            entry["if_index"] = _as_int(value)
        elif col == "3":
            entry["mask"] = str(value)
    entries = [e for e in grouped.values() if e.get("addr")]
    return {"total": len(entries), "addresses": entries[:_MAX_WALK_ROWS]}


def _op_routing_table(mods: dict, target: str, port: int, auth) -> dict:
    dests = _walk_flat(mods, target, port, auth, _OID_IP_ROUTE_DEST)
    hops = dict(_walk_flat(mods, target, port, auth, _OID_IP_ROUTE_NEXTHOP))
    masks = dict(_walk_flat(mods, target, port, auth, _OID_IP_ROUTE_MASK))

    entries = []
    for oid, dest in dests:
        key = oid[len(_OID_IP_ROUTE_DEST) + 1:]
        entries.append({
            "dest": str(dest),
            "mask": str(masks.get(f"{_OID_IP_ROUTE_MASK}.{key}", "")),
            "next_hop": str(hops.get(f"{_OID_IP_ROUTE_NEXTHOP}.{key}", "")),
        })
    return {"total": len(entries), "routes": entries[:_MAX_WALK_ROWS]}


def _op_get(mods: dict, target: str, port: int, auth, op_params: dict) -> dict:
    oid = (op_params.get("oid") or "").strip()
    if not oid:
        return {"_errors": {"get": "oid is required"}}
    try:
        value = _snmp_get_one(mods, target, port, auth, oid)
    except Exception as e:
        return {"_errors": {"get": f"{type(e).__name__}: {e}"}}
    return {"oid": oid, "value": value}


def _op_walk(mods: dict, target: str, port: int, auth, op_params: dict) -> dict:
    base_oid = (op_params.get("oid") or "").strip()
    if not base_oid:
        return {"_errors": {"walk": "oid is required"}}
    try:
        rows = _walk_flat(mods, target, port, auth, base_oid)
    except Exception as e:
        return {"_errors": {"walk": f"{type(e).__name__}: {e}"}}
    return {
        "base_oid": base_oid,
        "total": len(rows),
        "rows": [{"oid": o, "value": str(v)} for o, v in rows[:_MAX_WALK_ROWS]],
    }


def _op_community_probe(mods: dict, target: str, port: int) -> dict:
    """Try a short, hardcoded list of default community strings. Every hit is
    a finding — weak community = unauthenticated device read access."""
    accepted: list[str] = []
    errors: dict[str, str] = {}
    for community in _DEFAULT_COMMUNITIES:
        try:
            auth = mods["CommunityData"](community, mpModel=1)  # v2c
            _snmp_get_one(mods, target, port, auth, _OID_SYS_DESCR, timeout=3, retries=0)
            accepted.append(community)
        except Exception as e:
            errors[community] = f"{type(e).__name__}: {e}"
    return {
        "accepted_communities": accepted,
        "tried": _DEFAULT_COMMUNITIES,
        "_errors": errors if not accepted else {},
    }


# ── pysnmp helpers ───────────────────────────────────────────────────


def _snmp_get_one(mods: dict, target: str, port: int, auth, oid: str,
                  timeout: int = 5, retries: int = 1):
    iterator = mods["getCmd"](
        mods["SnmpEngine"](),
        auth,
        mods["UdpTransportTarget"]((target, port), timeout=timeout, retries=retries),
        mods["ContextData"](),
        mods["ObjectType"](mods["ObjectIdentity"](oid)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        raise SNMPError(str(errorIndication))
    if errorStatus:
        raise SNMPError(f"{errorStatus.prettyPrint()} at {errorIndex}")
    if not varBinds:
        return None
    _, value = varBinds[0]
    return _coerce(value)


def _walk_flat(mods: dict, target: str, port: int, auth, base_oid: str,
               timeout: int = 5, retries: int = 1) -> list[tuple[str, Any]]:
    """GETNEXT walk rooted at base_oid. Returns (oid_str, coerced_value) pairs,
    stopping when we leave the base subtree or hit the row cap."""
    iterator = mods["nextCmd"](
        mods["SnmpEngine"](),
        auth,
        mods["UdpTransportTarget"]((target, port), timeout=timeout, retries=retries),
        mods["ContextData"](),
        mods["ObjectType"](mods["ObjectIdentity"](base_oid)),
        lexicographicMode=False,
        maxRows=_MAX_WALK_ROWS,
    )
    results: list[tuple[str, Any]] = []
    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            raise SNMPError(str(errorIndication))
        if errorStatus:
            raise SNMPError(f"{errorStatus.prettyPrint()} at {errorIndex}")
        for oid, value in varBinds:
            results.append((str(oid), _coerce(value)))
        if len(results) >= _MAX_WALK_ROWS:
            break
    return results


def _walk_columns(mods: dict, target: str, port: int, auth,
                  columns: dict[str, str]) -> dict[str, dict]:
    """Walk multiple columns of a conceptual SNMP table and join by row index.
    `columns` maps field_name → column_oid_prefix. Returns rows keyed by the
    trailing index, e.g. {"1": {...}, "2": {...}}."""
    rows: dict[str, dict] = {}
    for field, col_oid in columns.items():
        for oid, value in _walk_flat(mods, target, port, auth, col_oid):
            idx = oid[len(col_oid) + 1:]
            rows.setdefault(idx, {"index": idx})[field] = value
    return rows


def _coerce(v) -> Any:
    """pysnmp values → JSON-friendly. OCTET STRING stays string; OID → str; ints → int."""
    if v is None:
        return None
    # OctetString bytes → utf-8 if printable, else hex.
    try:
        from pysnmp.proto.rfc1902 import OctetString, Integer32, Counter32, Counter64, Gauge32, TimeTicks, IpAddress
        if isinstance(v, OctetString):
            raw = v.asOctets()
            try:
                s = raw.decode("utf-8")
                if all(c.isprintable() or c in "\t\n\r" for c in s):
                    return s
            except Exception:
                pass
            return raw.hex()
        if isinstance(v, (Integer32, Counter32, Counter64, Gauge32, TimeTicks)):
            return int(v)
        if isinstance(v, IpAddress):
            return str(v.prettyPrint())
    except Exception:
        pass
    try:
        return v.prettyPrint()
    except Exception:
        return str(v)


def _as_int(v) -> int | None:
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _format_mac(v) -> str | None:
    """Coerce phys-address bytes/hex-string to colon-separated MAC."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.replace(":", "").replace("-", "").replace(" ", "")
        if len(s) == 12 and all(c in "0123456789abcdefABCDEF" for c in s):
            return ":".join(s[i:i + 2].lower() for i in range(0, 12, 2))
        return v
    return str(v)


def _if_status(v) -> str:
    return {1: "up", 2: "down", 3: "testing", 4: "unknown",
            5: "dormant", 6: "notPresent", 7: "lowerLayerDown"}.get(_as_int(v), "unknown")


def _arp_type(v) -> str:
    return {1: "other", 2: "invalid", 3: "dynamic", 4: "static"}.get(_as_int(v), "unknown")
