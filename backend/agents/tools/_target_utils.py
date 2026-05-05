"""Shared helpers for protocol-tool dispatchers."""

from __future__ import annotations


def split_host_port(target: str) -> tuple[str, int | None]:
    """Parse `host:port`, `[ipv6]:port`, or bare host. Port-less returns None.

    Lets users enter `ssh:2222` or `ldap:1389` in the audit target field and
    have the port propagate through to the relay handler. Each protocol tool
    decides whether to forward the port via credentials (SSH) or via
    `config["port"]` (LDAP/SMB/WMI/SNMP).
    """
    if not target:
        return target, None
    if target.startswith("["):
        host, sep, port = target.rpartition("]:")
        if sep and port.isdigit():
            return host[1:], int(port)
        return target.strip("[]"), None
    if target.count(":") == 1:
        host, _, port = target.rpartition(":")
        if port.isdigit():
            return host, int(port)
    return target, None


def resolve_asset_target(asset) -> tuple[str | None, int | None]:
    """Return ``(host, port_or_none)`` for dispatching a protocol tool against ``asset``.

    Prefers the clean identity in ``fqdn/hostname/ip`` + a port stashed in
    ``easm_data['audit_target_port']`` (set by the free-form target flow).
    Falls back to parsing ``host:port`` out of the identity field itself for
    older rows that smuggled the port there before the split was introduced.
    """
    host = (asset.fqdn or asset.hostname or asset.ip) if asset else None
    if not host:
        return host, None
    host, port = split_host_port(host)
    if port is None:
        data = asset.easm_data or {}
        if isinstance(data, dict):
            atp = data.get("audit_target_port")
            try:
                n = int(atp) if atp is not None else None
            except (TypeError, ValueError):
                n = None
            if n is not None and 0 < n <= 65535:
                port = n
    return host, port
