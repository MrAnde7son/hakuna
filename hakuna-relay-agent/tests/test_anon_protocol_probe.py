"""Unit tests for agent.anon_protocol_probe (Phase 4.1).

Each protocol's network layer is mocked — we don't open real sockets.
The contract under test is:

  - The handler's op allowlist rejects unknown ops.
  - Each probe returns the expected decisive field for the agent
    (`anonymous_login_allowed`, `auth_required`, `axfr_allowed`,
    `kdc_reachable`, `readable_files`) given a mocked transport.
  - Connection failures surface as a structured `_errors` field rather
    than raising.
  - The TFTP filename list is fixed at the relay — `op_params` cannot
    inject paths.

Sockets are mocked at `socket.create_connection` / `socket.socket`. The
optional `dns.query` import is patched via `sys.modules`.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from unittest.mock import MagicMock, patch

import pytest

from agent import anon_protocol_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Handler dispatch / allowlist ─────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(anon_protocol_probe.AnonProtocolProbeError, match="unknown anon protocol probe op"):
        _run(anon_protocol_probe.anon_protocol_probe_handler(
            ws=None, task={}, transport_config={"target": "x", "port": 1},
            credentials={}, params={"op": "kerberoast"},
        ))


def test_handler_requires_target():
    with pytest.raises(anon_protocol_probe.AnonProtocolProbeError, match="target is required"):
        _run(anon_protocol_probe.anon_protocol_probe_handler(
            ws=None, task={}, transport_config={}, credentials={}, params={"op": "ftp"},
        ))


def test_handler_op_allowlist_matches_phase_4_1_scope():
    """The allowlist is the second wall behind the backend tool palette.
    Adding a new op deliberately requires updating this test."""
    assert set(anon_protocol_probe._OP_HANDLERS.keys()) == {
        "ftp", "vnc", "dns_axfr", "kerberos", "tftp",
    }


# ── FTP ──────────────────────────────────────────────────────────────


class _FakeSocket:
    """Minimal scripted socket — feed it a list of `recv` chunks and
    capture every `sendall` for shape assertions."""
    def __init__(self, recv_chunks: list[bytes] | None = None):
        self._recv_chunks = list(recv_chunks or [])
        self.sent: list[bytes] = []
        self.closed = False
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, n):
        if not self._recv_chunks:
            return b""
        chunk = self._recv_chunks.pop(0)
        return chunk[:n]

    def close(self):
        self.closed = True


def test_ftp_probe_anonymous_login_allowed_when_230_returned():
    """USER anonymous → 331; PASS → 230 = anon login allowed; STAT yields a
    sample listing whose protocol-envelope lines (211-, 211 End) are
    filtered out."""
    fake = _FakeSocket(recv_chunks=[
        b"220 ProFTPD\r\n",
        b"331 Password required\r\n",
        b"230 Anonymous login OK\r\n",
        b"211-status of /:\r\n-rw-r--r-- 1 ftp ftp 42 file1.txt\r\n211 End\r\n",
    ])

    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_ftp("h", 21, {}, 5)

    assert out["anonymous_login_allowed"] is True
    assert out["banner"].startswith("220")
    assert any("file1.txt" in line for line in out["sample_listing"])
    # USER + PASS + STAT + QUIT — the QUIT may or may not actually be
    # sent depending on mock timing, but the first three are mandatory.
    assert fake.sent[0] == b"USER anonymous\r\n"
    assert fake.sent[1] == b"PASS anonymous@hakuna\r\n"
    assert fake.sent[2] == b"STAT\r\n"


def test_ftp_probe_anonymous_login_refused_when_530_returned():
    """USER anonymous → 530 = anon login refused. The probe must NOT
    flag the asset as anon-allowed."""
    fake = _FakeSocket(recv_chunks=[
        b"220 vsftpd\r\n",
        b"530 Permission denied\r\n",
    ])
    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_ftp("h", 21, {}, 5)

    assert out["anonymous_login_allowed"] is False


def test_ftp_probe_connect_failure_returns_errors_dict():
    with patch("agent.anon_protocol_probe.socket.create_connection",
               side_effect=ConnectionRefusedError("nope")):
        out = anon_protocol_probe._probe_ftp("h", 21, {}, 5)

    assert "_errors" in out
    assert "ftp" in out["_errors"]


# ── VNC ──────────────────────────────────────────────────────────────


def test_vnc_probe_auth_not_required_when_security_type_1_offered():
    """RFB 3.8: server sends version, then 1 byte count + N type bytes.
    Type 1 = None auth — auth_required=False."""
    # 12-byte RFB version, then 1 byte count=2, then 2 type bytes [1, 2]
    fake = _FakeSocket(recv_chunks=[
        b"RFB 003.008\n",
        b"\x02",
        b"\x01\x02",
    ])
    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_vnc("h", 5900, {}, 5)

    assert out["auth_required"] is False
    assert 1 in out["security_types"]
    assert out["rfb_version"] == "RFB 003.008"


def test_vnc_probe_auth_required_when_only_password_type_offered():
    """Type 2 = VNC password — auth_required=True."""
    fake = _FakeSocket(recv_chunks=[
        b"RFB 003.008\n",
        b"\x01",
        b"\x02",
    ])
    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_vnc("h", 5900, {}, 5)

    assert out["auth_required"] is True
    assert out["security_types"] == [2]


def test_vnc_probe_rejects_non_rfb_banner():
    fake = _FakeSocket(recv_chunks=[b"GET / HTTP\r\n\r\n"])
    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_vnc("h", 5900, {}, 5)

    assert "_errors" in out and "vnc" in out["_errors"]


# ── DNS AXFR ─────────────────────────────────────────────────────────


def test_dns_axfr_probe_returns_axfr_allowed_when_zone_materializes():
    """When dnspython successfully materializes a zone, axfr_allowed must
    flip true and a record sample (capped) is returned for evidence."""
    fake_zone = MagicMock()
    records = []
    for i, name in enumerate(["www", "mail", "ns1"]):
        rds = MagicMock()
        rds.rdtype.name = "A"
        rds.to_text.return_value = f"10.0.0.{i+1}"
        records.append((name, rds))
    fake_zone.iterate_rdatasets.return_value = iter(records)

    fake_dns_query = MagicMock()
    fake_dns_zone = MagicMock()
    fake_dns_exception = MagicMock()
    fake_dns_exception.FormError = type("FormErr", (Exception,), {})
    fake_dns_exception.DNSException = type("DNSException", (Exception,), {})
    fake_dns_query.xfr.return_value = iter([])
    fake_dns_zone.from_xfr.return_value = fake_zone
    # `import dns.query` rebinds the local name `dns` — attribute access
    # then goes through `dns.query` not sys.modules['dns.query']. Wire
    # the submodules onto the parent namespace so that path resolves.
    fake_dns_root = MagicMock()
    fake_dns_root.query = fake_dns_query
    fake_dns_root.zone = fake_dns_zone
    fake_dns_root.exception = fake_dns_exception

    with patch.dict(sys.modules, {
        "dns": fake_dns_root,
        "dns.query": fake_dns_query,
        "dns.zone": fake_dns_zone,
        "dns.exception": fake_dns_exception,
    }):
        out = anon_protocol_probe._probe_dns_axfr(
            "10.0.0.53", 53, {"zone": "example.com"}, 5,
        )

    assert out["axfr_allowed"] is True
    assert out["zone"] == "example.com"
    assert out["record_count"] == 3
    assert any("www" in r for r in out["sample_records"])


def test_dns_axfr_probe_axfr_refused_returns_false_not_error():
    """A FormError from dnspython means the server refused AXFR — that's
    a normal "no finding" outcome, not a probe failure."""
    fake_form = type("FormErr", (Exception,), {})

    fake_dns_query = MagicMock()
    fake_dns_query.xfr.side_effect = fake_form("REFUSED")
    fake_dns_zone = MagicMock()
    fake_dns_exception = MagicMock()
    fake_dns_exception.FormError = fake_form
    fake_dns_exception.DNSException = type("DNSException", (Exception,), {})
    fake_dns_root = MagicMock()
    fake_dns_root.query = fake_dns_query
    fake_dns_root.zone = fake_dns_zone
    fake_dns_root.exception = fake_dns_exception

    with patch.dict(sys.modules, {
        "dns": fake_dns_root,
        "dns.query": fake_dns_query,
        "dns.zone": fake_dns_zone,
        "dns.exception": fake_dns_exception,
    }):
        out = anon_protocol_probe._probe_dns_axfr(
            "10.0.0.53", 53, {"zone": "example.com"}, 5,
        )

    assert out["axfr_allowed"] is False
    assert "_errors" not in out


def test_dns_axfr_probe_requires_zone_param():
    out = anon_protocol_probe._probe_dns_axfr("10.0.0.53", 53, {}, 5)
    assert "_errors" in out and "dns_axfr" in out["_errors"]


# ── Kerberos ─────────────────────────────────────────────────────────


def test_kerberos_probe_marks_kdc_reachable_on_any_well_shaped_reply():
    """Any KDC reply (even malformed) past the length-prefix proves
    something is listening on TCP/88. We don't need a parseable
    KRB-ERROR to mark it reachable."""
    # Length-prefix = 32 bytes, then a tiny ASN.1-ish blob containing
    # the realm "EXAMPLE.COM".
    body = b"\x7e\x10\xa0\x03\x02\x01\x05" + b"EXAMPLE.COM" + b"\x00" * 14
    fake = _FakeSocket(recv_chunks=[
        len(body).to_bytes(4, "big"),
        body,
    ])
    with patch("agent.anon_protocol_probe.socket.create_connection", return_value=fake):
        out = anon_protocol_probe._probe_kerberos("h", 88, {}, 5)

    assert out["kdc_reachable"] is True
    # The realm extractor picks the longest dotted-uppercase token —
    # "EXAMPLE.COM" should win.
    assert out["realm"] == "EXAMPLE.COM"


def test_kerberos_probe_connect_failure_returns_errors():
    with patch("agent.anon_protocol_probe.socket.create_connection",
               side_effect=socket.timeout("timed out")):
        out = anon_protocol_probe._probe_kerberos("h", 88, {}, 1)

    assert "_errors" in out and "kerberos" in out["_errors"]


def test_kerberos_realm_extractor_picks_longest_dotted_uppercase_token():
    """Direct-test the parser: the helper should pick `CORP.AD.LOCAL` —
    longest valid realm-shape — out of mixed bytes."""
    blob = b"\x00\x01garbage CORP.AD.LOCAL more\xff lower.case BAD"
    realm = anon_protocol_probe._extract_kerberos_realm(blob)
    assert realm == "CORP.AD.LOCAL"


# ── TFTP ─────────────────────────────────────────────────────────────


def _fake_udp_socket(per_filename_responses: dict[str, bytes | None]):
    """Build a fake UDP socket whose recvfrom returns the next response
    for whichever filename was just sent. None means "timeout"."""
    state = {"last_filename": None}

    class _UDP:
        def settimeout(self, t):
            pass

        def sendto(self, packet, addr):
            # RRQ packet = 0x00 0x01 + filename + 0 + mode + 0
            assert packet[:2] == b"\x00\x01"
            tail = packet[2:]
            filename = tail.split(b"\x00", 1)[0].decode("ascii", "replace")
            state["last_filename"] = filename

        def recvfrom(self, n):
            resp = per_filename_responses.get(state["last_filename"])
            if resp is None:
                raise socket.timeout("timed out")
            return resp, ("h", 69)

        def close(self):
            pass

    return _UDP()


def test_tftp_probe_reports_filenames_that_returned_data():
    """A DATA opcode (0x00 0x03) means the file is readable. Our probe
    never ACKs — the server gives up — so contents don't stream."""
    responses = {fn: None for fn in anon_protocol_probe._TFTP_COMMON_FILES}
    responses["running-config"] = b"\x00\x03\x00\x01" + b"hostname switch"
    responses["pxelinux.cfg/default"] = b"\x00\x03\x00\x01" + b"prompt 0"

    with patch("agent.anon_protocol_probe.socket.socket",
               return_value=_fake_udp_socket(responses)):
        out = anon_protocol_probe._probe_tftp("h", 69, {}, 2)

    assert sorted(out["readable_files"]) == sorted(["running-config", "pxelinux.cfg/default"])
    assert out["probed_count"] == len(anon_protocol_probe._TFTP_COMMON_FILES)


def test_tftp_probe_ignores_op_params_filenames_for_safety():
    """The hardcoded filename list is the single source of truth.
    Anything an LLM passes through op_params must be ignored."""
    responses = {fn: None for fn in anon_protocol_probe._TFTP_COMMON_FILES}
    captured = []

    class _UDP:
        def settimeout(self, t): pass
        def sendto(self, packet, addr):
            tail = packet[2:]
            captured.append(tail.split(b"\x00", 1)[0].decode("ascii", "replace"))
        def recvfrom(self, n):
            raise socket.timeout("timed out")
        def close(self): pass

    with patch("agent.anon_protocol_probe.socket.socket", return_value=_UDP()):
        anon_protocol_probe._probe_tftp(
            "h", 69, {"filenames": ["/etc/shadow", "../../passwd"]}, 2,
        )

    # Captured filenames must equal the hardcoded list exactly — no
    # smuggled paths from op_params.
    assert captured == list(anon_protocol_probe._TFTP_COMMON_FILES)


def test_tftp_probe_treats_error_opcode_as_unreadable():
    """A 0x00 0x05 (ERROR) opcode means the file isn't readable — the
    filename must NOT appear in readable_files."""
    responses = {fn: None for fn in anon_protocol_probe._TFTP_COMMON_FILES}
    responses["startup-config"] = b"\x00\x05\x00\x01File not found\x00"

    with patch("agent.anon_protocol_probe.socket.socket",
               return_value=_fake_udp_socket(responses)):
        out = anon_protocol_probe._probe_tftp("h", 69, {}, 2)

    assert out["readable_files"] == []
