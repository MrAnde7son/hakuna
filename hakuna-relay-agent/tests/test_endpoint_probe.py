"""Unit tests for agent.endpoint_probe — SIP OPTIONS, RTSP DESCRIBE, WS-Discovery.

Socket layer is mocked. We verify:
  - op allowlist
  - SIP OPTIONS request bytes match RFC 3261 §11
  - SIP response parser handles 200 OK + 401 Unauthorized + malformed input
  - RTSP DESCRIBE request bytes match RFC 7826 §13.2
  - RTSP response parser extracts Server/auth + SDP body
  - WS-Discovery envelope contains the required SOAP elements
  - WS-Discovery match parser extracts XAddrs / Scopes / EndpointReference
"""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest

from agent import endpoint_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ── Op allowlist ─────────────────────────────────────────────────────


def test_handler_rejects_unknown_op():
    with pytest.raises(endpoint_probe.EndpointProbeError, match="unknown endpoint probe op"):
        _run(endpoint_probe.endpoint_probe_handler(
            ws=None, task={},
            transport_config={"target": "10.0.0.1", "port": 5060},
            credentials={}, params={"op": "sip_register"},
        ))


def test_unicast_op_requires_target():
    with pytest.raises(endpoint_probe.EndpointProbeError, match="target is required"):
        _run(endpoint_probe.endpoint_probe_handler(
            ws=None, task={}, transport_config={}, credentials={},
            params={"op": "sip_options"},
        ))


# ── SIP request bytes ────────────────────────────────────────────────


def test_sip_options_builds_valid_request_line():
    pdu = endpoint_probe._build_sip_options("10.0.0.5", 5060)
    text = pdu.decode("ascii")
    assert text.startswith("OPTIONS sip:10.0.0.5 SIP/2.0\r\n")
    assert "Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bK" in text
    assert "Max-Forwards: 70" in text
    assert "CSeq: 1 OPTIONS" in text
    assert "Content-Length: 0" in text
    # Ends with CRLF CRLF.
    assert text.endswith("\r\n\r\n")


# ── SIP response parsing ─────────────────────────────────────────────


def test_sip_parse_200_ok_with_user_agent():
    response = (
        b"SIP/2.0 200 OK\r\n"
        b"Via: SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bKxyz\r\n"
        b"User-Agent: Yealink SIP-T46S 66.84.0.125\r\n"
        b"Server: Yealink T46S\r\n"
        b"Allow: INVITE, ACK, OPTIONS, CANCEL, BYE, REGISTER\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    out = endpoint_probe._parse_sip_response(response)
    assert out["status_code"] == 200
    assert out["reason"] == "OK"
    assert "Yealink SIP-T46S 66.84.0.125" == out["user_agent"]
    assert out["server"] == "Yealink T46S"
    assert "REGISTER" in out["allow"]
    assert out["auth_scheme"] == ""  # no 401 challenge


def test_sip_parse_401_extracts_auth_realm():
    response = (
        b"SIP/2.0 401 Unauthorized\r\n"
        b'WWW-Authenticate: Digest realm="asterisk", nonce="abc"\r\n'
        b"User-Agent: Asterisk PBX 18.0.0\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    out = endpoint_probe._parse_sip_response(response)
    assert out["status_code"] == 401
    assert out["auth_scheme"] == "digest"
    assert out["auth_realm"] == "asterisk"


def test_sip_parse_empty_response_returns_error():
    out = endpoint_probe._parse_sip_response(b"")
    assert "_errors" in out


def test_sip_parse_malformed_status_line_still_returns_dict():
    """The parser must not raise on garbage — return what it could extract."""
    out = endpoint_probe._parse_sip_response(b"garbage\r\nServer: x\r\n\r\n")
    # status_code stays None; the Server header is still parsed.
    assert out["status_code"] is None
    assert out["server"] == "x"


# ── SIP end-to-end with mocked UDP socket ────────────────────────────


def test_probe_sip_options_udp_happy_path():
    response = (
        b"SIP/2.0 200 OK\r\n"
        b"User-Agent: Polycom-VVX-VVX_411-UA/6.4.4.4768\r\n"
        b"Server: Polycom VVX 411\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    sent: list = []

    class FakeSock:
        def settimeout(self, t): pass
        def sendto(self, data, addr):
            sent.append((data, addr))
        def recvfrom(self, n):
            return response, ("10.0.0.7", 5060)
        def close(self): pass

    with patch("agent.endpoint_probe.socket.socket", return_value=FakeSock()):
        out = endpoint_probe._probe_sip_options("10.0.0.7", 5060, {"transport": "udp"}, 5)

    assert out["status_code"] == 200
    assert "Polycom" in out["user_agent"]
    assert sent[0][1] == ("10.0.0.7", 5060)


def test_probe_sip_options_rejects_invalid_transport():
    out = endpoint_probe._probe_sip_options("x", 5060, {"transport": "sctp"}, 5)
    assert "_errors" in out
    assert "sctp" in out["_errors"]["sip_options"]


# ── RTSP request bytes ───────────────────────────────────────────────


def test_rtsp_describe_builds_valid_request():
    pdu = endpoint_probe._build_rtsp_describe("10.0.0.5", 554, "/stream1")
    text = pdu.decode("ascii")
    assert text.startswith("DESCRIBE rtsp://10.0.0.5:554/stream1 RTSP/1.0\r\n")
    assert "CSeq: 1" in text
    assert "Accept: application/sdp" in text
    assert text.endswith("\r\n\r\n")


# ── RTSP response parsing ────────────────────────────────────────────


def test_rtsp_parse_200_with_sdp_body():
    response = (
        b"RTSP/1.0 200 OK\r\n"
        b"CSeq: 1\r\n"
        b"Server: Hipcam RealServer/V1.0\r\n"
        b"Content-Base: rtsp://10.0.0.5/onvif1/\r\n"
        b"Content-Type: application/sdp\r\n"
        b"Content-Length: 372\r\n"
        b"\r\n"
        b"v=0\r\no=- 1234 1 IN IP4 10.0.0.5\r\ns=Session\r\n"
        b"c=IN IP4 0.0.0.0\r\nt=0 0\r\nm=video 0 RTP/AVP 96\r\n"
    )
    out = endpoint_probe._parse_rtsp_response(response, path="/")
    assert out["status_code"] == 200
    assert "Hipcam" in out["server"]
    assert out["content_base"] == "rtsp://10.0.0.5/onvif1/"
    assert out["content_type"] == "application/sdp"
    assert "RTP/AVP" in out["sdp_excerpt"]


def test_rtsp_parse_401_extracts_auth_realm():
    response = (
        b"RTSP/1.0 401 Unauthorized\r\n"
        b'WWW-Authenticate: Digest realm="AXIS_ACCC8EAABBCC", nonce="abc"\r\n'
        b"\r\n"
    )
    out = endpoint_probe._parse_rtsp_response(response, path="/")
    assert out["status_code"] == 401
    assert out["auth_scheme"] == "digest"
    assert out["auth_realm"] == "AXIS_ACCC8EAABBCC"


# ── WS-Discovery envelope ────────────────────────────────────────────


def test_ws_discovery_probe_envelope_well_formed():
    pdu = endpoint_probe._build_ws_discovery_probe()
    text = pdu.decode("utf-8")
    # SOAP envelope wrapping a WS-Discovery Probe addressed to the
    # well-known discovery group with the ONVIF NetworkVideoTransmitter
    # type.
    assert "<e:Envelope" in text
    assert "ws/2005/04/discovery/Probe" in text
    assert "urn:schemas-xmlsoap-org:ws:2005:04:discovery" in text
    assert "NetworkVideoTransmitter" in text
    # Unique MessageID each call (UUID).
    pdu2 = endpoint_probe._build_ws_discovery_probe()
    assert pdu != pdu2


# ── WS-Discovery match parsing ───────────────────────────────────────


_PROBE_MATCH_REPLY = (
    b'<?xml version="1.0" encoding="UTF-8"?>'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"'
    b' xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"'
    b' xmlns:wsdd="http://schemas.xmlsoap.org/ws/2005/04/discovery"'
    b' xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    b'<SOAP-ENV:Body>'
    b'<wsdd:ProbeMatches><wsdd:ProbeMatch>'
    b'<wsa:EndpointReference><wsa:Address>urn:uuid:abc-123</wsa:Address></wsa:EndpointReference>'
    b'<wsdd:Types>dn:NetworkVideoTransmitter</wsdd:Types>'
    b'<wsdd:Scopes>onvif://www.onvif.org/name/AXIS_P1448-LE'
    b' onvif://www.onvif.org/hardware/P1448-LE'
    b' onvif://www.onvif.org/Profile/Streaming</wsdd:Scopes>'
    b'<wsdd:XAddrs>http://10.0.0.5/onvif/device_service</wsdd:XAddrs>'
    b'</wsdd:ProbeMatch></wsdd:ProbeMatches></SOAP-ENV:Body>'
    b'</SOAP-ENV:Envelope>'
)


def test_ws_discovery_parse_extracts_all_fields():
    out = endpoint_probe._parse_ws_discovery_match(_PROBE_MATCH_REPLY, source=("10.0.0.5", 3702))
    assert out is not None
    assert out["source_ip"] == "10.0.0.5"
    assert out["xaddrs"] == ["http://10.0.0.5/onvif/device_service"]
    assert "NetworkVideoTransmitter" in out["types"]
    assert out["name"] == "AXIS_P1448-LE"
    assert out["hardware"] == "P1448-LE"
    assert out["endpoint_reference"] == "urn:uuid:abc-123"


def test_ws_discovery_parse_drops_replies_without_xaddrs():
    """A SOAP reply without XAddrs isn't a useful ONVIF match — return None."""
    reply = (
        b'<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope"><env:Body>'
        b'<ns:ProbeMatch xmlns:ns="x"><ns:Types>foo</ns:Types></ns:ProbeMatch>'
        b'</env:Body></env:Envelope>'
    )
    assert endpoint_probe._parse_ws_discovery_match(reply, source=("x", 0)) is None


def test_ws_discovery_parse_handles_different_prefixes():
    """Some vendors use d: or ns0: prefixes — parser must work regardless."""
    reply = (
        b'<env:Envelope xmlns:env="x"><env:Body>'
        b'<d:ProbeMatches xmlns:d="y"><d:ProbeMatch>'
        b'<d:Types>tds:Device</d:Types>'
        b'<d:XAddrs>http://10.0.0.7/onvif/device_service</d:XAddrs>'
        b'</d:ProbeMatch></d:ProbeMatches></env:Body></env:Envelope>'
    )
    out = endpoint_probe._parse_ws_discovery_match(reply, source=("10.0.0.7", 0))
    assert out is not None
    assert out["xaddrs"] == ["http://10.0.0.7/onvif/device_service"]
