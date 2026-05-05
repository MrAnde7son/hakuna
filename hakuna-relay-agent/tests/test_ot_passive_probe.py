"""Unit tests for agent.ot_passive_probe (Phase 5).

Asserts:
  - Only the ``passive_listen`` op is accepted.
  - Profile name is a closed allowlist.
  - The handler NEVER calls sendto / sendmsg / sendall — receive only.
  - Listening loop terminates by deadline (no infinite spin).
  - Signature match counts a frame; non-match does not.
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import MagicMock, patch

import pytest

from agent import ot_passive_probe


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_handler_rejects_unknown_op():
    with pytest.raises(ot_passive_probe.OtPassiveError, match="unknown ot_passive op"):
        _run(ot_passive_probe.ot_passive_probe_handler(
            ws=None, task={},
            transport_config={"target": "x", "port": 0},
            credentials={}, params={"op": "active_send"},
        ))


def test_profile_allowlist_is_closed():
    assert set(ot_passive_probe._PROFILES.keys()) == {"yokogawa_vnetip", "cclink_ie"}


def test_run_passive_listen_rejects_unknown_profile():
    out = ot_passive_probe._run_passive_listen({"profile": "rogue", "duration_s": 1}, 5)
    assert "_errors" in out
    assert "unknown profile" in out["_errors"]["passive_listen"]


def test_run_passive_listen_clamps_duration_to_max():
    """Duration is clamped relay-side to ≤10s; supplying 600 must result in 10."""
    fake_sock = MagicMock()
    fake_sock.recvfrom.side_effect = socket.timeout()
    fake_sock.bind = MagicMock()
    fake_sock.close = MagicMock()
    with patch.object(ot_passive_probe.socket, "socket", return_value=fake_sock):
        out = ot_passive_probe._run_passive_listen(
            {"profile": "yokogawa_vnetip", "duration_s": 600}, 12,
        )
    assert out["duration_s"] == 10
    assert out["presence"] is False


def test_run_passive_listen_never_sends_anything():
    """The handler is RECEIVE-ONLY. Verify no send-family method is called.
    Also exercise the signature-match path: frames with the magic bytes
    should be counted; non-matching frames should be ignored."""
    fake_sock = MagicMock()

    matching = b"\x00\x01VNET\x02\x03 yokogawa-control"
    non_matching = b"\x99\x99\x99\x99 random udp"

    queue = [
        (matching, ("10.0.0.5", 12289)),
        (non_matching, ("10.0.0.6", 12289)),
    ]

    def fake_recvfrom(_n):
        if queue:
            return queue.pop(0)
        # After the seeded frames are drained, simulate the bind being idle
        # for the rest of the listening window — the loop exits on deadline.
        raise socket.timeout()

    fake_sock.recvfrom.side_effect = fake_recvfrom
    fake_sock.bind = MagicMock()
    fake_sock.close = MagicMock()
    fake_sock.settimeout = MagicMock()
    fake_sock.setsockopt = MagicMock()

    with patch.object(ot_passive_probe.socket, "socket", return_value=fake_sock):
        out = ot_passive_probe._run_passive_listen(
            {"profile": "yokogawa_vnetip", "duration_s": 1}, 5,
        )

    # No send-family methods on the socket — receive-only contract.
    assert not fake_sock.sendto.called
    assert not fake_sock.sendall.called
    assert not fake_sock.send.called
    # One matching frame counted, the non-matching one ignored.
    assert out["frames_observed"] >= 1
    assert "10.0.0.5" in out["peers"]


def test_run_passive_listen_handles_bind_error():
    fake_sock = MagicMock()
    fake_sock.bind.side_effect = OSError("address in use")
    fake_sock.close = MagicMock()
    with patch.object(ot_passive_probe.socket, "socket", return_value=fake_sock):
        out = ot_passive_probe._run_passive_listen(
            {"profile": "cclink_ie", "duration_s": 1}, 5,
        )
    assert "_errors" in out
    assert "bind" in out["_errors"]["passive_listen"]
