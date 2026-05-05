"""Regression tests for RelayBroker reconnect / disconnect handling.

The broker stores one ws per agent_id. A relay agent that drops and reconnects
within the same second produces overlapping handlers: the old socket's
``finally`` runs after ``register`` has already swapped in the new socket.
Without ws-scoped unregister the stale handler clobbers the live entry.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

from services.relay_broker import RelayBroker


def _fake_ws():
    ws = MagicMock()
    ws.send_json = AsyncMock()
    ws.close = AsyncMock()
    return ws


def test_unregister_with_matching_ws_clears_entry():
    broker = RelayBroker()
    ws = _fake_ws()

    asyncio.run(broker.register("a1", ws))
    assert broker.is_connected("a1")

    asyncio.run(broker.unregister("a1", ws=ws))
    assert not broker.is_connected("a1")


def test_unregister_with_stale_ws_does_not_clobber_live_socket():
    """Old handler running after a reconnect must not pop the new socket."""
    broker = RelayBroker()
    old_ws = _fake_ws()
    new_ws = _fake_ws()

    asyncio.run(broker.register("a1", old_ws))
    asyncio.run(broker.register("a1", new_ws))   # reconnect supersedes old_ws
    assert broker._connections["a1"] is new_ws

    # Old handler's finally fires late — it must NOT remove the new ws.
    asyncio.run(broker.unregister("a1", ws=old_ws))
    assert broker.is_connected("a1")
    assert broker._connections["a1"] is new_ws


def test_unregister_without_ws_legacy_still_clears_entry():
    """Callers that haven't been updated to pass ws keep the old behavior."""
    broker = RelayBroker()
    ws = _fake_ws()

    asyncio.run(broker.register("a1", ws))
    asyncio.run(broker.unregister("a1"))
    assert not broker.is_connected("a1")


def test_send_task_translates_closed_socket_to_connection_error():
    """Starlette raises RuntimeError when the ws closed under us; tools
    expect ConnectionError so they can degrade gracefully."""
    broker = RelayBroker()
    ws = _fake_ws()
    ws.send_json = AsyncMock(
        side_effect=RuntimeError(
            'Cannot call "send" once a close message has been sent.'
        )
    )
    asyncio.run(broker.register("a1", ws))

    async def go():
        try:
            await broker.send_task("a1", method="ssh_query", config={})
        except ConnectionError as e:
            return ("ok", str(e))
        except Exception as e:
            return ("wrong", repr(e))
        return ("none", None)

    kind, _ = asyncio.run(go())
    assert kind == "ok"
    # Dead ws should also be evicted so future is_connected() returns False.
    assert not broker.is_connected("a1")
