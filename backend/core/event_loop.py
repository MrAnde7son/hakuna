"""Tracks the FastAPI/uvicorn main event loop so worker threads can dispatch
coroutines back onto it.

Why this exists: in-process services like ``RelayBroker`` keep state
(``asyncio.Future`` objects, websocket refs) bound to the loop where they
were created. When code on a ``ThreadPoolExecutor`` worker thread (e.g. the
agent-resume ``job_manager`` worker) needs to ``await`` one of those futures,
it must do so via the *owning* loop — calling ``asyncio.run(coro)`` in the
worker thread spins up a fresh loop whose futures the WS handler can never
wake up. Result: the worker hangs until the task timeout fires.

``run_on_main_loop(coro)`` is the thread-safe bridge: it submits the coroutine
to the captured main loop and blocks the worker until the result is ready.

Capture happens once during FastAPI startup; ``run_on_main_loop`` is a no-op
fallback that just runs the coroutine locally if the main loop hasn't been
captured yet (tests, CLI scripts, audit-worker process).
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Awaitable, Optional, TypeVar

logger = logging.getLogger(__name__)

_T = TypeVar("_T")
_main_loop: Optional[asyncio.AbstractEventLoop] = None
_main_thread_id: Optional[int] = None


def capture_main_loop() -> None:
    """Record the currently-running loop as the backend's main loop.

    Call once from a startup coroutine (FastAPI ``startup`` event handler
    or equivalent). Safe to call repeatedly — later calls are ignored.
    """
    global _main_loop, _main_thread_id
    if _main_loop is not None:
        return
    try:
        _main_loop = asyncio.get_running_loop()
        _main_thread_id = threading.get_ident()
        logger.info("Captured main event loop (thread=%s)", _main_thread_id)
    except RuntimeError:
        logger.warning("capture_main_loop() called without a running loop — skipping")


def get_main_loop() -> Optional[asyncio.AbstractEventLoop]:
    return _main_loop


def is_on_main_loop() -> bool:
    """True when the caller is executing on the captured main loop's thread.

    Used by sync helpers to decide whether to dispatch via
    ``run_coroutine_threadsafe`` (cross-thread) or just call locally.
    """
    if _main_loop is None or _main_thread_id is None:
        return False
    return threading.get_ident() == _main_thread_id


def run_on_main_loop(coro: Awaitable[_T], *, timeout: Optional[float] = None) -> _T:
    """Run ``coro`` on the captured main loop and block the calling thread
    until it completes.

    Falls back to ``asyncio.run(coro)`` when the main loop hasn't been
    captured (tests, scripts, audit-worker process). Raises whatever
    ``coro`` raises.
    """
    if _main_loop is None or not _main_loop.is_running():
        return asyncio.run(coro)
    if is_on_main_loop():
        # We're already on the right loop — but it's running, so we can't
        # nest another asyncio.run. Caller should ``await`` directly in
        # this case; defensively, run on a worker thread.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result(timeout=timeout)
    fut = asyncio.run_coroutine_threadsafe(coro, _main_loop)
    return fut.result(timeout=timeout)
