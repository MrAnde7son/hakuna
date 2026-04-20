"""Pluggable handler registry for task methods received by the relay agent.

A method handler is an async function:

    async def handler(ws, task, transport_config, credentials, params) -> dict

It returns a dict that the executor sends back as `task_complete.result`.
Handlers self-register at import time via `@register_method("name")`.

Why this exists: before the Collector abstraction, `executor.py` hardcoded
the `method == "wmi_query"` branch. To add osquery we would have copy-pasted.
Each new method handler now lives next to its transport module and plugs in
with a single decorator call, no executor edits.
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable


Handler = Callable[..., Awaitable[dict]]


METHOD_HANDLERS: dict[str, Handler] = {}


def register_method(name: str):
    def decorator(fn: Handler) -> Handler:
        METHOD_HANDLERS[name] = fn
        return fn
    return decorator


def get_handler(name: str) -> Handler | None:
    return METHOD_HANDLERS.get(name)
