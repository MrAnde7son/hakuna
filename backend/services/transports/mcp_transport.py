"""MCP Transport — call tools via Model Context Protocol."""

import re
import json
import logging
from typing import AsyncIterator

import httpx

from .base import BaseTransport, ConnectResult, PushResult

logger = logging.getLogger(__name__)

_TEMPLATE_RE = re.compile(r'\{\{(\w+(?:\.\w+)*)\}\}')


def _substitute(value, context: dict):
    if isinstance(value, str):
        def _replacer(m):
            path = m.group(1)
            parts = path.split(".")
            obj = context
            for p in parts:
                if isinstance(obj, dict):
                    obj = obj.get(p, "")
                else:
                    return ""
            return str(obj) if obj is not None else ""
        return _TEMPLATE_RE.sub(_replacer, value)
    if isinstance(value, dict):
        return {k: _substitute(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute(item, context) for item in value]
    return value


class McpTransport(BaseTransport):

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Call an MCP tool and return the result."""
        try:
            server_url = config.get("server_url", "").rstrip("/")
            tool_name = config.get("tool_name", "")
            tool_arguments = config.get("tool_arguments", {})

            if not server_url or not tool_name:
                return ConnectResult(success=False, error="server_url and tool_name are required")

            context = {"params": config.get("params", {}), "credentials": credentials}
            resolved_args = _substitute(tool_arguments, context)

            headers = {"Content-Type": "application/json"}
            api_key = credentials.get("mcp_api_key")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            # MCP JSON-RPC call
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": resolved_args,
                },
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(server_url, headers=headers, json=payload)

            if resp.status_code >= 400:
                return ConnectResult(success=False, error=f"HTTP {resp.status_code}: {resp.text[:500]}")

            data = resp.json()

            # Extract result from JSON-RPC response
            result = data.get("result", data)
            if isinstance(result, dict) and "content" in result:
                # MCP tool result format: {content: [{type: "text", text: "..."}]}
                contents = result.get("content", [])
                records = []
                for c in contents:
                    if c.get("type") == "text":
                        try:
                            parsed = json.loads(c["text"])
                            if isinstance(parsed, list):
                                records.extend(parsed)
                            else:
                                records.append(parsed)
                        except (json.JSONDecodeError, KeyError):
                            records.append({"text": c.get("text", "")})
                    elif c.get("type") == "resource":
                        records.append(c)
                return ConnectResult(success=True, sample_records=records[:10], raw_response=data)

            # If result is already a list
            if isinstance(result, list):
                return ConnectResult(success=True, sample_records=result[:10], raw_response=data)

            # Wrap single result
            return ConnectResult(success=True, sample_records=[result], raw_response=data)

        except Exception as e:
            logger.exception("McpTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Fetch all records — MCP tools typically return all data at once."""
        merged_config = {**config}
        if params:
            merged_config.setdefault("params", {}).update(params)

        result = await self.connect(merged_config, credentials)
        if result.success:
            for record in result.sample_records:
                yield record

    async def push(self, config: dict, credentials: dict, payload: dict) -> PushResult:
        """Push data by calling an MCP tool with the payload as arguments."""
        try:
            server_url = config.get("server_url", "").rstrip("/")
            tool_name = config.get("tool_name", "")

            headers = {"Content-Type": "application/json"}
            api_key = credentials.get("mcp_api_key")
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": payload},
            }

            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(server_url, headers=headers, json=rpc_payload)

            return PushResult(
                success=resp.status_code < 400,
                response=resp.json() if resp.status_code < 400 else resp.text[:500],
                status_code=resp.status_code,
                error=None if resp.status_code < 400 else f"HTTP {resp.status_code}",
            )
        except Exception as e:
            return PushResult(success=False, error=str(e))
