"""Lightweight API transport for the relay agent.

This is a simplified version of the backend's ApiTransport — handles
template substitution, auth injection, pagination, and HTTP requests.
Runs entirely inside the customer's network.
"""

import re
import base64
import logging
from typing import AsyncIterator

import httpx

logger = logging.getLogger(__name__)

_TEMPLATE_RE = re.compile(r'\{\{(\w+(?:\.\w+)*)\}\}')


def _substitute(value, context: dict):
    """Recursively substitute {{key.subkey}} templates."""
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


def _resolve_dot_path(obj, path):
    """Resolve a dot-path like 'response.results' into an object."""
    if not path:
        return obj
    for part in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _inject_auth(headers: dict, credentials: dict):
    """Inject authentication into request headers."""
    auth_type = credentials.get("_auth_type", "")

    if auth_type == "api_key":
        header_name = credentials.get("header_name", "Authorization")
        headers[header_name] = credentials.get("api_key", "") or credentials.get("api_token", "")

    elif auth_type in ("bearer", "oauth2", "client_credentials"):
        token = credentials.get("access_token", "") or credentials.get("token", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"

    elif auth_type == "basic":
        username = credentials.get("username") or credentials.get("email", "")
        password = credentials.get("password") or credentials.get("api_token", "")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    elif auth_type == "pat":
        token = credentials.get("pat") or credentials.get("token", "")
        headers["Authorization"] = f"Bearer {token}"


def _build_context(config: dict, credentials: dict, params: dict = None):
    return {
        "params": params or config.get("params", {}),
        "credentials": credentials,
        "instance_url": credentials.get("instance_url", config.get("base_url", "")),
    }


class LocalApiTransport:
    """Executes HTTP requests locally against on-prem services."""

    def __init__(self, timeout: int = 60, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    async def connect(self, config: dict, credentials: dict) -> dict:
        """Single test request — returns ConnectResult-compatible dict."""
        try:
            ctx = _build_context(config, credentials)
            base_url = _substitute(config.get("base_url", ""), ctx)
            path = _substitute(config.get("path", ""), ctx)
            method = config.get("method", "GET").upper()
            headers = _substitute(config.get("headers", {}), ctx)
            query_params = _substitute(config.get("query_params", {}), ctx)
            body = _substitute(config.get("body"), ctx)

            _inject_auth(headers, credentials)

            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if path else base_url

            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.request(
                    method, url, headers=headers, params=query_params,
                    json=body if body and method != "GET" else None,
                )

            if resp.status_code >= 400:
                return {
                    "success": False,
                    "error": f"HTTP {resp.status_code}: {resp.text[:500]}",
                    "raw_response": resp.text[:2000],
                }

            raw = resp.json()
            records_path = config.get("records_path")
            records = _resolve_dot_path(raw, records_path) if records_path else raw

            if isinstance(records, list):
                sample = records[:10]
            elif isinstance(records, dict):
                sample = [records]
            else:
                sample = []

            return {
                "success": True,
                "sample_records": sample,
                "raw_response": raw,
                "detected_records_path": records_path,
            }
        except httpx.RequestError as e:
            return {"success": False, "error": f"Connection error: {e}"}
        except Exception as e:
            logger.exception("connect failed")
            return {"success": False, "error": str(e)}

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Fetch all records with pagination. Yields records one at a time."""
        pagination = config.get("pagination", {})
        strategy = pagination.get("strategy", "none")

        if strategy == "none":
            result = await self.connect(config, credentials)
            if result.get("success"):
                for record in result.get("sample_records", []):
                    yield record
            return

        if strategy == "offset":
            async for record in self._paginate_offset(config, credentials, params, pagination):
                yield record
        elif strategy == "cursor":
            async for record in self._paginate_cursor(config, credentials, params, pagination):
                yield record
        elif strategy == "page":
            async for record in self._paginate_page(config, credentials, params, pagination):
                yield record
        else:
            result = await self.connect(config, credentials)
            if result.get("success"):
                for record in result.get("sample_records", []):
                    yield record

    async def push(self, config: dict, credentials: dict, payload: dict) -> dict:
        """Send a single payload to the configured endpoint."""
        try:
            ctx = _build_context(config, credentials)
            base_url = _substitute(config.get("base_url", ""), ctx)
            path = _substitute(config.get("path", ""), ctx)
            method = config.get("method", "POST").upper()
            headers = _substitute(config.get("headers", {}), ctx)

            _inject_auth(headers, credentials)

            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if path else base_url

            async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
                resp = await client.request(method, url, headers=headers, json=payload)

            return {
                "success": resp.status_code < 400,
                "response": resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:2000],
                "status_code": resp.status_code,
                "error": None if resp.status_code < 400 else f"HTTP {resp.status_code}",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── Pagination helpers ──

    async def _make_request(self, config, credentials, params, extra_query=None):
        ctx = _build_context(config, credentials, params)
        base_url = _substitute(config.get("base_url", ""), ctx)
        path = _substitute(config.get("path", ""), ctx)
        method = config.get("method", "GET").upper()
        headers = _substitute(config.get("headers", {}), ctx)
        query_params = _substitute(config.get("query_params", {}), ctx)
        body = _substitute(config.get("body"), ctx)

        if extra_query:
            query_params.update(extra_query)

        _inject_auth(headers, credentials)

        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if path else base_url

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            resp = await client.request(
                method, url, headers=headers, params=query_params,
                json=body if body and method != "GET" else None,
            )

        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")

        raw = resp.json()
        records_path = config.get("records_path")
        records = _resolve_dot_path(raw, records_path) if records_path else raw
        if not isinstance(records, list):
            records = [records] if records else []
        return records, raw

    async def _paginate_offset(self, config, credentials, params, pagination):
        page_size = pagination.get("page_size", 100)
        offset_param = pagination.get("offset_param", "offset")
        page_size_param = pagination.get("page_size_param", "limit")
        total_field = pagination.get("total_field")
        offset = 0

        while True:
            extra = {offset_param: str(offset), page_size_param: str(page_size)}
            records, raw = await self._make_request(config, credentials, params, extra_query=extra)
            for record in records:
                yield record
            if len(records) < page_size:
                break
            offset += len(records)
            if total_field:
                total = _resolve_dot_path(raw, total_field)
                if total is not None and offset >= int(total):
                    break

    async def _paginate_cursor(self, config, credentials, params, pagination):
        cursor_param = pagination.get("cursor_param", "cursor")
        cursor_field = pagination.get("cursor_field", "next_cursor")
        page_size = pagination.get("page_size", 100)
        page_size_param = pagination.get("page_size_param", "limit")
        cursor = None

        while True:
            extra = {page_size_param: str(page_size)}
            if cursor:
                extra[cursor_param] = cursor
            records, raw = await self._make_request(config, credentials, params, extra_query=extra)
            for record in records:
                yield record
            cursor = _resolve_dot_path(raw, cursor_field)
            if not cursor or len(records) == 0:
                break

    async def _paginate_page(self, config, credentials, params, pagination):
        page_param = pagination.get("page_param", "page")
        page_size = pagination.get("page_size", 100)
        page_size_param = pagination.get("page_size_param", "limit")
        total_field = pagination.get("total_field")
        page = 1

        while True:
            extra = {page_param: str(page), page_size_param: str(page_size)}
            records, raw = await self._make_request(config, credentials, params, extra_query=extra)
            for record in records:
                yield record
            if len(records) < page_size:
                break
            page += 1
            if total_field:
                total = _resolve_dot_path(raw, total_field)
                if total is not None and (page - 1) * page_size >= int(total):
                    break
