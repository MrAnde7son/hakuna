"""API Transport — HTTP-based integration transport with pagination."""

import re
import logging
from typing import AsyncIterator

import httpx

from .base import BaseTransport, ConnectResult, PushResult

logger = logging.getLogger(__name__)

# Template substitution: {{params.X}}, {{credentials.X}}, {{instance_url}}
_TEMPLATE_RE = re.compile(r'\{\{(\w+(?:\.\w+)*)\}\}')


def _substitute(value, context: dict):
    """Recursively substitute {{key.subkey}} templates in strings, dicts, lists."""
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
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _inject_auth(headers: dict, credentials: dict):
    """Inject authentication into request headers based on credential type."""
    auth_type = credentials.get("_auth_type", "")

    if auth_type == "api_key":
        header_name = credentials.get("header_name", "Authorization")
        location = credentials.get("location", "header")
        if location == "header":
            headers[header_name] = credentials.get("api_key", "")

    elif auth_type in ("bearer", "oauth2"):
        token = credentials.get("access_token", "")
        headers["Authorization"] = f"Bearer {token}"

    elif auth_type == "basic":
        import base64
        username = credentials.get("username", "")
        password = credentials.get("password", "")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    elif auth_type == "pat":
        token = credentials.get("token", "")
        headers["Authorization"] = f"Bearer {token}"

    # If auth is injected via template substitution in config headers, that's handled
    # by _substitute already — this covers the standard patterns.


def _build_context(config: dict, credentials: dict, params: dict = None):
    """Build substitution context from config, credentials, and params."""
    return {
        "params": params or config.get("params", {}),
        "credentials": credentials,
        "instance_url": credentials.get("instance_url", config.get("base_url", "")),
    }


class ApiTransport(BaseTransport):

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Make a single request and return sample records."""
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

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                resp = await client.request(
                    method, url, headers=headers, params=query_params,
                    json=body if body and method != "GET" else None,
                )

            if resp.status_code >= 400:
                return ConnectResult(
                    success=False,
                    error=f"HTTP {resp.status_code}: {resp.text[:500]}",
                    raw_response=resp.text[:2000],
                )

            raw = resp.json()
            records_path = config.get("records_path")
            records = _resolve_dot_path(raw, records_path) if records_path else raw

            # Auto-detect records path if not specified
            detected_path = records_path
            if not records_path and isinstance(raw, dict):
                detected_path = _detect_records_path(raw)
                if detected_path:
                    records = _resolve_dot_path(raw, detected_path)

            if isinstance(records, list):
                sample = records[:10]
            elif isinstance(records, dict):
                sample = [records]
            else:
                sample = []

            return ConnectResult(
                success=True,
                sample_records=sample,
                raw_response=raw,
                detected_records_path=detected_path,
            )

        except httpx.RequestError as e:
            return ConnectResult(success=False, error=f"Connection error: {e}")
        except Exception as e:
            logger.exception("ApiTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Fetch all records with pagination. Yields records one at a time."""
        pagination = config.get("pagination", {})
        strategy = pagination.get("strategy", "none")

        if strategy == "none":
            result = await self.connect(config, credentials)
            if result.success:
                for record in result.sample_records:
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
            # Unknown strategy, do single fetch
            result = await self.connect(config, credentials)
            if result.success:
                for record in result.sample_records:
                    yield record

    async def push(self, config: dict, credentials: dict, payload: dict) -> PushResult:
        """Send a single payload to the configured endpoint."""
        try:
            ctx = _build_context(config, credentials)
            base_url = _substitute(config.get("base_url", ""), ctx)
            path = _substitute(config.get("path", ""), ctx)
            method = config.get("method", "POST").upper()
            headers = _substitute(config.get("headers", {}), ctx)

            _inject_auth(headers, credentials)

            url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if path else base_url

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                resp = await client.request(method, url, headers=headers, json=payload)

            return PushResult(
                success=resp.status_code < 400,
                response=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else resp.text[:2000],
                status_code=resp.status_code,
                error=None if resp.status_code < 400 else f"HTTP {resp.status_code}",
            )
        except Exception as e:
            return PushResult(success=False, error=str(e))

    # ── Pagination strategies ──

    async def _make_request(self, config, credentials, params, extra_query=None, extra_body=None):
        """Helper: make a single HTTP request and return (records, raw_response)."""
        ctx = _build_context(config, credentials, params)
        base_url = _substitute(config.get("base_url", ""), ctx)
        path = _substitute(config.get("path", ""), ctx)
        method = config.get("method", "GET").upper()
        headers = _substitute(config.get("headers", {}), ctx)
        query_params = _substitute(config.get("query_params", {}), ctx)
        body = _substitute(config.get("body"), ctx)

        if extra_query:
            query_params.update(extra_query)
        if extra_body and isinstance(body, dict):
            body.update(extra_body)

        _inject_auth(headers, credentials)

        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}" if path else base_url

        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
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


def _detect_records_path(obj, prefix="", depth=0):
    """Auto-detect the most likely records array in a response."""
    if depth > 3:
        return None
    best_path = None
    best_len = 0
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, list) and len(value) > best_len:
                # Prefer arrays of dicts (records)
                if value and isinstance(value[0], dict):
                    best_path = path
                    best_len = len(value)
            elif isinstance(value, dict):
                deeper = _detect_records_path(value, path, depth + 1)
                if deeper:
                    deeper_val = _resolve_dot_path(obj, deeper)
                    if isinstance(deeper_val, list) and len(deeper_val) > best_len:
                        best_path = deeper
                        best_len = len(deeper_val)
    return best_path
