"""API Transport — HTTP-based integration transport with pagination."""

import re
import logging
from typing import AsyncIterator

import httpx

from .base import BaseTransport, ConnectResult, PushResult

logger = logging.getLogger(__name__)

# Template substitution: {{params.X}}, {{credentials.X}}, {{instance_url}}
_TEMPLATE_RE = re.compile(r'\{\{(\w+(?:\.\w+)*)\}\}')

# AWS Query API and other XML APIs commonly wrap list items in singular tags
# (e.g. <Users><member>…</member><member>…</member></Users>). xmltodict collapses
# single-element wrappers to dicts; force these well-known keys to always be lists
# so dot-path resolution and pagination work consistently.
_XML_FORCE_LIST_KEYS = frozenset({
    "item", "member", "Bucket", "Tag", "Group", "Role", "User", "Policy",
    "AttachedPolicy", "InstanceProfile", "AccessKeyMetadata", "ServerCertificate",
    "Reservation", "Instance", "BlockDeviceMapping", "NetworkInterface",
    "GroupIdentifier", "ProductCode", "SecurityGroup", "Address", "Volume",
    "Snapshot", "Image", "KeyPair", "Subnet", "Vpc", "RouteTable", "Route",
    "InternetGateway", "Attachment",
})


def _parse_response(resp: httpx.Response):
    """Parse an HTTP response body as JSON or XML based on content-type.

    AWS Query APIs (EC2, IAM, S3) return XML; we transparently convert that to
    a JSON-shaped dict via xmltodict so connector field maps can use the same
    dot-path syntax regardless of the underlying wire format.
    """
    content_type = (resp.headers.get("content-type") or "").lower()
    body = resp.text or ""

    # XML detection: explicit content-type or sniff the leading character.
    is_xml = (
        "xml" in content_type
        or body.lstrip().startswith("<?xml")
        or body.lstrip().startswith("<")
        and not (body.lstrip().startswith("{") or body.lstrip().startswith("["))
    )

    if is_xml and body.strip():
        try:
            import xmltodict
        except ImportError as exc:
            raise RuntimeError(
                "xmltodict is required to parse XML responses. Install it: pip install xmltodict"
            ) from exc

        def _force_list(path, key, value):
            return key in _XML_FORCE_LIST_KEYS

        parsed = xmltodict.parse(
            body,
            process_namespaces=False,
            force_list=_force_list,
            attr_prefix="@",
            cdata_key="#text",
        )
        return _strip_xml_namespaces(parsed)

    # Default: JSON
    try:
        return resp.json()
    except Exception:
        # Last resort: return raw text wrapped so callers don't crash
        return {"_raw": body}


def _strip_xml_namespaces(obj):
    """Strip XML namespace prefixes from dict keys recursively (e.g. 'ns:Foo' -> 'Foo').

    AWS XML responses sometimes use default namespaces; xmltodict preserves them
    when process_namespaces=False, but the prefixes vary across services and
    confuse field mapping. We normalize by stripping anything before the colon.
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            new_key = k.split(":", 1)[1] if ":" in k and not k.startswith("@") and not k.startswith("#") else k
            # Skip XML namespace declaration attributes
            if new_key.startswith("@xmlns"):
                continue
            cleaned[new_key] = _strip_xml_namespaces(v)
        return cleaned
    if isinstance(obj, list):
        return [_strip_xml_namespaces(item) for item in obj]
    return obj


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
    """Resolve a dot-path into an object, supporting array indexing.

    Supports:
      - simple keys:  'response.results'
      - fixed index:  'reservationSet.item[0].instanceId'
      - flatten all:  'reservationSet.item[*].instancesSet.item[*]'  (returns flat list)
    """
    if not path:
        return obj
    if "[*]" in path:
        before, after = path.split("[*]", 1)
        arr = _resolve_dot_path(obj, before)
        if not isinstance(arr, list):
            return None
        after = after.lstrip(".")
        if not after:
            return arr
        # Recursively resolve and flatten one level
        flat = []
        for item in arr:
            sub = _resolve_dot_path(item, after)
            if isinstance(sub, list):
                flat.extend(sub)
            elif sub is not None:
                flat.append(sub)
        return flat

    parts = re.split(r'\.(?![^\[]*\])', path)
    current = obj
    for part in parts:
        if current is None:
            return None
        # Handle bracket index: 'item[0]'
        match = re.match(r'^(.+?)\[(\d+)\]$', part)
        if match:
            key, idx = match.group(1), int(match.group(2))
            if isinstance(current, dict):
                current = current.get(key)
            else:
                return None
            if isinstance(current, list) and idx < len(current):
                current = current[idx]
            else:
                return None
        elif isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _inject_auth(headers: dict, credentials: dict):
    """Inject authentication into request headers based on credential type.

    Skips injection if an Authorization header was already set via template
    substitution (e.g. ``Authorization: Bearer {{credentials.api_token}}``).
    """
    if headers.get("Authorization"):
        return

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
        # Support email/api_token (Jira) as well as username/password
        username = credentials.get("username") or credentials.get("email", "")
        password = credentials.get("password") or credentials.get("api_token", "")
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {encoded}"

    elif auth_type == "pat":
        token = credentials.get("token", "")
        headers["Authorization"] = f"Bearer {token}"

    # If auth is injected via template substitution in config headers, that's handled
    # by _substitute already — this covers the standard patterns.


def _inject_aws_sigv4(headers: dict, credentials: dict, config: dict, method: str, url: str, body=None):
    """Sign a request with AWS SigV4 using requests-aws4auth."""
    try:
        from requests_aws4auth import AWS4Auth
    except ImportError:
        raise RuntimeError("requests-aws4auth is required for AWS SigV4 auth. Install it: pip install requests-aws4auth")

    region = credentials.get("region") or config.get("params", {}).get("region", "us-east-1")
    service = config.get("aws_service", "execute-api")
    access_key = credentials.get("access_key_id", "")
    secret_key = credentials.get("secret_access_key", "")

    auth = AWS4Auth(access_key, secret_key, region, service)

    # AWS4Auth works with requests library; we extract headers manually
    from urllib.parse import urlparse
    import datetime

    parsed = urlparse(url)
    host = parsed.hostname

    # Build a minimal requests-compatible object for signing
    from requests import Request
    req = Request(method=method, url=url, headers={**headers, "Host": host})
    if body:
        import json as _json
        req.data = _json.dumps(body) if isinstance(body, dict) else body
    prepared = req.prepare()
    auth(prepared)

    # Copy signed headers back
    for key, value in prepared.headers.items():
        if key.lower() in ("authorization", "x-amz-date", "x-amz-content-sha256", "x-amz-security-token"):
            headers[key] = value


def _inject_gcp_service_account(headers: dict, credentials: dict, config: dict):
    """Generate an OAuth2 access token from GCP service account credentials."""
    try:
        from google.oauth2 import service_account as sa
        from google.auth.transport.requests import Request as GoogleAuthRequest
    except ImportError:
        raise RuntimeError("google-auth is required for GCP service account auth. Install it: pip install google-auth")

    email = credentials.get("service_account_email", "")
    private_key = credentials.get("private_key", "")
    scopes = config.get("gcp_scopes", ["https://www.googleapis.com/auth/cloud-platform"])

    # Build credentials from the provided email + key
    info = {
        "type": "service_account",
        "client_email": email,
        "private_key": private_key,
        "token_uri": "https://oauth2.googleapis.com/token",
    }
    creds = sa.Credentials.from_service_account_info(info, scopes=scopes)
    creds.refresh(GoogleAuthRequest())

    headers["Authorization"] = f"Bearer {creds.token}"


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

            # Cloud provider auth strategies
            auth_strategy = config.get("auth_strategy")
            if auth_strategy == "aws_sigv4":
                _inject_aws_sigv4(headers, credentials, config, method, url, body)
            elif auth_strategy == "gcp_service_account":
                _inject_gcp_service_account(headers, credentials, config)

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

            raw = _parse_response(resp)
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

            ct = resp.headers.get("content-type", "")
            if ct.startswith("application/json") or "xml" in ct.lower():
                response_payload = _parse_response(resp)
            else:
                response_payload = resp.text[:2000]
            return PushResult(
                success=resp.status_code < 400,
                response=response_payload,
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

        # Cloud provider auth strategies
        auth_strategy = config.get("auth_strategy")
        if auth_strategy == "aws_sigv4":
            _inject_aws_sigv4(headers, credentials, config, method, url, body)
        elif auth_strategy == "gcp_service_account":
            _inject_gcp_service_account(headers, credentials, config)

        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            resp = await client.request(
                method, url, headers=headers, params=query_params,
                json=body if body and method != "GET" else None,
            )

        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:500]}")

        raw = _parse_response(resp)
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
