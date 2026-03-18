"""MCP Transport — call tools via Model Context Protocol with auto-discovery."""

import re
import json
import logging
from typing import AsyncIterator, List, Optional

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


def _build_headers(credentials: dict) -> dict:
    """Build auth headers from credentials."""
    headers = {"Content-Type": "application/json"}
    auth_type = credentials.get("_auth_type", "")

    if auth_type == "oauth2":
        token = credentials.get("access_token", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif credentials.get("mcp_api_key"):
        headers["Authorization"] = f"Bearer {credentials['mcp_api_key']}"
    elif credentials.get("access_token"):
        headers["Authorization"] = f"Bearer {credentials['access_token']}"

    return headers


async def discover_tools(server_url: str, credentials: dict) -> dict:
    """Call tools/list to discover available tools on the MCP server.

    Returns: {tools: [{name, title, description, inputSchema}], server_info: {...}}
    """
    server_url = server_url.rstrip("/")
    headers = _build_headers(credentials)

    async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
        # Step 1: Initialize handshake
        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "hakuna", "version": "1.0"},
            },
        }

        server_info = {}
        try:
            resp = await client.post(server_url, headers=headers, json=init_payload)
            if resp.status_code < 400:
                data = resp.json()
                result = data.get("result", {})
                server_info = result.get("serverInfo", {})

                # Send initialized notification
                await client.post(server_url, headers=headers, json={
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                })
        except Exception as e:
            logger.debug("MCP initialize handshake failed (server may not require it): %s", e)

        # Step 2: List tools
        list_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }

        resp = await client.post(server_url, headers=headers, json=list_payload)

        if resp.status_code == 401 or resp.status_code == 403:
            # Discover OAuth authorization server per MCP spec
            www_auth = resp.headers.get("www-authenticate", "")
            oauth_info = _parse_www_authenticate(www_auth)
            oauth_metadata = await _discover_oauth_metadata(server_url, oauth_info, client)
            raise McpAuthRequired(
                message=f"Authentication required (HTTP {resp.status_code})",
                oauth_info=oauth_info,
                oauth_metadata=oauth_metadata,
                protected_resource_url=server_url,
            )

        if resp.status_code >= 400:
            raise RuntimeError(f"tools/list failed: HTTP {resp.status_code} — {resp.text[:300]}")

        data = resp.json()
        tools = data.get("result", {}).get("tools", [])

        return {
            "tools": tools,
            "server_info": server_info,
            "tool_count": len(tools),
        }


def _parse_www_authenticate(header: str) -> dict:
    """Parse WWW-Authenticate header to extract OAuth info."""
    info = {}
    if not header:
        return info
    # Bearer realm="...", resource_metadata="..."
    for match in re.finditer(r'(\w+)="([^"]*)"', header):
        info[match.group(1)] = match.group(2)
    return info


async def _discover_oauth_metadata(server_url: str, www_auth_info: dict, client: httpx.AsyncClient) -> dict:
    """Discover OAuth authorization server metadata per MCP OAuth 2.1 spec.

    Flow:
    1. Try /.well-known/oauth-protected-resource on the MCP server
    2. Extract authorization_servers URL
    3. Fetch /.well-known/oauth-authorization-server from that URL
    4. Return full metadata (authorization_endpoint, token_endpoint, scopes, etc.)
    """
    from urllib.parse import urlparse
    parsed = urlparse(server_url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    metadata = {}

    # Step 1: Fetch protected resource metadata
    resource_metadata_url = www_auth_info.get("resource_metadata")
    if not resource_metadata_url:
        resource_metadata_url = f"{base_origin}/.well-known/oauth-protected-resource"

    try:
        resp = await client.get(resource_metadata_url)
        if resp.status_code == 200:
            resource_meta = resp.json()
            metadata["resource"] = resource_meta
            metadata["resource_url"] = resource_metadata_url
            auth_servers = resource_meta.get("authorization_servers", [])
            scopes = resource_meta.get("scopes_supported", [])
            metadata["scopes_supported"] = scopes

            # Step 2: Fetch authorization server metadata
            if auth_servers:
                auth_server_url = auth_servers[0]
                as_metadata_url = f"{auth_server_url}/.well-known/oauth-authorization-server"
                try:
                    as_resp = await client.get(as_metadata_url)
                    if as_resp.status_code == 200:
                        as_meta = as_resp.json()
                        metadata["authorization_endpoint"] = as_meta.get("authorization_endpoint")
                        metadata["token_endpoint"] = as_meta.get("token_endpoint")
                        metadata["registration_endpoint"] = as_meta.get("registration_endpoint")
                        metadata["scopes_supported"] = as_meta.get("scopes_supported", scopes)
                        metadata["code_challenge_methods_supported"] = as_meta.get("code_challenge_methods_supported", ["S256"])
                        metadata["issuer"] = as_meta.get("issuer")
                        metadata["auth_server_raw"] = as_meta
                except Exception as e:
                    logger.debug("Failed to fetch AS metadata from %s: %s", as_metadata_url, e)
    except Exception as e:
        logger.debug("Failed to fetch resource metadata from %s: %s", resource_metadata_url, e)

    # Fallback: try oauth-authorization-server directly on base origin
    if "authorization_endpoint" not in metadata:
        try:
            resp = await client.get(f"{base_origin}/.well-known/oauth-authorization-server")
            if resp.status_code == 200:
                as_meta = resp.json()
                metadata["authorization_endpoint"] = as_meta.get("authorization_endpoint")
                metadata["token_endpoint"] = as_meta.get("token_endpoint")
                metadata["registration_endpoint"] = as_meta.get("registration_endpoint")
                metadata["scopes_supported"] = as_meta.get("scopes_supported", [])
                metadata["code_challenge_methods_supported"] = as_meta.get("code_challenge_methods_supported", ["S256"])
                metadata["issuer"] = as_meta.get("issuer")
                metadata["auth_server_raw"] = as_meta
        except Exception:
            pass

    # Fallback: try openid-configuration
    if "authorization_endpoint" not in metadata:
        try:
            resp = await client.get(f"{base_origin}/.well-known/openid-configuration")
            if resp.status_code == 200:
                oidc = resp.json()
                metadata["authorization_endpoint"] = oidc.get("authorization_endpoint")
                metadata["token_endpoint"] = oidc.get("token_endpoint")
                metadata["scopes_supported"] = oidc.get("scopes_supported", [])
        except Exception:
            pass

    return metadata


class McpAuthRequired(Exception):
    """Raised when MCP server requires authentication."""
    def __init__(self, message: str, oauth_info: dict = None, oauth_metadata: dict = None, protected_resource_url: str = None):
        super().__init__(message)
        self.oauth_info = oauth_info or {}
        self.oauth_metadata = oauth_metadata or {}
        self.protected_resource_url = protected_resource_url


class McpTransport(BaseTransport):

    async def connect(self, config: dict, credentials: dict) -> ConnectResult:
        """Connect to MCP server. If tool_name is set, call it. Otherwise discover tools."""
        try:
            server_url = config.get("server_url", "").rstrip("/")
            tool_name = config.get("tool_name", "")

            if not server_url:
                return ConnectResult(success=False, error="server_url is required")

            # If no tool selected yet, discover available tools
            if not tool_name:
                try:
                    discovery = await discover_tools(server_url, credentials)
                    return ConnectResult(
                        success=True,
                        sample_records=[],
                        raw_response={
                            "_mcp_discovery": True,
                            "tools": discovery["tools"],
                            "server_info": discovery["server_info"],
                            "tool_count": discovery["tool_count"],
                        },
                    )
                except McpAuthRequired as e:
                    return ConnectResult(
                        success=False,
                        error=str(e),
                        raw_response={
                            "_mcp_auth_required": True,
                            "oauth_info": e.oauth_info,
                            "protected_resource_url": e.protected_resource_url,
                        },
                    )

            # Tool selected — call it
            tool_arguments = config.get("tool_arguments", {})
            context = {"params": config.get("params", {}), "credentials": credentials}
            resolved_args = _substitute(tool_arguments, context)

            headers = _build_headers(credentials)

            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": resolved_args},
            }

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                resp = await client.post(server_url, headers=headers, json=payload)

            if resp.status_code >= 400:
                return ConnectResult(success=False, error=f"HTTP {resp.status_code}: {resp.text[:500]}")

            data = resp.json()
            result = data.get("result", data)

            # Parse MCP tool result
            records = self._extract_records(result)

            return ConnectResult(
                success=True,
                sample_records=records[:10],
                raw_response=data,
            )

        except Exception as e:
            logger.exception("McpTransport.connect failed")
            return ConnectResult(success=False, error=str(e))

    async def fetch_all(self, config: dict, credentials: dict, params: dict = None) -> AsyncIterator:
        """Fetch all records from an MCP tool call."""
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
            headers = _build_headers(credentials)

            rpc_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": payload},
            }

            async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
                resp = await client.post(server_url, headers=headers, json=rpc_payload)

            return PushResult(
                success=resp.status_code < 400,
                response=resp.json() if resp.status_code < 400 else resp.text[:500],
                status_code=resp.status_code,
                error=None if resp.status_code < 400 else f"HTTP {resp.status_code}",
            )
        except Exception as e:
            return PushResult(success=False, error=str(e))

    def _extract_records(self, result) -> list:
        """Extract records from MCP tool result format."""
        if isinstance(result, list):
            return result

        if isinstance(result, dict) and "content" in result:
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
            return records

        if isinstance(result, dict):
            return [result]

        return []
