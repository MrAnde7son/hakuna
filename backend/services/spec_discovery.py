"""API Spec Discovery Engine — auto-detect OpenAPI, GraphQL, or LLM-parse docs."""

import json
import re
import logging
from typing import Optional, List
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

# Well-known OpenAPI paths to probe
OPENAPI_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml",
    "/api/swagger.json", "/api/v1/openapi.json", "/api/v2/openapi.json",
    "/v1/openapi.json", "/docs/openapi.json", "/api-docs", "/api-docs.json",
    "/.well-known/openapi.json",
]

# Known spec registry: hostname pattern → spec URL
KNOWN_SPECS = {
    "atlassian.net": "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.json",
    "api.crowdstrike.com": "https://assets.falcon.crowdstrike.com/support/api/swagger.json",
    "service-now.com": "{instance_url}/api/now/doc/table/schema",
}

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]

INTROSPECTION_QUERY = """
query {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind description
      fields {
        name description
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind ofType { name kind } } }
      }
    }
  }
}
"""


@dataclass
class DiscoveryResult:
    spec_source: str  # openapi | graphql | llm | registry | none
    tool_name: str = ""
    base_url: str = ""
    auth_schemes: List[dict] = field(default_factory=list)
    endpoints: List[dict] = field(default_factory=list)
    endpoint_count: int = 0
    raw_spec: Optional[dict] = None
    error: Optional[str] = None


async def discover(url: str, progress_callback=None) -> DiscoveryResult:
    """Try strategies in order, return on first success."""
    base_url = url.rstrip("/")

    # Strategy 1: Well-known OpenAPI paths
    if progress_callback:
        progress_callback("trying", strategy="well-known paths")
    result = await _try_openapi_paths(base_url)
    if result:
        if progress_callback:
            progress_callback("found", strategy="openapi", endpoint_count=result.endpoint_count)
        return result
    if progress_callback:
        progress_callback("failed", strategy="well-known paths")

    # Strategy 2: HTML scraping for spec link
    if progress_callback:
        progress_callback("trying", strategy="html scraping")
    result = await _try_html_scraping(base_url)
    if result:
        if progress_callback:
            progress_callback("found", strategy="html scraping", endpoint_count=result.endpoint_count)
        return result
    if progress_callback:
        progress_callback("failed", strategy="html scraping")

    # Strategy 3: GraphQL introspection
    if progress_callback:
        progress_callback("trying", strategy="graphql introspection")
    result = await _try_graphql(base_url)
    if result:
        if progress_callback:
            progress_callback("found", strategy="graphql", endpoint_count=result.endpoint_count)
        return result
    if progress_callback:
        progress_callback("failed", strategy="graphql introspection")

    # Strategy 4: Known spec registry
    if progress_callback:
        progress_callback("trying", strategy="known spec registry")
    result = await _try_known_registry(base_url)
    if result:
        if progress_callback:
            progress_callback("found", strategy="registry", endpoint_count=result.endpoint_count)
        return result
    if progress_callback:
        progress_callback("failed", strategy="known spec registry")

    return DiscoveryResult(
        spec_source="none",
        base_url=base_url,
        error="No machine-readable API spec found. Try pasting a docs URL or uploading docs.",
    )


# ── Strategy 1: Well-known OpenAPI paths ──

async def _try_openapi_paths(base_url: str) -> Optional[DiscoveryResult]:
    """Probe well-known paths for OpenAPI/Swagger specs."""
    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
        for path in OPENAPI_PATHS:
            try:
                resp = await client.get(f"{base_url}{path}")
                if resp.status_code == 200:
                    content_type = resp.headers.get("content-type", "")
                    text = resp.text
                    if "json" in content_type or text.strip().startswith("{"):
                        spec = json.loads(text)
                        if _is_openapi_spec(spec):
                            return _parse_openapi(spec, base_url)
            except Exception:
                continue
    return None


# ── Strategy 2: HTML scraping ──

async def _try_html_scraping(base_url: str) -> Optional[DiscoveryResult]:
    """Scrape HTML pages for embedded spec URLs."""
    pages = [base_url, f"{base_url}/docs", f"{base_url}/api/docs", f"{base_url}/developer"]

    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
        for page_url in pages:
            try:
                resp = await client.get(page_url)
                if resp.status_code != 200:
                    continue
                html = resp.text

                # Look for SwaggerUI bundle URL
                match = re.search(r'SwaggerUIBundle\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', html)
                if match:
                    spec_url = _resolve_url(base_url, match.group(1))
                    return await _fetch_and_parse_spec(client, spec_url, base_url)

                # Look for Redoc
                match = re.search(r'Redoc\.init\(\s*["\']([^"\']+)["\']', html)
                if match:
                    spec_url = _resolve_url(base_url, match.group(1))
                    return await _fetch_and_parse_spec(client, spec_url, base_url)

                # Look for link tags
                for link_match in re.finditer(r'href=["\']([^"\']*(?:openapi|swagger)[^"\']*\.(?:json|yaml))["\']', html, re.I):
                    spec_url = _resolve_url(base_url, link_match.group(1))
                    result = await _fetch_and_parse_spec(client, spec_url, base_url)
                    if result:
                        return result
            except Exception:
                continue
    return None


# ── Strategy 3: GraphQL introspection ──

async def _try_graphql(base_url: str) -> Optional[DiscoveryResult]:
    """Try GraphQL introspection on common endpoints."""
    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        for path in GRAPHQL_PATHS:
            try:
                resp = await client.post(
                    f"{base_url}{path}",
                    json={"query": INTROSPECTION_QUERY},
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data and "__schema" in data["data"]:
                        return _parse_graphql(data["data"]["__schema"], base_url, path)
            except Exception:
                continue
    return None


# ── Strategy 4: Known registry ──

async def _try_known_registry(base_url: str) -> Optional[DiscoveryResult]:
    """Check if the hostname matches a known spec URL."""
    from urllib.parse import urlparse
    hostname = urlparse(base_url).hostname or ""

    for pattern, spec_url_template in KNOWN_SPECS.items():
        if pattern in hostname:
            spec_url = spec_url_template.replace("{instance_url}", base_url)
            async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
                try:
                    result = await _fetch_and_parse_spec(client, spec_url, base_url)
                    if result:
                        result.spec_source = "registry"
                        return result
                except Exception:
                    pass
    return None


# ── LLM-assisted parsing (called externally via route) ──

async def parse_docs_with_llm(content: str, base_url: str = "") -> DiscoveryResult:
    """Send documentation text to the configured LLM for structured extraction.

    Routes through the central LLM router so the system default
    (Vertex Gemini, covered by GCP credits) is used unless the
    operator has configured a different provider.
    """
    try:
        import asyncio

        from core.database import SessionLocal
        from core.llm_router import router as llm_router

        prompt = f"""Extract structured API connector configuration from the following documentation.
Respond ONLY with valid JSON. No preamble, no markdown fences, no explanation.

Return JSON matching this schema:
{{
  "tool_name": "string",
  "base_url": "string",
  "auth_schemes": [{{"type": "api_key|oauth2|basic|bearer", "location": "header|query", "param_name": "string", "description": "string"}}],
  "endpoints": [{{
    "method": "GET|POST|PUT|DELETE",
    "path": "string",
    "operation_id": "string",
    "summary": "string",
    "tags": ["string"],
    "parameters": [{{"name": "string", "in": "query|path|header", "required": true, "type": "string", "description": "string"}}],
    "response_schema": {{"records_path": "string", "fields": [{{"path": "string", "type": "string"}}]}},
    "pagination_hints": {{"detected": true, "strategy": "offset|cursor|page|none", "page_param": "string", "size_param": "string"}}
  }}]
}}

If a field cannot be determined, omit it. Extract up to 20 most useful endpoints for pulling security data.

Documentation:
{content[:80000]}"""

        def _sync_call() -> str:
            with SessionLocal() as db:
                text, _model = llm_router.call(
                    db,
                    user=prompt,
                    max_tokens=4000,
                )
                return text

        response_text = (await asyncio.to_thread(_sync_call)).strip()
        # Strip markdown fences if present
        if response_text.startswith("```"):
            response_text = re.sub(r'^```\w*\n?', '', response_text)
            response_text = re.sub(r'\n?```$', '', response_text)

        parsed = json.loads(response_text)

        endpoints = []
        for ep in parsed.get("endpoints", []):
            endpoints.append({
                "method": ep.get("method", "GET"),
                "path": ep.get("path", ""),
                "operation_id": ep.get("operation_id", ""),
                "summary": ep.get("summary", ""),
                "tags": ep.get("tags", []),
                "parameters": ep.get("parameters", []),
                "response_schema": ep.get("response_schema"),
                "pagination_hints": ep.get("pagination_hints"),
            })

        return DiscoveryResult(
            spec_source="llm",
            tool_name=parsed.get("tool_name", ""),
            base_url=parsed.get("base_url", base_url),
            auth_schemes=parsed.get("auth_schemes", []),
            endpoints=endpoints,
            endpoint_count=len(endpoints),
            raw_spec=parsed,
        )
    except Exception as e:
        logger.exception("LLM doc parsing failed")
        return DiscoveryResult(spec_source="none", error=f"LLM parsing failed: {e}")


# ── Parsers ──

def _is_openapi_spec(data: dict) -> bool:
    """Check if a JSON dict looks like an OpenAPI/Swagger spec."""
    return (
        "openapi" in data or "swagger" in data
        or "paths" in data or "info" in data
    )


def _parse_openapi(spec: dict, base_url: str) -> DiscoveryResult:
    """Parse an OpenAPI 2.x or 3.x spec into normalized endpoints."""
    info = spec.get("info", {})
    title = info.get("title", "")

    # Extract auth schemes
    auth_schemes = []
    security_defs = spec.get("securityDefinitions", {})  # Swagger 2
    if not security_defs:
        components = spec.get("components", {})
        security_defs = components.get("securitySchemes", {})

    for name, scheme in security_defs.items():
        auth_schemes.append({
            "type": scheme.get("type", ""),
            "location": scheme.get("in", "header"),
            "param_name": scheme.get("name", name),
            "description": scheme.get("description", ""),
            "flows": scheme.get("flows", {}),
        })

    # Extract endpoints
    endpoints = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.startswith("x-") or method == "parameters":
                continue
            if not isinstance(op, dict):
                continue

            params = []
            for p in op.get("parameters", []):
                if isinstance(p, dict):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", "query"),
                        "required": p.get("required", False),
                        "type": _extract_param_type(p),
                        "description": p.get("description", ""),
                    })

            # Extract response schema hint
            response_schema = None
            responses = op.get("responses", {})
            success_resp = responses.get("200", responses.get("201", {}))
            if isinstance(success_resp, dict):
                schema = success_resp.get("schema") or _get_response_schema_3x(success_resp)
                if schema:
                    response_schema = _analyze_response_schema(schema, spec)

            # Detect pagination hints from parameter names
            pagination_hints = _detect_pagination(params)

            endpoints.append({
                "method": method.upper(),
                "path": path,
                "operation_id": op.get("operationId", ""),
                "summary": op.get("summary", ""),
                "tags": op.get("tags", []),
                "parameters": params,
                "request_body_schema": _extract_request_body(op, spec),
                "response_schema": response_schema,
                "pagination_hints": pagination_hints,
            })

    return DiscoveryResult(
        spec_source="openapi",
        tool_name=title,
        base_url=base_url,
        auth_schemes=auth_schemes,
        endpoints=endpoints,
        endpoint_count=len(endpoints),
        raw_spec=spec,
    )


def _parse_graphql(schema: dict, base_url: str, path: str) -> DiscoveryResult:
    """Parse GraphQL introspection result into normalized endpoints."""
    endpoints = []
    types_map = {t["name"]: t for t in schema.get("types", []) if t.get("name")}

    query_type_name = schema.get("queryType", {}).get("name", "Query")
    mutation_type_name = (schema.get("mutationType") or {}).get("name", "Mutation")

    for type_name, gql_method in [(query_type_name, "GET"), (mutation_type_name, "POST")]:
        type_def = types_map.get(type_name)
        if not type_def or not type_def.get("fields"):
            continue
        for field in type_def["fields"]:
            params = []
            for arg in field.get("args", []):
                params.append({
                    "name": arg.get("name", ""),
                    "in": "body",
                    "required": arg.get("type", {}).get("kind") == "NON_NULL",
                    "type": _gql_type_name(arg.get("type", {})),
                    "description": "",
                })
            endpoints.append({
                "method": "POST",
                "path": path,
                "operation_id": field.get("name", ""),
                "summary": field.get("description", "") or f"GraphQL {'query' if gql_method == 'GET' else 'mutation'}: {field['name']}",
                "tags": ["Query" if gql_method == "GET" else "Mutation"],
                "parameters": params,
                "response_schema": {"type": _gql_type_name(field.get("type", {}))},
            })

    return DiscoveryResult(
        spec_source="graphql",
        tool_name="GraphQL API",
        base_url=base_url,
        auth_schemes=[],
        endpoints=endpoints,
        endpoint_count=len(endpoints),
        raw_spec=schema,
    )


# ── Helpers ──

def _resolve_url(base_url: str, url: str) -> str:
    if url.startswith("http"):
        return url
    if url.startswith("//"):
        return "https:" + url
    if url.startswith("/"):
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}{url}"
    return f"{base_url}/{url}"


async def _fetch_and_parse_spec(client, spec_url: str, base_url: str) -> Optional[DiscoveryResult]:
    try:
        resp = await client.get(spec_url)
        if resp.status_code == 200:
            spec = json.loads(resp.text)
            if _is_openapi_spec(spec):
                return _parse_openapi(spec, base_url)
    except Exception:
        pass
    return None


def _extract_param_type(param: dict) -> str:
    schema = param.get("schema", {})
    return schema.get("type", param.get("type", "string"))


def _get_response_schema_3x(resp: dict) -> Optional[dict]:
    """Extract schema from OpenAPI 3.x response object."""
    content = resp.get("content", {})
    for media_type in ["application/json", "*/*"]:
        if media_type in content:
            return content[media_type].get("schema")
    # Try first content type
    for _, media in content.items():
        return media.get("schema")
    return None


def _analyze_response_schema(schema: dict, spec: dict) -> Optional[dict]:
    """Analyze response schema to find the records array path."""
    if not schema:
        return None
    # Resolve $ref
    if "$ref" in schema:
        ref_path = schema["$ref"].replace("#/", "").split("/")
        resolved = spec
        for p in ref_path:
            resolved = resolved.get(p, {})
        schema = resolved

    if schema.get("type") == "array":
        return {"records_path": "", "type": "array"}

    if schema.get("type") == "object" and schema.get("properties"):
        for prop_name, prop_schema in schema["properties"].items():
            if prop_schema.get("type") == "array":
                return {"records_path": prop_name, "type": "array"}
    return None


def _detect_pagination(params: list) -> dict:
    """Detect pagination strategy from parameter names."""
    param_names = {p["name"].lower() for p in params}

    if "offset" in param_names or "skip" in param_names:
        return {
            "detected": True, "strategy": "offset",
            "page_param": next((p["name"] for p in params if p["name"].lower() in ("offset", "skip")), "offset"),
            "size_param": next((p["name"] for p in params if p["name"].lower() in ("limit", "page_size", "pagesize", "count")), "limit"),
        }
    if "cursor" in param_names or "after" in param_names or "next_token" in param_names:
        return {
            "detected": True, "strategy": "cursor",
            "page_param": next((p["name"] for p in params if p["name"].lower() in ("cursor", "after", "next_token")), "cursor"),
        }
    if "page" in param_names or "page_number" in param_names:
        return {
            "detected": True, "strategy": "page",
            "page_param": next((p["name"] for p in params if p["name"].lower() in ("page", "page_number")), "page"),
            "size_param": next((p["name"] for p in params if p["name"].lower() in ("page_size", "per_page", "limit")), "page_size"),
        }

    return {"detected": False, "strategy": "none"}


def _extract_request_body(op: dict, spec: dict) -> Optional[dict]:
    """Extract request body schema from an operation."""
    request_body = op.get("requestBody", {})
    if not request_body:
        return None
    content = request_body.get("content", {})
    for media_type in ["application/json", "*/*"]:
        if media_type in content:
            return content[media_type].get("schema")
    return None


def _gql_type_name(type_info: dict) -> str:
    """Extract a human-readable type name from GraphQL type info."""
    if not type_info:
        return "Unknown"
    name = type_info.get("name")
    if name:
        return name
    of_type = type_info.get("ofType", {})
    if of_type:
        inner = _gql_type_name(of_type)
        kind = type_info.get("kind", "")
        if kind == "LIST":
            return f"[{inner}]"
        if kind == "NON_NULL":
            return f"{inner}!"
        return inner
    return "Unknown"
