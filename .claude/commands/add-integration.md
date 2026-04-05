Add a new integration connector to pull data from an external security tool.

User description: $ARGUMENTS

## Integration Architecture

Integrations are JSON connector templates in `backend/integrations/connectors/`. They are loaded at startup by `connector_loader.py` and define how to connect to a vendor API, paginate, authenticate, and map source fields to Hakuna's normalized schema.

**No Python code is needed.** Each connector is a single `.json` file.

## Steps

1. Read `backend/integrations/schema.py` for the normalized schema (asset, finding, action entities)
2. Read 1-2 existing connectors as reference:
   - `backend/integrations/connectors/crowdstrike_findings.json` (findings with OAuth2)
   - `backend/integrations/connectors/crowdstrike_assets.json` (assets with expression transforms)
   - `backend/integrations/connectors/qualys_findings.json` (findings with basic auth + instance URL)
   - `backend/integrations/connectors/wiz_issues.json` (GraphQL + OAuth2)
   - `backend/integrations/connectors/okta_identities.json` (identity/asset with API key)
3. Create `backend/integrations/connectors/<vendor>_<entity>.json` with the structure below
4. Create an SVG logo at `frontend/public/logos/vendors/<vendor>.svg` (40x40, rounded rect background, simple mark)
5. Verify the JSON is valid: `python3 -c "import json; json.load(open('backend/integrations/connectors/<file>.json'))"`

## Connector JSON Structure

```json
{
  "id": "vendor_entity",
  "name": "Vendor Name — Entity Type",
  "description": "Pull X from Y via Z API",
  "logo": "/logos/vendors/vendor.svg",
  "direction": "pull",
  "entity": "finding | asset",
  "transport_type": "api",
  "transport_config": {
    "base_url": "https://api.vendor.com",
    "method": "GET | POST",
    "path": "/api/v1/endpoint",
    "headers": { "Authorization": "Bearer {{credentials.api_token}}" },
    "query_params": {},
    "pagination": {
      "strategy": "cursor | offset | page",
      "page_size": 100,
      "cursor_field": "meta.next_cursor",
      "cursor_param": "cursor"
    }
  },
  "records_path": "data.items",
  "credential_acquisition": { ... },
  "default_field_map": [ ... ],
  "dedup_key": ["source_system", "source_id"],
  "params_schema": {}
}
```

## Normalized Schema Target Fields

### Finding targets
- `source_id` (string, required) — unique ID in the source tool
- `source_system` (string, required) — auto-set from connector ID
- `asset.hostname` — hostname of the affected asset
- `asset.ip_address` — IP of the affected asset
- `cve_id` — CVE identifier (e.g. "CVE-2024-1234")
- `plugin_id` — scanner check/rule ID
- `title` (required) — finding title
- `description` — detailed description
- `severity` (required, enum) — must be one of: `critical`, `high`, `medium`, `low`, `info`
- `cvss_score` (float) — CVSS base score
- `cvss_vector` — CVSS vector string
- `exploit_available` (boolean) — whether a public exploit exists
- `solution` — remediation recommendation
- `first_seen` (datetime) — first detection timestamp
- `last_seen` (datetime) — most recent detection
- `status` (enum) — `open`, `in_progress`, `resolved`, `accepted`

### Asset targets
- `source_id` (string, required)
- `source_system` (string, required)
- `hostname`, `ip_address`, `fqdn`, `os`, `os_version`
- `tags` (string array)
- `criticality` (integer 1-5)
- `last_seen` (datetime)
- `asset_identity` (JSON via expression transform) — composite identity fields
- `asset_attributes` (JSON via expression transform) — vendor-specific metadata
- `asset_type` (via expression) — e.g. `"identity"` for IAM/HR sources

## Field Map Entry Format

```json
{
  "source": "vendor.field.path",
  "target": "schema_field",
  "transform": {
    "type": "map | float | boolean | datetime | expression",
    "mapping": { "CRITICAL": "critical", "HIGH": "high" },
    "truthy": ["true", "True", "1", "yes"],
    "expr": "{'key': record.get('field', '')}"
  }
}
```

Transform types:
- `map` — static value mapping (use for severity, status)
- `float` — cast to float (use for cvss_score)
- `boolean` — cast to boolean with truthy values (use for exploit_available)
- `datetime` — parse to datetime (use for timestamps)
- `expression` — Python expression with access to `value` (current field) and `record` (full source record)

## Credential Acquisition Patterns

### API Key (guided_generation)
```json
{
  "pattern": "guided_generation",
  "instance_url_field": { "label": "API URL", "placeholder": "https://your-instance.vendor.com" },
  "steps": [
    { "instruction": "Log into the admin console" },
    { "instruction": "Go to Settings > API Keys > Create",
      "capture": { "field": "api_key", "label": "API Key", "type": "password", "auto_validate": true } }
  ],
  "validation_request": {
    "method": "GET", "path": "/api/v1/me",
    "headers": { "Authorization": "Bearer {{api_key}}" },
    "success_condition": "status == 200",
    "error_message": "Authentication failed. Check your API key."
  }
}
```

### OAuth2 Client Credentials
```json
{
  "pattern": "client_credentials",
  "token_url": "https://auth.vendor.com/oauth2/token",
  "scopes": ["read:vulnerabilities"],
  "fields": [
    { "field": "client_id", "label": "Client ID", "type": "text" },
    { "field": "client_secret", "label": "Client Secret", "type": "password" }
  ]
}
```

### OAuth2 with tenant
```json
{
  "pattern": "oauth2",
  "token_url": "https://login.microsoftonline.com/{{credentials.tenant_id}}/oauth2/v2.0/token",
  "grant_type": "client_credentials",
  "client_id_field": { "label": "Client ID", "type": "text" },
  "client_secret_field": { "label": "Client Secret", "type": "password" },
  "scopes": ["https://api.vendor.com/.default"]
}
```

## Pagination Strategies

### Cursor-based
```json
{ "strategy": "cursor", "page_size": 100, "cursor_field": "meta.next", "cursor_param": "cursor" }
```

### Offset-based
```json
{ "strategy": "offset", "page_size": 100, "offset_param": "offset", "total_field": "meta.total" }
```

### Page-based
```json
{ "strategy": "page", "page_size": 100, "page_param": "page" }
```

### GraphQL cursor (with has_next_field)
```json
{ "strategy": "cursor", "page_size": 100, "cursor_field": "data.items.pageInfo.endCursor", "has_next_field": "data.items.pageInfo.hasNextPage" }
```

## Severity Mapping

Always include a severity map transform. Every vendor has different severity labels — normalize them:
- Numeric: `"5"→critical, "4"→high, "3"→medium, "2"→low, "1"→info`
- String: `"CRITICAL"→critical, "HIGH"→high, "MEDIUM"→medium, "LOW"→low, "INFORMATIONAL"→info`
- Priority: `"1"→critical (urgent), "2"→high, "3"→medium, "4"→low`

## SVG Logo Template

Create a 40x40 SVG with a colored rounded-rect background and a simple vendor mark:

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40">
  <rect width="40" height="40" rx="8" fill="#BRAND_COLOR"/>
  <!-- Simple mark: text, shape, or icon -->
  <text x="20" y="27" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="16" font-weight="bold">VN</text>
</svg>
```

Use the vendor's brand color for the background. Prefer a simple shape or initials over complex artwork.

## Checklist

- [ ] JSON file created in `backend/integrations/connectors/`
- [ ] `id` is unique snake_case
- [ ] `entity` is "finding" or "asset"
- [ ] `records_path` points to the array of records in the API response
- [ ] `default_field_map` maps source fields to normalized schema targets
- [ ] Severity mapping included with all vendor severity levels covered
- [ ] Status mapping included if the vendor has statuses
- [ ] `dedup_key` defined (typically `["source_system", "source_id"]`)
- [ ] `credential_acquisition` has a `validation_request` to test connectivity
- [ ] Pagination configured matching the vendor's actual API behavior
- [ ] SVG logo created at `frontend/public/logos/vendors/<vendor>.svg`
- [ ] JSON validates: `python3 -c "import json; json.load(open('<file>'))"`
