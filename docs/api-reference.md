# API Reference

The backend exposes a RESTful API at `http://localhost:8000`. Interactive Swagger UI docs are available at `/docs` when running.

All authenticated endpoints require a `Authorization: Bearer <token>` header.

## Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user account |
| POST | `/api/auth/login` | Login and receive a JWT token |
| GET | `/api/auth/me` | Get current user profile |
| POST | `/api/auth/orgs` | Create a new organization |
| POST | `/api/auth/invite` | Invite a user to the current org |
| PUT | `/api/auth/locale` | Update user locale preference |
| POST | `/api/auth/password-reset` | Request a password reset |
| POST | `/api/auth/tokens` | Mint a long-lived API token (`hak_…`) for programmatic access |
| GET | `/api/auth/tokens` | List the caller's API tokens |
| DELETE | `/api/auth/tokens/{id}` | Revoke an API token |

API tokens (`hak_…`) and JWTs both work in the `Authorization: Bearer` header. Tokens are issued from **Settings → API Tokens** and are required for MCP clients (see [mcp.md](mcp.md)).

## MCP server

Hakuna ships an MCP (Model Context Protocol) server so customers can connect their own agents (Claude Desktop, Cursor, Claude Agent SDK) and query Hakuna data through tools.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/mcp` | JSON-RPC 2.0 endpoint (Streamable HTTP transport): `initialize`, `tools/list`, `tools/call` |
| GET | `/api/mcp` | Server info + tool catalog |

See [mcp.md](mcp.md) for setup, available tools, and client config snippets.

## Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload a scan file (auto-detects format; max 500 MB) |
| GET | `/api/scans` | List all imported scans |
| GET | `/api/scans/{id}` | Get scan details |
| DELETE | `/api/scans/{id}` | Delete a scan |
| GET | `/api/scans/compare` | Compare two scans (query params: `scan_a`, `scan_b`) |

## VM Scanner

Active scanning against live targets via the `hakuna-vm-scanner` container.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/vm/scan` | Launch an active scan (Nuclei + optional Schemathesis + agent specialists) |
| POST | `/api/vm/refresh/{scan_id}` | Poll Celery job statuses and ingest new findings |
| POST | `/api/vm/rescan/{scan_id}` | Re-run a scan with optional overrides (edit-and-rerun) |
| GET | `/api/vm/health` | VM scanner container health check |

**Scan body fields:** `targets`, `asset_ids`, `credential_id`, `auth_profile_id`, `enable_agents` (bool), `agent_categories` (list — `injection`, `xss`, `ssrf`, `authn`, `authz`), `template_tags`.

## Auth Profiles

Credential profiles that authenticate Hakuna-initiated scans.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/auth-profiles` | List auth profiles for the current org |
| POST | `/api/auth-profiles` | Create a profile (static or form_login) |
| GET | `/api/auth-profiles/{id}` | Get a profile |
| PATCH | `/api/auth-profiles/{id}` | Update a profile |
| DELETE | `/api/auth-profiles/{id}` | Delete a profile |
| POST | `/api/auth-profiles/{id}/test` | Run a test login via Playwright |
| POST | `/api/auth-profiles/detect-flow` | LLM-powered detection of login-flow steps from a login URL |

**Profile types:** `static` (references a credential vault entry) or `form_login` (Playwright-driven). Form-login profiles include `login_url`, `login_flow` (ordered steps), `success_condition`, `session_ttl_seconds`, and optional TOTP.

## Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assets` | List assets with filtering, sorting, pagination |
| GET | `/api/assets/{id}` | Get asset details |
| GET | `/api/assets/{id}/findings` | Get findings for an asset |
| GET | `/api/assets/{id}/sources` | Per-source observation snapshots for an asset |

**Query parameters:** `scan_id`, `search`, `tag`, `environment`, `asset_type`, `sort_by`, `order`, `page`, `page_size`

## Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings` | List findings with filtering, sorting, pagination |
| GET | `/api/findings/{id}` | Get finding details |
| PATCH | `/api/findings/{id}/status` | Update finding workflow status |
| GET | `/api/findings/{id}/sources` | Per-source observation snapshots for a finding |
| POST | `/api/findings/{id}/validate` | Trigger LLM validation (writes `verdict`, `confidence`, `validated_at`) |
| POST | `/api/findings/bulk-status` | Bulk status update |

**Query parameters:** `scan_id`, `severity`, `search`, `tag`, `status`, `effort`, `sla_status`, `sort_by`, `order`, `page`, `page_size`

## Attack Paths & Correlation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/correlations/run` | Dispatch correlation as a background job; returns `job_id` |
| GET | `/api/correlations/attack-paths` | List attack paths |
| GET | `/api/correlations/attack-paths/{id}` | Path details with steps, score breakdown, narrative, mitigations |
| GET | `/api/correlations/corroborated` | Findings confirmed by multiple scanners |
| GET | `/api/blast-radius/{asset_id}` | Risk propagation from a given asset |
| GET | `/api/graph/attack-graph` | Materialized attack graph for visualization |

**Attack path filters:** `severity`, `search`, `min_score`, `narrated`, `scan_id`, `entry_asset_id`, `target_asset_id`.

## SIEM

### Event Ingest

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ingest/webhook/{endpoint_id}` | Generic webhook ingest (HMAC-signed) |
| POST | `/api/ingest/hec/{endpoint_id}` | Splunk HEC-compatible ingest |
| POST | `/api/ingest/cef/{endpoint_id}` | CEF/LEEF syslog events |
| GET | `/api/siem/endpoints` | List ingest endpoints |
| POST | `/api/siem/endpoints` | Create an ingest endpoint (returns secret once) |
| POST | `/api/siem/endpoints/{id}/rotate` | Rotate the HMAC secret |

### Events & Search

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/siem/events` | Search events with time range, severity, source filter |
| GET | `/api/siem/events/histogram` | Event volume histogram |
| GET | `/api/siem/field-mappings` | Field mapping registry for normalization |

### Detection Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/detection-rules` | List rules (filter by `source`: `user`, `sigma`, `builtin`) |
| POST | `/api/detection-rules` | Create a detection rule |
| PATCH | `/api/detection-rules/{id}` | Update a rule |
| DELETE | `/api/detection-rules/{id}` | Delete a rule |
| POST | `/api/detection-rules/{id}/test` | Dry-run against recent events |
| POST | `/api/detection-rules/import-sigma` | Import a Sigma YAML rule |
| GET | `/api/detection-rules/library` | Pre-built template catalog |

### Alerts & Suppressions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (status, severity, assignee filters) |
| PATCH | `/api/alerts/{id}` | Triage an alert (status, assignee, campaign_id, notes) |
| GET | `/api/suppression-rules` | List suppression rules |
| POST | `/api/suppression-rules` | Create a suppression rule |

### SIEM Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/siem-volume` | Event volume over time |
| GET | `/api/reports/siem-noisy-sources` | Top noisy sources |
| GET | `/api/reports/siem-alert-severity` | Alert severity distribution |

## NLP Search

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/nlp-search` | Parse natural language query into structured filters |

**Query parameters:** `q` (natural language query string)

**Example queries:**
- `critical Windows servers with exploits`
- `quick wins in production`
- `SLA breached high risk assets`

## Inventory

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/inventory/users` | Extracted user accounts |
| GET | `/api/inventory/groups` | Group memberships |
| GET | `/api/inventory/services` | Running services |
| GET | `/api/inventory/connections` | Network connections |
| GET | `/api/inventory/tasks` | Scheduled tasks |
| GET | `/api/inventory/patches` | Installed patches |
| GET | `/api/inventory/logged-on` | Logged-on users |
| GET | `/api/inventory/shares` | Network shares |
| GET | `/api/inventory/software` | Installed software |
| GET | `/api/inventory/certificates` | SSL/TLS certificates |
| GET | `/api/inventory/security-controls` | Security products |
| GET | `/api/inventory/computers` | Domain computers |
| GET | `/api/inventory/password-policies` | Password policies |
| GET | `/api/inventory/env-vars` | Environment variables |
| GET | `/api/inventory/ai-tools` | AI/ML tools |
| GET | `/api/inventory/processes` | Running processes |
| GET | `/api/inventory/databases` | Database instances |
| GET | `/api/inventory/credentials` | Discovered credentials |

## Asset Type Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/asset-type-rules` | List asset type classification rules |
| POST | `/api/asset-type-rules` | Create a classification rule |
| GET | `/api/asset-type-rules/{id}` | Get rule details |
| PATCH | `/api/asset-type-rules/{id}` | Update a rule |
| DELETE | `/api/asset-type-rules/{id}` | Delete a rule |
| POST | `/api/asset-type-rules/test` | Test a rule against sample asset data |
| GET | `/api/asset-type-rules/condition-catalog` | List available condition fields and operators |

**Rule body fields:** `name`, `conditions`, `condition_logic` (AND/OR), `target_asset_type`, `identity_mapping`, `default_attributes`, `priority`, `source_filter`, `is_enabled`

## SBOM

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sbom/components` | List SBOM components |

**Query parameters:** `has_cves`, `is_eol`, `is_running`, `priority_tier`, `search`

## Campaigns

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/campaigns` | List campaigns |
| POST | `/api/campaigns` | Create a campaign |
| GET | `/api/campaigns/{id}` | Get campaign details |
| PUT | `/api/campaigns/{id}` | Update a campaign |
| DELETE | `/api/campaigns/{id}` | Delete a campaign |
| POST | `/api/campaigns/preview` | Preview blast radius for a rule set |
| POST | `/api/campaigns/{id}/assign` | Assign campaign owner |

## Aggregated Solutions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/aggregated-solutions` | List grouped remediation recommendations |

## Tags

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/tags` | List all tags |
| POST | `/api/tags` | Create a tag |
| PUT | `/api/tags/{id}` | Update a tag |
| DELETE | `/api/tags/{id}` | Delete a tag |
| POST | `/api/tags/assign` | Assign tags to assets/findings |
| POST | `/api/auto-tag-rules` | Create an auto-tag rule |
| GET | `/api/auto-tag-rules` | List auto-tag rules |

## Workflows

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/workflows` | List workflow definitions |
| POST | `/api/workflows` | Create a workflow |
| GET | `/api/workflows/{id}` | Get workflow details |
| PUT | `/api/workflows/{id}` | Update a workflow |
| DELETE | `/api/workflows/{id}` | Delete a workflow |
| POST | `/api/workflows/{id}/execute` | Execute a workflow |
| GET | `/api/workflows/{id}/executions` | List workflow executions |

## AI Agents

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/agents` | List agent definitions |
| POST | `/api/agents` | Create an agent |
| GET | `/api/agents/{id}` | Get agent details |
| PUT | `/api/agents/{id}` | Update an agent |
| DELETE | `/api/agents/{id}` | Delete an agent |
| POST | `/api/agents/{id}/run` | Execute an agent (supports streaming) |
| GET | `/api/agents/{id}/runs` | List agent run history |
| GET | `/api/agents/templates` | List agent template gallery |
| POST | `/api/agents/{id}/schedule` | Set up cron schedule |
| POST | `/api/agents/{id}/documents` | Upload knowledge base document |
| GET | `/api/agents/pipelines` | List multi-stage agent pipelines |
| POST | `/api/agents/pipelines/{id}/run` | Execute a pipeline |

## Copilot

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/copilot/message` | Send a message; returns streamed response with rich blocks |
| GET | `/api/copilot/conversations` | List conversation history |
| GET | `/api/copilot/autonomy` | Get autonomy level (Conservative/Standard/Autonomous) |
| PUT | `/api/copilot/autonomy` | Update autonomy level |
| POST | `/api/copilot/suggestions` | Get context-aware suggested prompts for the current page |

## Integrations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/integrations` | List configured integrations |
| POST | `/api/integrations` | Create/update integration config |
| POST | `/api/integrations/{type}/test` | Test integration connectivity |
| DELETE | `/api/integrations/{type}` | Remove integration config |

**Types:** `jira`, `servicenow`, `slack`, `teams`, `email`, `tenable_io`, `tenable_sc`, `crowdstrike`

## Integration Builder

No-code connector platform for custom data sources.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/integration-builder/connectors` | List built connectors |
| POST | `/api/integration-builder/connectors` | Create a connector |
| GET | `/api/integration-builder/connectors/{id}` | Get connector config |
| PATCH | `/api/integration-builder/connectors/{id}` | Update a connector |
| DELETE | `/api/integration-builder/connectors/{id}` | Delete a connector |
| POST | `/api/integration-builder/connectors/{id}/run` | Trigger an on-demand sync |
| GET | `/api/integration-builder/target-models` | Available target models (Finding, Asset, Alert, etc.) |
| POST | `/api/integration-builder/detect-schema` | Auto-detect schema from a sample response |
| POST | `/api/integration-builder/auto-map` | Field auto-mapping suggestions |
| POST | `/api/integration-builder/validate` | Validate connector end-to-end (auth + fetch + map) |
| POST | `/api/integration-builder/oauth/start` | Initiate OAuth2 authorization flow |
| POST | `/api/integration-builder/oauth/callback` | Exchange code for tokens |

**Transport types:** `api`, `sql`, `file`, `ldap`, `mcp`, `webhook`.

**Auth types:** `none`, `bearer`, `oauth2_client_credentials`, `api_key_header`, `basic`.

## Relay Agents

Manage on-prem relay agents for connecting to products behind firewalls.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/relay-agents` | List all relay agents for the current org |
| POST | `/api/relay-agents` | Create a new agent (returns one-time token) |
| GET | `/api/relay-agents/{id}` | Get agent details and live status |
| PUT | `/api/relay-agents/{id}` | Update agent name, allowed hosts, labels, or credentials mode |
| DELETE | `/api/relay-agents/{id}` | Delete an agent (fails if linked to integrations) |
| POST | `/api/relay-agents/{id}/rotate-token` | Generate a new token (invalidates old, disconnects agent) |
| GET | `/api/relay-agents/{id}/setup` | Get deployment instructions (Docker commands, env var reference) |

**WebSocket:** `wss://<host>/ws/relay` — relay agents connect here with `?token=<agent-token>` or `Authorization: Bearer <agent-token>`

**Create request body:**

```json
{
  "name": "DC-East Relay",
  "allowed_hosts": ["jira.internal:8080", "snow.internal"],
  "credentials_mode": "agent_local",
  "labels": { "site": "dc-east", "env": "production" }
}
```

**Credentials modes:** `agent_local` (default — agent loads creds from env vars), `cloud_managed` (Hakuna sends creds per-request)

## Threat Intelligence

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/threat-intel/groups` | List threat groups |
| GET | `/api/threat-intel/techniques` | List ATT&CK techniques |
| GET | `/api/threat-intel/campaigns` | List threat campaigns |
| GET | `/api/threat-intel/cve/{cve_id}` | CVE enrichment data |
| POST | `/api/threat-intel/sync` | Trigger MITRE ATT&CK sync |
| GET | `/api/threat-intel/impact-search` | Search for threat impact |

## Exceptions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/exceptions` | List global exceptions |
| POST | `/api/exceptions` | Create an exception rule |
| PUT | `/api/exceptions/{id}` | Update an exception |
| DELETE | `/api/exceptions/{id}` | Delete an exception |

## SLA

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/sla/config` | Get SLA configuration |
| PUT | `/api/sla/config` | Update SLA configuration |
| POST | `/api/sla/recalculate` | Recalculate SLA across scans |

## EASM (External Attack Surface)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/easm/setup` | Setup wizard (infer domains from email) |
| POST | `/api/easm/scan` | Trigger external domain scan |
| POST | `/api/easm/refresh` | Refresh EASM scan data |
| POST | `/api/easm/import` | Import EASM results as synthetic scan |

## Benchmarks

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/benchmarks/industry` | Industry baseline comparison |
| GET | `/api/benchmarks/platform` | Platform-wide peer comparison |

## Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/reports/summary` | Dashboard summary metrics |
| GET | `/api/reports/trending` | Metrics over time |
| GET | `/api/reports/velocity` | Remediation velocity |
| GET | `/api/reports/regressions` | Regression report |

## Export

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/export/assets` | Export assets as CSV/JSON |
| GET | `/api/export/findings` | Export findings as CSV/JSON |
| GET | `/api/export/inventory/{type}` | Export inventory table as CSV/JSON |

**Query parameters:** `format` (`csv` or `json`), `scan_id`

## Config Portability

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/config/export` | Export org configuration envelope |
| POST | `/api/config/import` | Import configuration with conflict resolution |

**Import strategies:** `overwrite`, `skip`, `merge`

## Audit Log

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit-log` | Query audit trail |

**Query parameters:** `action`, `entity_type`, `actor`, `from_date`, `to_date`, `page`, `page_size`

## Custom Fields

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/custom-fields` | List custom fields |
| POST | `/api/custom-fields` | Create a custom field |
| PATCH | `/api/custom-fields/{id}` | Update a custom field |
| DELETE | `/api/custom-fields/{id}` | Delete a custom field |
| POST | `/api/custom-fields/{id}/backfill` | Backfill the field across existing records |

**Supported types:** `string`, `number`, `boolean`, `date`, `enum`, `multi_enum`.

## Ownership & Rules

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/ownership-rules` | List ownership rules |
| POST | `/api/ownership-rules` | Create an ownership rule |
| POST | `/api/ownership-rules/preview` | Preview which records would match |
| POST | `/api/ownership-rules/run` | Execute all rules now |

## LLM Interactions (Admin)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/llm-interactions` | Query LLM interaction audit log |
| GET | `/api/llm-interactions/{id}` | Get full interaction trace (messages, tool calls, tokens) |
| POST | `/api/llm-interactions/{id}/outcome` | Record an outcome score (-1 to +1) |
| GET | `/api/llm-interactions/exemplars` | Retrieve similar past interactions (Postgres/pgvector only) |

## Validation

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/validation/findings/{id}` | Trigger LLM validation for a finding |
| GET | `/api/validation/findings/{id}` | Retrieve validation verdict + confidence |
| POST | `/api/validation/bulk` | Bulk validate by filter |

## Control Assessments

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/control-assessments/frameworks` | Available frameworks (CIS, NIST CSF, ISO 27001, custom) |
| GET | `/api/control-assessments/{framework}` | Coverage per control |
| POST | `/api/control-assessments/{framework}/assess` | Re-run assessment |

## Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/notifications` | List notifications (unread first) |
| GET | `/api/notifications/count` | Unread count |
| PATCH | `/api/notifications/{id}/read` | Mark as read |
| POST | `/api/notifications/mark-all-read` | Mark all read |

## Onboarding

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/onboarding/state` | Current onboarding progress |
| POST | `/api/onboarding/step` | Advance to the next onboarding step |
| POST | `/api/onboarding/skip` | Skip onboarding |

## Scan Planner

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan-planner/plan` | Generate an intelligent scan plan (asset selection, template tags) |
| POST | `/api/scan-planner/execute` | Execute a generated plan |

## SAML / SSO

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/saml/metadata` | Service-provider metadata XML |
| POST | `/api/saml/acs` | Assertion consumer service (SAML response handler) |
| GET | `/api/saml/discovery` | IdP discovery endpoint |
| GET | `/api/auth/sso/config` | Current SSO configuration |
| PUT | `/api/auth/sso/config` | Update SSO configuration (SAML or OIDC) |

## Billing

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/billing/plan` | Current plan and entitlements |
| POST | `/api/billing/checkout` | Initiate checkout session |
| GET | `/api/billing/portal` | Customer portal URL |
| GET | `/api/billing/usage` | Usage metrics for the current period |
| POST | `/api/billing/webhook` | Stripe webhook handler |
