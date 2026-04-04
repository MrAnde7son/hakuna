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

## Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload a scan file (auto-detects format) |
| GET | `/api/scans` | List all imported scans |
| GET | `/api/scans/{id}` | Get scan details |
| DELETE | `/api/scans/{id}` | Delete a scan |
| GET | `/api/scans/compare` | Compare two scans (query params: `scan_a`, `scan_b`) |

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

**Query parameters:** `scan_id`, `severity`, `search`, `tag`, `status`, `effort`, `sla_status`, `sort_by`, `order`, `page`, `page_size`

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

## Integrations

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/integrations` | List configured integrations |
| POST | `/api/integrations` | Create/update integration config |
| POST | `/api/integrations/{type}/test` | Test integration connectivity |
| DELETE | `/api/integrations/{type}` | Remove integration config |

**Types:** `jira`, `servicenow`, `slack`, `teams`, `email`

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
