# Multi-Tenancy & MSSP Guide

The platform supports full multi-tenancy for MSSPs (Managed Security Service Providers) and enterprise organizations with multiple business units.

## Organizations

Each organization is an isolated workspace with:
- Separate scan data and findings
- Independent risk configuration and SLA settings
- Own tag hierarchies and auto-tag rules
- Dedicated integration configs
- Isolated campaigns and workflows

## Roles

### Built-in Roles

| Role | Scope | Description |
|------|-------|-------------|
| Superadmin | Platform | Full access to all orgs and platform settings |
| Org Admin | Organization | Full access within their organization |
| Analyst | Organization | Read/write access to operational features |
| Viewer | Organization | Read-only access |
| Custom | Organization | Admin-defined permission set |

### Custom Roles

Org admins can create custom roles with:
- **30+ granular permissions** across pages, data access, and actions
- **Tri-state toggles** — Off, allow, or deny per permission
- **Per-tag restrictions** — Grant or deny access to specific tags

## MSSP Workflow

### Setting Up Client Organizations

1. Log in as superadmin
2. Navigate to **Settings > Organizations**
3. Click **Create Organization**
4. Name the client org and optionally set a parent org
5. Invite client users or assign existing analysts

### Parent-Child Hierarchies

Organizations support parent-child relationships for:
- Reseller models where a parent MSSP manages multiple client orgs
- Enterprise models where a parent company oversees business units

### Org Switching

Users with access to multiple organizations see an **Org Switcher** in the sidebar:
- Select a different org context to view its data
- All subsequent actions apply to the selected org
- The current org is persisted in the session

## Permission Model

### Page Permissions

Control access to each page in the navigation:
- Reports, Threat Intel, Assets, Findings, Inventory
- Campaigns, Remediation, Agents
- Settings, Users, Integrations, Workflows, Tags

### Data Access Permissions

- Read scans, read findings, read assets
- Read inventory, read threat intel, read audit log

### Action Permissions

- Write scans (upload), write findings (update status)
- Manage campaigns, manage workflows
- Manage tags, manage integrations
- Manage exceptions, manage SLA
- Manage users, manage agents

## Audit Trail

All tenant-scoped actions are recorded in the audit log:
- Who performed the action
- What was changed (with before/after diff)
- When it occurred
- Which organization context
