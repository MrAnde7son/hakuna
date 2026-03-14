Add or extend a dashboard/report widget in the ReportBuilder system.

User description: $ARGUMENTS

## Architecture

The dashboard system is a **widget-based ReportBuilder** in `frontend/src/components/reports/ReportBuilder.jsx`.
Reports are collections of widgets. Two built-in templates exist: `DEFAULT_DASHBOARD` (Security Overview) and `EXECUTIVE_DASHBOARD` (Executive Overview).

The data flow is: **Backend API → Data Source → Data Preset → Widget Renderer**

## Widget Types

| Type | Description | Default Width | Compatible Preset Types |
|------|-------------|---------------|------------------------|
| `card` | Single metric number | quarter | metric |
| `pie_chart` | Pie or donut chart | half | categories |
| `bar_chart` | Vertical or horizontal bars | full | categories, series |
| `line_chart` | Line or area chart | full | series |
| `table` | Tabular data with columns | full | table |
| `heatmap` | Severity × Family matrix | full | (uses summary directly) |
| `header` | Section title + subtitle | full | (layout only) |
| `divider` | Horizontal rule | full | (layout only) |
| `image` | Embedded image via URL | half | (layout only) |

Width options: `quarter` (1/4), `third` (1/3), `half` (1/2), `two-thirds` (2/3), `full`

## Steps

### Step 1 — Determine if existing presets cover the need

Read `frontend/src/components/reports/ReportBuilder.jsx` and search for the `DATA_PRESETS` object.
There are 190+ existing presets across groups: Severity, Risk, SLA & Ops, Coverage, Temporal, Tags, Assets & Findings, Inventory, Filtered.

If an existing preset already has the data you need, skip to Step 5.

### Step 2 — Check if a data source exists

Search for the `DATA_SOURCES` object in `ReportBuilder.jsx`. Available sources include:
- `summary` → `/api/reports/summary` (severity, effort, owners, coverage, quick wins, exploit counts)
- `sla` → `/api/sla/summary` (compliance, breached, MTTR)
- `trending` → `/api/reports/trending` (per-scan severity counts)
- `metrics_timeline` → `/api/reports/metrics-timeline` (full scan-over-scan metrics)
- `delta_timeline` → `/api/scans/delta-timeline` (new/fixed/recurring counts)
- `velocity` → `/api/reports/remediation-velocity` (resolved per period)
- `temporal` → `/api/reports/temporal-summary` (zombies, regressions, age distribution)
- `risk_by_tags` → `/api/reports/risk-by-tags` (tag group benchmarking)
- `assets`, `findings`, `remediation_queue` — entity lists with filters
- `inv_summary`, `inv_users`, `inv_groups`, `inv_services`, `inv_netconns`, `inv_tasks`, `inv_patches`, `inv_logged_on`, `inv_shares`, `inv_software`, `inv_security_ctrls`, `inv_computers`, `inv_pw_policies`, `inv_certificates`, `inv_ai_tools`, `inv_processes` — inventory data
- `automation_wishlist`, `plugin_families`

If the backend already returns the data you need, skip to Step 3.

If a **new backend endpoint** is needed:
1. Add the endpoint to `backend/app.py` following existing patterns (org filtering, scan_id, tags support)
2. Add the API function to `frontend/src/api.js`
3. Add a new entry to `DATA_SOURCES` in `ReportBuilder.jsx`:
```js
new_source: (scanId, filters) => apiFunction(scanId, filters),
```

If existing endpoint needs **new fields** (e.g., adding coverage to `/api/reports/summary`):
1. Update the backend endpoint in `backend/app.py` to compute and return the new data
2. If model changes are needed, update `backend/models/models.py` and add columns via ALTER TABLE
3. If parser changes are needed, update `backend/parsers/parser.py` to extract new fields
4. Update asset/finding creation in `backend/app.py` upload handler to store new fields

### Step 3 — Add data preset(s)

Add entries to `DATA_PRESETS` in `ReportBuilder.jsx`. Follow the pattern of existing presets:

**Metric preset** (for `card` widgets):
```js
my_metric: {
  label: 'My Metric',
  group: 'GroupName',        // Severity, Risk, SLA & Ops, Coverage, Temporal, Tags, etc.
  source: 'summary',         // which DATA_SOURCE to use
  type: 'metric',
  extract: d => d?.my_field ?? 0,
  format: 'pct',             // optional: 'pct' appends %, otherwise toLocaleString()
  color: '#16a34a',          // hex color for the card number
},
```

**Categories preset** (for `pie_chart` or `bar_chart`):
```js
my_breakdown: {
  label: 'My Breakdown',
  group: 'GroupName',
  source: 'summary',
  type: 'categories',
  extract: d => [
    { name: 'Category A', value: d?.field_a || 0, color: '#16a34a' },
    { name: 'Category B', value: d?.field_b || 0, color: '#dc2626' },
  ].filter(r => r.value > 0),
},
```

**Series preset** (for `line_chart` or stacked `bar_chart`):
```js
my_trend: {
  label: 'My Trend',
  group: 'GroupName',
  source: 'metrics_timeline',
  type: 'series',
  xField: 'scan_name',
  fields: ['field_a', 'field_b'],
  colors: { field_a: '#16a34a', field_b: '#dc2626' },
  extract: d => Array.isArray(d) ? d : [],
},
```

**Table preset** (for `table` widgets):
```js
my_table: {
  label: 'My Table',
  group: 'GroupName',
  source: 'my_source',
  type: 'table',
  extract: d => d?.items || [],
  columns: [
    { key: 'name', label: 'Name' },
    { key: 'count', label: 'Count' },
    { key: 'score', label: 'Score', render: v => v?.toFixed(1) },
  ],
},
```

### Step 4 — Add drill-down (REQUIRED when data is filterable)

Every widget that represents a filterable dataset MUST have a drill-down entry in the `DRILL_DOWN` object. Widgets are drillable when clicking them can navigate the user to a filtered view of the underlying data (findings, assets, inventory, etc.). Only skip drill-down for purely layout widgets (`header`, `divider`, `image`) or aggregations with no meaningful filtered destination.

Add entries to the `DRILL_DOWN` object:

```js
// Card drill-down (string URL — navigates on card click):
my_metric: '/findings?some_filter=value',

// Categories drill-down (function receiving the clicked slice/bar name):
my_breakdown: (name) => `/findings?category=${encodeURIComponent(name)}`,

// Table drill-down (function receiving the clicked row object):
my_table: (row) => `/findings?plugin_id=${row.plugin_id}`,
```

**Guidelines:**
- `card` → always drillable. Link to the filtered list that the metric counts.
- `pie_chart` / `bar_chart` → always drillable. Map each slice/bar name to the corresponding filter.
- `table` → drillable when rows represent entities that have a detail/filtered view.
- `line_chart` → drillable when individual data points map to a filterable view (e.g., a specific scan).
- `heatmap` → drillable when cells map to a severity+family filter combination.
- Use existing URL patterns: `/findings?severity=4`, `/assets?tag=...`, `/inventory?tab=users&...` etc.

### Step 5 — Add widget to dashboard template(s)

Add widget entries to `EXECUTIVE_DASHBOARD` and/or `DEFAULT_DASHBOARD`:

```js
{ id: 'ex13', type: 'card',      title: 'My Metric',     width: 'quarter', config: { preset: 'my_metric' } },
{ id: 'ex14', type: 'pie_chart', title: 'My Breakdown',  width: 'half',    config: { preset: 'my_breakdown', donut: true } },
{ id: 'ex15', type: 'bar_chart', title: 'My Trend',      width: 'full',    config: { preset: 'my_trend', stacked: true } },
```

Widget IDs must be unique. Use `dw` prefix for DEFAULT_DASHBOARD, `ex` prefix for EXECUTIVE_DASHBOARD.

Config options by type:
- `card`: `{ preset, label? }`
- `pie_chart`: `{ preset, donut? }`
- `bar_chart`: `{ preset, horizontal?, stacked? }`
- `line_chart`: `{ preset, areaFill? }`
- `table`: `{ preset, limit? }` (limit: 5, 10, 20, or 50)

### Step 6 — Add source filters (optional)

If the widget's data source supports filtering, add entries to `SOURCE_FILTERS`:

```js
my_source: [
  { key: 'status', label: 'Status', type: 'select', options: [
    { value: '', label: 'All' }, { value: 'active', label: 'Active' }
  ]},
  { key: 'search', label: 'Search', type: 'text', placeholder: 'Keyword...' },
],
```

### Step 7 — Verify

1. Run `cd frontend && npx vite build` to check for build errors
2. Run `cd backend && source .venv/bin/activate && python -c "from app import app"` to verify backend
3. If new DB columns were added, run ALTER TABLE migration

## Key Files

- `frontend/src/components/reports/ReportBuilder.jsx` — Widget types, data sources, presets, templates, rendering
- `frontend/src/api.js` — API client functions
- `backend/app.py` — API endpoints (reports section starts at `/api/reports/summary`)
- `backend/models/models.py` — SQLAlchemy models (Asset, Finding, Scan, etc.)
- `backend/parsers/parser.py` — Nessus file parsers (HTML, XML, CSV)
- `frontend/src/components/shared/ui.jsx` — Shared UI primitives (Card, StatCard, etc.)

## Conventions

- Presets use `source: 'summary'` for data derived from `/api/reports/summary` — avoid creating new endpoints when data can be added to existing ones
- Colors: use hex codes matching existing severity/status palette (#dc2626 red, #ea580c orange, #d97706 amber, #65a30d green, #0ea5e9 blue, #6366f1 indigo, #8b5cf6 purple)
- Group names must match existing groups or the preset won't appear in the grouped dropdown
- All API endpoints should support `scan_id`, `tags`, and `tag_logic` parameters for filtering
- Backend endpoints must use `get_accessible_org_ids` + `apply_scan_org_filter` for multi-tenant support
