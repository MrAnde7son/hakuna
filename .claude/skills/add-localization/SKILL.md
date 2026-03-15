---
name: add-localization
description: Add or extend i18n localization to a frontend component. Use when adding new UI strings, creating new components, or extending translation coverage to untranslated pages.
---

# Localization (i18n)

This app uses **react-i18next** for full internationalization across **12 languages**.

## Supported Languages

en (English), ja (Japanese), fr (French), de (German), he (Hebrew, RTL), ru (Russian), zh (Chinese), es (Spanish), pt (Portuguese), nl (Dutch), ar (Arabic, RTL), it (Italian)

## Architecture

- **i18n config**: `frontend/src/i18n/index.js` — defines SUPPORTED_LANGUAGES, RTL_LANGUAGES, loads from HTTP backend
- **Translation files**: `frontend/public/locales/{lang}/translation.json` — one JSON file per language, flat namespace structure
- **RTL styles**: `frontend/src/i18n/rtl.css` — layout adjustments for Hebrew and Arabic
- **Backend locale**: `PUT /api/auth/locale` — persists user preference (validated in `backend/routes/auth_routes.py`)

## Translation File Structure

Keys are organized by namespace in a single `translation.json` per language:

```json
{
  "app": { "name": "Hakuna", ... },
  "nav": { "findings": "Findings", ... },
  "severity": { "critical": "Critical", ... },
  "findings": { "title": "Findings", "exportCsv": "Export CSV", ... },
  "findingDetail": { "synopsis": "Synopsis", ... },
  "assets": { "title": "Assets", "critLabels": { "1": "Minimal", ... }, ... },
  "campaigns": { "title": "Campaigns", ... },
  "reports": { "title": "Reports", "funnel": { ... }, ... },
  "inventory": { "title": "Inventory Explorer", ... },
  "remediation": { "title": "Remediation Queue", ... },
  "aggregated": { "title": "Aggregated Solutions", ... },
  "threats": { "title": "Threat Intel", ... },
  "sla": { "resolved": "Resolved", "daysLeft": "{{days}}d left", ... },
  "common": { "save": "Save", "cancel": "Cancel", ... },
  "errors": { ... },
  "settings": { ... },
  "roles": { ... },
  "rootCauses": { ... },
  ...
}
```

## How to Add Localization to a Component

### Step 1: Add the import and hook

```jsx
import { useTranslation } from 'react-i18next'

export default function MyComponent() {
  const { t } = useTranslation()
  // ...
}
```

### Step 2: Replace hardcoded strings

```jsx
// Before
<h2>Findings</h2>
<span>Filter by severity</span>
<Button>Export CSV</Button>

// After
<h2>{t('findings.title')}</h2>
<span>{t('findings.filterBySeverity')}</span>
<Button>{t('findings.exportCsv')}</Button>
```

### Step 3: Handle interpolation

```jsx
// Use {{variable}} syntax in translation keys
// translation.json: "pageOf": "Page {{page}} of {{total}}"
<span>{t('findings.pageOf', { page: 1, total: 10 })}</span>
```

### Step 4: Handle constants defined outside components

When labels are in objects/arrays outside the component (like `const OPTIONS = [...]`), convert them to functions:

```jsx
// Before (static, not translated)
const SEV_OPTIONS = [
  { value: '4', label: 'Critical' },
]

// After (function that accepts t)
const getSevOptions = (t) => [
  { value: '4', label: t('severity.critical') },
]

// Usage inside component
const options = getSevOptions(t)
```

### Step 5: Add keys to English translation file

Add new keys to `frontend/public/locales/en/translation.json` under the appropriate namespace.

### Step 6: Add translations to all other language files

Update all 11 other files in `frontend/public/locales/{lang}/translation.json` with translated values for the new keys.

## What to Translate

- Page/section headings
- Button labels
- Filter placeholders and dropdown options
- Empty state titles and descriptions
- Column headers in tables
- Modal titles and form labels
- Status labels and badges
- Pagination text
- Tooltip text

## What NOT to Translate

- API data (plugin names, CVE IDs, descriptions from Nessus)
- Technical abbreviations used as-is across languages (CVSS, KEV, EPSS, SLA, CVE, FQDN, DNS, etc.)
- Chart data labels from presets (they are data-driven)
- Single-letter abbreviations used as visual indicators (C/H/M/L/I for severity counts)

## Currently Localized Components (18/35)

**Fully localized**: App.jsx, Login, Register, UploadScan, UserDocs, ui.jsx, AuthContext, FindingExplorer, FindingDetail, AssetInventory, ReportBuilder, InventoryExplorer, Campaigns, CampaignDetail, RemediationQueue, AggregatedSolutions, ThreatIntelCenter, ExternalSources

**Not yet localized**: Settings, UserManagement, UsersPanel, TagManager, TagMappings, SLASettings, RiskSettings, IntegrationSettings, GlobalExceptions, OwnershipRules, RoleManager, OrgsPanel, AuditLog, WorkflowBuilder, AgentBuilder, NLPReportBuilder, BlastRadiusPanel, NLPSearchBar, AutomateModal, RuleBuilder
