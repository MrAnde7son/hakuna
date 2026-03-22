---
name: smoke-test
description: Run Playwright smoke tests that verify every lazy-loaded page route renders without crashing. Use after making frontend changes, adding new pages, or updating dependencies to catch broken imports and page-load regressions before they reach production.
---

# Smoke Test

Runs Playwright smoke tests against every frontend route to catch page-load regressions — broken imports, missing exports, stale Vite caches, and runtime init errors.

## When to use

- After adding or modifying lazy-loaded components
- After adding/updating frontend dependencies (especially ESM-only packages)
- After modifying `App.jsx` routes
- Before creating a PR with frontend changes
- When a page reports "Failed to fetch dynamically imported module"

## How to run

```bash
cd frontend && npx playwright test tests/smoke.spec.js
```

For headed mode (see the browser):
```bash
cd frontend && npx playwright test tests/smoke.spec.js --headed
```

## Prerequisites

- Vite dev server must be running on port 3000, OR Playwright will start it automatically via the `webServer` config in `playwright.config.js`
- Chromium must be installed: `npx playwright install chromium`

## What it checks

For every route defined in `App.jsx`:
1. The page loads without the ErrorBoundary showing "Page failed to load"
2. No `Failed to fetch dynamically imported module` errors in the console
3. Authenticated routes are tested with a fake token so the JS loads even if API calls 401

## Adding a new route

When adding a new page route to `App.jsx`, also add it to `frontend/tests/smoke.spec.js` in the `ROUTES` or `PUBLIC_ROUTES` array.

## Troubleshooting

If tests fail with `504 Outdated Optimize Dep`:
1. Stop the Vite dev server
2. Run `rm -rf node_modules/.vite`
3. Restart the dev server
4. Add the problematic ESM package to `optimizeDeps.include` in `vite.config.js`
