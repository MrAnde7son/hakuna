/**
 * Smoke tests — verify every lazy-loaded page route renders without crashing.
 *
 * These tests don't assert business logic; they catch broken imports,
 * missing exports, stale Vite caches, and runtime init errors that
 * prevent a page from loading at all.
 *
 * Run:  npx playwright test tests/smoke.spec.js
 */
import { test, expect } from '@playwright/test'

// All authenticated routes and the lazy component they load.
// Keep this list in sync with App.jsx <Route> definitions.
const ROUTES = [
  { path: '/', name: 'Reports' },
  { path: '/reports/1', name: 'Report Detail' },
  { path: '/assets', name: 'Assets' },
  { path: '/assets/1', name: 'Asset Detail' },
  { path: '/findings', name: 'Findings' },
  { path: '/findings/1', name: 'Finding Detail' },
  { path: '/campaigns', name: 'Campaigns' },
  { path: '/campaigns/1', name: 'Campaign Detail' },
  { path: '/aggregated-solutions', name: 'Remediation' },
  { path: '/workflows/1', name: 'Workflow Builder' },
  { path: '/inventory', name: 'Inventory' },
  { path: '/agents', name: 'Agents' },
  { path: '/tags', name: 'Tags' },
  { path: '/custom-fields', name: 'Custom Fields' },
  { path: '/threat-intel', name: 'Threat Intel' },
  { path: '/settings', name: 'Settings' },
  { path: '/profile', name: 'Profile' },
  { path: '/docs', name: 'Docs' },
  { path: '/onboarding', name: 'Onboarding Wizard' },
  { path: '/siem/search', name: 'SIEM Event Search' },
  { path: '/siem/rules', name: 'SIEM Detection Rules' },
  { path: '/siem/alerts', name: 'SIEM Alert Triage' },
  { path: '/attack-paths', name: 'Attack Paths' },
  { path: '/compliance', name: 'Compliance Frameworks' },
  { path: '/compliance/cis_v8', name: 'Compliance Framework Overview' },
  { path: '/compliance/cis_v8/control/1', name: 'Compliance Control Detail' },
  { path: '/ot-posture', name: 'OT Posture Dashboard' },
]

// Public routes (no auth required).
const PUBLIC_ROUTES = [
  { path: '/login', name: 'Login' },
  { path: '/register', name: 'Register' },
  { path: '/forgot-password', name: 'Forgot Password' },
  { path: '/reset-password', name: 'Reset Password' },
  { path: '/campaigns/accept?expired=1', name: 'Campaign Accept (expired)' },
]

for (const route of PUBLIC_ROUTES) {
  test(`public route ${route.name} (${route.path}) loads without error`, async ({ page }) => {
    await page.goto(route.path, { waitUntil: 'networkidle' })

    // The ErrorBoundary shows "Page failed to load" on crash
    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })

    // No uncaught chunk/module load errors
    const errors = []
    page.on('pageerror', (err) => errors.push(err.message))
    expect(errors.filter(e => /Failed to fetch dynamically imported module/.test(e))).toHaveLength(0)
  })
}

for (const route of ROUTES) {
  test(`authenticated route ${route.name} (${route.path}) loads without error`, async ({ page }) => {
    // Seed a fake auth token so the app doesn't redirect to /login.
    // The API calls will 401 but the page JS should still load and render.
    await page.goto('/login', { waitUntil: 'networkidle' })
    await page.evaluate(() => {
      localStorage.setItem('token', 'smoke-test-token')
      localStorage.setItem('user', JSON.stringify({ id: 0, email: 'smoke@test', name: 'Smoke Test', role: 'admin' }))
    })

    const errors = []
    page.on('pageerror', (err) => errors.push(err.message))

    await page.goto(route.path, { waitUntil: 'networkidle' })

    // The ErrorBoundary shows "Page failed to load" on crash
    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })

    // No dynamic import failures
    const importErrors = errors.filter(e => /Failed to fetch dynamically imported module/.test(e))
    expect(importErrors).toHaveLength(0)
  })
}
