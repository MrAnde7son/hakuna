/**
 * Mobile copilot smoke — verifies the bottom tab bar and full-screen
 * copilot overlay render on a mobile viewport without crashing.
 */
import { test, expect, devices } from '@playwright/test'

test.use({ ...devices['Pixel 5'] })

test.describe('mobile copilot shell', () => {
  test.beforeEach(async ({ page }) => {
    // Stub backend calls so AuthContext hydrates without a live API.
    await page.route(/\/api\/auth\/me$/, route => route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        id: 1, email: 'smoke@test', name: 'Smoke', role: 'admin',
        org: { id: 1, name: 'Smoke Org' },
        accessible_orgs: [{ id: 1, name: 'Smoke Org' }],
        effective_permissions: {
          page_reports: true, page_findings: true, page_assets: true,
          page_campaigns: true, page_threat_intel: true, page_inventory: true,
          page_siem: true, page_remediation: true, page_agents: true, page_settings: true,
        },
        locale: 'en',
      }),
    }))
    await page.route(/\/api\/onboarding\/status$/, route => route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ completed: true }),
    }))
    await page.route(/\/api\/scans/, route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify([]),
    }))
    await page.route(/\/api\/findings/, route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ items: [], total: 0 }),
    }))

    await page.goto('/login', { waitUntil: 'domcontentloaded' })
    await page.evaluate(() => {
      localStorage.setItem('auth_token', 'smoke-test-token')
    })
    await page.goto('/findings', { waitUntil: 'domcontentloaded' })
    // Wait for AppShell to render (bottom nav)
    await page.waitForSelector('nav[aria-label="Primary"]', { timeout: 10000 })
  })

  test('bottom tab bar renders with copilot tab', async ({ page }) => {
    const nav = page.locator('nav[aria-label="Primary"]')
    await expect(nav).toBeVisible()
    await expect(nav.getByRole('button', { name: 'Copilot' })).toBeVisible()
  })

  test('tapping copilot tab opens full-screen overlay', async ({ page }) => {
    await page.getByRole('button', { name: 'Copilot' }).click()
    // Copilot empty state renders "Neo AI" heading
    await expect(page.getByText('Neo AI').first()).toBeVisible()
  })

  test('floating copilot FAB is hidden on mobile', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Neo AI Agent' })).toHaveCount(0)
  })
})
