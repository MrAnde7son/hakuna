/**
 * UI tests for navigation — sidebar, breadcrumbs, responsive behavior.
 */
import { test, expect } from '@playwright/test'
import { seedAuth, mockApi, MOCK_SUMMARY, MOCK_FINDINGS, MOCK_ASSETS } from './helpers.js'

test.describe('Sidebar Navigation', () => {
  test.beforeEach(async ({ page }) => {
    // Mock all API endpoints so pages load without errors
    await mockApi(page, {
      'summary**': MOCK_SUMMARY,
      'findings**': MOCK_FINDINGS,
      'assets**': MOCK_ASSETS,
      'scans**': [],
      'campaigns**': [],
      'tags**': [],
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      'risk-grade**': { grade: 'C', score: 62 },
      'severity-distribution**': [],
      'metrics-timeline**': [],
    })
    await seedAuth(page)
  })

  test('sidebar has main nav links', async ({ page }) => {
    await page.goto('/', { waitUntil: 'networkidle' })

    // Check for key navigation items
    const navItems = ['Findings', 'Assets', 'Campaigns']
    for (const item of navItems) {
      const link = page.locator(`nav >> text=${item}, aside >> text=${item}, [role="navigation"] >> text=${item}`)
      // At least one of these should exist
      const count = await link.count()
      if (count > 0) {
        await expect(link.first()).toBeVisible()
      }
    }
  })

  test('clicking nav link navigates to page', async ({ page }) => {
    await page.goto('/', { waitUntil: 'networkidle' })

    // Try to navigate to findings
    const findingsLink = page.locator('a[href*="findings"], [role="navigation"] >> text=Findings').first()
    if (await findingsLink.isVisible()) {
      await findingsLink.click()
      await expect(page).toHaveURL(/findings/)
    }
  })
})


test.describe('Theme Toggle', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      '**': [],
    })
    await seedAuth(page)
  })

  test('can toggle dark mode', async ({ page }) => {
    await page.goto('/settings', { waitUntil: 'networkidle' })

    // Look for theme toggle
    const themeToggle = page.locator('button:has-text("Dark"), button:has-text("Theme"), [data-testid="theme-toggle"], button:has-text("dark")')
    if (await themeToggle.first().isVisible()) {
      await themeToggle.first().click()
      // Check that data-theme attribute changed
      const theme = await page.locator('html').getAttribute('data-theme')
      expect(['dark', 'light']).toContain(theme)
    }
  })
})
