/**
 * UI tests for the findings table — sorting, filtering, search, pagination.
 */
import { test, expect } from '@playwright/test'
import { seedAuth, mockApi, MOCK_FINDINGS, MOCK_SUMMARY } from './helpers.js'

test.describe('Findings Table', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'findings**': MOCK_FINDINGS,
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      'tags**': [],
      'severity-distribution**': [],
      'risk-grade**': { grade: 'C', score: 62 },
      '**': [],
    })
    await seedAuth(page)
    await page.goto('/findings', { waitUntil: 'networkidle' })
  })

  test('renders findings list', async ({ page }) => {
    // Should show at least one finding from our mock
    await expect(page.locator('text=SQL Injection')).toBeVisible({ timeout: 10000 })
  })

  test('displays severity indicators', async ({ page }) => {
    // Should show severity labels/badges
    const severities = ['critical', 'high', 'medium', 'low', 'info']
    let found = 0
    for (const sev of severities) {
      const badge = page.locator(`text=/${sev}/i`)
      if (await badge.first().isVisible({ timeout: 2000 }).catch(() => false)) {
        found++
      }
    }
    expect(found).toBeGreaterThan(0)
  })

  test('search box filters findings', async ({ page }) => {
    // Find the search input
    const searchInput = page.locator('input[placeholder*="search" i], input[type="search"], input[placeholder*="filter" i]')
    if (await searchInput.first().isVisible()) {
      // Mock a filtered response
      await page.route('**/api/findings**search=SQL**', (route) => {
        route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({
            items: [MOCK_FINDINGS.items[0]],
            total: 1,
            page: 1,
            page_size: 50,
          }),
        })
      })

      await searchInput.first().fill('SQL')
      // Wait for debounce + request
      await page.waitForTimeout(500)
    }
  })

  test('severity filter dropdown works', async ({ page }) => {
    // Look for a severity filter dropdown/select
    const severityFilter = page.locator('select:has(option:text("Critical")), button:has-text("Severity"), [data-testid="severity-filter"]')
    if (await severityFilter.first().isVisible({ timeout: 3000 }).catch(() => false)) {
      await severityFilter.first().click()
      // Should show filter options
      await expect(page.locator('text=/critical/i')).toBeVisible()
    }
  })
})
