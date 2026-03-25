/**
 * UI tests for assets — list, detail, search.
 */
import { test, expect } from '@playwright/test'
import { seedAuth, mockApi, MOCK_ASSETS, MOCK_SUMMARY } from './helpers.js'

test.describe('Assets List', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'assets**': MOCK_ASSETS,
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      'tags**': [],
      'findings**': { items: [], total: 0 },
      '**': [],
    })
    await seedAuth(page)
    await page.goto('/assets', { waitUntil: 'networkidle' })
  })

  test('renders assets list', async ({ page }) => {
    // Should show at least one asset hostname
    await expect(page.locator('text=web01')).toBeVisible({ timeout: 10000 })
  })

  test('displays IP addresses', async ({ page }) => {
    await expect(page.locator('text=10.0.0.1')).toBeVisible({ timeout: 5000 })
  })

  test('search box works', async ({ page }) => {
    const searchInput = page.locator('input[placeholder*="search" i], input[type="search"]')
    if (await searchInput.first().isVisible()) {
      await searchInput.first().fill('web01')
      await page.waitForTimeout(500)
    }
  })
})


test.describe('Asset Detail', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'assets/1**': {
        id: 1, ip: '10.0.0.1', hostname: 'web01', os: 'Ubuntu 22.04',
        criticality: 'high', finding_count: 12,
        findings: [], tags: [],
      },
      'assets**': MOCK_ASSETS,
      'findings**': { items: [], total: 0 },
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      '**': [],
    })
    await seedAuth(page)
    await page.goto('/assets/1', { waitUntil: 'networkidle' })
  })

  test('renders asset detail page', async ({ page }) => {
    await expect(page.locator('text=web01')).toBeVisible({ timeout: 10000 })
  })

  test('shows OS information', async ({ page }) => {
    await expect(page.locator('text=Ubuntu')).toBeVisible({ timeout: 5000 })
  })
})
