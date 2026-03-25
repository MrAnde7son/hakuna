/**
 * UI tests for campaigns — list, create form, detail.
 */
import { test, expect } from '@playwright/test'
import { seedAuth, mockApi, MOCK_CAMPAIGNS, MOCK_SUMMARY, MOCK_FINDINGS } from './helpers.js'

test.describe('Campaigns List', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'campaigns**': MOCK_CAMPAIGNS,
      'findings**': MOCK_FINDINGS,
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      'tags**': [],
      '**': [],
    })
    await seedAuth(page)
    await page.goto('/campaigns', { waitUntil: 'networkidle' })
  })

  test('renders campaigns page', async ({ page }) => {
    // Should show campaign names
    await expect(page.locator('text=Q1 Critical Fixes')).toBeVisible({ timeout: 10000 })
  })

  test('shows campaign status', async ({ page }) => {
    // Should show status indicators
    const statusText = page.locator('text=/active|completed/i')
    await expect(statusText.first()).toBeVisible({ timeout: 5000 })
  })
})


test.describe('Campaign Detail', () => {
  test.beforeEach(async ({ page }) => {
    await mockApi(page, {
      'campaigns/1**': {
        id: 1,
        name: 'Q1 Critical Fixes',
        status: 'active',
        description: 'Fix all critical findings',
        findings: MOCK_FINDINGS.items.slice(0, 3),
        finding_count: 3,
        progress: 40,
        created_at: '2026-01-15T10:00:00Z',
      },
      'campaigns**': MOCK_CAMPAIGNS,
      'findings**': MOCK_FINDINGS,
      'summary**': MOCK_SUMMARY,
      'auth/me**': { user: { id: 1, email: 'test@test.com', role: 'org_admin' }, org: { id: 1, name: 'Test' } },
      '**': [],
    })
    await seedAuth(page)
    await page.goto('/campaigns/1', { waitUntil: 'networkidle' })
  })

  test('renders campaign detail page', async ({ page }) => {
    await expect(page.locator('text=Q1 Critical Fixes')).toBeVisible({ timeout: 10000 })
  })
})
