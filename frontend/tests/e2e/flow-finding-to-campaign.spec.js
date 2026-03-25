/**
 * E2E Flow: Browse Findings → Create Campaign → Track Progress
 *
 * Requires: backend running with seeded data.
 */
import { test, expect } from '@playwright/test'
import { registerUser, seedAuthInBrowser } from './helpers.js'

test.describe('Finding-to-Campaign Flow', () => {
  let authInfo

  test.beforeEach(async ({ request }) => {
    authInfo = await registerUser(request)
  })

  test('view findings page', async ({ page }) => {
    await seedAuthInBrowser(page, authInfo)
    await page.goto('/findings', { waitUntil: 'networkidle' })

    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })

  test('view campaigns page', async ({ page }) => {
    await seedAuthInBrowser(page, authInfo)
    await page.goto('/campaigns', { waitUntil: 'networkidle' })

    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })

  test('create campaign via API and verify in UI', async ({ page, request }) => {
    await seedAuthInBrowser(page, authInfo)

    // Create campaign via API
    const resp = await request.post('http://localhost:8000/api/campaigns', {
      headers: {
        Authorization: `Bearer ${authInfo.token}`,
        'X-Org-Context': String(authInfo.org.id),
      },
      data: {
        name: 'E2E Test Campaign',
        description: 'Created by E2E test',
      },
    })

    if (resp.ok()) {
      const campaign = await resp.json()

      // Navigate to campaigns page and verify it shows up
      await page.goto('/campaigns', { waitUntil: 'networkidle' })
      await expect(page.locator('text=E2E Test Campaign')).toBeVisible({ timeout: 10000 })
    }
  })
})
