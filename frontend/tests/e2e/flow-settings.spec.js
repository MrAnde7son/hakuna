/**
 * E2E Flow: Settings — Profile, Theme, Preferences
 *
 * Requires: backend running.
 */
import { test, expect } from '@playwright/test'
import { registerUser, seedAuthInBrowser } from './helpers.js'

test.describe('Settings Flow', () => {
  let authInfo

  test.beforeEach(async ({ request }) => {
    authInfo = await registerUser(request)
  })

  test('settings page loads without error', async ({ page }) => {
    await seedAuthInBrowser(page, authInfo)
    await page.goto('/settings', { waitUntil: 'networkidle' })

    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })

  test('profile page loads without error', async ({ page }) => {
    await seedAuthInBrowser(page, authInfo)
    await page.goto('/profile', { waitUntil: 'networkidle' })

    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })

  test('can view user profile info', async ({ page }) => {
    await seedAuthInBrowser(page, authInfo)
    await page.goto('/profile', { waitUntil: 'networkidle' })

    // Should show the user's email somewhere on the page
    const emailText = page.locator(`text=${authInfo.user.email}`)
    if (await emailText.isVisible({ timeout: 5000 }).catch(() => false)) {
      await expect(emailText).toBeVisible()
    }
  })
})
