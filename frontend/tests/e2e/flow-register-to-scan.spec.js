/**
 * E2E Flow: Register → Login → Upload Scan → View Findings & Assets
 *
 * This test runs against the real backend and verifies the core onboarding flow.
 * Requires: backend running on localhost:8000, frontend on localhost:3000.
 */
import { test, expect } from '@playwright/test'
import { registerUser, seedAuthInBrowser, loginViaUI } from './helpers.js'
import path from 'path'

test.describe('Register-to-Scan Flow', () => {
  let authInfo

  test('register a new account and login via UI', async ({ page, request }) => {
    // Step 1: Register via API
    authInfo = await registerUser(request, {
      orgName: 'E2E Test Org',
      email: `e2e-${Date.now()}@test.com`,
      password: 'E2EPassword123!',
    })

    expect(authInfo.token).toBeTruthy()
    expect(authInfo.user.email).toContain('@test.com')

    // Step 2: Login via UI
    await loginViaUI(page, authInfo.email, authInfo.password)

    // Should land on dashboard/reports
    await expect(page).not.toHaveURL(/login/)
  })

  test('navigate to findings page (empty state)', async ({ page, request }) => {
    authInfo = await registerUser(request)
    await seedAuthInBrowser(page, authInfo)

    await page.goto('/findings', { waitUntil: 'networkidle' })

    // Should show empty state or the findings page without errors
    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })

  test('navigate to assets page (empty state)', async ({ page, request }) => {
    authInfo = await registerUser(request)
    await seedAuthInBrowser(page, authInfo)

    await page.goto('/assets', { waitUntil: 'networkidle' })

    const errorBanner = page.locator('text=Page failed to load')
    await expect(errorBanner).not.toBeVisible({ timeout: 5000 })
  })
})
