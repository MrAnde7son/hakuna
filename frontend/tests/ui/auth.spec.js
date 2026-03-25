/**
 * UI tests for authentication pages — login form, register form, error states.
 */
import { test, expect } from '@playwright/test'

test.describe('Login Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login', { waitUntil: 'networkidle' })
  })

  test('renders login form', async ({ page }) => {
    await expect(page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]')).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('shows validation error on empty submit', async ({ page }) => {
    // Find and click the submit/login button
    const submitBtn = page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")')
    await submitBtn.first().click()
    // Should stay on login page (not redirect)
    await expect(page).toHaveURL(/login/)
  })

  test('shows error on invalid credentials', async ({ page }) => {
    // Mock the login API to return 401
    await page.route('**/api/auth/login', (route) => {
      route.fulfill({
        status: 401,
        contentType: 'application/json',
        body: JSON.stringify({ detail: 'Invalid credentials' }),
      })
    })

    await page.fill('input[type="email"], input[name="email"], input[placeholder*="email" i]', 'wrong@test.com')
    await page.fill('input[type="password"]', 'wrongpass')
    const submitBtn = page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")')
    await submitBtn.first().click()

    // Should show error message
    await expect(page.locator('text=/invalid|error|incorrect|failed/i')).toBeVisible({ timeout: 5000 })
  })

  test('successful login redirects to dashboard', async ({ page }) => {
    // Mock the login API to return a token
    await page.route('**/api/auth/login', (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          token: 'test-jwt-token',
          user: { id: 1, email: 'test@test.com', name: 'Test', role: 'org_admin', org_id: 1 },
          org: { id: 1, name: 'Test Org' },
        }),
      })
    })

    // Mock dashboard data so the redirect doesn't error
    await page.route('**/api/summary**', (route) => {
      route.fulfill({ status: 200, contentType: 'application/json', body: '{}' })
    })
    await page.route('**/api/**', (route) => {
      if (!route.request().url().includes('auth/login')) {
        route.fulfill({ status: 200, contentType: 'application/json', body: '[]' })
      }
    })

    await page.fill('input[type="email"], input[name="email"], input[placeholder*="email" i]', 'test@test.com')
    await page.fill('input[type="password"]', 'testpass123')
    const submitBtn = page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")')
    await submitBtn.first().click()

    // Should redirect away from login
    await expect(page).not.toHaveURL(/login/, { timeout: 10000 })
  })
})


test.describe('Register Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/register', { waitUntil: 'networkidle' })
  })

  test('renders registration form', async ({ page }) => {
    await expect(page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]')).toBeVisible()
    await expect(page.locator('input[type="password"]').first()).toBeVisible()
  })

  test('shows link to login page', async ({ page }) => {
    const loginLink = page.locator('a[href*="login"], button:has-text("Log in"), a:has-text("Log in"), a:has-text("Sign in")')
    await expect(loginLink.first()).toBeVisible()
  })
})


test.describe('Forgot Password Page', () => {
  test('renders forgot password form', async ({ page }) => {
    await page.goto('/forgot-password', { waitUntil: 'networkidle' })
    await expect(page.locator('input[type="email"], input[name="email"], input[placeholder*="email" i]')).toBeVisible()
  })
})
