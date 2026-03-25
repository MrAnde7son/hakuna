/**
 * E2E test helpers — these tests run against the real backend.
 */

const API_BASE = 'http://localhost:8000'

/**
 * Register a new org + user via the API and return auth info.
 */
export async function registerUser(request, { orgName, email, password, displayName } = {}) {
  orgName = orgName || `Test Org ${Date.now()}`
  email = email || `test-${Date.now()}@e2e.test`
  password = password || 'E2ETestPass123!'
  displayName = displayName || 'E2E Tester'

  const resp = await request.post(`${API_BASE}/api/auth/register`, {
    data: { org_name: orgName, email, password, display_name: displayName },
  })

  const data = await resp.json()
  return {
    token: data.token,
    user: data.user,
    org: data.org,
    email,
    password,
  }
}

/**
 * Login via the API and return the token.
 */
export async function loginUser(request, email, password) {
  const resp = await request.post(`${API_BASE}/api/auth/login`, {
    data: { email, password },
  })
  return await resp.json()
}

/**
 * Seed auth into the browser's localStorage so the frontend is logged in.
 */
export async function seedAuthInBrowser(page, authInfo) {
  await page.goto('/login', { waitUntil: 'networkidle' })
  await page.evaluate((info) => {
    localStorage.setItem('token', info.token)
    localStorage.setItem('user', JSON.stringify(info.user))
  }, authInfo)
}

/**
 * Navigate via the UI login form.
 */
export async function loginViaUI(page, email, password) {
  await page.goto('/login', { waitUntil: 'networkidle' })
  await page.fill('input[type="email"], input[name="email"], input[placeholder*="email" i]', email)
  await page.fill('input[type="password"]', password)
  const submitBtn = page.locator('button[type="submit"], button:has-text("Log in"), button:has-text("Sign in"), button:has-text("Login")')
  await submitBtn.first().click()
  // Wait for redirect away from login
  await page.waitForURL((url) => !url.pathname.includes('/login'), { timeout: 15000 })
}
