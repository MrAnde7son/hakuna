/**
 * Shared helpers for UI tests.
 */

/**
 * Seed a fake auth token into localStorage so the app doesn't redirect to /login.
 * Also mocks API routes to return fixture data.
 */
export async function seedAuth(page) {
  await page.goto('/login', { waitUntil: 'networkidle' })
  await page.evaluate(() => {
    localStorage.setItem('token', 'ui-test-token')
    localStorage.setItem('user', JSON.stringify({
      id: 1,
      email: 'test@hakuna.io',
      name: 'Test User',
      display_name: 'Test User',
      role: 'org_admin',
      org_id: 1,
    }))
  })
}

/**
 * Mock API responses using Playwright's route interception.
 */
export async function mockApi(page, mocks) {
  for (const [pattern, response] of Object.entries(mocks)) {
    await page.route(`**/api/${pattern}`, (route) => {
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(response),
      })
    })
  }
}

/** Sample findings fixture */
export const MOCK_FINDINGS = {
  items: [
    { id: 1, plugin_name: 'SQL Injection', severity: 'critical', priority_score: 9.5, ip: '10.0.0.1', hostname: 'web01', status: 'open', plugin_id: '10001' },
    { id: 2, plugin_name: 'XSS Stored', severity: 'high', priority_score: 7.8, ip: '10.0.0.2', hostname: 'web02', status: 'open', plugin_id: '10002' },
    { id: 3, plugin_name: 'Missing Patches', severity: 'medium', priority_score: 5.2, ip: '10.0.0.3', hostname: 'db01', status: 'open', plugin_id: '10003' },
    { id: 4, plugin_name: 'SSL Weak Cipher', severity: 'low', priority_score: 2.1, ip: '10.0.0.4', hostname: 'api01', status: 'open', plugin_id: '10004' },
    { id: 5, plugin_name: 'Info Disclosure', severity: 'info', priority_score: 0.5, ip: '10.0.0.5', hostname: 'cdn01', status: 'open', plugin_id: '10005' },
  ],
  total: 5,
  page: 1,
  page_size: 50,
}

/** Sample assets fixture */
export const MOCK_ASSETS = {
  items: [
    { id: 1, ip: '10.0.0.1', hostname: 'web01', os: 'Ubuntu 22.04', criticality: 'high', finding_count: 12 },
    { id: 2, ip: '10.0.0.2', hostname: 'web02', os: 'CentOS 8', criticality: 'medium', finding_count: 5 },
    { id: 3, ip: '10.0.0.3', hostname: 'db01', os: 'Windows Server 2022', criticality: 'critical', finding_count: 23 },
  ],
  total: 3,
  page: 1,
  page_size: 50,
}

/** Sample campaigns fixture */
export const MOCK_CAMPAIGNS = [
  { id: 1, name: 'Q1 Critical Fixes', status: 'active', description: 'Fix all critical findings', finding_count: 15, progress: 40 },
  { id: 2, name: 'Patch Tuesday', status: 'completed', description: 'Monthly patches', finding_count: 8, progress: 100 },
]

/** Summary/dashboard fixture */
export const MOCK_SUMMARY = {
  total_findings: 150,
  total_assets: 45,
  critical: 12,
  high: 38,
  medium: 55,
  low: 30,
  info: 15,
  risk_grade: 'C',
  risk_score: 62,
}
