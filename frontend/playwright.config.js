import { defineConfig } from '@playwright/test'

export default defineConfig({
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: 'http://localhost:3000',
    headless: true,
  },
  webServer: {
    command: 'npm run dev',
    port: 3000,
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [
    {
      name: 'smoke',
      testDir: './tests',
      testMatch: 'smoke.spec.js',
    },
    {
      name: 'ui',
      testDir: './tests/ui',
      testMatch: '**/*.spec.js',
    },
    {
      name: 'e2e',
      testDir: './tests/e2e',
      testMatch: '**/*.spec.js',
      timeout: 60_000,
    },
  ],
})
