import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './e2e',
  timeout: 60000,
  retries: 1,
  use: {
    baseURL: process.env.E2E_BASE_URL || 'https://ip-check.leviatron02.com',
    viewport: { width: 1280, height: 900 },
    ignoreHTTPSErrors: true,
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', channel: 'chrome' } },
  ],
})
