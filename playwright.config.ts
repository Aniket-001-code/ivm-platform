import { defineConfig, devices } from '@playwright/test'

export default defineConfig({ testDir: './e2e', fullyParallel: false, retries: 0, reporter: 'list', use: { baseURL: 'http://localhost:8080', trace: 'retain-on-failure' }, projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }] })
