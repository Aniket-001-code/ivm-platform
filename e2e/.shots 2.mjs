import { chromium } from '@playwright/test'
const out = process.argv[2]
const base = 'http://127.0.0.1:5173'
const browser = await chromium.launch()
async function as(email, shots) {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } })
  await page.goto(base + '/login')
  await page.getByLabel('Email address').fill(email)
  await page.getByLabel('Password').fill('DemoPass!234')
  await page.getByRole('button', { name: /continue/i }).click()
  await page.getByRole('navigation', { name: 'Main navigation' }).waitFor()
  for (const [name, path, action] of shots) {
    if (path) await page.goto(base + path)
    await page.waitForLoadState('networkidle')
    if (action) await action(page)
    await page.waitForTimeout(400)
    await page.screenshot({ path: `${out}/${name}.png`, fullPage: true })
  }
  await page.close()
}
await as('user11@demo.bank', [['ciso-dashboard', '/']])
await as('user2@demo.bank', [['analyst-dashboard', '/'], ['findings', '/findings'], ['attack-paths', '/attack-paths'],
  ['assistant', '/assistant', async (p) => { await p.getByLabel('Ask the IVM assistant').fill('What are the top priorities?'); await p.getByRole('button', { name: /send/i }).click(); await p.locator('.ai-sources').waitFor() }]])
await as('user4@demo.bank', [['manager-dashboard', '/'], ['tasks', '/tasks'], ['exceptions', '/exceptions']])
await as('user1@demo.bank', [['admin', '/admin'], ['asset-detail', '/assets', async (p) => { await p.locator('.asset-card h3 a').first().click(); await p.waitForLoadState('networkidle') }]])
await as('user5@demo.bank', [['auditor-dashboard', '/'], ['audit', '/auditor']])
await browser.close()
