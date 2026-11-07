// Records the demonstration video (docs/demo/ivm-demo.webm) with on-screen captions.
// Requires the stack running with raised limits:  LOGIN_RATE_LIMIT=100 ./scripts/dev.sh
// Run from the repository root:                    node e2e/demo/record-demo.mjs
import { chromium } from '@playwright/test'
import { mkdirSync, renameSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'

const BASE = process.env.DEMO_BASE_URL ?? 'http://127.0.0.1:5173'
const OUT = 'docs/demo'
const TMP = join(OUT, '.raw')
mkdirSync(TMP, { recursive: true })

const browser = await chromium.launch()
const context = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  recordVideo: { dir: TMP, size: { width: 1440, height: 900 } },
})
const page = await context.newPage()
const pause = (ms = 1600) => page.waitForTimeout(ms)

async function caption(title, text) {
  await page.evaluate(
    ([t, b]) => {
      let el = document.getElementById('demo-caption')
      if (!el) {
        el = document.createElement('div')
        el.id = 'demo-caption'
        el.style.cssText =
          'position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:9999;max-width:880px;' +
          'background:rgba(16,35,63,.94);color:#fff;padding:14px 20px;border-radius:10px;' +
          'font:500 15px/1.45 system-ui,sans-serif;box-shadow:0 10px 30px rgba(0,0,0,.25);pointer-events:none'
        document.body.appendChild(el)
      }
      el.innerHTML = `<div style="font-size:11px;letter-spacing:1.2px;color:#7fd1c5;font-weight:700">${t}</div>${b}`
    },
    [title, text],
  )
}

async function login(email, label) {
  await page.goto(`${BASE}/login`)
  await caption('SIGN IN', `Signing in as ${label} (${email}). Every role gets its own menu, data scope and dashboard.`)
  await page.getByLabel('Email address').fill(email)
  await page.getByLabel('Password').fill('DemoPass!234')
  await pause(1200)
  await page.getByRole('button', { name: /continue/i }).click()
  await page.getByRole('navigation', { name: 'Main navigation' }).waitFor()
  await page.waitForLoadState('networkidle')
}

async function logout() {
  await page.locator('.user-switch').click()
  await page.getByRole('heading', { name: 'Sign in to IVM' }).waitFor()
}

// 1. Executive view
await login('user11@demo.bank', 'the CISO')
await caption('UC-12 · EXECUTIVE REPORTING', 'Portfolio KPIs, SLA compliance, risk trend and risk reduction — scoped to what a CISO may see.')
await pause(3000)
await page.mouse.wheel(0, 700)
await caption('SECTION 13 DASHBOARDS', 'Risk by business unit, internet-facing high-risk assets, attack paths to crown jewels and expiring exceptions.')
await pause(3200)
await page.mouse.wheel(0, 700)
await caption('EXECUTIVE HEATMAP', 'Heatmap by business service and overdue work by owner and SLA category.')
await pause(3000)
await page.getByRole('link', { name: /reports & insights/i }).click()
await page.waitForLoadState('networkidle')
await caption('SUCCESS CRITERIA · MEASURED LIVE', 'SC-1 to SC-12 are measured from the live data, not asserted — each row shows its evidence.')
await pause(3500)
await page.mouse.wheel(0, 900)
await caption('RECOMMENDATION ENGINE', 'Remediation sequencing by risk removed per hour of effort, plus SLA-breach and risk-trend forecasts.')
await pause(3500)
await logout()

// 2. Analyst: findings, explainability, attack paths, AI
await login('user2@demo.bank', 'a security analyst')
await page.getByRole('link', { name: 'Findings', exact: true }).click()
await page.getByRole('heading', { name: 'Findings', exact: true }).waitFor()
await caption('UC-6 · RISK SCORING', 'Correlated findings ranked by contextual risk — server-side search, filters, sorting, paging and CSV export.')
await page.getByLabel('Risk band').selectOption('critical')
await pause(2500)
await page.locator('a.table-primary').first().click()
await page.waitForLoadState('networkidle')
await caption('EXPLAINABILITY', 'Eight weighted factors explain the score: CVSS, criticality, exposure, exploitability, threat intel, data, regulation, attack path.')
await pause(3500)
await page.mouse.wheel(0, 600)
await caption('UC-5 · THREAT CONTEXT', 'KEV, active exploitation, ransomware use and EPSS feed the score; attack-path context shows base → final score.')
await pause(3500)
await page.getByRole('link', { name: /attack paths/i }).click()
await page.waitForLoadState('networkidle')
await caption('UC-7 · ATTACK PATHS', 'Routes from internet-facing entry points to crown jewels, and how path context raises finding priority.')
await pause(3200)
await page.getByRole('link', { name: /ai assistant/i }).click()
await caption('UC-14 · NATURAL LANGUAGE', 'Ask in plain English; the assistant understands business units, assets and CVEs, and follow-up questions.')
for (const question of ['Critical findings in Treasury', 'what about Retail Banking?', 'What should we fix first?']) {
  await page.getByLabel('Ask the IVM assistant').fill(question)
  await pause(700)
  await page.getByRole('button', { name: /send/i }).click()
  await page.locator('.chat-exchange').last().waitFor()
  await pause(2400)
}
await caption('GROUNDED ANSWERS', 'Every answer lists the tables and row counts it used, and every question is written to the audit trail.')
await pause(2500)
await page.getByRole('link', { name: /data imports/i }).click()
await page.getByLabel('Source type').selectOption('easm')
await page.locator('input[type=file]').setInputFiles('backend/data/synthetic/easm_findings.json')
await caption('UC-3/UC-4 · INGESTION', 'Importing an external attack-surface export: rows are normalized, correlated with scanner findings and de-duplicated.')
await page.getByRole('button', { name: /run import/i }).click()
await page.getByText(/import finished/i).waitFor({ timeout: 30_000 })
await pause(2600)
await caption('RELIABILITY', 'Rows for unknown hosts are kept with their error and can be retried after the asset is registered.')
await pause(2600)
await logout()

// 3. Manager: remediation, ticketing, exceptions
await login('user4@demo.bank', 'the vulnerability manager')
await page.getByRole('link', { name: /remediation/i }).click()
await page.waitForLoadState('networkidle')
await caption('UC-8/9/10 · REMEDIATION', 'Tasks are auto-assigned to owners with SLA dates; a learned model predicts breach risk.')
await pause(2500)
await page.locator('tbody tr').filter({ has: page.locator('.status-pill', { hasText: /^open$/ }) }).first().locator('.link-button').click()
const drawer = page.getByRole('dialog', { name: 'Task details' })
await drawer.waitFor()
await caption('TASK DETAIL', 'Ownership with reason, breach-risk factors, escalations and the full status timeline.')
await pause(3000)
await drawer.getByRole('button', { name: /create jira ticket/i }).click()
await caption('SC-11 · TICKETING', 'Raising a simulated Jira ticket; external systems call back through an HMAC-signed webhook.')
await pause(2800)
await page.keyboard.press('Escape')
await page.getByRole('link', { name: /risk exceptions/i }).click()
await page.waitForLoadState('networkidle')
await caption('UC-11 · EXCEPTIONS', 'Time-bound risk acceptance with segregation of duties, expiry tracking and downloadable review packs.')
await pause(3200)
await logout()

// 4. Auditor
await login('user5@demo.bank', 'the auditor')
await page.getByRole('link', { name: /audit trail/i }).click()
await page.waitForLoadState('networkidle')
await page.getByRole('button', { name: /verify integrity/i }).click()
await caption('AUDITABILITY', 'Every import, scoring change, assignment, exception and approval is hash-chained; the database rejects edits and deletes.')
await pause(4000)

await context.close()
await browser.close()
const [raw] = readdirSync(TMP).filter((f) => f.endsWith('.webm'))
renameSync(join(TMP, raw), join(OUT, 'ivm-demo.webm'))
rmSync(TMP, { recursive: true, force: true })
console.log(`Demo video written to ${join(OUT, 'ivm-demo.webm')}`)
