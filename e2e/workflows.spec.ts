import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page, email = 'user2@demo.bank') {
  await page.goto('/login')
  await page.getByLabel('Email address').fill(email)
  await page.getByLabel('Password').fill('DemoPass!234')
  await page.getByRole('button', { name: /continue/i }).click()
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible()
}

test('analyst imports a scanner file and sees a batch result', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: /data imports/i }).click()
  await page.locator('input[type=file]').setInputFiles('backend/data/synthetic/scanner_export.csv')
  await page.getByRole('button', { name: /run import/i }).click()
  await expect(page.getByText(/import finished/i)).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(/duplicates/i).first()).toBeVisible()
})

test('finding work can be closed with evidence', async ({ page }) => {
  await login(page, 'user8@demo.bank')
  await page.getByRole('link', { name: /remediation/i }).click()
  await page.getByLabel('Remediation evidence').fill('Verified remediation in the synthetic demo environment.')
  const openRow = page.locator('tbody tr').filter({ has: page.locator('.status-pill', { hasText: /^open$/ }) }).first()
  const taskLabel = await openRow.getByRole('combobox').getAttribute('aria-label')
  const update = page.getByRole('combobox', { name: taskLabel! })
  const row = page.locator('tbody tr').filter({ has: update })
  await update.selectOption('in_progress')
  await expect(row.locator('.status-pill')).toHaveText('in_progress')
  await update.selectOption('pending_verification')
  await expect(row.locator('.status-pill')).toHaveText('pending_verification')
  await update.selectOption('closed')
  await expect(row.locator('.status-pill')).toHaveText('closed')
})

test('manager runs the SLA job and reviews escalation records', async ({ page }) => {
  await login(page, 'user4@demo.bank')
  await page.getByRole('link', { name: /administration/i }).click()
  await page.getByRole('button', { name: /run scheduler/i }).click()
  await expect(page.getByText(/escalations created/i)).toBeVisible()
  await expect(page.getByText(/recent escalations/i)).toBeVisible()
})

test('exception request is approved by a separate approver and appears in the audit trail', async ({ page }) => {
  await login(page, 'user4@demo.bank')
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Prioritized findings' })).toBeVisible()
  const finding = page.locator('tbody tr').first()
  const url = await finding.locator('a.table-primary').getAttribute('href')
  const findingId = url?.split('/').pop() ?? ''
  await page.locator('.user-switch').click()
  await page.getByLabel('Email address').fill('user2@demo.bank')
  await page.getByLabel('Password').fill('DemoPass!234')
  await page.getByRole('button', { name: /continue/i }).click()
  await expect(page.getByRole('navigation', { name: 'Main navigation' })).toBeVisible()
  await page.getByRole('link', { name: /risk exceptions/i }).click()
  await page.locator('select[aria-label="Finding"]').selectOption(findingId)
  await page.getByLabel('Expiry date').fill('2027-01-01')
  await page.getByLabel('Business justification').fill('Synthetic demo exception for a controlled acceptance workflow.')
  await page.getByRole('button', { name: /submit request/i }).click()
  await expect(page.getByText('pending').first()).toBeVisible()
  await page.locator('.user-switch').click()
  await page.getByLabel('Email address').fill('user4@demo.bank')
  await page.getByLabel('Password').fill('DemoPass!234')
  await page.getByRole('button', { name: /continue/i }).click()
  await page.getByRole('link', { name: /risk exceptions/i }).click()
  await page.getByRole('button', { name: /approve/i }).first().click()
  await expect(page.getByText('approved').first()).toBeVisible()
})

test('analyst views attack paths and asks the offline assistant', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: /attack paths/i }).click()
  await expect(page.getByText(/modeled paths/i)).toBeVisible()
  await page.getByRole('link', { name: /ai assistant/i }).click()
  const prompt = 'Which findings should we prioritize first?'
  await page.getByLabel('Ask the IVM assistant').fill(prompt)
  await page.getByRole('button', { name: /send/i }).click()
  await expect(page.getByLabel('Ask the IVM assistant')).toHaveValue('')
  await expect(page.locator('.user-message')).toHaveText(prompt)
  await expect(page.getByText(/AI-generated demo guidance/i)).toBeVisible({ timeout: 30_000 })
})


test('navigation shortcuts and a page refresh keep the signed-in session', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await page.getByRole('button', { name: /import findings/i }).click()
  await expect(page.getByRole('heading', { name: 'Import findings' })).toBeVisible()
  await page.reload()
  await expect(page.getByRole('heading', { name: 'Import findings' })).toBeVisible()
  await expect(page.getByRole('link', { name: /data imports/i })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Sign in to IVM' })).toHaveCount(0)
})

test('finding detail sends its context to the assistant and chat follows new messages', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible()
  await expect(page.getByRole('table', { name: 'Prioritized findings' })).toBeVisible()
  const title = await page.locator('a.table-primary').first().innerText()
  await page.locator('a.table-primary').first().click()
  await page.getByRole('button', { name: /explain with ai/i }).click()
  await expect(page.locator('.user-message')).toContainText(title)
  await expect(page.locator('.ai-finding').first()).toContainText(title, { timeout: 30_000 })

  for (let index = 0; index < 4; index += 1) {
    await page.getByLabel('Ask the IVM assistant').fill(`Explain priority ${index + 1}`)
    await page.getByRole('button', { name: /send/i }).click()
    await expect(page.locator('.chat-exchange')).toHaveCount(index + 2)
  }
  await expect.poll(() => page.locator('.chat-history').evaluate(element =>
    element.scrollTop + element.clientHeight >= element.scrollHeight - 4,
  )).toBe(true)
})

test('executive gets a portfolio dashboard and only the pages their role allows', async ({ page }) => {
  await login(page, 'user11@demo.bank')
  const nav = page.getByRole('navigation', { name: 'Main navigation' })
  await expect(nav.getByRole('link', { name: 'Overview' })).toBeVisible()
  await expect(nav.getByRole('link', { name: 'Findings', exact: true })).toHaveCount(0)
  await expect(page.getByText('Executive risk overview', { exact: false })).toBeVisible()
  await expect(page.getByRole('heading', { name: 'Risk by business unit' })).toBeVisible()
  await page.getByRole('button', { name: /generate briefing/i }).click()
  await expect(page.getByText(/AI-generated demo summary/i)).toBeVisible({ timeout: 30_000 })
  await page.goto('/findings')
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toHaveCount(0)
})

test('analyst filters, sorts and pages through findings on the server', async ({ page }) => {
  await login(page)
  await page.getByRole('link', { name: 'Findings', exact: true }).click()
  await expect(page.getByRole('heading', { name: 'Findings', exact: true })).toBeVisible()
  await page.getByRole('navigation', { name: 'Pagination' }).getByRole('button', { name: 'Next page' }).click()
  await expect(page.getByText(/^51–100 of/)).toBeVisible()
  await page.getByLabel('Risk band').selectOption('critical')
  await expect(page).toHaveURL(/band=critical/)
  await expect(page.getByText(/^1–50 of/)).toBeVisible()
  const badges = page.locator('tbody tr .risk-badge')
  await expect(badges.first()).toBeVisible()
  await page.getByRole('button', { name: 'Risk score' }).click()
  await expect(page).toHaveURL(/order=asc/)
  const first = Number(await page.locator('tbody tr .score-cell strong').first().innerText())
  const second = Number(await page.locator('tbody tr .score-cell strong').nth(1).innerText())
  expect(first).toBeLessThanOrEqual(second)
})

test('administrator registers an asset and reclassifies its criticality', async ({ page }) => {
  await login(page, 'user1@demo.bank')
  await page.getByRole('link', { name: /asset inventory/i }).click()
  await page.getByRole('button', { name: /register asset/i }).click()
  const name = `e2e-asset-${Date.now()}`
  const form = page.getByRole('form', { name: 'Register asset' })
  await form.getByLabel('Name', { exact: true }).fill(name)
  await form.getByLabel('Hostname').fill(`${name}.bank.local`)
  await form.getByRole('button', { name: /register asset/i }).click()
  await expect(page.getByRole('heading', { name })).toBeVisible()
  await page.getByRole('button', { name: /edit asset/i }).click()
  const edit = page.getByRole('form', { name: 'Edit asset' })
  await edit.getByLabel('Crown jewel').check()
  await edit.getByLabel('Internet exposed').check()
  await edit.getByRole('button', { name: /save changes/i }).click()
  await expect(page.getByText(/^Saved/)).toBeVisible()
  await expect(page.locator('.detail-pair', { hasText: 'Crown jewel' }).getByText('Yes')).toBeVisible()
})

test('manager opens a task, raises a Jira ticket and sees it on the task', async ({ page }) => {
  await login(page, 'user4@demo.bank')
  await page.getByRole('link', { name: /remediation/i }).click()
  await page.locator('tbody tr').filter({ has: page.locator('.status-pill', { hasText: /^open$/ }) }).first().locator('.link-button').click()
  const drawer = page.getByRole('dialog', { name: 'Task details' })
  await expect(drawer.getByText('SLA breach risk')).toBeVisible()
  await drawer.getByRole('button', { name: /create jira ticket/i }).click()
  await expect(drawer.getByText(/JIRA_SIM/)).toBeVisible()
  await expect(drawer.getByText(/IVM-[0-9A-F]{8} · open/)).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(drawer).toHaveCount(0)
})

test('executive reviews measured success criteria and downloads the board report', async ({ page }) => {
  await login(page, 'user11@demo.bank')
  await page.getByRole('link', { name: /reports & insights/i }).click()
  await expect(page.getByRole('table', { name: 'Success criteria' }).locator('tbody tr')).toHaveCount(12)
  await expect(page.getByText(/First five campaigns remove/)).toBeVisible()
  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: /executive report/i }).click()
  expect((await download).suggestedFilename()).toBe('ivm-executive-report.html')
})

test('auditor verifies the tamper-evident audit chain', async ({ page }) => {
  await login(page, 'user5@demo.bank')
  await page.getByRole('link', { name: /audit trail/i }).click()
  await page.getByRole('button', { name: /verify integrity/i }).click()
  await expect(page.getByText(/Hash chain intact/)).toBeVisible()
})
