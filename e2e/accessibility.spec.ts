import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

// WCAG 2 A/AA automated audit of every main page (axe-core). Serious and critical issues fail the run.
const PAGES = ['/', '/findings', '/assets', '/attack-paths', '/tasks', '/exceptions', '/imports', '/assistant', '/reports', '/auditor', '/admin', '/account']

test('main pages have no serious or critical WCAG A/AA violations', async ({ page }) => {
  test.setTimeout(120_000)
  await page.goto('/login')
  const login = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()
  const problems: string[] = []
  const collect = (path: string, result: Awaited<ReturnType<AxeBuilder['analyze']>>) => {
    for (const v of result.violations.filter((x) => x.impact === 'serious' || x.impact === 'critical')) {
      problems.push(`${path}: ${v.id} (${v.impact}) × ${v.nodes.length} — ${v.nodes[0]?.target.join(' ')}`)
    }
  }
  collect('/login', login)
  await page.getByLabel('Email address').fill('user1@demo.bank')
  await page.getByLabel('Password').fill('DemoPass!234')
  await page.getByRole('button', { name: /continue/i }).click()
  await page.getByRole('navigation', { name: 'Main navigation' }).waitFor()
  for (const path of PAGES) {
    await page.goto(path)
    await page.waitForLoadState('networkidle')
    collect(path, await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze())
  }
  expect(problems, problems.join('\n')).toEqual([])
})
