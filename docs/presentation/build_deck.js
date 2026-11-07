// Source of IVM_Final_Presentation.pptx (pptxgenjs 3.12). Needs: npm i pptxgenjs react-icons react react-dom sharp jszip,
// SKILL_DIR pointing at a folder with scripts/apply_theme.js, and slide screenshots in ./img. Usage: node build_deck.js out.pptx

const path = require('path')
const pptxgen = require('pptxgenjs')
const React = require('react')
const ReactDOMServer = require('react-dom/server')
const sharp = require('sharp')
const fa = require('react-icons/fa6')
const { applyTheme } = require(process.env.SKILL_DIR + '/scripts/apply_theme.js')

const IMG = path.join(__dirname, 'img')
const OUT = process.argv[2]

const THEME = {
  name: 'IVM Risk Command',
  headFontFace: 'Arial',
  bodyFontFace: 'Calibri',
  colors: {
    dk1: '10233F', // navy text / dark backgrounds
    lt1: 'FFFFFF',
    dk2: '33475E', // secondary text
    lt2: 'EEF3F6', // light panels
    accent1: '087E7B', // teal (dominant accent)
    accent2: 'D66650', // coral (risk)
    accent3: 'E29A35', // amber (high)
    accent4: '6688C4', // blue (medium)
    accent5: '42A57E', // green (low / pass)
    accent6: '7FD1C5', // mint (on dark)
    hlink: '087E7B',
    folHlink: '33475E',
  },
}
const HEX = THEME.colors

async function icon(Comp, color, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(Comp, { color: '#' + color, size: String(size) }))
  const buf = await sharp(Buffer.from(svg)).png().toBuffer()
  return 'image/png;base64,' + buf.toString('base64')
}

async function main() {
  const pres = new pptxgen()
  pres.layout = 'LAYOUT_WIDE' // 13.333 x 7.5
  pres.title = 'Intelligent Vulnerability Management & Risk Prioritization Platform'
  pres.author = 'IVM capstone team'
  pres.subject = 'Final presentation'
  pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace }
  const C = pres.SchemeColor

  // ---- Layouts ------------------------------------------------------------------------
  pres.defineSlideMaster({
    title: 'DARK_TITLE',
    background: { color: HEX.dk1 },
    objects: [
      { placeholder: { options: { name: 'title', type: 'title', x: 0.8, y: 2.3, w: 11.7, h: 1.6, fontSize: 40, bold: true, color: C.background1, valign: 'top' }, text: '' } },
      { placeholder: { options: { name: 'body', type: 'body', x: 0.8, y: 4.0, w: 11.0, h: 1.4, fontSize: 18, color: C.accent6, valign: 'top' }, text: '' } },
    ],
  })
  pres.defineSlideMaster({
    title: 'CONTENT',
    background: { color: HEX.lt1 },
    margin: [0.5, 0.6, 0.6, 0.6],
    objects: [
      { placeholder: { options: { name: 'title', type: 'title', x: 0.6, y: 0.35, w: 12.1, h: 0.8, fontSize: 30, bold: true, color: C.text1, valign: 'middle' }, text: '' } },
      { text: { text: 'IVM · Intelligent Vulnerability Management · synthetic data only', options: { x: 0.6, y: 7.05, w: 8, h: 0.3, fontSize: 10, color: C.text2 } } },
    ],
    slideNumber: { x: 12.3, y: 7.05, w: 0.5, h: 0.3, fontSize: 10, color: HEX.dk2 },
  })

  const ic = {
    shield: await icon(fa.FaShieldHalved, HEX.accent1),
    db: await icon(fa.FaDatabase, HEX.lt1),
    merge: await icon(fa.FaCodeMerge, HEX.lt1),
    gauge: await icon(fa.FaGaugeHigh, HEX.lt1),
    route: await icon(fa.FaRoute, HEX.lt1),
    tasks: await icon(fa.FaListCheck, HEX.lt1),
    scale: await icon(fa.FaScaleBalanced, HEX.lt1),
    chart: await icon(fa.FaChartLine, HEX.lt1),
    robot: await icon(fa.FaRobot, HEX.lt1),
    lock: await icon(fa.FaUserLock, HEX.lt1),
    key: await icon(fa.FaKey, HEX.lt1),
    link: await icon(fa.FaLink, HEX.lt1),
    filter: await icon(fa.FaFilter, HEX.lt1),
    cloud: await icon(fa.FaCloud, HEX.lt1),
    check: await icon(fa.FaCircleCheck, HEX.accent5),
    warn: await icon(fa.FaTriangleExclamation, HEX.accent3),
  }

  const iconCircle = (slide, data, x, y, d = 0.62, fill = C.accent1) => {
    slide.addShape(pres.shapes.OVAL, { x, y, w: d, h: d, fill: { color: fill }, line: { type: 'none' } })
    slide.addImage({ data, x: x + d * 0.24, y: y + d * 0.24, w: d * 0.52, h: d * 0.52 })
  }
  const card = (slide, x, y, w, h, name) =>
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w, h, rectRadius: 0.12, fill: { color: C.background2 }, line: { type: 'none' }, objectName: name,
    })
  const text = (slide, t, opts) => slide.addText(t, { isTextBox: true, margin: 0, color: C.text1, fontSize: 14, valign: 'top', ...opts })
  const shot = (slide, file, x, y, w, name) => {
    const h = w / (2380 / 1800)
    slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x - 0.04, y: y - 0.04, w: w + 0.08, h: h + 0.08, rectRadius: 0.08, fill: { color: 'D9E2EA' }, line: { type: 'none' }, shadow: { type: 'outer', color: '10233F', opacity: 0.18, blur: 8, offset: 3, angle: 90 } })
    slide.addImage({ path: path.join(IMG, file), x, y, w, h, objectName: name, altText: name })
  }
  const stat = (slide, value, label, x, y, w, color = C.accent1) => {
    text(slide, value, { x, y, w, h: 0.8, fontSize: 40, bold: true, color, fontFace: 'Arial' })
    text(slide, label, { x, y: y + 0.82, w, h: 0.6, fontSize: 13, color: C.text2 })
  }

  // ---- 1. Title ------------------------------------------------------------------------
  pres.addSection({ title: 'Opening' })
  let s = pres.addSlide({ masterName: 'DARK_TITLE', sectionTitle: 'Opening' })
  s.addImage({ data: await icon(fa.FaShieldHalved, HEX.accent6), x: 0.8, y: 1.15, w: 0.8, h: 0.8 })
  s.addText('Intelligent Vulnerability Management & Risk Prioritization Platform', { placeholder: 'title' })
  s.addText('From thousands of noisy scanner rows to owned, explainable, business-aware remediation\nBarclays Early Careers · final-year software engineering capstone', { placeholder: 'body' })
  text(s, 'Synthetic data only · no live bank systems', { x: 0.8, y: 6.6, w: 8, h: 0.4, fontSize: 12, color: C.accent6 })
  s.addNotes('Introduce the platform in one sentence: it consolidates findings from six simulated sources, scores them with business and threat context, assigns owners, tracks SLAs and exceptions, and gives every role its own view. Everything shown uses a deterministic synthetic dataset.')

  // ---- 2. Problem ----------------------------------------------------------------------
  pres.addSection({ title: 'Problem and solution' })
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Problem and solution' })
  s.addText('Security teams drown in findings that lack business context', { placeholder: 'title' })
  const problems = [
    ['2,500', 'raw rows from five tools in one import cycle'],
    ['28.6%', 'of rows are duplicates of the same issue'],
    ['3,454', 'open findings — which ones matter first?'],
    ['?', 'who owns the fix, and is the SLA at risk?'],
  ]
  problems.forEach(([v, l], i) => {
    const x = 0.6 + i * 3.1
    card(s, x, 1.5, 2.85, 2.2, `problem-card-${i}`)
    stat(s, v, l, x + 0.25, 1.75, 2.4, i === 3 ? C.accent2 : C.accent1)
  })
  text(s, 'Our answer', { x: 0.6, y: 4.15, w: 6, h: 0.5, fontSize: 22, bold: true, fontFace: 'Arial' })
  text(s, [
    { text: 'Consolidate and de-duplicate every source into one record per issue', options: { bullet: true, breakLine: true } },
    { text: 'Score with eight explainable factors: technical, threat and business context', options: { bullet: true, breakLine: true } },
    { text: 'Route each fix to an accountable owner with an SLA, escalation and evidence trail', options: { bullet: true, breakLine: true } },
    { text: 'Show every role — analyst to CISO — exactly the view and data it needs', options: { bullet: true } },
  ], { x: 0.6, y: 4.7, w: 12, h: 2.1, fontSize: 16, paraSpaceAfter: 6 })
  s.addNotes('Numbers come from the seeded academic dataset (seed 42). The point: volume and duplication hide the real risk; context and ownership are what turn findings into action.')

  // ---- 3. Capabilities ----------------------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Problem and solution' })
  s.addText('One platform covers all 14 use cases end to end', { placeholder: 'title' })
  const caps = [
    [ic.db, 'Asset inventory', 'Register assets, criticality, crown jewels, regulatory tags, owners (UC-1/2)'],
    [ic.merge, 'Ingest & correlate', 'Scanner, CSPM, pentest, container/K8s, identity, EASM, threat intel (UC-3/4/5)'],
    [ic.gauge, 'Explainable risk', '8-factor configurable score with a what-if preview (UC-6)'],
    [ic.route, 'Attack paths', 'Graph routes to crown jewels raise priority (UC-7)'],
    [ic.tasks, 'Remediation', 'Auto-ownership, SLA, escalation, tickets, evidence (UC-8/9/10)'],
    [ic.scale, 'Exceptions', 'Temporary/long-term risk acceptance, review packs (UC-11)'],
    [ic.chart, 'Reporting', 'Role dashboards, heatmap, MTTR, forecasts, board report (UC-12)'],
    [ic.robot, 'AI assistant', 'Plain-English questions, recommendations, remediation plan (UC-13/14)'],
  ]
  caps.forEach(([img, h, b], i) => {
    const col = i % 4, row = Math.floor(i / 4)
    const x = 0.6 + col * 3.1, y = 1.45 + row * 2.75
    card(s, x, y, 2.85, 2.5, `capability-${i}`)
    iconCircle(s, img, x + 0.25, y + 0.25)
    text(s, h, { x: x + 0.25, y: y + 1.0, w: 2.4, h: 0.4, fontSize: 17, bold: true, fontFace: 'Arial' })
    text(s, b, { x: x + 0.25, y: y + 1.45, w: 2.4, h: 0.95, fontSize: 13, color: C.text2 })
  })
  s.addNotes('Walk left to right as the data flows: inventory, ingestion, scoring, attack paths, remediation, exceptions, reporting, AI. Each tile names the use cases it satisfies.')

  // ---- 4. Architecture ----------------------------------------------------------------
  pres.addSection({ title: 'Architecture and engine' })
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Architecture and engine' })
  s.addText('Layered, API-first architecture with one scoring path', { placeholder: 'title' })
  const layers = [
    ['React + TypeScript UI', 'permission-driven menus, 14 pages, token refresh'],
    ['FastAPI REST API (104 operations)', 'central default-deny RBAC, row-level scope, OpenAPI'],
    ['Services', 'ingestion · scoring · attack paths · ownership · SLA · exceptions · analytics · forecasting · AI · reports'],
    ['SQLAlchemy + Alembic', 'PostgreSQL 15 (prod) / SQLite (dev); hash-chained, append-only audit'],
  ]
  layers.forEach(([h, b], i) => {
    const y = 1.45 + i * 1.3
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y, w: 7.4, h: 1.1, rectRadius: 0.1, fill: { color: i === 2 ? C.accent1 : C.background2 }, line: { type: 'none' }, objectName: `layer-${i}` })
    text(s, h, { x: 0.85, y: y + 0.14, w: 7, h: 0.4, fontSize: 17, bold: true, fontFace: 'Arial', color: i === 2 ? C.background1 : C.text1 })
    text(s, b, { x: 0.85, y: y + 0.55, w: 7, h: 0.45, fontSize: 13, color: i === 2 ? C.background1 : C.text2 })
  })
  text(s, 'Deployment options', { x: 8.5, y: 1.45, w: 4.2, h: 0.45, fontSize: 18, bold: true, fontFace: 'Arial' })
  const deploy = [
    [ic.cloud, 'Kubernetes', 'HPA API replicas, single scheduler, TLS ingress, NetworkPolicies'],
    [ic.db, 'Docker Compose', 'PostgreSQL, API, nginx, optional TLS proxy'],
    [ic.tasks, 'Dev script & CI', 'one-command start; CI lint, tests, scans, E2E, build'],
  ]
  deploy.forEach(([img, h, b], i) => {
    const y = 2.05 + i * 1.55
    iconCircle(s, img, 8.5, y, 0.6)
    text(s, h, { x: 9.3, y, w: 3.4, h: 0.4, fontSize: 16, bold: true, fontFace: 'Arial' })
    text(s, b, { x: 9.3, y: y + 0.42, w: 3.4, h: 0.9, fontSize: 13, color: C.text2 })
  })
  s.addNotes('Key design decision: every score — at import, after a weights change, an asset edit or a threat-feed update — goes through one rescoring service, so threat intel and attack-path context are never lost. Scheduling can be split out so the API scales horizontally.')

  // ---- 5. Risk engine (chart) -----------------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Architecture and engine' })
  s.addText('Eight explainable factors combine into one priority', { placeholder: 'title' })
  s.addChart(pres.charts.BAR, [{
    name: 'Max points',
    labels: ['CVSS severity', 'Asset criticality', 'Threat intelligence', 'Internet exposure', 'Exploitability', 'Data sensitivity', 'Attack path', 'Regulatory impact'],
    values: [25, 15, 15, 10, 10, 10, 10, 5],
  }], {
    x: 0.6, y: 1.4, w: 7.2, h: 5.3, barDir: 'bar', chartColors: [HEX.accent1],
    showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk1, dataLabelFontSize: 12, dataLabelFontFace: '+mn-lt',
    catAxisLabelColor: HEX.dk2, catAxisLabelFontSize: 12, catAxisLabelFontFace: '+mn-lt', catAxisOrientation: 'maxMin',
    valAxisHidden: true, valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false,
    showTitle: true, title: 'Default maximum points per factor (configurable, total 100)', titleFontSize: 13, titleColor: HEX.dk2, titleFontFace: '+mn-lt',
  })
  text(s, 'Why it works', { x: 8.3, y: 1.5, w: 4.4, h: 0.45, fontSize: 20, bold: true, fontFace: 'Arial' })
  text(s, [
    { text: 'Every point has a stated reason on the finding page', options: { bullet: true, breakLine: true } },
    { text: 'Bands: critical ≥ 80, high ≥ 60, medium ≥ 40', options: { bullet: true, breakLine: true } },
    { text: 'Weights are versioned; a what-if preview shows the re-ranking before saving', options: { bullet: true, breakLine: true } },
    { text: '2,588 of 3,454 open findings land in a different band than scanner severity alone', options: { bullet: true, breakLine: true } },
    { text: '444 findings would drop a band without KEV/exploitation signals (SC-5)', options: { bullet: true } },
  ], { x: 8.3, y: 2.05, w: 4.4, h: 4.6, fontSize: 15, paraSpaceAfter: 8 })
  s.addNotes('This is the spec formula implemented literally: CVSS + criticality + exposure + exploitability + threat intel + data sensitivity + regulatory + attack path. Show the finding page live to prove explainability.')

  // ---- 6. Explainability screenshot -----------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Architecture and engine' })
  s.addText('Every score is explained, with threat and path context', { placeholder: 'title' })
  shot(s, 'finding-crop.png', 0.6, 1.4, 7.4, 'Finding detail screenshot')
  text(s, [
    { text: 'Factor-by-factor points and reasons', options: { bullet: true, breakLine: true } },
    { text: 'Threat intel: KEV, active exploitation, ransomware, EPSS', options: { bullet: true, breakLine: true } },
    { text: 'Attack-path context shows base → final score', options: { bullet: true, breakLine: true } },
    { text: 'Source records prove survivorship across tools', options: { bullet: true, breakLine: true } },
    { text: '"Explain with AI" sends the finding to the assistant', options: { bullet: true } },
  ], { x: 8.4, y: 1.5, w: 4.3, h: 4.5, fontSize: 16, paraSpaceAfter: 10 })
  s.addNotes('Point at one factor bar and read the reason aloud. Then the attack-path card: this finding gained ten points because it sits on a modeled route to a crown jewel.')

  // ---- 7. Attack paths ----------------------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Architecture and engine' })
  s.addText('Exposure chains change what gets fixed first', { placeholder: 'title' })
  shot(s, 'attack-crop.png', 5.3, 1.4, 7.4, 'Attack path screenshot')
  stat(s, '555', 'findings sit on modeled routes from internet entry points to crown jewels', 0.6, 1.5, 4.3)
  stat(s, '300', 'were raised a full risk band by path context (SC-9)', 0.6, 3.25, 4.3, C.accent2)
  stat(s, '+9.7', 'points average increase on path findings', 0.6, 5.0, 4.3)
  s.addNotes('networkx finds simple paths of up to five hops from internet-exposed assets to crown-jewel or sensitive targets. Path risk feeds back into each finding as the attack-path factor. The graph also exports to Neo4j Cypher and GraphML.')

  // ---- 8. Ingestion ----------------------------------------------------------------
  pres.addSection({ title: 'Workflow' })
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Workflow' })
  s.addText('Six sources become one trustworthy record per issue', { placeholder: 'title' })
  const flow = ['Upload CSV / JSON', 'Normalize to common schema', 'Match asset (host, FQDN, URL, IP)', 'Correlate & survivorship', 'Score & assign owner']
  flow.forEach((t, i) => {
    const x = 0.6 + i * 2.5
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 1.5, w: 2.2, h: 1.1, rectRadius: 0.1, fill: { color: i === 3 ? C.accent1 : C.background2 }, line: { type: 'none' }, objectName: `flow-${i}` })
    text(s, t, { x: x + 0.15, y: 1.6, w: 1.9, h: 0.9, fontSize: 14, bold: true, align: 'center', valign: 'middle', color: i === 3 ? C.background1 : C.text1 })
    if (i < flow.length - 1) s.addShape(pres.shapes.RIGHT_ARROW, { x: x + 2.23, y: 1.9, w: 0.24, h: 0.3, fill: { color: C.accent1 }, line: { type: 'none' } })
  })
  stat(s, '714', 'duplicate rows merged on the seed load (28.6%)', 0.6, 3.1, 3.8)
  stat(s, '500', 'findings corroborated by two or more tools', 4.7, 3.1, 3.8)
  stat(s, '0', 'rows lost: failures are kept with their error and retryable', 8.8, 3.1, 3.9, C.accent5)
  text(s, 'Survivorship keeps the highest severity and CVSS, the most specific description and the CVE link; findings seen again after closure are reopened with their task. Threat-feed updates rescore affected findings immediately.', { x: 0.6, y: 5.2, w: 12.1, h: 1.2, fontSize: 15, color: C.text2 })
  s.addNotes('Demo the EASM import: 70 rows, 13 merge into existing scanner findings, 5 unknown hosts are rejected but kept — register the asset and press retry.')

  // ---- 9. Remediation ----------------------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Workflow' })
  s.addText('Accountable remediation with SLAs that predict breaches', { placeholder: 'title' })
  shot(s, 'task-crop.png', 0.6, 1.4, 7.0, 'Remediation task drawer screenshot')
  stat(s, '100%', 'of tasks routed to the dataset owner (SC-6, target 90%)', 8.1, 1.45, 4.6)
  stat(s, '4.4 / 8.5 d', 'MTTR for critical / high', 8.1, 3.1, 4.6)
  stat(s, '≈ 96%', 'SLA compliance; breaches escalate in three policy-driven levels', 8.1, 4.75, 4.6, C.accent3)
  s.addNotes('Ownership rules match business unit, service, asset type, environment or regulatory tag, then fall back to the asset owner and BU manager. Closing requires evidence and closes the finding. The breach model learns typical time-to-close and each owner\'s on-time rate from history. Jira and ServiceNow simulators plus a signed webhook cover SC-11.')

  // ---- 10. Governance -----------------------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Workflow' })
  s.addText('Risk acceptance with segregation of duties and evidence', { placeholder: 'title' })
  const gov = [
    [ic.scale, 'Request', 'Temporary (≤ 90 days) or long-term (≤ 365 days) with justification and compensating controls'],
    [ic.lock, 'Approve', 'Requester can never approve; long-term needs a security architect'],
    [ic.warn, 'Expire', 'Warnings at 14 and 7 days; expiry reopens the finding and its SLA'],
    [ic.shield, 'Evidence', 'One-click review pack: risk breakdown, threat intel, paths, checklist and hash-chained audit trail'],
  ]
  gov.forEach(([img, h, b], i) => {
    const x = 0.6 + i * 3.1
    card(s, x, 1.55, 2.85, 4.2, `governance-${i}`)
    iconCircle(s, img, x + 0.25, 1.8, 0.62, i === 2 ? C.accent3 : C.accent1)
    text(s, `${i + 1}. ${h}`, { x: x + 0.25, y: 2.6, w: 2.4, h: 0.45, fontSize: 18, bold: true, fontFace: 'Arial' })
    text(s, b, { x: x + 0.25, y: 3.15, w: 2.4, h: 2.4, fontSize: 14, color: C.text2 })
  })
  text(s, 'Every reviewed exception has an audit record (SC-8).', { x: 0.6, y: 6.1, w: 12, h: 0.5, fontSize: 15, bold: true, color: C.accent1 })
  s.addNotes('Show a pending request approved by a different user, then download the review pack — designed for auditors.')

  // ---- 11. Reporting & AI -----------------------------------------------------------
  pres.addSection({ title: 'Insight' })
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Insight' })
  s.addText('Every role gets its own dashboard; executives get a board report', { placeholder: 'title' })
  shot(s, 'dashboard-crop.png', 0.6, 1.4, 6.0, 'Executive dashboard screenshot')
  shot(s, 'dashboard2-crop.png', 6.75, 1.4, 6.0, 'Executive dashboard sections screenshot')
  text(s, 'Covers every section-13 item: top risky assets, critical by business unit, internet-facing high-risk assets, overdue by owner and SLA category, expiring exceptions, paths to crown jewels, trend, risk reduction, MTTR and a service heatmap — plus forecasts and a printable board report.', { x: 0.6, y: 6.15, w: 12.1, h: 0.8, fontSize: 14, color: C.text2 })
  s.addNotes('Executive, analyst, manager and auditor views come from distinct endpoints scoped to the user. Under 25 concurrent users the API serves about 65 requests per second with p95 1.5 s against the 3 s target.')

  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Insight' })
  s.addText('An assistant that answers from the data and shows its sources', { placeholder: 'title' })
  shot(s, 'assistant-crop.png', 5.3, 1.4, 7.4, 'AI assistant screenshot')
  text(s, 'Try asking', { x: 0.6, y: 1.5, w: 4.4, h: 0.45, fontSize: 20, bold: true, fontFace: 'Arial' })
  text(s, [
    { text: '“Critical findings in Treasury” → “what about Retail Banking?”', options: { bullet: true, breakLine: true } },
    { text: '“What should we fix first?” — effort-weighted plan', options: { bullet: true, breakLine: true } },
    { text: '“Tell me about CVE-2021-44228”', options: { bullet: true, breakLine: true } },
    { text: '“Who owns server-051?”', options: { bullet: true, breakLine: true } },
    { text: '“Is risk getting worse?” — trend forecast', options: { bullet: true } },
  ], { x: 0.6, y: 2.05, w: 4.4, h: 3.2, fontSize: 15, paraSpaceAfter: 8 })
  text(s, 'Role-scoped queries, a sources table on every answer, every question audited. Claude can rephrase answers from aggregates when an API key is configured.', { x: 0.6, y: 5.35, w: 4.4, h: 1.4, fontSize: 13, color: C.text2 })
  s.addNotes('The offline engine recognises business units, assets, CVEs and risk bands, carries context into follow-ups, and never sees data outside the user\'s scope. Answers cite tables and row counts so they can be checked.')

  // ---- 13. Security ------------------------------------------------------------------
  pres.addSection({ title: 'Assurance' })
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Assurance' })
  s.addText('Security engineered in, not bolted on', { placeholder: 'title' })
  const sec = [
    [ic.lock, 'Access control', '9 roles × 28 permissions, central default-deny, one row-level scope rule set, tested role by endpoint'],
    [ic.key, 'Identity', 'bcrypt, lockout, rate limits, rotating refresh tokens, TOTP MFA (encrypted secrets), password policy'],
    [ic.link, 'Tamper-evident audit', 'SHA-256 hash chain, append-only DB triggers, one-click integrity verification'],
    [ic.filter, 'Input & output safety', 'strict validation, CSV formula-injection guard, signed webhooks, CSP and security headers'],
    [ic.cloud, 'Secrets & platform', 'env-only secrets, weak-key refusal, non-root containers, TLS, NetworkPolicies'],
    [ic.shield, 'DevSecOps', 'bandit, pip-audit, npm audit, gitleaks and type checks gate every CI run'],
  ]
  sec.forEach(([img, h, b], i) => {
    const col = i % 3, row = Math.floor(i / 3)
    const x = 0.6 + col * 4.1, y = 1.45 + row * 2.75
    card(s, x, y, 3.85, 2.5, `security-${i}`)
    iconCircle(s, img, x + 0.25, y + 0.25)
    text(s, h, { x: x + 1.05, y: y + 0.32, w: 2.6, h: 0.5, fontSize: 17, bold: true, fontFace: 'Arial' })
    text(s, b, { x: x + 0.25, y: y + 1.05, w: 3.4, h: 1.3, fontSize: 14, color: C.text2 })
  })
  s.addNotes('34 defects were found and closed during hardening, including scope leaks through AI endpoints, an MFA bypass for non-privileged roles and a re-score that silently erased attack-path context. All are in the defect summary with their regression tests.')

  // ---- 14. Quality evidence (chart) --------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Assurance' })
  s.addText('Measured quality: tests, coverage, scans and speed', { placeholder: 'title' })
  s.addChart(pres.charts.BAR, [{ name: 'Automated tests', labels: ['Backend (pytest)', 'Frontend (Vitest)', 'End-to-end (Playwright)'], values: [114, 12, 14] }], {
    x: 0.6, y: 1.4, w: 6.4, h: 4.2, barDir: 'col', chartColors: [HEX.accent1],
    showValue: true, dataLabelPosition: 'outEnd', dataLabelColor: HEX.dk1, dataLabelFontSize: 14, dataLabelFontFace: '+mn-lt',
    catAxisLabelColor: HEX.dk2, catAxisLabelFontSize: 13, catAxisLabelFontFace: '+mn-lt', valAxisHidden: true,
    valGridLine: { style: 'none' }, catGridLine: { style: 'none' }, showLegend: false,
    showTitle: true, title: 'Automated tests — all passing', titleFontSize: 14, titleColor: HEX.dk2, titleFontFace: '+mn-lt',
  })
  stat(s, '86%', 'whole-backend line coverage (gate: 70%)', 7.5, 1.5, 2.6)
  stat(s, '0 errors', '600 requests from 25 concurrent users, p95 1.5 s (target < 3 s)', 10.2, 1.5, 2.6)
  stat(s, '0', 'bandit issues; 0 serious WCAG violations (axe)', 7.5, 3.4, 2.6, C.accent5)
  stat(s, '0', 'known vulnerable dependencies (pip-audit, npm audit)', 10.2, 3.4, 2.6, C.accent5)
  text(s, 'Regenerate everything with scripts/collect_evidence.sh --with-e2e → docs/evidence/', { x: 0.6, y: 6.1, w: 12.1, h: 0.5, fontSize: 14, color: C.text2 })
  s.addNotes('Evidence files are committed under docs/evidence with exit codes. Not verified locally: Docker/PostgreSQL runtime and gitleaks — both run in CI.')

  // ---- 15. Success criteria (table) ------------------------------------------------
  s = pres.addSlide({ masterName: 'CONTENT', sectionTitle: 'Assurance' })
  s.addText('All twelve success criteria met — measured, not asserted', { placeholder: 'title' })
  const rows = [
    ['SC-1', 'All 300 dataset assets tracked'], ['SC-2', '5 import sources (+ EASM, threat intel)'], ['SC-3', '714 duplicates merged automatically'],
    ['SC-4', 'Business context re-bands 2,588 findings'], ['SC-5', 'Threat intel moves 444 findings a band'], ['SC-6', '100% ownership accuracy (target 90%)'],
    ['SC-7', 'Every overdue task escalated'], ['SC-8', 'Exceptions end-to-end with audit records'], ['SC-9', '300 findings raised a band by paths'],
    ['SC-10', 'Four role dashboards + board report'], ['SC-11', 'Jira/ServiceNow + signed webhook'], ['SC-12', '≈ 99 analyst hours saved (stated assumptions)'],
  ]
  const cell = (t, o = {}) => ({ text: t, options: { fontSize: 14, color: HEX.dk1, valign: 'middle', ...o } })
  const table = []
  for (let r = 0; r < 6; r++) {
    const a = rows[r], b = rows[r + 6]
    table.push([
      cell(a[0], { bold: true, color: HEX.accent1 }), cell(a[1]), cell('✔', { color: HEX.accent5, bold: true, align: 'center' }),
      cell(b[0], { bold: true, color: HEX.accent1 }), cell(b[1]), cell('✔', { color: HEX.accent5, bold: true, align: 'center' }),
    ])
  }
  s.addTable(table, {
    x: 0.6, y: 1.5, w: 12.1, colW: [0.8, 4.6, 0.65, 0.8, 4.6, 0.65], rowH: 0.62,
    border: { type: 'solid', pt: 1, color: 'DCE4EA' }, fill: { color: HEX.lt1 }, fontFace: 'Calibri',
  })
  text(s, 'Live scorecard: Reports & insights → Success criteria (computed from the database on every visit).', { x: 0.6, y: 5.6, w: 12.1, h: 0.5, fontSize: 14, color: C.text2 })
  s.addNotes('Open the Reports page live — each row carries the evidence string computed from the current data, so assessors can see exactly how each criterion is met.')

  // ---- 16. Close -------------------------------------------------------------------
  pres.addSection({ title: 'Close' })
  s = pres.addSlide({ masterName: 'DARK_TITLE', sectionTitle: 'Close' })
  s.addText('Limits we are honest about — and what comes next', { placeholder: 'title' })
  s.addText([
    { text: 'Access tokens live 15 min after logout → add token versioning', options: { bullet: true, breakLine: true } },
    { text: 'Audit immutability at DB level → add external WORM storage', options: { bullet: true, breakLine: true } },
    { text: 'Docker/PostgreSQL and Kubernetes verified in CI design only → run in a real cluster', options: { bullet: true, breakLine: true } },
    { text: 'Business-unit scoping policy → stakeholder sign-off before real data', options: { bullet: true } },
  ], { placeholder: 'body', fontSize: 18, paraSpaceAfter: 8 })
  text(s, 'Thank you — questions welcome', { x: 0.8, y: 6.4, w: 8, h: 0.5, fontSize: 20, bold: true, color: C.background1, fontFace: 'Arial' })
  s.addNotes('Close on limits stated plainly, then invite questions. Demo video: docs/demo/ivm-demo.webm.')

  await pres.writeFile({ fileName: OUT })
  await applyTheme(OUT, THEME)
  console.log('wrote', OUT)
}

main().catch((e) => { console.error(e); process.exit(1) })
