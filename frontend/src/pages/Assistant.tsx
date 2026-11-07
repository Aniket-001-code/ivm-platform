import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Activity, Bot, Shield } from 'lucide-react'
import { api } from '../api/client'
import { label } from '../access'
import { ErrorState, PageTitle, RiskBadge } from '../components/ui'
import type { AiSource, Factor } from '../types'

type AiRow = {
  id: string
  title: string
  risk_band: string
  risk_score: number | string
  description?: string | null
  risk_breakdown?: Factor[]
}

type Answer = {
  answer: string
  intent: string
  entities?: { cve: string | null; business_unit: string | null; asset: string | null; band: string | null; carried_from_previous: boolean }
  data: AiRow[] | Record<string, number>
  sources?: AiSource[]
  used_llm: boolean
  disclaimer: string
}

type Exchange = { question: string; answer: Answer }

const SUGGESTIONS = [
  'Explain the top priorities',
  'What should we fix first?',
  'Critical findings in Treasury',
  'What is overdue?',
  'What is our MTTR and SLA compliance?',
  'Is risk getting worse?',
  'Tell me about CVE-2021-44228',
  'Which business unit is riskiest?',
  'Which findings are actively exploited?',
  'Show attack paths to crown jewels',
]

// Rows in these intents are findings and can link to the finding page.
const FINDING_INTENTS = new Set(['explain_finding', 'prioritize_findings', 'threat_exposure', 'sla_status', 'exception_status'])

export function AssistantPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const navigationContext = location.state as { question?: string; findingId?: string } | null
  const [question, setQuestion] = useState(navigationContext?.question ?? '')
  const [findingId] = useState<string | null>(navigationContext?.findingId ?? null)
  const [conversation, setConversation] = useState<Exchange[]>([])
  const chatHistoryRef = useRef<HTMLDivElement>(null)
  const autoSubmitted = useRef(false)
  const historyRef = useRef<string[]>([])
  // Local request state: a mutation observer loses an in-flight request when React StrictMode
  // remounts the page, which left the chat stuck on "Thinking…".
  const [pending, setPending] = useState(false)
  const [askError, setAskError] = useState<string | null>(null)
  const send = useCallback(async (submittedQuestion: string, contextId: string | null) => {
    setPending(true)
    setAskError(null)
    try {
      const answer = await api<Answer>('/ai/ask', {
        method: 'POST',
        body: JSON.stringify({
          question: submittedQuestion,
          // Earlier questions let the assistant resolve follow-ups like "what about Treasury?".
          history: historyRef.current.slice(-5),
          ...(contextId ? { finding_id: contextId } : {}),
        }),
      })
      historyRef.current = [...historyRef.current, submittedQuestion]
      setConversation((previous) => [...previous, { question: submittedQuestion, answer }])
    } catch (err) {
      setAskError((err as Error).message)
      setQuestion((current) => current || submittedQuestion)
    } finally {
      setPending(false)
    }
  }, [])
  useEffect(() => {
    if (!navigationContext?.question || !navigationContext.findingId || autoSubmitted.current) return
    autoSubmitted.current = true
    setQuestion('')
    void send(navigationContext.question.trim(), navigationContext.findingId)
    navigate(location.pathname, { replace: true, state: null })
  }, [location.pathname, navigate, navigationContext, send])
  useEffect(() => {
    const history = chatHistoryRef.current
    if (history) history.scrollTo({ top: history.scrollHeight, behavior: 'smooth' })
  }, [conversation, pending])
  function ask(e: FormEvent) {
    e.preventDefault()
    const submittedQuestion = question.trim()
    if (!submittedQuestion || pending) return
    setQuestion('')
    void send(submittedQuestion, findingId)
  }
  return (
    <>
      <PageTitle
        eyebrow="AI COPILOT"
        title="Risk assistant"
        description="Ask plain-language questions about prioritized synthetic risk data."
      />
      <div className="assistant-layout">
        <section className="panel chat-panel">
          <div className="chat-top">
            <span className="bot-avatar">
              <Bot size={18} />
            </span>
            <span>
              <strong>IVM Assistant</strong>
              <small>
                <i className="status-dot" /> Offline-ready · role-scoped data
              </small>
            </span>
            <span className="ai-label">AI GENERATED</span>
          </div>
          <div className="chat-history" ref={chatHistoryRef} aria-live="polite">
            <div className="assistant-message">
              Hello. I can explain risk scores, summarize exposure, or help you choose what to remediate first.
            </div>
            {conversation.map((exchange, index) => (
              <div className="chat-exchange" key={`${index}-${exchange.question}`}>
                <div className="user-message">{exchange.question}</div>
                <AnswerBubble answer={exchange.answer} />
              </div>
            ))}
            {pending && (
              <div className="assistant-message" role="status">
                Thinking…
              </div>
            )}
          </div>
          <div className="suggestions">
            <span>Try asking</span>
            {SUGGESTIONS.map((q) => (
              <button type="button" key={q} onClick={() => setQuestion(q)}>
                {q}
              </button>
            ))}
          </div>
          <form className="chat-input" onSubmit={ask}>
            <input
              aria-label="Ask the IVM assistant"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask a question…"
              maxLength={1500}
            />
            <button className="primary-btn" disabled={pending || !question.trim()}>
              Send ↑
            </button>
          </form>
          {askError && <ErrorState message={askError} />}
        </section>
        <aside className="panel assistant-side">
          <span className="panel-kicker">HOW IT WORKS</span>
          <h2>Grounded in your data</h2>
          <p>
            Answers come from role-scoped queries against this synthetic demo database. Each answer lists the tables
            and row counts it used. If an Anthropic API key is configured, Claude rewrites the summary from the same
            aggregates only.
          </p>
          <div className="privacy-line">
            <Shield size={16} /> No customer or production data
          </div>
          <div className="privacy-line">
            <Activity size={16} /> Questions are written to the audit log
          </div>
        </aside>
      </div>
    </>
  )
}

function AnswerBubble({ answer }: { answer: Answer }) {
  const rows = Array.isArray(answer.data) ? answer.data : null
  const counts = !Array.isArray(answer.data) ? Object.entries(answer.data ?? {}) : []
  const linkFindings = FINDING_INTENTS.has(answer.intent)
  return (
    <div className="assistant-message">
      <p>{answer.answer}</p>
      {answer.entities && (answer.entities.business_unit || answer.entities.asset || answer.entities.cve || answer.entities.band) && (
        <div className="entity-chips" aria-label="Understood filters">
          {[answer.entities.business_unit, answer.entities.asset, answer.entities.cve, answer.entities.band]
            .filter(Boolean)
            .map((e) => (
              <span key={String(e)}>{e}</span>
            ))}
          {answer.entities.carried_from_previous && <span className="muted">from previous question</span>}
        </div>
      )}
      <small>
        {answer.disclaimer}
        {answer.used_llm ? ' · Claude-assisted summary' : ' · offline rules engine'}
      </small>
      {rows && rows.length > 0 && (
        <div className="ai-table">
          {rows.slice(0, 6).map((row) => (
            <article className="ai-finding" key={row.id}>
              <div>
                <strong>
                  {linkFindings ? <Link to={`/findings/${row.id}`}>{row.title}</Link> : row.title}
                </strong>
                <RiskBadge band={row.risk_band} />
                <b>{row.risk_score}</b>
              </div>
              {row.description && <p>{row.description}</p>}
              {Array.isArray(row.risk_breakdown) && (
                <ul>
                  {row.risk_breakdown.slice(0, 4).map((factor, index) => (
                    <li key={`${factor.factor}-${index}`}>
                      <strong>{label(factor.factor)}</strong> · {factor.points}/{factor.max_points} pts · {factor.reason}
                    </li>
                  ))}
                </ul>
              )}
            </article>
          ))}
        </div>
      )}
      {counts.length > 0 && (
        <div className="ai-counts">
          {counts.map(([key, value]) => (
            <span key={key}>
              {label(key)}: <b>{Number(value).toLocaleString()}</b>
            </span>
          ))}
        </div>
      )}
      {answer.sources && answer.sources.length > 0 && (
        <table className="ai-sources" aria-label="Answer sources">
          <thead>
            <tr>
              <th>Source table</th>
              <th>What was read</th>
              <th>Rows</th>
            </tr>
          </thead>
          <tbody>
            {answer.sources.map((source, index) => (
              <tr key={`${source.table}-${index}`}>
                <td>{source.table}</td>
                <td>{source.description}</td>
                <td>{source.rows.toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
