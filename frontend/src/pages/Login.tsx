import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Shield, ShieldAlert } from 'lucide-react'
import { api } from '../api/client'
import type { User } from '../types'

type LoginResult = { access_token: string; refresh_token: string; user: User }

export function Login({ onLogin }: { onLogin: (result: LoginResult) => void }) {
  const [email, setEmail] = useState('user2@demo.bank')
  const [password, setPassword] = useState('DemoPass!234')
  const [error, setError] = useState('')
  const [needsCode, setNeedsCode] = useState(false)
  const [code, setCode] = useState('')
  const mutation = useMutation({
    mutationFn: () =>
      api<LoginResult>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password, ...(needsCode ? { totp_code: code } : {}) }),
      }),
    onSuccess: onLogin,
    onError: (reason: Error) => {
      if (reason.message === 'MFA code required') {
        setNeedsCode(true)
        setError('')
        return
      }
      setError(reason.message)
    },
  })
  function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    mutation.mutate()
  }
  return (
    <main className="login-screen">
      <div className="login-art">
        <div className="brand-mark">
          <Shield size={21} /> IVM
        </div>
        <div className="login-copy">
          <span className="eyebrow">SECURITY OPERATIONS / 01</span>
          <h1>
            Put risk in
            <br />
            <em>business context.</em>
          </h1>
          <p>A single, explainable view of exposure across critical services.</p>
          <div className="login-visual">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="orbit-center">
              <ShieldAlert size={28} />
            </div>
            <span className="orbit-label label-a">THREAT SIGNAL</span>
            <span className="orbit-label label-b">BUSINESS IMPACT</span>
            <span className="orbit-label label-c">ATTACK PATH</span>
          </div>
        </div>
        <div className="login-foot">LOCAL DEMO · SYNTHETIC DATA ONLY</div>
      </div>
      <section className="login-panel">
        <form className="login-form" onSubmit={submit}>
          <span className="eyebrow">WELCOME BACK</span>
          <h2>Sign in to IVM</h2>
          <p className="muted">Use a seeded demo account to explore the platform.</p>
          <label htmlFor="email">Email address</label>
          <input
            id="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value)
              setNeedsCode(false)
            }}
            type="email"
            required
            autoComplete="username"
          />
          <label htmlFor="password">Password</label>
          <input
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            type="password"
            required
            autoComplete="current-password"
          />
          {needsCode && (
            <>
              <label htmlFor="totp">Authenticator code</label>
              <input
                id="totp"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
                placeholder="6-digit code"
              />
            </>
          )}
          {error && (
            <div className="error-box" role="alert">
              {error}
            </div>
          )}
          <button className="primary-btn full" disabled={mutation.isPending}>
            {mutation.isPending ? 'Signing in…' : 'Continue'} <span>→</span>
          </button>
          <div className="demo-account">
            <span>DEMO ACCESS</span>
            <strong>user1@demo.bank … user12@demo.bank</strong>
            <small>Password: DemoPass!234 · see README for each account's role</small>
          </div>
        </form>
        <div className="login-legal">For academic demonstration only. No production systems are connected.</div>
      </section>
    </main>
  )
}
