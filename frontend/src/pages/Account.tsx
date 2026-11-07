import { useState, type FormEvent } from 'react'
import { useMutation } from '@tanstack/react-query'
import { KeyRound, ShieldCheck } from 'lucide-react'
import { api } from '../api/client'
import { label } from '../access'
import { ErrorState, PageTitle } from '../components/ui'
import type { User } from '../types'

export function AccountPage({ user, onUserChange }: { user: User; onUserChange: (user: User) => void }) {
  return (
    <>
      <PageTitle
        eyebrow="MY ACCOUNT"
        title={user.full_name}
        description={`${user.email} · ${label(user.role)} · ${user.permissions.length} permissions`}
      />
      <div className="admin-grid">
        <MfaPanel user={user} onUserChange={onUserChange} />
        <PasswordPanel />
        <section className="panel admin-note">
          <span className="panel-kicker">ACCESS</span>
          <h2>What your role can do</h2>
          <div className="tag-list">
            {user.permissions.map((p) => (
              <span key={p}>{p}</span>
            ))}
          </div>
        </section>
      </div>
    </>
  )
}

function MfaPanel({ user, onUserChange }: { user: User; onUserChange: (user: User) => void }) {
  const [enrollment, setEnrollment] = useState<{ secret: string; provisioning_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [currentCode, setCurrentCode] = useState('')
  const [password, setPassword] = useState('')
  const setup = useMutation({
    mutationFn: () =>
      api<{ secret: string; provisioning_uri: string }>('/auth/mfa/setup', {
        method: 'POST',
        body: JSON.stringify(user.mfa_enabled ? { current_code: currentCode } : {}),
      }),
    onSuccess: (data) => {
      setEnrollment(data)
      onUserChange({ ...user, mfa_enabled: false })
    },
  })
  const verify = useMutation({
    mutationFn: () => api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) }),
    onSuccess: () => {
      setEnrollment(null)
      setCode('')
      onUserChange({ ...user, mfa_enabled: true })
    },
  })
  const disable = useMutation({
    mutationFn: () =>
      api('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ code: currentCode, password }) }),
    onSuccess: () => {
      setCurrentCode('')
      setPassword('')
      onUserChange({ ...user, mfa_enabled: false })
    },
  })
  const error = (setup.error || verify.error || disable.error) as Error | null
  return (
    <section className="panel form-panel">
      <div>
        <span className="panel-kicker">MULTI-FACTOR AUTHENTICATION</span>
        <h2>
          <ShieldCheck size={15} /> {user.mfa_enabled ? 'MFA is on' : 'MFA is off'}
        </h2>
      </div>
      <p className="muted">
        Use any TOTP authenticator app. Once enabled, sign-in asks for a 6-digit code after your password.
      </p>
      {enrollment ? (
        <>
          <label>
            Secret key (enter it in your authenticator)
            <input readOnly value={enrollment.secret} aria-label="MFA secret" className="mono-input" />
          </label>
          <label>
            Setup link
            <input readOnly value={enrollment.provisioning_uri} aria-label="MFA setup link" className="mono-input" />
          </label>
          <label>
            6-digit code from the app
            <input
              inputMode="numeric"
              autoComplete="one-time-code"
              aria-label="Verification code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
            />
          </label>
          <button className="primary-btn" disabled={code.length < 6 || verify.isPending} onClick={() => verify.mutate()}>
            Verify and turn on
          </button>
        </>
      ) : user.mfa_enabled ? (
        <>
          <label>
            Current 6-digit code
            <input
              inputMode="numeric"
              aria-label="Current MFA code"
              value={currentCode}
              onChange={(e) => setCurrentCode(e.target.value.replace(/\D/g, '').slice(0, 8))}
            />
          </label>
          <label>
            Password (to turn MFA off)
            <input type="password" aria-label="Password to disable MFA" value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <div className="button-row">
            <button className="secondary-btn" disabled={currentCode.length < 6 || setup.isPending} onClick={() => setup.mutate()}>
              Replace authenticator
            </button>
            <button
              className="secondary-btn danger-text"
              disabled={currentCode.length < 6 || !password || disable.isPending}
              onClick={() => disable.mutate()}
            >
              Turn off MFA
            </button>
          </div>
        </>
      ) : (
        <button className="primary-btn" disabled={setup.isPending} onClick={() => setup.mutate()}>
          Set up MFA <KeyRound size={14} />
        </button>
      )}
      {verify.isSuccess && <p className="success-note">MFA is now required at your next sign-in.</p>}
      {error && <ErrorState message={error.message} />}
    </section>
  )
}

function PasswordPanel() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const change = useMutation({
    mutationFn: () =>
      api('/auth/password', { method: 'POST', body: JSON.stringify({ current_password: current, new_password: next }) }),
    onSuccess: () => {
      setCurrent('')
      setNext('')
      setConfirm('')
    },
  })
  const mismatch = confirm.length > 0 && confirm !== next
  function submit(e: FormEvent) {
    e.preventDefault()
    if (!mismatch) change.mutate()
  }
  return (
    <form className="panel form-panel" onSubmit={submit}>
      <div>
        <span className="panel-kicker">PASSWORD</span>
        <h2>Change password</h2>
      </div>
      <p className="muted">At least 12 characters with upper- and lower-case letters, a number and a symbol. Other sessions are signed out.</p>
      <label>
        Current password
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
      </label>
      <label>
        New password
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
      </label>
      <label>
        Confirm new password
        <input
          type="password"
          autoComplete="new-password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          aria-invalid={mismatch}
        />
      </label>
      {mismatch && <ErrorState message="The new passwords do not match." />}
      <button className="primary-btn" disabled={!current || next.length < 12 || mismatch || change.isPending}>
        Change password
      </button>
      {change.isSuccess && <p className="success-note">Password changed.</p>}
      {change.error && <ErrorState message={(change.error as Error).message} />}
    </form>
  )
}
