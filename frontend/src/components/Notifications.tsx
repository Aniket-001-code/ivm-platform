import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell } from 'lucide-react'
import { api } from '../api/client'

type Item = {
  id: string
  kind: string
  severity: 'high' | 'medium'
  title: string
  detail: string
  link: string
  escalation_id?: string
}

/** Top-bar inbox: escalations, overdue/at-risk work and approvals waiting on the user. */
export function NotificationBell() {
  const [open, setOpen] = useState(false)
  const panel = useRef<HTMLDivElement>(null)
  const qc = useQueryClient()
  const inbox = useQuery({
    queryKey: ['my-notifications'],
    queryFn: () => api<{ count: number; items: Item[] }>('/me/notifications'),
    refetchInterval: 60_000,
  })
  const ack = useMutation({
    mutationFn: (id: string) => api(`/escalations/${id}/acknowledge`, { method: 'POST' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['my-notifications'] }),
  })
  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent | KeyboardEvent) => {
      if (event instanceof KeyboardEvent ? event.key === 'Escape' : !panel.current?.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', close)
    document.addEventListener('keydown', close)
    return () => {
      document.removeEventListener('mousedown', close)
      document.removeEventListener('keydown', close)
    }
  }, [open])
  const count = inbox.data?.count ?? 0
  return (
    <div className="notify" ref={panel}>
      <button
        className="icon-button notify-button"
        aria-label={`Notifications, ${count} unread`}
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <Bell size={18} />
        {count > 0 && <span className="notify-count">{count > 99 ? '99+' : count}</span>}
      </button>
      {open && (
        <div className="notify-panel" role="dialog" aria-label="Notifications">
          <strong>Notifications</strong>
          {!inbox.data?.items.length && <p className="muted">You're all caught up.</p>}
          <ul>
            {inbox.data?.items.slice(0, 20).map((item) => (
              <li key={item.id} className={`notify-item ${item.severity}`}>
                <Link to={item.link} onClick={() => setOpen(false)}>
                  <b>{item.title}</b>
                  <small>{item.detail}</small>
                </Link>
                {item.escalation_id && (
                  <button className="text-btn" onClick={() => ack.mutate(item.escalation_id!)} disabled={ack.isPending}>
                    Acknowledge
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
