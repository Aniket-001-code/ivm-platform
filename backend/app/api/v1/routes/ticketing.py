"""Simulated Jira / ServiceNow integration (SC-11).

* Users create tickets from remediation tasks; one active ticket per task and system.
* Ticket transitions (from the UI or the external system) keep the task in step.
* External systems call ``POST /integrations/ticketing/webhook`` signed with
  ``X-IVM-Signature: sha256=<hmac of body>`` using INTEGRATION_WEBHOOK_SECRET.
"""

import hashlib
import hmac
import json
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.v1.common import _check_asset_scope, audit, settings
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import Asset, Finding, RemediationTask, TicketRecord, User
from app.services.audit import record_audit

router = APIRouter(prefix="/api/v1")

SYSTEMS = {"jira-sim": ("JIRA_SIM", "IVM"), "servicenow-sim": ("SERVICENOW_SIM", "INC")}
TICKET_STATUSES = {"open", "in_progress", "resolved", "closed", "cancelled"}
# How an external ticket status moves the remediation task.
TASK_STATUS_FOR_TICKET = {
    "in_progress": "in_progress",
    "resolved": "pending_verification",
}


def _system(system: str) -> tuple[str, str]:
    if system not in SYSTEMS:
        raise HTTPException(status_code=400, detail="Unsupported ticketing system")
    return SYSTEMS[system]


def _ticket_dict(ticket: TicketRecord) -> dict:
    return {
        "ticket_key": ticket.ticket_key,
        "system": ticket.system,
        "status": ticket.status,
        "task_id": str(ticket.task_id),
        "payload": ticket.payload,
        "created_at": ticket.created_at,
    }


def _scoped_task(db: Session, task_id: UUID, user: User) -> RemediationTask:
    task = db.get(RemediationTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    _check_asset_scope(db.get(Asset, task.asset_id), user, db)
    return task


def _sync_task(db: Session, ticket: TicketRecord) -> RemediationTask | None:
    task = db.get(RemediationTask, ticket.task_id)
    target = TASK_STATUS_FOR_TICKET.get(ticket.status)
    if task and target and task.status not in {"closed", target}:
        # Ticket "resolved" means the fix is claimed; closure still needs evidence in IVM.
        task.status = target
    return task


class TicketInput(BaseModel):
    task_id: UUID
    summary: str | None = Field(default=None, max_length=300)


@router.post("/ticketing/{system}/issues", status_code=201)
def create_ticket(
    system: str,
    body: TicketInput,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    system_name, prefix = _system(system)
    task = _scoped_task(db, body.task_id, user)
    active = db.scalar(
        select(TicketRecord).where(
            TicketRecord.task_id == task.id,
            TicketRecord.system == system_name,
            TicketRecord.status.notin_(["closed", "cancelled"]),
        )
    )
    if active:
        raise HTTPException(
            status_code=409,
            detail=f"Task already has an open ticket {active.ticket_key}",
        )
    finding = db.get(Finding, task.finding_id)
    asset = db.get(Asset, task.asset_id)
    key = f"{prefix}-{uuid4().hex[:8].upper()}"
    ticket = TicketRecord(
        task_id=task.id,
        system=system_name,
        ticket_key=key,
        status="open",
        payload={
            "summary": body.summary
            or f"Remediate {finding.title if finding else task.finding_id} on {asset.name if asset else ''}",
            "priority": task.priority,
            "due": task.sla_due_date.isoformat() if task.sla_due_date else None,
            "risk_score": finding.risk_score if finding else None,
        },
    )
    task.ticket_ref = key
    db.add(ticket)
    audit(
        db,
        user,
        "ticket_created",
        "remediation_task",
        task.id,
        new={"system": system_name, "ticket_key": key},
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return _ticket_dict(ticket)


@router.get("/ticketing/issues")
def list_tickets(
    task_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    query = select(TicketRecord).order_by(TicketRecord.created_at.desc())
    if task_id:
        _scoped_task(db, task_id, user)
        query = query.where(TicketRecord.task_id == task_id)
    rows = db.scalars(query.limit(500)).all()
    visible = []
    for ticket in rows:
        try:
            _scoped_task(db, ticket.task_id, user)
        except HTTPException:
            continue
        visible.append(_ticket_dict(ticket))
    return visible


def _get_ticket(db: Session, system: str, ticket_key: str) -> TicketRecord:
    system_name, _ = _system(system)
    ticket = db.scalar(
        select(TicketRecord).where(
            TicketRecord.ticket_key == ticket_key, TicketRecord.system == system_name
        )
    )
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


class TransitionInput(BaseModel):
    status: str = "in_progress"
    comment: str | None = Field(default=None, max_length=1000)


@router.post("/ticketing/{system}/issues/{ticket_key}/transition")
@router.patch("/ticketing/{system}/issues/{ticket_key}/transition")
def transition_ticket(
    system: str,
    ticket_key: str,
    body: TransitionInput,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    ticket = _get_ticket(db, system, ticket_key)
    _scoped_task(db, ticket.task_id, user)
    status = body.status.lower()
    if status not in TICKET_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported ticket status")
    old = ticket.status
    ticket.status = status
    task = _sync_task(db, ticket)
    audit(
        db,
        user,
        "ticket_transition",
        "ticket_record",
        ticket.id,
        {"status": old},
        {"status": status, "comment": body.comment},
        request.client.host if request.client else None,
    )
    db.commit()
    return {
        "ticket_key": ticket.ticket_key,
        "status": ticket.status,
        "task_status": task.status if task else None,
    }


@router.get("/ticketing/{system}/issues/{ticket_key}")
def get_ticket(
    system: str,
    ticket_key: str,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    ticket = _get_ticket(db, system, ticket_key)
    _scoped_task(db, ticket.task_id, user)
    return _ticket_dict(ticket)


@router.post("/integrations/ticketing/webhook")
async def ticketing_webhook(
    request: Request,
    x_ivm_signature: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    """Inbound status updates from an external ticketing system (HMAC-signed)."""
    secret = settings.integration_webhook_secret
    if not secret:
        raise HTTPException(
            status_code=503, detail="Webhook integration is not configured"
        )
    raw = await request.body()
    if len(raw) > 64 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large")
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not x_ivm_signature or not hmac.compare_digest(expected, x_ivm_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    try:
        payload = json.loads(raw)
        key, status = str(payload["ticket_key"]), str(payload["status"]).lower()
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=422, detail="Expected ticket_key and status"
        ) from exc
    if status not in TICKET_STATUSES:
        raise HTTPException(status_code=422, detail="Unsupported ticket status")
    ticket = db.scalar(select(TicketRecord).where(TicketRecord.ticket_key == key))
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    old = ticket.status
    ticket.status = status
    task = _sync_task(db, ticket)
    record_audit(
        db,
        None,
        "ticket_webhook_received",
        "ticket_record",
        ticket.id,
        {"status": old},
        {"status": status, "source": ticket.system},
        request.client.host if request.client else None,
    )
    db.commit()
    return {
        "ticket_key": key,
        "status": status,
        "task_status": task.status if task else None,
    }
