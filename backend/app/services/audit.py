"""Tamper-evident audit trail.

Every audit row stores ``prev_hash`` (the previous row's hash) and ``row_hash`` (a SHA-256
over its own content plus ``prev_hash``). Editing or deleting any row breaks the chain, which
``verify_chain`` detects. Database triggers (migration 0002) additionally reject UPDATE and
DELETE on ``audit_logs``.
"""

import hashlib
import json
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import event, select, text
from sqlalchemy.orm import Session

from app.models.entities import AuditLog

GENESIS = "0" * 64


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def compute_hash(prev_hash: str, row: AuditLog) -> str:
    created = row.created_at
    if created is not None and created.tzinfo is not None:
        created = created.astimezone(timezone.utc).replace(tzinfo=None)
    payload = _canonical(
        {
            "id": str(row.id),
            "actor": str(row.actor_user_id) if row.actor_user_id else None,
            "action": row.action,
            "entity_type": row.entity_type,
            "entity_id": str(row.entity_id) if row.entity_id else None,
            "old": row.old_value,
            "new": row.new_value,
            "ip": row.ip_address,
            "created_at": (
                created.isoformat(timespec="microseconds") if created else None
            ),
        }
    )
    return hashlib.sha256(f"{prev_hash}|{payload}".encode()).hexdigest()


_HEAD_KEY = "audit_chain_head"


_LOCK_ID = 7_340_001  # arbitrary constant for the PostgreSQL advisory lock


@event.listens_for(Session, "after_transaction_end")
def _forget_head(session: Session, _transaction) -> None:
    # Any commit, rollback or savepoint end may invalidate the cached head; re-read it.
    session.info.pop(_HEAD_KEY, None)


def _chain_head(db: Session) -> tuple[int, str]:
    """(last sequence, last hash), cached per session so bulk writes stay O(1)."""
    head = db.info.get(_HEAD_KEY)
    if head is None:
        if db.get_bind().dialect.name == "postgresql":
            # Serialize appends so two transactions can never extend the same head.
            db.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": _LOCK_ID})
        db.flush()
        row = db.execute(
            select(AuditLog.sequence, AuditLog.row_hash)
            .where(AuditLog.sequence.is_not(None))
            .order_by(AuditLog.sequence.desc())
            .limit(1)
        ).first()
        head = (row[0], row[1] or GENESIS) if row else (0, GENESIS)
    return head


def record_audit(
    db: Session,
    actor_id: UUID | None,
    action: str,
    entity_type: str,
    entity_id: UUID | None = None,
    old=None,
    new=None,
    ip: str | None = None,
) -> AuditLog:
    """Append one audit row to the hash chain (caller commits)."""
    row = AuditLog(
        id=uuid4(),
        actor_user_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        old_value=old,
        new_value=new,
        ip_address=ip,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    sequence, previous = _chain_head(db)
    row.sequence = sequence + 1
    row.prev_hash = previous
    row.row_hash = compute_hash(previous, row)
    db.add(row)
    db.info[_HEAD_KEY] = (row.sequence, row.row_hash)
    return row


def verify_chain(db: Session) -> dict:
    """Recompute every hash in sequence order and report the first break, if any."""
    previous = GENESIS
    checked = 0
    legacy = 0
    for row in db.scalars(
        select(AuditLog).order_by(AuditLog.sequence, AuditLog.created_at)
    ):
        if row.row_hash is None:
            legacy += 1  # rows written before the hash chain existed
            continue
        if (
            row.prev_hash != previous
            or compute_hash(row.prev_hash, row) != row.row_hash
        ):
            return {
                "valid": False,
                "checked": checked,
                "legacy_unchained": legacy,
                "broken_at": str(row.id),
                "sequence": row.sequence,
            }
        previous = row.row_hash
        checked += 1
    return {
        "valid": True,
        "checked": checked,
        "legacy_unchained": legacy,
        "head": previous,
    }
