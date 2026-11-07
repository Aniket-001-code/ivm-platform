from uuid import UUID

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    audit,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import (
    ImportBatch,
    RawFinding,
    User,
)
from app.services.ingestion import (
    SOURCE_TYPES,
    ingest_records,
    parse_upload,
    retry_failed_rows,
)

router = APIRouter(prefix="/api/v1")


@router.post("/imports/{source_type}")
async def import_file(
    source_type: str,
    file: UploadFile = File(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if source_type not in SOURCE_TYPES:
        raise HTTPException(status_code=400, detail="Unsupported source type")
    content = await file.read(10 * 1024 * 1024 + 1)
    try:
        records = parse_upload(source_type, file.filename or "upload", content)
        batch = ingest_records(db, source_type, file.filename or "upload", records)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit(
        db,
        user,
        "import_completed",
        "import_batch",
        batch.id,
        new={
            "total": batch.total_records,
            "failed": batch.failed_count,
            "duplicates": batch.duplicate_count,
        },
    )
    db.commit()
    return {
        "id": str(batch.id),
        "source_name": batch.source_name,
        "status": batch.status,
        "total_records": batch.total_records,
        "success_count": batch.success_count,
        "failed_count": batch.failed_count,
        "duplicate_count": batch.duplicate_count,
        "errors": batch.errors,
    }


@router.get("/imports")
def imports(db: Session = Depends(get_db), _: User = Depends(current_user)):
    return [
        {
            "id": str(x.id),
            "source_name": x.source_name,
            "file_name": x.file_name,
            "status": x.status,
            "total_records": x.total_records,
            "success_count": x.success_count,
            "failed_count": x.failed_count,
            "duplicate_count": x.duplicate_count,
            "created_at": x.created_at,
        }
        for x in db.scalars(
            select(ImportBatch).order_by(ImportBatch.created_at.desc()).limit(100)
        )
    ]


@router.get("/imports/{batch_id}")
def import_detail(
    batch_id: UUID, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    batch = db.get(ImportBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Import batch not found")
    return {
        "id": str(batch.id),
        "source_name": batch.source_name,
        "status": batch.status,
        "total_records": batch.total_records,
        "success_count": batch.success_count,
        "failed_count": batch.failed_count,
        "duplicate_count": batch.duplicate_count,
        "errors": batch.errors,
    }


@router.post("/imports/{batch_id}/retry")
def retry_import(
    batch_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Reprocess the rows that failed in a batch (e.g. after registering a missing asset)."""
    batch = db.get(ImportBatch, batch_id)
    if not batch:
        raise HTTPException(status_code=404, detail="Import batch not found")
    pending = db.scalar(
        select(func.count()).where(
            RawFinding.import_batch_id == batch.id, RawFinding.status == "failed"
        )
    )
    if not pending:
        raise HTTPException(
            status_code=409, detail="This batch has no failed rows to retry"
        )
    result = retry_failed_rows(db, batch)
    audit(
        db,
        user,
        "import_retried",
        "import_batch",
        result.id,
        new={
            "source_batch_id": str(batch.id),
            "recovered": result.success_count + result.duplicate_count,
            "still_failed": result.failed_count,
        },
        ip=request.client.host if request.client else None,
    )
    db.commit()
    return {
        "id": str(result.id),
        "status": result.status,
        "total_records": result.total_records,
        "success_count": result.success_count,
        "failed_count": result.failed_count,
        "duplicate_count": result.duplicate_count,
        "errors": result.errors,
    }


@router.get("/imports/{batch_id}/failed-rows")
def failed_rows(
    batch_id: UUID, db: Session = Depends(get_db), _: User = Depends(current_user)
):
    """Rows kept for recovery: the original payload plus the validation error."""
    return [
        {"id": str(r.id), "payload": r.raw_payload, "error": r.error_message}
        for r in db.scalars(
            select(RawFinding)
            .where(
                RawFinding.import_batch_id == batch_id, RawFinding.status == "failed"
            )
            .limit(500)
        )
    ]
