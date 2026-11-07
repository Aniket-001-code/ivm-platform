"""Ingestion pipeline (UC-3/UC-4): parse, normalize, correlate, apply survivorship, score.

Supported sources: scanner (CSV), cspm, pentest, container/Kubernetes, easm (JSON) and
identity (CSV). Every row is kept as a RawFinding, including rows that fail validation, so
failed rows can be retried later (for example after the missing asset is registered).

Survivorship when a row matches an existing finding (same asset + CVE or title):
* severity and CVSS keep the highest reported value;
* the most specific description wins (longest non-generic text);
* a missing catalog link is filled in when a later source supplies the CVE;
* sources are unioned and ``last_seen`` is refreshed;
* a closed finding that is reported again is reopened (regression) and its task reopened;
* a finding whose evidence changed is rescored.
"""

import csv
import io
import json
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    Finding,
    FindingSource,
    ImportBatch,
    RawFinding,
    VulnerabilityCatalog,
)
from app.services.audit import record_audit
from app.services.normalization import (
    asset_key,
    finding_fingerprint,
    normalize_severity,
)
from app.services.remediation import reopen_task
from app.services.scoring import path_influence, rescore_findings

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
SOURCE_TYPES = {"scanner", "cspm", "pentest", "container", "identity", "easm"}
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
GENERIC_DESCRIPTION = "Synthetic imported finding"


def parse_upload(source_type: str, filename: str, content: bytes) -> list[dict]:
    if not content or len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("Upload must be between 1 byte and 10 MB")
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension == "csv":
        return list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))
    if extension == "json":
        payload = json.loads(content.decode("utf-8"))
        if isinstance(payload, dict):
            payload = payload.get("findings", payload.get("items", [payload]))
        if not isinstance(payload, list):
            raise ValueError("JSON import must contain an array of records")
        return payload
    raise ValueError("Only CSV and JSON imports are supported")


def _pick(row: dict, *keys: str):
    return next((row.get(key) for key in keys if row.get(key) not in (None, "")), None)


def _float(value) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


class _Context:
    """Lookups shared across one batch."""

    def __init__(self, db: Session):
        self.assets: dict[str, Asset] = {}
        for stored in db.scalars(select(Asset).where(Asset.status != "retired")):
            for name in (stored.name, stored.hostname, stored.ip_address):
                if name:
                    self.assets[asset_key(name)] = stored
        self.catalog = {
            item.cve_id.lower(): item
            for item in db.scalars(select(VulnerabilityCatalog))
        }


def _normalize_row(row: dict, source_type: str, ctx: _Context) -> dict:
    if not isinstance(row, dict):
        raise ValueError("Row is not an object")
    target = _pick(
        row,
        "host",
        "hostname",
        "target",
        "resource_id",
        "image_name",
        "asset",
        "fqdn",
        "domain",
        "url",
        "ip",
    )
    asset = ctx.assets.get(asset_key(str(target))) if target else None
    if not asset:
        raise ValueError(f"Asset not found for target '{target}'")
    cve_id = _pick(row, "cve", "cve_id", "CVE", "vulnerability")
    cve_id = str(cve_id).upper() if cve_id else None
    title = str(
        _pick(
            row,
            "plugin_name",
            "rule_title",
            "finding_title",
            "issue",
            "title",
            "issue_type",
            "service",
        )
        or cve_id
        or "Finding"
    )[:300]
    catalog = ctx.catalog.get(cve_id.lower()) if cve_id else None
    cvss = _float(_pick(row, "cvss", "cvss_score", "cvss_base_score"))
    if cvss is None and catalog and catalog.cvss_base_score is not None:
        cvss = catalog.cvss_base_score
    if cvss is not None and not 0 <= cvss <= 10:
        raise ValueError(f"CVSS score {cvss} is outside 0-10")
    finding_type = (
        "cve"
        if cve_id
        else {
            "identity": "identity_issue",
            "easm": "external_exposure",
            "pentest": "pentest_issue",
        }.get(source_type, "misconfiguration")
    )
    return {
        "asset": asset,
        "cve_id": cve_id,
        "catalog": catalog,
        "title": title,
        "severity": normalize_severity(_pick(row, "severity", "risk_rating", "risk")),
        "cvss": cvss,
        "description": str(
            _pick(row, "description", "details", "rule_title", "evidence")
            or GENERIC_DESCRIPTION
        ),
        "finding_type": finding_type,
    }


def _apply_survivorship(finding: Finding, data: dict, source_type: str) -> list[str]:
    """Merge a duplicate observation into the surviving record; return changed fields."""
    changed = []
    if SEVERITY_RANK.get(data["severity"], 0) > SEVERITY_RANK.get(finding.severity, 0):
        finding.severity = data["severity"]
        changed.append("severity")
    if data["cvss"] is not None and data["cvss"] > float(finding.cvss_score or 0):
        finding.cvss_score = data["cvss"]
        changed.append("cvss_score")
    current = finding.description or ""
    if data["description"] != GENERIC_DESCRIPTION and (
        current == GENERIC_DESCRIPTION or len(data["description"]) > len(current)
    ):
        finding.description = data["description"]
        changed.append("description")
    if not finding.vulnerability_id and data["catalog"] is not None:
        finding.vulnerability_id = data["catalog"].id
        changed.append("vulnerability_id")
    sources = list(finding.sources or [])
    if source_type not in sources:
        finding.sources = [*sources, source_type]
        changed.append("sources")
    finding.last_seen = datetime.now(timezone.utc)
    return changed


def _process_row(
    db: Session,
    batch: ImportBatch,
    raw: RawFinding,
    source_type: str,
    ctx: _Context,
    seen: dict[str, Finding],
    to_score: dict[str, Finding],
) -> None:
    data = _normalize_row(raw.raw_payload, source_type, ctx)
    asset = data["asset"]
    fingerprint = finding_fingerprint(str(asset.id), data["cve_id"], data["title"])
    finding = seen.get(fingerprint) or db.scalar(
        select(Finding).where(Finding.fingerprint == fingerprint)
    )
    if finding is not None:
        changed = _apply_survivorship(finding, data, source_type)
        batch.duplicate_count += 1
        if finding.status == "closed":
            finding.status = "open"
            finding.closed_at = None
            finding.reopened_count = (finding.reopened_count or 0) + 1
            reopen_task(db, finding)
            record_audit(
                db,
                None,
                "finding_reopened",
                "finding",
                finding.id,
                new={"source": source_type, "batch_id": str(batch.id)},
            )
            changed.append("status")
        if {"severity", "cvss_score", "vulnerability_id", "status"} & set(changed):
            to_score[fingerprint] = finding
    else:
        now = datetime.now(timezone.utc)
        finding = Finding(
            asset_id=asset.id,
            vulnerability_id=data["catalog"].id if data["catalog"] else None,
            finding_type=data["finding_type"],
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            cvss_score=data["cvss"] if data["cvss"] is not None else 0.0,
            sources=[source_type],
            first_seen=now,
            last_seen=now,
            status="open",
            fingerprint=fingerprint,
            risk_score=0,
            risk_band="low",
            risk_breakdown=[],
        )
        db.add(finding)
        db.flush()
        to_score[fingerprint] = finding
        batch.success_count += 1
    seen[fingerprint] = finding
    raw.status = "normalized"
    raw.error_message = None
    db.add(
        FindingSource(
            finding_id=finding.id, raw_finding_id=raw.id, source_name=source_type
        )
    )


def _run(
    db: Session, batch: ImportBatch, source_type: str, raws: list[RawFinding]
) -> None:
    ctx = _Context(db)
    seen: dict[str, Finding] = {}
    to_score: dict[str, Finding] = {}
    for index, raw in enumerate(raws, 1):
        try:
            with db.begin_nested():
                _process_row(db, batch, raw, source_type, ctx, seen, to_score)
        except Exception as exc:  # each row fails independently; nothing is dropped
            batch.failed_count += 1
            raw.status = "failed"
            raw.error_message = str(exc)[:500]
            batch.errors = [
                *(batch.errors or []),
                {"row": index, "error": str(exc)[:500]},
            ]
    if to_score:
        rescore_findings(db, list(to_score.values()), influence=path_influence(db))
    batch.status = "completed" if batch.failed_count == 0 else "completed_with_errors"
    batch.finished_at = datetime.now(timezone.utc)


def ingest_records(
    db: Session, source_type: str, filename: str, records: list[dict]
) -> ImportBatch:
    if source_type not in SOURCE_TYPES:
        raise ValueError(f"Unsupported source type '{source_type}'")
    batch = ImportBatch(
        source_name=source_type,
        file_name=filename,
        total_records=len(records),
        started_at=datetime.now(timezone.utc),
        status="processing",
        errors=[],
    )
    db.add(batch)
    db.flush()
    raws = []
    for row in records:
        raw = RawFinding(
            source_name=source_type,
            source_type=source_type,
            import_batch_id=batch.id,
            raw_payload=row if isinstance(row, dict) else {"value": row},
            status="new",
        )
        db.add(raw)
        raws.append(raw)
    db.flush()
    _run(db, batch, source_type, raws)
    db.commit()
    db.refresh(batch)
    return batch


def retry_failed_rows(db: Session, batch: ImportBatch) -> ImportBatch:
    """Reprocess only the rows that failed in ``batch`` into a new, linked batch."""
    failed = db.scalars(
        select(RawFinding).where(
            RawFinding.import_batch_id == batch.id, RawFinding.status == "failed"
        )
    ).all()
    retry = ImportBatch(
        source_name=batch.source_name,
        file_name=f"retry of {batch.file_name}"[:255],
        total_records=len(failed),
        started_at=datetime.now(timezone.utc),
        status="processing",
        errors=[],
    )
    db.add(retry)
    db.flush()
    for raw in failed:
        raw.import_batch_id = retry.id
    _run(db, retry, batch.source_name, list(failed))
    db.commit()
    db.refresh(retry)
    return retry
