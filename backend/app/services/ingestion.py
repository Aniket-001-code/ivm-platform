"""Validate, normalize, correlate, and store the four simulated source formats."""

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
    ScoringConfig,
    VulnerabilityCatalog,
)
from app.services.normalization import (
    asset_key,
    finding_fingerprint,
    normalize_severity,
)
from app.services.risk_engine import score_finding
from app.services.remediation import create_task_for_finding

MAX_UPLOAD_BYTES = 10 * 1024 * 1024


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


def ingest_records(
    db: Session, source_type: str, filename: str, records: list[dict]
) -> ImportBatch:
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
    assets = db.scalars(select(Asset)).all()
    asset_lookup = {}
    for stored_asset in assets:
        for name in (stored_asset.name, stored_asset.hostname, stored_asset.ip_address):
            if name:
                asset_lookup[asset_key(name)] = stored_asset
    cve_lookup = {
        item.cve_id.lower(): item
        for item in db.scalars(select(VulnerabilityCatalog)).all()
    }
    active_config = db.scalar(
        select(ScoringConfig).where(ScoringConfig.is_active.is_(True))
    )
    weights = active_config.weights if active_config else None
    for index, row in enumerate(records, 1):
        try:
            target = _pick(
                row,
                "host",
                "hostname",
                "target",
                "resource_id",
                "image_name",
                "asset",
                "ip",
            )
            asset = asset_lookup.get(asset_key(str(target)))
            if not asset:
                raise ValueError(f"Asset not found for target '{target}'")
            cve_id = _pick(row, "cve", "cve_id", "CVE", "vulnerability")
            title = str(
                _pick(
                    row, "plugin_name", "rule_title", "finding_title", "issue", "title"
                )
                or cve_id
                or "Finding"
            )
            severity = normalize_severity(_pick(row, "severity", "risk_rating"))
            raw = RawFinding(
                source_name=source_type,
                source_type=source_type,
                import_batch_id=batch.id,
                raw_payload=row,
                status="normalized",
            )
            db.add(raw)
            db.flush()
            fingerprint = finding_fingerprint(
                str(asset.id), str(cve_id) if cve_id else None, title
            )
            finding = db.scalar(
                select(Finding).where(Finding.fingerprint == fingerprint)
            )
            if finding:
                source_names = list(finding.sources or [])
                if source_type not in source_names:
                    source_names.append(source_type)
                finding.sources = source_names
                finding.last_seen = datetime.now(timezone.utc)
                batch.duplicate_count += 1
            else:
                catalog = cve_lookup.get(str(cve_id).lower()) if cve_id else None
                finding = Finding(
                    asset_id=asset.id,
                    vulnerability_id=catalog.id if catalog else None,
                    finding_type=(
                        "cve"
                        if cve_id
                        else (
                            "identity_issue"
                            if source_type == "identity"
                            else "misconfiguration"
                        )
                    ),
                    title=title,
                    description=str(
                        _pick(row, "description", "rule_title")
                        or "Synthetic imported finding"
                    ),
                    severity=severity,
                    cvss_score=float(
                        str(
                            _pick(row, "cvss")
                            or (
                                catalog.cvss_base_score
                                if catalog and catalog.cvss_base_score is not None
                                else 0.0
                            )
                        )
                    ),
                    sources=[source_type],
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    status="open",
                    fingerprint=fingerprint,
                    risk_score=0,
                    risk_band="low",
                    risk_breakdown={},
                )
                intel = (
                    {
                        "epss_score": catalog.epss_score,
                        "in_kev_list": catalog.in_kev_list,
                        "ransomware_used": catalog.ransomware_used,
                        "actively_exploited": catalog.actively_exploited,
                    }
                    if catalog
                    else {}
                )
                result = score_finding(finding, asset, intel, weights=weights)
                finding.risk_score, finding.risk_band, finding.risk_breakdown = (
                    result.score,
                    result.band,
                    result.breakdown,
                )
                db.add(finding)
                db.flush()
                create_task_for_finding(db, finding, asset)
                batch.success_count += 1
            db.add(
                FindingSource(
                    finding_id=finding.id,
                    raw_finding_id=raw.id,
                    source_name=source_type,
                )
            )
        except Exception as exc:
            batch.failed_count += 1
            batch.errors = [*batch.errors, {"row": index, "error": str(exc)}]
    batch.status = "completed" if batch.failed_count == 0 else "completed_with_errors"
    batch.finished_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(batch)
    return batch
