"""Load the repeatable fictional dataset into an empty database."""

import csv
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4
from pathlib import Path

import bcrypt
from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.core.timeutil import as_utc
from app.services.audit import record_audit
from app.models.entities import (
    TaskUpdate,
    Asset,
    AssetConnection,
    BusinessService,
    BusinessUnit,
    Escalation,
    Finding,
    RemediationTask,
    RiskException,
    RiskScoreHistory,
    ScoringConfig,
    SlaPolicy,
    User,
    VulnerabilityCatalog,
)
from app.services.ingestion import ingest_records
from app.services.normalization import finding_fingerprint
from app.services.remediation import create_task_for_finding
from app.services.risk_engine import (
    DEFAULT_MAX_POINTS,
    DEFAULT_THRESHOLDS,
    score_finding,
)

DATA = Path(__file__).resolve().parents[2] / "data" / "synthetic"
DEMO_PASSWORD = (
    "DemoPass!234"  # nosec B105 -- documented synthetic demo-only credential
)


def seed_demo(db: Session) -> None:
    if db.scalar(select(Asset.id).limit(1)):
        return

    def read_json(name: str):
        return json.loads((DATA / name).read_text(encoding="utf-8"))

    units = {name: BusinessUnit(name=name) for name in read_json("business_units.json")}
    db.add_all(units.values())
    db.flush()
    services = {}
    for row in read_json("business_services.json"):
        service = BusinessService(
            name=row["name"],
            business_unit_id=units[row["business_unit"]].id,
            description=row["description"],
        )
        db.add(service)
        services[row["name"]] = service
    roles = [
        "platform_admin",
        "security_analyst",
        "security_analyst",
        "vulnerability_manager",
        "auditor",
        "security_architect",
        "system_administrator",
        "it_asset_owner",
        "it_asset_owner",
        "it_asset_owner",
        "executive_ciso",
        "business_unit_manager",
    ]
    users = {}
    password_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()
    for index, role in enumerate(roles, 1):
        email = f"user{index}@demo.bank"
        user = User(
            email=email,
            full_name=f"Demo {role.replace('_', ' ').title()} {index}",
            hashed_password=password_hash,
            role=role,
            business_unit_id=units[list(units)[(index - 1) % len(units)]].id,
            is_active=True,
            mfa_enabled=False,
        )
        db.add(user)
        users[email] = user
    db.flush()
    assets = {}
    for row in read_json("assets.json"):
        asset = Asset(
            name=row["name"],
            hostname=row["hostname"],
            ip_address=row["ip_address"],
            asset_type=row["asset_type"],
            environment=row["environment"],
            business_unit_id=units[row["business_unit"]].id,
            business_service_id=services[row["business_service"]].id,
            owner_user_id=users[row["owner_email"]].id,
            criticality_tier=row["criticality_tier"],
            is_customer_facing=row["is_customer_facing"],
            is_crown_jewel=row["is_crown_jewel"],
            has_sensitive_data=row["has_sensitive_data"],
            regulatory_tags=row["regulatory_tags"],
            internet_exposed=row["internet_exposed"],
            os_or_platform=row["os_or_platform"],
            status=row["status"],
        )
        db.add(asset)
        assets[row["id"]] = asset
    db.flush()
    for row in read_json("vulnerability_catalog.json"):
        row = dict(row)
        row["published_date"] = __import__("datetime").date.fromisoformat(
            row["published_date"]
        )
        db.add(VulnerabilityCatalog(**row))
    for row in read_json("asset_connections.json"):
        db.add(
            AssetConnection(
                source_asset_id=assets[row["source"]].id,
                target_asset_id=assets[row["target"]].id,
                connection_type=row["connection_type"],
                port_or_protocol=row["port_or_protocol"],
            )
        )
    for band, days, l1, l2 in [
        ("critical", 7, 0, 7),
        ("high", 15, 0, 7),
        ("medium", 30, 15, 30),
        ("low", 90, 45, 90),
    ]:
        db.add(
            SlaPolicy(
                risk_band=band,
                sla_days=days,
                escalation_level_1_days=l1,
                escalation_level_2_days=l2,
            )
        )
    db.add(
        ScoringConfig(
            version=1,
            weights=DEFAULT_MAX_POINTS,
            band_thresholds=DEFAULT_THRESHOLDS,
            is_active=True,
        )
    )
    db.commit()
    for source, filename in [
        ("scanner", "scanner_export.csv"),
        ("cspm", "cspm_findings.json"),
        ("pentest", "pentest_report.json"),
        ("container", "container_k8s_findings.json"),
        ("identity", "identity_findings.csv"),
    ]:
        path = DATA / filename
        if filename.endswith(".csv"):
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream))
        else:
            rows = json.loads(path.read_text(encoding="utf-8"))
        ingest_records(db, source, filename, rows)
    findings = list(db.scalars(select(Finding)).all())
    catalog = list(
        db.scalars(
            select(VulnerabilityCatalog).order_by(VulnerabilityCatalog.cve_id)
        ).all()
    )
    # Keep a deterministic set of high-confidence synthetic threat examples so the
    # demo visibly exercises the Critical band and threat-intel factor.
    for vulnerability in catalog[:8]:
        vulnerability.cvss_base_score = max(
            float(vulnerability.cvss_base_score or 0), 9.8
        )
        vulnerability.epss_score = max(float(vulnerability.epss_score or 0), 0.95)
        vulnerability.exploit_maturity = "weaponized"
        vulnerability.in_kev_list = True
        vulnerability.actively_exploited = True
        vulnerability.ransomware_used = True
    db.flush()
    high_cvss = [
        c
        for c in catalog
        if (c.cvss_base_score or 0) >= 9 and c.exploit_maturity == "weaponized"
    ]
    high_catalog = [
        c
        for c in catalog
        if (c.cvss_base_score or 0) >= 8.5 and c.exploit_maturity == "weaponized"
    ]
    if not high_cvss:
        high_cvss = [c for c in catalog if (c.cvss_base_score or 0) >= 9]
    if not high_catalog:
        high_catalog = [c for c in catalog if (c.cvss_base_score or 0) >= 8]
    used_fingerprints = {f.fingerprint for f in findings}
    now = datetime.now(timezone.utc)
    ordered_assets = sorted(assets.values(), key=lambda item: item.name)
    critical_assets = ordered_assets[:10]
    high_assets = ordered_assets[10:40]
    for index, asset in enumerate(critical_assets):
        asset.criticality_tier = 1
        asset.is_crown_jewel = True
        asset.has_sensitive_data = True
        asset.is_customer_facing = True
        asset.internet_exposed = True
        asset.regulatory_tags = ["PCI-DSS"]
    for asset in high_assets:
        asset.criticality_tier = 2
        asset.is_crown_jewel = False
        asset.has_sensitive_data = True
        asset.is_customer_facing = True
        asset.internet_exposed = False
        asset.regulatory_tags = ["SOX"]

    # Expand the synthetic catalog-to-asset matrix to a meaningful deduplicated queue.
    for asset_index, asset in enumerate(ordered_assets):
        if asset in critical_assets:
            candidates = high_cvss
        elif asset in high_assets:
            candidates = high_catalog
        else:
            offset = (asset_index * 7) % len(catalog)
            candidates = catalog[offset:] + catalog[:offset]
        created_for_asset = 0
        for catalog_index, vulnerability in enumerate(candidates):
            title = vulnerability.title or vulnerability.cve_id
            fingerprint = finding_fingerprint(
                str(asset.id), vulnerability.cve_id, title
            )
            if fingerprint in used_fingerprints:
                continue
            finding = Finding(
                asset_id=asset.id,
                vulnerability_id=vulnerability.id,
                finding_type="cve",
                title=title,
                description=vulnerability.description
                or "Synthetic catalog-linked exposure.",
                severity=(
                    "critical"
                    if (vulnerability.cvss_base_score or 0) >= 9
                    else (
                        "high"
                        if (vulnerability.cvss_base_score or 0) >= 7
                        else "medium"
                    )
                ),
                cvss_score=vulnerability.cvss_base_score,
                sources=["synthetic_catalog"],
                first_seen=now - timedelta(days=90 + (asset_index % 180)),
                last_seen=now,
                status="open",
                fingerprint=fingerprint,
                risk_score=0,
                risk_band="low",
                risk_breakdown=[],
            )
            result = score_finding(
                finding,
                asset,
                {
                    "epss_score": vulnerability.epss_score,
                    "exploit_maturity": vulnerability.exploit_maturity,
                    "in_kev_list": vulnerability.in_kev_list,
                    "actively_exploited": vulnerability.actively_exploited,
                    "ransomware_used": vulnerability.ransomware_used,
                },
                weights=DEFAULT_MAX_POINTS,
                band_thresholds=DEFAULT_THRESHOLDS,
            )
            finding.risk_score, finding.risk_band, finding.risk_breakdown = (
                result.score,
                result.band,
                result.breakdown,
            )
            db.add(finding)
            db.flush()
            used_fingerprints.add(fingerprint)
            findings.append(finding)
            create_task_for_finding(db, finding, asset)
            created_for_asset += 1
            if created_for_asset >= 6:
                break

    db.flush()
    tasks = db.scalars(
        select(RemediationTask)
        .where(RemediationTask.status != "closed")
        .order_by(RemediationTask.created_at)
    ).all()
    # Seed staged overdue examples so all three escalation levels are visible immediately.
    overdue_tasks = tasks[:3]
    managers = [u for u in users.values() if u.role == "business_unit_manager"]
    ciso = users["user11@demo.bank"]
    for index, task in enumerate(overdue_tasks):
        task.sla_due_date = now - timedelta(
            days=2 if index == 0 else 9 if index == 1 else 16
        )
        task.finding_id = task.finding_id
        for level, recipient in (
            (1, managers[0] if managers else None),
            (2, managers[0] if managers else None),
            (3, ciso),
        ):
            db.add(
                Escalation(
                    task_id=task.id,
                    level=level,
                    escalated_to_user_id=recipient.id if recipient else None,
                    reason=f"Synthetic overdue demonstration · level {level}",
                )
            )

    # Six months of remediation history: every fifth remaining task was fixed in the past,
    # mostly within SLA and some late, so MTTR, SLA compliance, risk reduction and the
    # breach-forecast model have realistic history to learn from.
    sla_by_band = {"critical": 7, "high": 15}
    for index, task in enumerate(tasks[3::5]):
        created = now - timedelta(days=30 + (index * 7) % 150)
        sla = sla_by_band.get(task.priority, 15)
        late = index % 6 == 0
        duration = sla + 2 + index % 5 if late else max(1, (index * 3) % sla)
        task.created_at = created
        task.sla_due_date = created + timedelta(days=sla)
        task.closed_at = created + timedelta(days=duration, hours=index % 9)
        task.status = "closed"
        task.evidence_notes = "Patched and verified by rescan (synthetic history)."
        closed_finding = db.get(Finding, task.finding_id)
        if closed_finding:
            closed_finding.status = "closed"
            closed_finding.closed_at = task.closed_at
        if task.assigned_to_user_id:
            for old, new in (
                ("open", "in_progress"),
                ("in_progress", "pending_verification"),
                ("pending_verification", "closed"),
            ):
                db.add(
                    TaskUpdate(
                        task_id=task.id,
                        user_id=task.assigned_to_user_id,
                        old_status=old,
                        new_status=new,
                        comment="Synthetic remediation history",
                        created_at=task.closed_at,
                    )
                )
    db.flush()

    # Six pending plus four approved examples, including near-term expiries.
    eligible = [f for f in findings if f.status == "open"][:10]
    analysts = [users["user2@demo.bank"], users["user3@demo.bank"]]
    architect = users["user6@demo.bank"]
    for index, finding in enumerate(eligible):
        requester = (
            analysts[index % len(analysts)]
            if index < 6
            else users[f"user{8 + index % 3}@demo.bank"]
        )
        expiry_days = (3, 8, 12, 30)[index - 6] if index >= 6 else 45 + index
        approved = index >= 6
        item = RiskException(
            finding_id=finding.id,
            requested_by=requester.id,
            justification=f"Synthetic governance example {index + 1}: planned remediation window.",
            compensating_controls="Segmentation, monitoring, and documented change approval.",
            exception_type="temporary",
            requested_expiry_date=now + timedelta(days=expiry_days),
            status="approved" if approved else "pending",
            reviewed_by=architect.id if approved else None,
            review_comment=(
                "Approved by Security Architect for synthetic workflow demonstration."
                if approved
                else None
            ),
            approved_at=now if approved else None,
        )
        db.add(item)
        db.flush()
        record_audit(
            db,
            item.requested_by,
            "exception_requested",
            "risk_exception",
            item.id,
            new={"finding_id": str(finding.id), "seeded_demo": True},
        )
        if approved:
            finding.status = "risk_accepted"
            record_audit(
                db,
                architect.id,
                "exception_approved",
                "risk_exception",
                item.id,
                new={"finding_id": str(finding.id), "seeded_demo": True},
            )

    db.flush()
    db.commit()
    from app.services.attack_path import recalculate_paths

    recalculate_paths(db)
    # Written after path modeling so history ends at the path-aware score.
    # 26 weeks of score history for every finding (bulk insert): older weeks carried more
    # risk (findings since remediated, threat signals not yet mitigated), so the portfolio trend
    # and the risk-reduction KPI reflect a consistent population week to week.
    history_rows = []
    for finding_index, finding in enumerate(db.scalars(select(Finding)).all()):
        drift = 2.0 + finding_index % 5
        closed = as_utc(finding.closed_at) if finding.closed_at else None
        for week in range(26, -1, -1):
            calculated = now - timedelta(weeks=week)
            if closed and calculated > closed:
                break
            score = min(100.0, finding.risk_score + drift * week / 26)
            history_rows.append(
                {
                    "id": uuid4(),
                    "finding_id": finding.id,
                    "score": round(score, 1),
                    "band": finding.risk_band,
                    "config_version": 1,
                    "calculated_at": calculated,
                }
            )
    db.execute(insert(RiskScoreHistory), history_rows)
    db.commit()
