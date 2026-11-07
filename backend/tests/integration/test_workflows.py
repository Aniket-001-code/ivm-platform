from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import select

from app.api.v1.routes.exceptions import review_exception
from app.core.rbac import Permission, has_permission
from app.models.entities import (
    Asset,
    AssetConnection,
    AttackPath,
    BusinessUnit,
    Escalation,
    Finding,
    OwnershipRule,
    RemediationTask,
    RiskException,
    SlaPolicy,
    User,
)
from app.services.attack_path import recalculate_paths
from app.services.exceptions import expire_exceptions
from app.services.ingestion import ingest_records
from app.services.ownership import choose_owner
from app.services.sla import check_overdue_tasks


def user(email: str, role: str = "analyst") -> User:
    return User(
        email=email,
        full_name=email,
        hashed_password="not-used-in-this-test",
        role=role,
        is_active=True,
    )


def asset(name: str, unit_id, **flags) -> Asset:
    return Asset(
        name=name,
        hostname=f"{name}.bank.local",
        asset_type="server",
        environment="prod",
        business_unit_id=unit_id,
        criticality_tier=flags.pop("criticality_tier", 1),
        **flags,
    )


def test_import_normalize_score_and_create_task(db_session):
    db = db_session
    unit = BusinessUnit(name="Test Retail")
    owner = user("owner@test.local", "remediation_owner")
    db.add_all([unit, owner])
    db.flush()
    host = asset(
        "web01",
        unit.id,
        owner_user_id=owner.id,
        internet_exposed=True,
        criticality_tier=1,
        is_crown_jewel=True,
        has_sensitive_data=True,
        regulatory_tags=["PCI-DSS"],
    )
    db.add(host)
    db.commit()

    batch = ingest_records(
        db,
        "scanner",
        "sample.csv",
        [
            {
                "host": "web01.bank.local",
                "cve": "CVE-2024-9000",
                "plugin_name": "Synthetic remote issue",
                "cvss": "9.8",
                "severity": "Critical",
            }
        ],
    )
    finding = db.scalar(select(Finding))
    task = db.scalar(select(RemediationTask))
    assert batch.success_count == 1
    assert batch.failed_count == 0
    assert finding is not None and finding.risk_score > 0
    assert task is not None and task.assigned_to_user_id == owner.id


@pytest.mark.parametrize(
    "source,record",
    [
        (
            "cspm",
            {
                "resource_id": "app01",
                "rule_title": "Encryption disabled",
                "severity": "high",
            },
        ),
        (
            "pentest",
            {
                "target": "app01.bank.local",
                "finding_title": "Auth bypass",
                "risk_rating": "High",
            },
        ),
        (
            "container",
            {"image_name": "app01", "cve_id": "CVE-2024-9001", "severity": "High"},
        ),
        (
            "identity",
            {"asset": "app01.bank.local", "issue": "MFA missing", "severity": "Medium"},
        ),
    ],
)
def test_each_source_normalizes_to_a_finding(db_session, source, record):
    db = db_session
    unit = BusinessUnit(name=f"Unit {source}")
    db.add(unit)
    db.flush()
    db.add(asset("app01", unit.id))
    db.commit()
    batch = ingest_records(db, source, f"{source}.json", [record])
    assert batch.success_count == 1
    assert db.scalar(select(Finding)) is not None


def test_same_asset_cve_deduplicates_and_keeps_both_sources(db_session):
    db = db_session
    unit = BusinessUnit(name="Duplicate Unit")
    db.add(unit)
    db.flush()
    db.add(asset("db01", unit.id))
    db.commit()
    scanner = {
        "host": "db01",
        "cve": "CVE-2023-7788",
        "plugin_name": "Issue",
        "cvss": 8,
        "severity": "High",
    }
    ingest_records(db, "scanner", "one.csv", [scanner])
    container = {"image_name": "db01", "cve_id": "CVE-2023-7788", "severity": "High"}
    second = ingest_records(db, "container", "two.json", [container])
    finding = db.scalar(select(Finding))
    assert second.duplicate_count == 1
    assert db.query(Finding).count() == 1
    assert set(finding.sources) == {"scanner", "container"}


def test_asset_owner_fallback_and_ordered_ownership_rule(db_session):
    db = db_session
    unit = BusinessUnit(name="Owner Unit")
    owner_a = user("a@test.local")
    owner_b = user("b@test.local")
    db.add_all([unit, owner_a, owner_b])
    db.flush()
    host = asset("rulehost", unit.id, owner_user_id=owner_a.id)
    db.add(host)
    db.commit()
    assert choose_owner(db, host)[0] == owner_a.id
    db.add(
        OwnershipRule(
            priority_order=1,
            match_field="asset_type",
            match_value="server",
            assign_to_user_id=owner_b.id,
        )
    )
    db.commit()
    assert choose_owner(db, host)[0] == owner_b.id


def test_attack_path_connects_entry_to_crown_jewel_and_feedback(db_session):
    db = db_session
    unit = BusinessUnit(name="Path Unit")
    db.add(unit)
    db.flush()
    entry = asset("entry", unit.id, internet_exposed=True)
    middle = asset("middle", unit.id)
    crown = asset("crown", unit.id, is_crown_jewel=True)
    db.add_all([entry, middle, crown])
    db.flush()
    issue = Finding(
        asset_id=middle.id,
        finding_type="misconfiguration",
        title="Weak boundary",
        severity="high",
        fingerprint="path-finding",
        risk_score=55,
        risk_band="medium",
        status="open",
    )
    entry_issue = Finding(
        asset_id=entry.id,
        finding_type="cve",
        title="Entry issue",
        severity="high",
        cvss_score=7.0,
        fingerprint="path-entry",
        risk_score=40,
        risk_band="medium",
        status="open",
    )
    issue.cvss_score = 7.0
    target_issue = Finding(
        asset_id=crown.id,
        finding_type="cve",
        title="Target issue",
        severity="high",
        cvss_score=7.0,
        fingerprint="path-target",
        risk_score=40,
        risk_band="medium",
        status="open",
    )
    db.add_all(
        [
            issue,
            entry_issue,
            target_issue,
            AssetConnection(
                source_asset_id=entry.id,
                target_asset_id=middle.id,
                connection_type="network",
            ),
            AssetConnection(
                source_asset_id=middle.id,
                target_asset_id=crown.id,
                connection_type="data_flow",
            ),
        ]
    )
    db.commit()
    paths = recalculate_paths(db)
    refreshed = db.get(Finding, issue.id)
    assert len(paths) == 1
    assert paths[0].path_asset_ids == [str(entry.id), str(middle.id), str(crown.id)]
    path_factor = next(
        row
        for row in refreshed.risk_breakdown
        if row["factor"] == "attack_path_influence"
    )
    assert refreshed.risk_score > path_factor["base_score"]
    assert path_factor["final_score"] == refreshed.risk_score
    assert db.scalar(select(AttackPath)) is not None


def test_sla_escalation_levels_are_idempotent(db_session):
    db = db_session
    unit = BusinessUnit(name="SLA Unit")
    db.add(unit)
    db.flush()
    owner = asset("sla-host", unit.id)
    db.add(owner)
    db.flush()
    finding = Finding(
        asset_id=owner.id,
        finding_type="cve",
        title="Overdue",
        severity="high",
        fingerprint="sla",
        risk_score=72,
        risk_band="high",
        status="open",
    )
    db.add(finding)
    db.flush()
    db.add_all(
        [
            User(
                email="manager@test.local",
                full_name="Manager",
                hashed_password="x",
                role="manager",
            ),
            SlaPolicy(
                risk_band="high",
                sla_days=14,
                escalation_level_1_days=1,
                escalation_level_2_days=2,
            ),
            RemediationTask(
                finding_id=finding.id,
                asset_id=owner.id,
                status="open",
                priority="high",
                sla_category="high",
                sla_due_date=datetime.now(timezone.utc) - timedelta(days=15),
            ),
        ]
    )
    db.commit()
    assert check_overdue_tasks(db) == 3
    assert check_overdue_tasks(db) == 0
    assert db.query(Escalation).count() == 3


def test_exception_self_approval_blocked_and_approved_finding_accepted(db_session):
    db = db_session
    requester = user("requester@test.local", "analyst")
    approver = user("approver@test.local", "approver")
    unit = BusinessUnit(name="Exception Unit")
    db.add_all([requester, approver, unit])
    db.flush()
    host = asset("exception-host", unit.id)
    db.add(host)
    db.flush()
    finding = Finding(
        asset_id=host.id,
        finding_type="cve",
        title="Exception issue",
        severity="high",
        fingerprint="exception",
        status="open",
        risk_band="high",
        risk_score=66,
    )
    db.add(finding)
    db.flush()
    item = RiskException(
        finding_id=finding.id,
        requested_by=requester.id,
        justification="Time required for a controlled change.",
        compensating_controls="Network isolation and monitored access.",
        exception_type="temporary",
        requested_expiry_date=datetime.now(timezone.utc) + timedelta(days=20),
        status="pending",
    )
    db.add(item)
    db.commit()
    with pytest.raises(HTTPException) as denied:
        review_exception(item.id, "approved", "self", requester, db)
    assert denied.value.status_code == 403
    review_exception(item.id, "approved", "Controls accepted", approver, db)
    assert db.get(Finding, finding.id).status == "risk_accepted"


def test_exception_expiry_reopens_finding(db_session):
    db = db_session
    requester = user("expiry-requester@test.local")
    unit = BusinessUnit(name="Expiry Unit")
    db.add_all([requester, unit])
    db.flush()
    host = asset("expiry-host", unit.id)
    db.add(host)
    db.flush()
    finding = Finding(
        asset_id=host.id,
        finding_type="cve",
        title="Expired exception",
        severity="high",
        fingerprint="expired",
        status="risk_accepted",
        risk_band="high",
        risk_score=60,
    )
    db.add(finding)
    db.flush()
    db.add(
        RiskException(
            finding_id=finding.id,
            requested_by=requester.id,
            justification="Approved for test.",
            compensating_controls="Test control.",
            exception_type="temporary",
            requested_expiry_date=datetime.now(timezone.utc) - timedelta(days=1),
            status="approved",
        )
    )
    db.commit()
    assert expire_exceptions(db) == 1
    assert db.get(Finding, finding.id).status == "open"


def test_role_guard_denies_unauthorized_user():
    assert has_permission("auditor", Permission.AUDIT_READ)
    assert not has_permission("security_analyst", Permission.EXCEPTION_APPROVE_ALL)
