"""Tests for the SPEC capabilities added on 2026-11-07 (traceable in docs/20_RTM)."""

import csv
import hashlib
import hmac
import io
import json
from datetime import datetime, timedelta, timezone

import bcrypt
import pyotp
import pytest
from sqlalchemy import select, text

from app.api.v1 import common
from app.models.entities import (
    AiQueryLog,
    Asset,
    AttackPath,
    AuditLog,
    Escalation,
    Finding,
    OwnershipRule,
    RawFinding,
    RemediationTask,
    RiskException,
    SlaPolicy,
    TicketRecord,
    VulnerabilityCatalog,
)
from app.services.audit import record_audit, verify_chain
from app.services.ingestion import ingest_records
from app.services.normalization import asset_key
from app.services.ownership import decide_owner
from app.services.scoring import rescore_findings
from app.services.sla import check_overdue_tasks

# --- UC-3/UC-4: ingestion, normalization, correlation, survivorship, recovery -------------


def test_asset_keys_keep_ip_addresses_and_parse_urls():
    assert asset_key("10.0.0.2") == "10.0.0.2"
    assert asset_key("10.0.0.2") != asset_key("10.0.0.3")
    assert asset_key("https://host004.bank.local:8443/login") == "host004"
    assert asset_key("host001.bank.local") == "host001"


def test_survivorship_keeps_strongest_evidence_and_unions_sources(world):
    db = world["db"]
    first = ingest_records(
        db,
        "scanner",
        "a.csv",
        [
            {
                "host": "a.bank.local",
                "cve": "CVE-2099-0001",
                "severity": "Medium",
                "cvss": "5.0",
            }
        ],
    )
    assert first.success_count == 1
    second = ingest_records(
        db,
        "easm",
        "b.json",
        [
            {
                "url": "https://a.bank.local/",
                "cve_id": "CVE-2099-0001",
                "risk": "Critical",
                "cvss_score": 9.1,
                "evidence": "Externally observed vulnerable version with a long explanation.",
            }
        ],
    )
    assert second.duplicate_count == 1
    finding = db.scalar(select(Finding).where(Finding.title == "CVE-2099-0001"))
    assert finding.severity == "critical"
    assert finding.cvss_score == 9.1
    assert finding.sources == ["scanner", "easm"]
    assert "Externally observed" in finding.description


def test_failed_rows_are_kept_and_recoverable_after_asset_registration(world):
    db, client = world["db"], world["client"]
    batch = ingest_records(
        db,
        "easm",
        "shadow.json",
        [{"fqdn": "shadow-01.bank.example", "issue_type": "Unknown"}],
    )
    assert batch.failed_count == 1
    raw = db.scalar(select(RawFinding).where(RawFinding.import_batch_id == batch.id))
    assert raw.status == "failed" and "Asset not found" in raw.error_message
    h = world["headers"]("security_analyst")
    rows = client.get(f"/api/v1/imports/{batch.id}/failed-rows", headers=h).json()
    assert rows[0]["payload"]["fqdn"] == "shadow-01.bank.example"
    admin = world["headers"]("platform_admin")
    created = client.post(
        "/api/v1/assets",
        headers=admin,
        json={
            "name": "shadow-01",
            "hostname": "shadow-01.bank.example",
            "asset_type": "server",
        },
    )
    assert created.status_code == 201
    retry = client.post(f"/api/v1/imports/{batch.id}/retry", headers=h)
    assert retry.status_code == 200, retry.text
    assert retry.json()["success_count"] == 1 and retry.json()["failed_count"] == 0
    assert (
        client.post(f"/api/v1/imports/{batch.id}/retry", headers=h).status_code == 409
    )


def test_closed_finding_is_reopened_when_detected_again(world):
    db = world["db"]
    ingest_records(
        db, "scanner", "x.csv", [{"host": "a.bank.local", "cve": "CVE-2099-0002"}]
    )
    finding = db.scalar(select(Finding).where(Finding.title == "CVE-2099-0002"))
    finding.status = "closed"
    db.commit()
    ingest_records(
        db, "scanner", "y.csv", [{"host": "a.bank.local", "cve": "CVE-2099-0002"}]
    )
    db.refresh(finding)
    assert finding.status == "open" and finding.reopened_count == 1
    assert db.scalar(select(AuditLog).where(AuditLog.action == "finding_reopened"))


# --- UC-5/UC-6/UC-7: threat enrichment, scoring, attack-path context ---------------------


def test_threat_feed_parses_booleans_and_rescores_affected_findings(world):
    db, client = world["db"], world["client"]
    db.add(
        VulnerabilityCatalog(
            cve_id="CVE-2099-0003",
            title="t",
            description="",
            cvss_base_score=7.5,
            epss_score=0.01,
            exploit_maturity="none",
            in_kev_list=False,
            ransomware_used=False,
            actively_exploited=False,
        )
    )
    db.commit()
    ingest_records(
        db,
        "scanner",
        "z.csv",
        [{"host": "a.bank.local", "cve": "CVE-2099-0003", "cvss": "7.5"}],
    )
    finding = db.scalar(select(Finding).where(Finding.title == "CVE-2099-0003"))
    before = finding.risk_score
    response = client.post(
        "/api/v1/threat-intel/import",
        headers=world["headers"]("security_analyst"),
        json=[
            {
                "cve_id": "CVE-2099-0003",
                "in_kev_list": "true",
                "actively_exploited": "yes",
                "ransomware_used": "false",
                "epss_score": "0.9",
                "exploit_maturity": "weaponized",
            },
            {"cve_id": "not-a-cve"},
        ],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert (
        body["updated"] == 1
        and body["findings_rescored"] == 1
        and len(body["skipped"]) == 1
    )
    item = db.scalar(
        select(VulnerabilityCatalog).where(
            VulnerabilityCatalog.cve_id == "CVE-2099-0003"
        )
    )
    assert item.in_kev_list is True and item.ransomware_used is False
    db.refresh(finding)
    assert finding.risk_score > before


def test_rescoring_preserves_attack_path_influence(world):
    db = world["db"]
    f_a = world["f_a"]
    db.add(
        AttackPath(
            name="edge to crown",
            entry_asset_id=world["asset_b"].id,
            target_asset_id=world["asset_a"].id,
            path_asset_ids=[str(world["asset_b"].id), str(world["asset_a"].id)],
            path_finding_ids=[str(f_a.id)],
            path_risk_score=90.0,
        )
    )
    db.commit()
    rescore_findings(db, [f_a])
    factor = next(
        f for f in f_a.risk_breakdown if f["factor"] == "attack_path_influence"
    )
    assert factor["points"] > 0
    assert factor["final_score"] > factor["base_score"]


def test_attack_path_impact_reports_rank_and_band_changes(world):
    test_rescoring_preserves_attack_path_influence(world)
    body = (
        world["client"]
        .get(
            "/api/v1/attack-paths/impact", headers=world["headers"]("security_analyst")
        )
        .json()
    )
    assert body["findings_on_paths"] == 1
    assert body["findings"][0]["final_score"] > body["findings"][0]["base_score"]


# --- UC-1/UC-2: asset registration and criticality ---------------------------------------


def test_asset_registration_validates_and_audits(world):
    client, h = world["client"], world["headers"]("platform_admin")
    bad = client.post(
        "/api/v1/assets", headers=h, json={"name": "x", "asset_type": "toaster"}
    )
    assert bad.status_code == 422
    unknown_field = client.post(
        "/api/v1/assets", headers=h, json={"name": "x", "evil": 1}
    )
    assert unknown_field.status_code == 422
    ok = client.post(
        "/api/v1/assets",
        headers=h,
        json={
            "name": "pay-api",
            "asset_type": "application",
            "environment": "prod",
            "regulatory_tags": ["pci-dss", "PCI-DSS"],
        },
    )
    assert ok.status_code == 201
    assert (
        client.post("/api/v1/assets", headers=h, json={"name": "PAY-API"}).status_code
        == 409
    )
    detail = client.get(f"/api/v1/assets/{ok.json()['id']}", headers=h).json()
    assert detail["regulatory_tags"] == ["PCI-DSS"]
    assert world["db"].scalar(
        select(AuditLog).where(AuditLog.action == "asset_registered")
    )


def test_criticality_change_rescores_findings_and_is_audited(world):
    db, client = world["db"], world["client"]
    asset_b, f_b = world["asset_b"], world["f_b"]
    rescore_findings(db, [f_b])
    db.commit()
    before = f_b.risk_score
    response = client.patch(
        f"/api/v1/assets/{asset_b.id}",
        headers=world["headers"]("vulnerability_manager"),
        json={"is_crown_jewel": True, "internet_exposed": True, "criticality_tier": 1},
    )
    assert response.status_code == 200, response.text
    assert response.json()["findings_rescored"] == 1
    db.refresh(f_b)
    assert f_b.risk_score > before
    log = db.scalar(select(AuditLog).where(AuditLog.action == "asset_updated"))
    assert (
        log.old_value["is_crown_jewel"] is False
        and log.new_value["is_crown_jewel"] is True
    )
    assert (
        client.patch(
            f"/api/v1/assets/{asset_b.id}",
            headers=world["headers"]("security_analyst"),
            json={"criticality_tier": 2},
        ).status_code
        == 403
    )


def test_bulk_asset_import_reports_row_errors(world):
    body = (
        world["client"]
        .post(
            "/api/v1/assets/bulk-import",
            headers=world["headers"]("platform_admin"),
            json=[
                {"name": "bulk-1"},
                {"name": "asset-a"},
                {"name": "bulk-2", "environment": "moon"},
            ],
        )
        .json()
    )
    assert body["created"] == 1 and len(body["errors"]) == 2


# --- UC-8: ownership routing and accuracy -------------------------------------------------


def test_ownership_rules_match_names_tags_and_groups(world):
    db = world["db"]
    asset_a = world["asset_a"]
    asset_a.regulatory_tags = ["PCI-DSS"]
    db.add_all(
        [
            OwnershipRule(
                priority_order=5,
                match_field="tag",
                match_value="pci-dss",
                assign_to_group="payments-sre",
            ),
            OwnershipRule(
                priority_order=10,
                match_field="business_unit",
                match_value="Unit A",
                assign_to_user_id=world["users"]["system_administrator"].id,
            ),
        ]
    )
    db.commit()
    decision = decide_owner(db, asset_a)
    assert decision.group == "payments-sre" and decision.reason == "rule:tag=pci-dss"
    assert (
        decision.user_id == world["users"]["it_asset_owner"].id
    )  # group rule keeps asset owner
    asset_a.regulatory_tags = []
    assert (
        decide_owner(db, asset_a).user_id == world["users"]["system_administrator"].id
    )


def test_unowned_asset_falls_back_to_business_unit_manager(world):
    db = world["db"]
    asset = world["asset_a"]
    asset.owner_user_id = None
    assert decide_owner(db, asset).user_id == world["users"]["business_unit_manager"].id


def test_reassignment_requires_task_manage_and_is_audited(world):
    db, client = world["db"], world["client"]
    task = db.scalar(select(RemediationTask))
    payload = {
        "user_id": str(world["users"]["it_asset_owner"].id),
        "reason": "Asset changed team",
    }
    assert (
        client.post(
            f"/api/v1/tasks/{task.id}/assign",
            headers=world["headers"]("it_asset_owner"),
            json=payload,
        ).status_code
        == 403
    )
    ok = client.post(
        f"/api/v1/tasks/{task.id}/assign",
        headers=world["headers"]("vulnerability_manager"),
        json=payload,
    )
    assert ok.status_code == 200 and ok.json()["assigned_by_rule"] == "manual_override"
    assert db.scalar(select(AuditLog).where(AuditLog.action == "ownership_reassigned"))


# --- UC-9/UC-10: remediation workflow, SLA escalation, notifications ---------------------


def test_closing_a_task_closes_its_finding(world):
    db, client = world["db"], world["client"]
    task = db.scalar(select(RemediationTask))
    h = world["headers"]("system_administrator")
    for status in ("in_progress", "pending_verification"):
        assert (
            client.patch(
                f"/api/v1/tasks/{task.id}", headers=h, json={"status": status}
            ).status_code
            == 200
        )
    db.refresh(world["f_a"])
    assert world["f_a"].status == "in_remediation"
    closed = client.patch(
        f"/api/v1/tasks/{task.id}",
        headers=h,
        json={"status": "closed", "evidence_notes": "Patched"},
    )
    assert closed.status_code == 200
    db.refresh(world["f_a"])
    assert world["f_a"].status == "closed" and world["f_a"].closed_at is not None
    detail = client.get(f"/api/v1/tasks/{task.id}", headers=h).json()
    assert [u["new_status"] for u in detail["updates"]] == [
        "in_progress",
        "pending_verification",
        "closed",
    ]


def test_escalation_thresholds_follow_sla_policy(world):
    db = world["db"]
    db.add(
        SlaPolicy(
            risk_band="high",
            sla_days=15,
            escalation_level_1_days=1,
            escalation_level_2_days=30,
        )
    )
    task = db.scalar(select(RemediationTask))
    task.sla_category = "high"
    task.sla_due_date = datetime.now(timezone.utc) - timedelta(days=2)
    for item in db.scalars(select(RiskException)):
        item.status = "revoked"
    db.commit()
    assert (
        check_overdue_tasks(db) == 1
    )  # level 1 only: 2 days overdue < 30-day level-2 threshold
    assert {e.level for e in db.scalars(select(Escalation))} == {1}
    assert db.scalar(select(AuditLog).where(AuditLog.action == "sla_escalated"))


def test_escalation_acknowledgement_and_personal_inbox(world):
    db, client = world["db"], world["client"]
    task = db.scalar(select(RemediationTask))
    manager = world["users"]["business_unit_manager"]
    escalation = Escalation(
        task_id=task.id, level=1, escalated_to_user_id=manager.id, reason="late"
    )
    db.add(escalation)
    db.commit()
    inbox = client.get(
        "/api/v1/me/notifications", headers=world["headers"]("business_unit_manager")
    ).json()
    assert any(i["kind"] == "escalation" for i in inbox["items"])
    owner_inbox = client.get(
        "/api/v1/me/notifications", headers=world["headers"]("system_administrator")
    ).json()
    assert any(i["kind"] == "overdue_task" for i in owner_inbox["items"])
    assert (
        client.post(
            f"/api/v1/escalations/{escalation.id}/acknowledge",
            headers=world["headers"]("auditor"),
        ).status_code
        == 403
    )
    ack = client.post(
        f"/api/v1/escalations/{escalation.id}/acknowledge",
        headers=world["headers"]("business_unit_manager"),
    )
    assert ack.status_code == 200
    db.refresh(escalation)
    assert escalation.acknowledged and escalation.acknowledged_by == manager.id


def test_sla_report_and_breach_forecast(world):
    client, h = world["client"], world["headers"]("vulnerability_manager")
    report = client.get("/api/v1/tasks/export", headers=h)
    rows = list(csv.reader(io.StringIO(report.text)))
    assert rows[0][:3] == ["task_id", "finding_id", "asset_id"] and len(rows) == 2
    forecast = client.get("/api/v1/tasks/breach-forecast", headers=h).json()
    assert forecast["already_breached"] == 1


# --- SC-11: ticketing integration --------------------------------------------------------


def test_ticket_lifecycle_and_signed_webhook(world, monkeypatch):
    db, client = world["db"], world["client"]
    task = db.scalar(select(RemediationTask))
    task.status = "in_progress"
    db.commit()
    h = world["headers"]("system_administrator")
    created = client.post(
        "/api/v1/ticketing/jira-sim/issues", headers=h, json={"task_id": str(task.id)}
    )
    assert created.status_code == 201, created.text
    key = created.json()["ticket_key"]
    assert (
        client.post(
            "/api/v1/ticketing/jira-sim/issues",
            headers=h,
            json={"task_id": str(task.id)},
        ).status_code
        == 409
    )
    assert (
        client.get(
            f"/api/v1/ticketing/servicenow-sim/issues/{key}", headers=h
        ).status_code
        == 404
    )
    monkeypatch.setattr(
        common.settings, "integration_webhook_secret", "s3cret-for-tests"
    )
    body = json.dumps({"ticket_key": key, "status": "resolved"}).encode()
    bad = client.post(
        "/api/v1/integrations/ticketing/webhook",
        content=body,
        headers={"X-IVM-Signature": "sha256=00"},
    )
    assert bad.status_code == 401
    signature = (
        "sha256=" + hmac.new(b"s3cret-for-tests", body, hashlib.sha256).hexdigest()
    )
    good = client.post(
        "/api/v1/integrations/ticketing/webhook",
        content=body,
        headers={"X-IVM-Signature": signature},
    )
    assert (
        good.status_code == 200 and good.json()["task_status"] == "pending_verification"
    )
    assert db.scalar(select(TicketRecord)).status == "resolved"


# --- UC-11: exception evidence ------------------------------------------------------------


def test_exception_review_pack_json_and_html(world):
    db, client = world["db"], world["client"]
    exception = db.scalar(select(RiskException))
    h = world["headers"]("auditor")
    pack = client.get(
        f"/api/v1/exceptions/{exception.id}/review-pack", headers=h
    ).json()
    assert pack["exception"]["id"] == str(exception.id)
    assert {c["check"] for c in pack["review_checks"]} >= {
        "Compensating controls documented"
    }
    html_pack = client.get(
        f"/api/v1/exceptions/{exception.id}/review-pack?format=html", headers=h
    )
    assert html_pack.headers["content-type"].startswith("text/html")
    assert "<script" not in html_pack.text.lower()


# --- Security: MFA, passwords, audit chain, secrets --------------------------------------


def _password_user(world, role="security_architect", password="StrongDemo!123"):
    user = world["users"][role]
    user.hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    world["db"].commit()
    return user, password


def test_mfa_enrollment_login_and_rotation(world):
    client = world["client"]
    user, password = _password_user(world)
    h = world["headers"]("security_architect")
    setup = client.post("/api/v1/auth/mfa/setup", headers=h).json()
    totp = pyotp.TOTP(setup["secret"])
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", headers=h, json={"code": "000000"}
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/auth/mfa/verify", headers=h, json={"code": totp.now()}
        ).status_code
        == 200
    )
    need = client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    assert (
        need.status_code == 401
        and need.json()["error"]["message"] == "MFA code required"
    )
    wrong = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": password, "totp_code": "123456"},
    )
    assert wrong.status_code == 401
    ok = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": password, "totp_code": totp.now()},
    )
    assert ok.status_code == 200 and ok.json()["user"]["mfa_enabled"] is True
    assert (
        client.post("/api/v1/auth/mfa/setup", headers=h).status_code == 403
    )  # rotation needs a code
    common._rate_events.clear()


def test_mfa_applies_to_every_role_that_enables_it(world):
    client = world["client"]
    user, password = _password_user(world, role="auditor")
    h = world["headers"]("auditor")
    secret = client.post("/api/v1/auth/mfa/setup", headers=h).json()["secret"]
    client.post(
        "/api/v1/auth/mfa/verify", headers=h, json={"code": pyotp.TOTP(secret).now()}
    )
    response = client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": password}
    )
    assert response.status_code == 401
    common._rate_events.clear()


def test_password_change_enforces_policy_and_revokes_sessions(world):
    client = world["client"]
    user, password = _password_user(world, role="auditor")
    h = world["headers"]("auditor")
    assert (
        client.post(
            "/api/v1/auth/password",
            headers=h,
            json={"current_password": "nope", "new_password": "NewStrongPass!1"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/auth/password",
            headers=h,
            json={"current_password": password, "new_password": "alllowercase123!"},
        ).status_code
        == 422
    )
    ok = client.post(
        "/api/v1/auth/password",
        headers=h,
        json={"current_password": password, "new_password": "NewStrongPass!1"},
    )
    assert ok.status_code == 200
    world["db"].refresh(user)
    assert user.refresh_token_hash is None


def test_audit_chain_detects_tampering_and_triggers_block_edits(db_session):
    for i in range(3):
        record_audit(db_session, None, f"event_{i}", "test", new={"i": i})
    db_session.commit()
    assert verify_chain(db_session) == {
        **verify_chain(db_session),
        "valid": True,
        "checked": 3,
    }
    # Simulate an attacker editing a row directly in the database (no triggers in this test DB).
    db_session.execute(
        text("UPDATE audit_logs SET action = 'tampered' WHERE action = 'event_1'")
    )
    db_session.commit()
    db_session.expire_all()
    report = verify_chain(db_session)
    assert report["valid"] is False and report["sequence"] == 2
    # With the migration's triggers installed, edits and deletes are rejected outright.
    import importlib.util
    from pathlib import Path

    path = (
        Path(__file__).parents[2] / "alembic/versions/0002_audit_chain_and_workflow.py"
    )
    spec = importlib.util.spec_from_file_location("migration_0002", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    for statement in migration.SQLITE_TRIGGERS:
        db_session.execute(text(statement))
    with pytest.raises(Exception, match="append-only"):
        db_session.execute(text("DELETE FROM audit_logs"))
    db_session.rollback()


def test_audit_verify_endpoint(world):
    response = world["client"].get(
        "/api/v1/audit/verify", headers=world["headers"]("auditor")
    )
    assert response.status_code == 200 and response.json()["valid"] is True


def test_weak_secret_is_rejected_outside_development():
    from app.core.config import Settings

    with pytest.raises(ValueError, match="SECRET_KEY"):
        Settings(app_env="production", secret_key="short")
    assert Settings(app_env="production", secret_key="x" * 40).app_env == "production"


# --- UC-12/UC-13/UC-14, SC-6, SC-12: reporting, AI, measured criteria --------------------


def test_reports_endpoints_respond(world):
    client, h = world["client"], world["headers"]("platform_admin")
    for path in (
        "/api/v1/reports/success-criteria",
        "/api/v1/reports/automation-impact",
        "/api/v1/reports/ownership-accuracy",
        "/api/v1/reports/remediation-plan",
        "/api/v1/analytics/forecast",
        "/api/v1/reports/executive",
    ):
        response = client.get(path, headers=h)
        assert response.status_code == 200, (path, response.text[:200])
    criteria = client.get("/api/v1/reports/success-criteria", headers=h).json()[
        "criteria"
    ]
    assert [c["id"] for c in criteria] == [f"SC-{i}" for i in range(1, 13)]
    html_report = client.get("/api/v1/reports/executive?format=html", headers=h)
    assert "Executive vulnerability risk report" in html_report.text
    assert world["db"].scalar(
        select(AuditLog).where(AuditLog.action == "executive_report_generated")
    )


def test_assistant_understands_entities_and_follow_ups(world):
    db, client = world["db"], world["client"]
    h = world["headers"]("security_analyst")
    first = client.post(
        "/api/v1/ai/ask", headers=h, json={"question": "show high findings in Unit B"}
    ).json()
    assert (
        first["entities"]["business_unit"] == "Unit B"
        and first["entities"]["band"] == "high"
    )
    follow = client.post(
        "/api/v1/ai/ask",
        headers=h,
        json={
            "question": "what about Unit A?",
            "history": ["show high findings in Unit B"],
        },
    ).json()
    assert (
        follow["entities"]["business_unit"] == "Unit A"
        and follow["entities"]["carried_from_previous"]
    )
    owner = client.post(
        "/api/v1/ai/ask", headers=h, json={"question": "who owns asset-a"}
    ).json()
    assert owner["intent"] == "owner_lookup" and "It Asset Owner" in owner["answer"]
    plan = client.post(
        "/api/v1/ai/ask", headers=h, json={"question": "what should we fix first?"}
    ).json()
    assert plan["intent"] == "remediation_plan"
    assert db.scalar(
        select(AiQueryLog).where(AiQueryLog.detected_intent == "owner_lookup")
    )


def test_ownership_accuracy_uses_dataset_ground_truth(world):
    body = (
        world["client"]
        .get(
            "/api/v1/reports/ownership-accuracy",
            headers=world["headers"]("platform_admin"),
        )
        .json()
    )
    assert body["target_percent"] == 90
    assert body["ground_truth"].startswith("owner_email")


def test_asset_rows_unaffected(world):
    # Sanity: helper tests above must not leak data between tests.
    assert world["db"].scalar(select(Asset).where(Asset.name == "asset-a"))


def test_attack_graph_exports_for_graph_databases(world):
    client, h = world["client"], world["headers"]("security_analyst")
    cypher = client.get("/api/v1/attack-paths/export?format=cypher", headers=h)
    assert cypher.status_code == 200 and 'MERGE (:Asset {id: "' in cypher.text
    graphml = client.get("/api/v1/attack-paths/export?format=graphml", headers=h)
    assert (
        graphml.status_code == 200
        and "<graphml" in graphml.text
        and "asset-a" in graphml.text
    )
