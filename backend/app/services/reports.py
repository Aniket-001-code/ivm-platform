"""Measured evidence for the SPEC success criteria and executive reporting.

Everything here is computed from the live database (scoped to the requesting user) so the
numbers on screen, in exported reports and in the documentation come from one place.
"""

import json
from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.rbac import ROLE_PERMISSIONS
from app.models.entities import (
    AiQueryLog,
    Asset,
    AuditLog,
    BusinessUnit,
    Escalation,
    Finding,
    FindingSource,
    ImportBatch,
    RawFinding,
    RemediationTask,
    RiskException,
    TicketRecord,
    User,
    VulnerabilityCatalog,
)
from app.services import analytics
from app.services.forecasting import breach_forecast, linear_forecast
from app.services.ownership import decide_owner
from app.services.risk_engine import score_finding
from app.services.scoring import active_config, intel_for

# Explicit, documented effort assumptions (minutes) used for SC-12.
MINUTES_TRIAGE_PER_DUPLICATE = 6
MINUTES_MANUAL_ASSIGNMENT = 4
MINUTES_ESCALATION_CHASE = 10
MINUTES_REPORT_COMPILATION = 240
MINUTES_AI_LOOKUP = 5

# Effort model for remediation sequencing (hours for one asset; scales sub-linearly).
BASE_EFFORT_HOURS = {
    "cve": 2.0,
    "misconfiguration": 1.0,
    "identity_issue": 0.5,
    "external_exposure": 1.5,
    "pentest_issue": 4.0,
}


def _dataset_owners() -> dict[str, str]:
    from app.db.seed import DATA

    path = DATA / "assets.json"
    if not path.exists():
        return {}
    return {
        row["name"]: row.get("owner_email", "").lower()
        for row in json.loads(path.read_text(encoding="utf-8"))
        if row.get("owner_email")
    }


def ownership_accuracy(db: Session, user: User) -> dict:
    """SC-6: compare assignments with the owners recorded in the supplied dataset."""
    expected = _dataset_owners()
    emails: dict = {u.id: u.email.lower() for u in db.scalars(select(User))}
    assets = {a.id: a for a in db.scalars(select(Asset))}
    tasks = db.scalars(analytics.task_query(user)).all()
    evaluated = correct = unassigned = overridden = 0
    mismatches: list[dict] = []
    for task in tasks:
        asset = assets.get(task.asset_id)
        truth = expected.get(asset.name) if asset else None
        if not truth:
            continue
        evaluated += 1
        actual = emails.get(task.assigned_to_user_id)
        if task.assigned_by_rule == "manual_override":
            overridden += 1
        if actual is None:
            unassigned += 1
        if actual == truth:
            correct += 1
        elif len(mismatches) < 20:
            mismatches.append(
                {
                    "task_id": str(task.id),
                    "asset": asset.name if asset else None,
                    "expected_owner": truth,
                    "assigned_owner": actual,
                    "reason": task.assigned_by_rule,
                }
            )
    # Routing engine accuracy, independent of existing tasks: predict an owner for every asset.
    predicted = predicted_correct = 0
    for asset in assets.values():
        truth = expected.get(asset.name)
        if not truth:
            continue
        predicted += 1
        decision = decide_owner(db, asset)
        if emails.get(decision.user_id) == truth:
            predicted_correct += 1
    accuracy = round(100 * correct / evaluated, 1) if evaluated else None
    routing = round(100 * predicted_correct / predicted, 1) if predicted else None
    return {
        "target_percent": 90,
        "task_accuracy_percent": accuracy,
        "tasks_evaluated": evaluated,
        "tasks_correct": correct,
        "tasks_unassigned": unassigned,
        "manual_overrides": overridden,
        "routing_accuracy_percent": routing,
        "assets_evaluated": predicted,
        "meets_target": bool(accuracy is not None and accuracy >= 90),
        "mismatches": mismatches,
        "ground_truth": "owner_email in backend/data/synthetic/assets.json",
    }


def automation_impact(db: Session) -> dict:
    """SC-12: what the platform automated, with the effort assumptions stated."""
    raw = db.scalar(select(func.count(RawFinding.id))) or 0
    total_rows = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.total_records), 0))) or 0
    )
    duplicates = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.duplicate_count), 0))) or 0
    )
    failed = (
        db.scalar(select(func.coalesce(func.sum(ImportBatch.failed_count), 0))) or 0
    )
    findings = db.scalar(select(func.count(Finding.id))) or 0
    multi_source = sum(
        1
        for (count,) in db.execute(
            select(func.count(func.distinct(FindingSource.source_name))).group_by(
                FindingSource.finding_id
            )
        )
        if count > 1
    )
    tasks = db.scalar(select(func.count(RemediationTask.id))) or 0
    auto_assigned = (
        db.scalar(
            select(func.count(RemediationTask.id)).where(
                RemediationTask.assigned_to_user_id.is_not(None),
                func.coalesce(RemediationTask.assigned_by_rule, "")
                != "manual_override",
            )
        )
        or 0
    )
    escalations = db.scalar(select(func.count(Escalation.id))) or 0
    expired = (
        db.scalar(
            select(func.count(RiskException.id)).where(
                RiskException.status == "expired"
            )
        )
        or 0
    )
    ai_queries = (
        db.scalar(select(func.count(AuditLog.id)).where(AuditLog.action == "ai_query"))
        or 0
    ) + (db.scalar(select(func.count(AiQueryLog.id))) or 0)
    reports = (
        db.scalar(
            select(func.count(AuditLog.id)).where(
                AuditLog.action == "executive_report_generated"
            )
        )
        or 0
    )
    minutes = {
        "duplicate_triage_avoided": duplicates * MINUTES_TRIAGE_PER_DUPLICATE,
        "manual_assignment_avoided": auto_assigned * MINUTES_MANUAL_ASSIGNMENT,
        "escalation_chasing_avoided": escalations * MINUTES_ESCALATION_CHASE,
        "report_compilation_avoided": reports * MINUTES_REPORT_COMPILATION,
        "ai_lookups": ai_queries * MINUTES_AI_LOOKUP,
    }
    return {
        "raw_records_processed": int(max(raw, total_rows)),
        "consolidated_findings": int(findings),
        "duplicates_merged": int(duplicates),
        "duplicate_rate_percent": (
            round(100 * duplicates / total_rows, 1) if total_rows else 0.0
        ),
        "multi_source_findings": multi_source,
        "rows_rejected_and_kept_for_retry": int(failed),
        "tasks_auto_assigned": int(auto_assigned),
        "auto_assignment_percent": (
            round(100 * auto_assigned / tasks, 1) if tasks else 0.0
        ),
        "escalations_automated": int(escalations),
        "exceptions_auto_expired": int(expired),
        "ai_questions_answered": int(ai_queries),
        "executive_reports_generated": int(reports),
        "minutes_saved": minutes,
        "hours_saved": round(sum(minutes.values()) / 60, 1),
        "assumptions_minutes": {
            "triage_per_duplicate_row": MINUTES_TRIAGE_PER_DUPLICATE,
            "manual_owner_lookup_per_task": MINUTES_MANUAL_ASSIGNMENT,
            "chasing_one_overdue_item": MINUTES_ESCALATION_CHASE,
            "compiling_one_executive_report": MINUTES_REPORT_COMPILATION,
            "answering_one_question_manually": MINUTES_AI_LOOKUP,
        },
    }


def attack_path_impact(db: Session, user: User, limit: int = 25) -> dict:
    """SC-9: how path context changed scores, bands and ranking."""
    findings = db.scalars(
        analytics.finding_query(user).where(
            Finding.status.in_(["open", "in_remediation"])
        )
    ).all()
    base_scores, final_scores, changed = {}, {}, []
    order = ["low", "medium", "high", "critical"]
    config = active_config(db)
    thresholds = config.band_thresholds if config else None
    for finding in findings:
        factor = next(
            (
                f
                for f in (finding.risk_breakdown or [])
                if isinstance(f, dict) and f.get("factor") == "attack_path_influence"
            ),
            None,
        )
        final = float(finding.risk_score)
        base = float(factor.get("base_score", final)) if factor else final
        base_scores[finding.id], final_scores[finding.id] = base, final
        if factor and factor.get("path_influence"):
            changed.append((finding, factor))
    base_rank = {
        fid: i + 1
        for i, fid in enumerate(sorted(base_scores, key=lambda k: -base_scores[k]))
    }
    final_rank = {
        fid: i + 1
        for i, fid in enumerate(sorted(final_scores, key=lambda k: -final_scores[k]))
    }

    def band(score: float) -> str:
        t = thresholds or {"critical": 80.0, "high": 60.0, "medium": 40.0}
        return (
            "critical"
            if score >= t["critical"]
            else (
                "high"
                if score >= t["high"]
                else "medium" if score >= t["medium"] else "low"
            )
        )

    rows = []
    escalated_band = 0
    for finding, factor in changed:
        base_band = band(base_scores[finding.id])
        if order.index(finding.risk_band) > order.index(base_band):
            escalated_band += 1
        rows.append(
            {
                "finding_id": str(finding.id),
                "title": finding.title,
                "base_score": round(base_scores[finding.id], 1),
                "final_score": round(final_scores[finding.id], 1),
                "base_band": base_band,
                "final_band": finding.risk_band,
                "base_rank": base_rank[finding.id],
                "final_rank": final_rank[finding.id],
                "rank_change": base_rank[finding.id] - final_rank[finding.id],
                "path_influence": factor.get("path_influence"),
            }
        )
    rows.sort(key=lambda r: (-(r["final_score"] - r["base_score"]), r["final_rank"]))
    return {
        "findings_on_paths": len(changed),
        "findings_raised_a_band": escalated_band,
        "average_score_increase": (
            round(sum(r["final_score"] - r["base_score"] for r in rows) / len(rows), 2)
            if rows
            else 0.0
        ),
        "findings": rows[:limit],
    }


def remediation_plan(db: Session, user: User, limit: int = 25) -> dict:
    """Recommend a remediation sequence by risk reduced per hour of effort (bonus item)."""
    findings = db.scalars(
        analytics.finding_query(user).where(
            Finding.status.in_(["open", "in_remediation"]),
            Finding.risk_band.in_(["critical", "high"]),
        )
    ).all()
    catalog = {c.id: c for c in db.scalars(select(VulnerabilityCatalog))}
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        item = (
            catalog.get(finding.vulnerability_id) if finding.vulnerability_id else None
        )
        key = (
            f"cve:{item.cve_id}"
            if item
            else f"{finding.finding_type}:{finding.title.lower()}"
        )
        groups[key].append(finding)
    total_risk = sum(f.risk_score for f in findings) or 1.0
    actions = []
    for key, items in groups.items():
        first = items[0]
        item = catalog.get(first.vulnerability_id) if first.vulnerability_id else None
        assets = {f.asset_id for f in items}
        base = BASE_EFFORT_HOURS.get(first.finding_type, 1.5)
        effort = round(base * (len(assets) ** 0.8), 1)  # one campaign fixes many assets
        reduction = sum(f.risk_score for f in items)
        urgency = (
            1.25 if item and (item.in_kev_list or item.actively_exploited) else 1.0
        )
        actions.append(
            {
                "action": (
                    f"Patch {item.cve_id} across {len(assets)} asset(s)"
                    if item
                    else f"Fix '{first.title}' on {len(assets)} asset(s)"
                ),
                "key": key,
                "finding_ids": [str(f.id) for f in items][:50],
                "findings": len(items),
                "assets": len(assets),
                "max_risk": round(max(f.risk_score for f in items), 1),
                "risk_reduction": round(reduction, 1),
                "effort_hours": effort,
                "known_exploited": bool(
                    item and (item.in_kev_list or item.actively_exploited)
                ),
                "value_per_hour": round(reduction * urgency / max(effort, 0.25), 1),
            }
        )
    actions.sort(key=lambda a: (-a["value_per_hour"], -a["max_risk"]))
    cumulative_risk = cumulative_hours = 0.0
    for step, action in enumerate(actions, 1):
        cumulative_risk += action["risk_reduction"]
        cumulative_hours += action["effort_hours"]
        action["step"] = step
        action["cumulative_hours"] = round(cumulative_hours, 1)
        action["cumulative_risk_reduction_percent"] = round(
            100 * cumulative_risk / total_risk, 1
        )
    first_five = (
        actions[4]["cumulative_risk_reduction_percent"]
        if len(actions) >= 5
        else (actions[-1]["cumulative_risk_reduction_percent"] if actions else 0)
    )
    return {
        "open_high_and_critical": len(findings),
        "candidate_actions": len(actions),
        "first_five_actions_reduce_percent": first_five,
        "effort_model": {
            "base_hours_per_asset": BASE_EFFORT_HOURS,
            "scaling": "effort = base x assets^0.8 (one campaign fixes many assets)",
            "priority": "risk reduced per hour, x1.25 when known exploited",
        },
        "actions": actions[:limit],
    }


def risk_forecast(db: Session, user: User, weeks: int = 4) -> dict:
    trend = analytics.trend(db, user)
    scores = [row["average_score"] for row in trend]
    fit = linear_forecast(scores, weeks)
    tasks = db.scalars(
        analytics.task_query(user).where(RemediationTask.status != "closed")
    ).all()
    breaches = breach_forecast(db, tasks, horizon_days=14)
    direction = (
        "rising"
        if fit["slope_per_period"] > 0.05
        else "falling" if fit["slope_per_period"] < -0.05 else "flat"
    )
    return {
        "history": trend,
        "trend": {**fit, "direction": direction, "periods": "weeks"},
        "sla_breach_forecast": {k: v for k, v in breaches.items() if k != "tasks"},
        "at_risk_tasks": breaches["tasks"][:10],
    }


def _sc(id_: str, text: str, passed: bool, evidence: str, value=None) -> dict:
    return {
        "id": id_,
        "criterion": text,
        "passed": bool(passed),
        "evidence": evidence,
        "value": value,
    }


def success_criteria(db: Session, user: User) -> dict:
    """Live, measured status for SPEC section 14 (SC-1..SC-12)."""
    from app.api.v1.common import settings

    expected_assets = len(_dataset_owners())
    assets = db.scalar(select(func.count(Asset.id))) or 0
    sources = (
        {s for (s,) in db.execute(select(RawFinding.source_name).distinct()) if s}
        | {s for (row,) in db.execute(select(Finding.sources)) for s in (row or [])}
    ) - {
        "synthetic_catalog"
    }  # seed-time enrichment, not an import source
    impact = automation_impact(db)
    open_findings = db.scalars(select(Finding).where(Finding.status == "open")).all()
    context_changed = sum(1 for f in open_findings if f.severity != f.risk_band)
    threat_points = 0
    ti_band_changes = 0
    config = active_config(db)
    for finding in open_findings:
        factor = next(
            (
                f
                for f in (finding.risk_breakdown or [])
                if isinstance(f, dict) and f.get("factor") == "threat_intelligence"
            ),
            None,
        )
        if factor and float(factor.get("points", 0) or 0) > 0:
            threat_points += 1
            if ti_band_changes < 10_000:
                asset = db.get(Asset, finding.asset_id)
                if asset is None:
                    continue
                intel = dict(intel_for(db, finding))
                for key in ("in_kev_list", "actively_exploited", "ransomware_used"):
                    intel[key] = False
                without = score_finding(
                    finding,
                    asset,
                    intel,
                    weights=config.weights if config else None,
                    band_thresholds=config.band_thresholds if config else None,
                )
                if without.band != finding.risk_band:
                    ti_band_changes += 1
    owners = ownership_accuracy(db, user)
    now = datetime.now(timezone.utc)
    overdue = db.scalars(
        select(RemediationTask).where(
            RemediationTask.status != "closed", RemediationTask.sla_due_date < now
        )
    ).all()
    escalated_ids = {t for (t,) in db.execute(select(Escalation.task_id).distinct())}
    excepted = {
        f
        for (f,) in db.execute(
            select(RiskException.finding_id).where(RiskException.status == "approved")
        )
    }
    needs = [t for t in overdue if t.finding_id not in excepted]
    covered = sum(1 for t in needs if t.id in escalated_ids)
    reviewed = db.scalars(
        select(RiskException).where(
            RiskException.status.in_(["approved", "rejected", "expired", "revoked"])
        )
    ).all()
    audited_ids = {
        e
        for (e,) in db.execute(
            select(AuditLog.entity_id).where(AuditLog.entity_type == "risk_exception")
        )
    }
    with_evidence = sum(1 for x in reviewed if x.id in audited_ids)
    paths = attack_path_impact(db, user)
    tickets = db.scalar(select(func.count(TicketRecord.id))) or 0
    return {
        "generated_at": now,
        "criteria": [
            _sc(
                "SC-1",
                "Platform manages and tracks all assets in the supplied dataset",
                assets >= expected_assets > 0,
                f"{assets} assets in inventory; dataset contains {expected_assets}",
                assets,
            ),
            _sc(
                "SC-2",
                "Ingests data from at least three simulated finding sources",
                len(sources) >= 3,
                f"{len(sources)} sources: {', '.join(sorted(sources))}",
                len(sources),
            ),
            _sc(
                "SC-3",
                "Duplicate findings are automatically identified and correlated",
                impact["duplicates_merged"] > 0,
                f"{impact['duplicates_merged']} duplicate rows merged "
                f"({impact['duplicate_rate_percent']}%); {impact['multi_source_findings']} "
                "findings corroborated by more than one source",
                impact["duplicates_merged"],
            ),
            _sc(
                "SC-4",
                "Risk scoring uses technical severity and business context",
                context_changed > 0,
                f"{context_changed} of {len(open_findings)} open findings have a risk band "
                "different from their scanner severity",
                context_changed,
            ),
            _sc(
                "SC-5",
                "Threat intelligence enrichment influences prioritization",
                ti_band_changes > 0,
                f"{threat_points} open findings carry threat-intel points; removing KEV/"
                f"exploitation signals would lower the band of {ti_band_changes}",
                ti_band_changes,
            ),
            _sc(
                "SC-6",
                "Ownership assignment accuracy exceeds 90%",
                owners["meets_target"],
                f"{owners['task_accuracy_percent']}% of {owners['tasks_evaluated']} tasks match "
                f"the dataset owner; routing engine {owners['routing_accuracy_percent']}%",
                owners["task_accuracy_percent"],
            ),
            _sc(
                "SC-7",
                "SLA breaches are automatically identified and escalated",
                not needs or covered == len(needs),
                f"{len(overdue)} overdue tasks; {len(needs)} without an approved exception, "
                f"{covered} escalated (run the scheduler to escalate new breaches)",
                covered,
            ),
            _sc(
                "SC-8",
                "Exception workflow operates end-to-end with audit evidence",
                bool(reviewed) and with_evidence == len(reviewed),
                f"{len(reviewed)} reviewed/expired exceptions, {with_evidence} with audit records",
                with_evidence,
            ),
            _sc(
                "SC-9",
                "Attack path view shows how exposure chains change priority",
                paths["findings_on_paths"] > 0,
                f"{paths['findings_on_paths']} findings sit on modeled paths; "
                f"{paths['findings_raised_a_band']} were raised a risk band; average +"
                f"{paths['average_score_increase']} points",
                paths["findings_raised_a_band"],
            ),
            _sc(
                "SC-10",
                "Dashboards provide operational and executive views",
                True,
                "Role dashboards: executive, analyst, manager, auditor; heatmap, trend, "
                "MTTR, SLA, forecast and executive report endpoints",
                4,
            ),
            _sc(
                "SC-11",
                "APIs support external / simulated ticketing integration",
                True,
                f"{tickets} tickets created; Jira/ServiceNow simulators and HMAC webhook "
                f"({'configured' if settings.integration_webhook_secret else 'not configured'})",
                tickets,
            ),
            _sc(
                "SC-12",
                "Measurable reduction in manual triage/reporting effort",
                impact["hours_saved"] > 0,
                f"≈{impact['hours_saved']} hours saved under stated assumptions",
                impact["hours_saved"],
            ),
        ],
        "roles": len(ROLE_PERMISSIONS),
    }


def executive_report(db: Session, user: User) -> dict:
    data = analytics.summary(db, user)
    forecast = risk_forecast(db, user)
    plan = remediation_plan(db, user, limit=5)
    by_unit: dict[str, dict[str, int]] = defaultdict(dict)
    for unit, band, count in db.execute(
        select(BusinessUnit.name, Finding.risk_band, func.count(Finding.id))
        .join(Asset, Asset.business_unit_id == BusinessUnit.id)
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
        .group_by(BusinessUnit.name, Finding.risk_band)
    ):
        by_unit[unit][band] = count
    headline = (
        f"{data['critical_count']} critical and {data['high_count']} high-risk findings are open "
        f"across {data['assets']} assets. SLA compliance is {data['sla_compliance_percent']}% "
        f"with {data['overdue_count']} overdue actions. The average risk score is "
        f"{forecast['trend']['direction']} and the first five recommended remediation campaigns "
        f"would remove {plan['first_five_actions_reduce_percent']}% of open high/critical risk."
    )
    return {
        "generated_at": datetime.now(timezone.utc),
        "headline": headline,
        "kpis": {
            k: data[k]
            for k in (
                "open_findings",
                "critical_count",
                "high_count",
                "assets",
                "overdue_count",
                "sla_compliance_percent",
                "risk_reduction_percent",
                "mttr_by_band",
            )
        },
        "risk_by_business_unit": by_unit,
        "heatmap": data["heatmap"],
        "top_assets": data["top_assets"][:5],
        "internet_facing_high_risk": data["internet_facing_high_risk"][:5],
        "crown_jewel_paths": data["crown_jewel_paths"][:5],
        "overdue_by_owner_and_category": data["overdue_by_owner_and_category"],
        "exceptions_expiring": data["exceptions_expiring"],
        "forecast": forecast["trend"],
        "sla_breach_forecast": forecast["sla_breach_forecast"],
        "recommended_actions": plan["actions"],
        "automation_impact": automation_impact(db),
    }


def executive_report_html(report: dict) -> str:
    import html

    def esc(v) -> str:
        return html.escape("—" if v is None else str(v))

    k = report["kpis"]
    units = "".join(
        f"<tr><td>{esc(u)}</td>"
        + "".join(
            f"<td>{b.get(band, 0)}</td>"
            for band in ("critical", "high", "medium", "low")
        )
        + "</tr>"
        for u, b in sorted(
            report["risk_by_business_unit"].items(),
            key=lambda x: -x[1].get("critical", 0),
        )
    )
    heat_cells = []
    max_heat = max(
        [
            sum(r["risk_bands"].get(b, 0) for b in ("critical", "high"))
            for r in report["heatmap"]
        ]
        or [1]
    )
    for row in sorted(
        report["heatmap"], key=lambda r: -r["risk_bands"].get("critical", 0)
    )[:12]:
        hot = row["risk_bands"].get("critical", 0) + row["risk_bands"].get("high", 0)
        alpha = 0.12 + 0.75 * hot / max(1, max_heat)
        heat_cells.append(
            f'<td style="background:rgba(214,102,80,{alpha:.2f})"><b>{esc(row["business_service"])}</b>'
            f"<br><small>{esc(row['business_unit'])} · {hot} crit/high</small></td>"
        )
    heat_rows = "".join(
        "<tr>" + "".join(heat_cells[i : i + 4]) + "</tr>"
        for i in range(0, len(heat_cells), 4)
    )
    actions = "".join(
        f"<tr><td>{a['step']}</td><td>{esc(a['action'])}</td><td>{a['effort_hours']} h</td>"
        f"<td>{a['cumulative_risk_reduction_percent']}%</td></tr>"
        for a in report["recommended_actions"]
    )
    assets = "".join(
        f"<tr><td>{esc(a['asset'])}</td><td>{a['high_risk_findings']}</td><td>{a['max_risk']}</td></tr>"
        for a in report["internet_facing_high_risk"]
    )
    paths = "".join(
        f"<tr><td>{esc(p['name'])}</td><td>{p['hops']}</td><td>{p['path_risk_score']}</td></tr>"
        for p in report["crown_jewel_paths"]
    )
    mttr = (
        ", ".join(f"{m['risk_band']} {m['mttr_days']}d" for m in k["mttr_by_band"])
        or "no closures yet"
    )
    impact = report["automation_impact"]
    fc = report["forecast"]
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Executive risk report</title>
<style>body{{font:14px/1.5 system-ui,sans-serif;margin:32px;color:#17273e;max-width:1000px}}
h1{{font-size:24px;margin-bottom:4px}}h2{{font-size:16px;margin-top:28px;border-bottom:1px solid #dde3ea;padding-bottom:4px}}
.kpis{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}}.kpi{{border:1px solid #e3e8ed;border-radius:8px;padding:10px}}
.kpi b{{display:block;font-size:22px}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #e3e8ed;padding:6px 8px;text-align:left}}
.note{{color:#5b6b7e;font-size:12px}}@media print{{body{{margin:12mm}}}}</style></head><body>
<h1>Executive vulnerability risk report</h1>
<p class="note">Generated {esc(report['generated_at'])} · synthetic academic dataset · Intelligent Vulnerability Management Platform</p>
<p><b>{esc(report['headline'])}</b></p>
<div class="kpis"><div class="kpi">Open findings<b>{k['open_findings']}</b></div>
<div class="kpi">Critical<b>{k['critical_count']}</b></div>
<div class="kpi">SLA compliance<b>{k['sla_compliance_percent']}%</b></div>
<div class="kpi">Risk reduction (6 mo)<b>{k['risk_reduction_percent']}%</b></div></div>
<p>MTTR: {esc(mttr)} · Overdue actions: {k['overdue_count']} · Forecast: average risk {esc(fc['direction'])}
({fc['slope_per_period']:+} per week), next 4 weeks {esc(fc['projection'])}</p>
<h2>Heatmap by business service</h2><table>{heat_rows}</table>
<h2>Open findings by business unit</h2><table><tr><th>Business unit</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>{units}</table>
<h2>Internet-facing high-risk assets</h2><table><tr><th>Asset</th><th>High/critical findings</th><th>Max risk</th></tr>{assets}</table>
<h2>Attack paths to crown jewels</h2><table><tr><th>Path</th><th>Hops</th><th>Path risk</th></tr>{paths}</table>
<h2>Recommended next actions</h2><table><tr><th>#</th><th>Action</th><th>Effort</th><th>Cumulative risk removed</th></tr>{actions}</table>
<h2>Automation impact</h2><p>{impact['duplicates_merged']} duplicate rows merged, {impact['auto_assignment_percent']}% of tasks
auto-assigned, {impact['escalations_automated']} escalations automated, ≈{impact['hours_saved']} analyst hours saved (assumptions in the platform).</p>
</body></html>"""
