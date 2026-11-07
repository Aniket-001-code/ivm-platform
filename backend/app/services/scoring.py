"""Single entry point for (re)scoring findings.

Every caller (ingestion, scoring-config changes, asset edits, threat-intel imports, manual
recalculation) goes through ``rescore_findings`` so the same inputs are always used:
full threat context from the catalog and the attack-path influence of the latest path model.
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    AttackPath,
    Finding,
    RiskScoreHistory,
    ScoringConfig,
    VulnerabilityCatalog,
)
from app.services.risk_engine import (
    DEFAULT_MAX_POINTS,
    DEFAULT_THRESHOLDS,
    score_finding,
)


def active_config(db: Session) -> ScoringConfig | None:
    return db.scalar(select(ScoringConfig).where(ScoringConfig.is_active.is_(True)))


def intel_from_catalog(item: VulnerabilityCatalog | None) -> dict:
    if not item:
        return {}
    return {
        "epss_score": item.epss_score,
        "exploit_maturity": item.exploit_maturity,
        "in_kev_list": item.in_kev_list,
        "ransomware_used": item.ransomware_used,
        "actively_exploited": item.actively_exploited,
    }


def intel_for(db: Session, finding: Finding) -> dict:
    if not finding.vulnerability_id:
        return {}
    return intel_from_catalog(db.get(VulnerabilityCatalog, finding.vulnerability_id))


def path_influence(db: Session) -> dict[str, float]:
    """Finding id -> strongest path influence (0..1) from the stored attack-path model."""
    influence: dict[str, float] = {}
    for path in db.scalars(select(AttackPath)):
        value = min(1.0, float(path.path_risk_score or 0) / 100.0)
        for finding_id in path.path_finding_ids or []:
            influence[str(finding_id)] = max(influence.get(str(finding_id), 0.0), value)
    return influence


def rescore_findings(
    db: Session,
    findings,
    config: ScoringConfig | None = None,
    influence: dict[str, float] | None = None,
    record_history: bool = True,
    create_tasks: bool = True,
) -> int:
    """Rescore findings in place; returns how many changed band."""
    from app.services.remediation import create_task_for_finding

    config = config if config is not None else active_config(db)
    weights = config.weights if config else DEFAULT_MAX_POINTS
    thresholds = config.band_thresholds if config else DEFAULT_THRESHOLDS
    version = config.version if config else 1
    influence = influence if influence is not None else path_influence(db)
    changed = 0
    for finding in findings:
        asset = db.get(Asset, finding.asset_id)
        if asset is None:
            continue
        intel = intel_for(db, finding)
        path_value = influence.get(str(finding.id), 0.0)
        result = score_finding(
            finding,
            asset,
            intel,
            on_attack_path=path_value,
            weights=weights,
            band_thresholds=thresholds,
        )
        breakdown = result.breakdown
        if path_value:
            base = score_finding(
                finding, asset, intel, weights=weights, band_thresholds=thresholds
            )
            breakdown = [
                (
                    {
                        **factor,
                        "base_score": base.score,
                        "final_score": result.score,
                        "path_influence": path_value,
                    }
                    if factor["factor"] == "attack_path_influence"
                    else factor
                )
                for factor in result.breakdown
            ]
        if finding.risk_band != result.band:
            changed += 1
        finding.risk_score, finding.risk_band, finding.risk_breakdown = (
            result.score,
            result.band,
            breakdown,
        )
        if record_history:
            db.add(
                RiskScoreHistory(
                    finding_id=finding.id,
                    score=result.score,
                    band=result.band,
                    config_version=version,
                )
            )
        if (
            create_tasks
            and finding.status == "open"
            and result.band in {"critical", "high"}
        ):
            create_task_for_finding(db, finding, asset)
    return changed
