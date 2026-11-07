"""Attack-path scoring with a base-score pass followed by path feedback."""

import networkx as nx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.entities import (
    Asset,
    AssetConnection,
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


def _intel(db: Session, finding: Finding) -> dict:
    if not finding.vulnerability_id:
        return {}
    item = db.get(VulnerabilityCatalog, finding.vulnerability_id)
    if not item:
        return {}
    return {
        "epss_score": item.epss_score,
        "exploit_maturity": item.exploit_maturity,
        "in_kev_list": item.in_kev_list,
        "ransomware_used": item.ransomware_used,
        "actively_exploited": item.actively_exploited,
    }


def recalculate_paths(db: Session) -> list[AttackPath]:
    graph = nx.DiGraph()
    assets = db.scalars(select(Asset)).all()
    asset_by_id = {str(asset.id): asset for asset in assets}
    graph.add_nodes_from(asset_by_id)
    for edge in db.scalars(select(AssetConnection)).all():
        graph.add_edge(str(edge.source_asset_id), str(edge.target_asset_id))

    config = db.scalar(select(ScoringConfig).where(ScoringConfig.is_active.is_(True)))
    weights = config.weights if config else DEFAULT_MAX_POINTS
    thresholds = config.band_thresholds if config else DEFAULT_THRESHOLDS
    findings = db.scalars(select(Finding).where(Finding.status == "open")).all()
    findings_by_asset: dict[str, list[Finding]] = {}
    base_scores = {}
    for finding in findings:
        asset_key = str(finding.asset_id)
        findings_by_asset.setdefault(asset_key, []).append(finding)
        asset = asset_by_id.get(asset_key)
        if asset:
            base = score_finding(
                finding,
                asset,
                _intel(db, finding),
                weights=weights,
                band_thresholds=thresholds,
            )
            base_scores[finding.id] = base
            finding.risk_score, finding.risk_band, finding.risk_breakdown = (
                base.score,
                base.band,
                base.breakdown,
            )

    db.query(AttackPath).delete(synchronize_session=False)
    entries = [asset for asset in assets if asset.internet_exposed]
    targets = [
        asset for asset in assets if asset.is_crown_jewel or asset.has_sensitive_data
    ]
    paths: list[AttackPath] = []
    influence_by_finding: dict[object, float] = {}
    for entry in entries:
        for target in targets:
            if entry.id == target.id or not nx.has_path(
                graph, str(entry.id), str(target.id)
            ):
                continue
            try:
                route_iter = nx.all_simple_paths(
                    graph, str(entry.id), str(target.id), cutoff=5
                )
                kept = 0
                for route in route_iter:
                    per_node = []
                    plausible = True
                    for node in route:
                        eligible = [
                            f
                            for f in findings_by_asset.get(node, [])
                            if float(f.cvss_score or 0) >= 4
                        ]
                        if not eligible:
                            plausible = False
                            break
                        per_node.append(eligible)
                    if not plausible:
                        continue
                    route_findings = [
                        max(
                            rows,
                            key=lambda f: (
                                base_scores[f.id].score
                                if f.id in base_scores
                                else f.risk_score
                            ),
                        )
                        for rows in per_node
                    ]
                    if any(f.id not in base_scores for f in route_findings):
                        continue
                    hop_count = max(1, len(route) - 1)
                    path_score = (
                        sum(base_scores[f.id].score for f in route_findings) / hop_count
                    )
                    high_hops = sum(
                        base_scores[f.id].band in {"high", "critical"}
                        for f in route_findings
                    )
                    extra_high_hops = max(0, high_hops - 1)
                    path_score = min(100.0, path_score * (1 + 0.1 * extra_high_hops))
                    linked = []
                    for rows in per_node:
                        linked.extend(rows)
                    path = AttackPath(
                        name=f"{entry.name} to {target.name}",
                        entry_asset_id=entry.id,
                        target_asset_id=target.id,
                        path_asset_ids=route,
                        path_finding_ids=[str(f.id) for f in linked],
                        path_risk_score=round(path_score, 1),
                    )
                    db.add(path)
                    paths.append(path)
                    influence = min(1.0, path_score / 100.0)
                    for finding in linked:
                        influence_by_finding[finding.id] = max(
                            influence_by_finding.get(finding.id, 0.0), influence
                        )
                    kept += 1
                    if kept >= 3:
                        break
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    version = config.version if config else 1
    for finding in findings:
        asset = asset_by_id.get(str(finding.asset_id))
        base_result = base_scores.get(finding.id)
        if not asset or not base_result:
            continue
        influence = influence_by_finding.get(finding.id, 0.0)
        if influence:
            final = score_finding(
                finding,
                asset,
                _intel(db, finding),
                on_attack_path=influence,
                weights=weights,
                band_thresholds=thresholds,
            )
            finding.risk_score, finding.risk_band, finding.risk_breakdown = (
                final.score,
                final.band,
                final.breakdown,
            )
            finding.risk_breakdown = [
                (
                    {
                        **factor,
                        "base_score": base_result.score,
                        "final_score": final.score,
                        "path_influence": influence,
                    }
                    if factor["factor"] == "attack_path_influence"
                    else factor
                )
                for factor in final.breakdown
            ]
        db.add(
            RiskScoreHistory(
                finding_id=finding.id,
                score=finding.risk_score,
                band=finding.risk_band,
                config_version=version,
            )
        )
    db.commit()
    return paths
