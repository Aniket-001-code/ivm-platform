import json
import xml.etree.ElementTree as ET  # nosec B405 - builds XML, never parses untrusted input
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import false, select
from sqlalchemy.orm import Session

from app.api.v1.common import (
    _asset_scope,
    _check_asset_scope,
    _global_scope,
)
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.core.rbac import (
    Permission,
    require_permission,
)
from app.models.entities import (
    Asset,
    AssetConnection,
    AttackPath,
    Finding,
    User,
)
from app.services import analytics
from app.services.attack_path import recalculate_paths

from app.services import reports

router = APIRouter(prefix="/api/v1")


@router.get("/attack-paths")
def attack_paths(db: Session = Depends(get_db), user: User = Depends(current_user)):
    return _attack_path_list(db, user)


@analytics.cached
def _attack_path_list(db: Session, user: User):
    query = select(AttackPath)
    if not _global_scope(user):
        scope = analytics.asset_scope(user)
        query = (
            query.join(Asset, AttackPath.entry_asset_id == Asset.id).where(scope)
            if scope is not None
            else query.where(false())
        )
    return [
        {
            "id": str(p.id),
            "name": p.name,
            "entry_asset_id": str(p.entry_asset_id),
            "target_asset_id": str(p.target_asset_id),
            "path_asset_ids": p.path_asset_ids,
            "path_finding_ids": p.path_finding_ids,
            "path_risk_score": p.path_risk_score,
            **_path_score_values(db, p),
        }
        for p in db.scalars(
            query.order_by(AttackPath.path_risk_score.desc()).limit(200)
        )
    ]


def _path_score_values(db: Session, path: AttackPath):
    scores = []
    influences = []
    for raw_id in path.path_finding_ids or []:
        finding = db.get(Finding, UUID(raw_id))
        if not finding:
            continue
        factor = next(
            (
                x
                for x in finding.risk_breakdown or []
                if isinstance(x, dict) and x.get("factor") == "attack_path_influence"
            ),
            {},
        )
        scores.append(
            (
                float(factor.get("base_score", finding.risk_score)),
                float(factor.get("final_score", finding.risk_score)),
            )
        )
        influences.append(float(factor.get("path_influence", 0)))
    base = (
        round(sum(x for x, _ in scores) / len(scores), 1)
        if scores
        else path.path_risk_score
    )
    final = (
        round(sum(y for _, y in scores) / len(scores), 1)
        if scores
        else path.path_risk_score
    )
    return {
        "base_score": base,
        "final_score": final,
        "path_influence": round(max(influences, default=0), 2),
    }


@router.get("/attack-paths/graph")
def attack_graph(
    asset_id: UUID | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    assets = db.scalars(_asset_scope(select(Asset), user)).all()
    allowed_ids = {a.id for a in assets}
    edges = (
        db.scalars(
            select(AssetConnection).where(
                AssetConnection.source_asset_id.in_(allowed_ids),
                AssetConnection.target_asset_id.in_(allowed_ids),
            )
        ).all()
        if allowed_ids
        else []
    )
    selected = next(
        (
            p
            for p in db.scalars(select(AttackPath))
            if asset_id and asset_id in [UUID(x) for x in p.path_asset_ids]
        ),
        None,
    )
    path_nodes = set(selected.path_asset_ids) if selected else set()
    nodes = []
    for asset in assets:
        open_findings = db.scalars(
            select(Finding).where(
                Finding.asset_id == asset.id, Finding.status == "open"
            )
        ).all()
        top = max(open_findings, key=lambda row: row.risk_score, default=None)
        base_scores = []
        influences = []
        for finding in open_findings:
            factor = next(
                (
                    x
                    for x in finding.risk_breakdown or []
                    if isinstance(x, dict)
                    and x.get("factor") == "attack_path_influence"
                ),
                {},
            )
            base_scores.append(float(factor.get("base_score", finding.risk_score)))
            influences.append(float(factor.get("path_influence", 0)))
        nodes.append(
            {
                "id": str(asset.id),
                "name": asset.name,
                "risk_band": (
                    top.risk_band
                    if top
                    else (
                        "critical"
                        if asset.is_crown_jewel
                        else "high" if asset.internet_exposed else "low"
                    )
                ),
                "base_score": round(
                    max(base_scores, default=top.risk_score if top else 0), 1
                ),
                "final_score": round(
                    max([x.risk_score for x in open_findings], default=0), 1
                ),
                "path_influence": round(max(influences, default=0), 2),
                "is_crown_jewel": asset.is_crown_jewel,
                "selected": str(asset.id) in path_nodes,
                "findings": [
                    {
                        "id": str(x.id),
                        "title": x.title,
                        "risk_score": x.risk_score,
                        "risk_band": x.risk_band,
                    }
                    for x in sorted(
                        open_findings, key=lambda x: x.risk_score, reverse=True
                    )[:10]
                ],
            }
        )
    return {
        "nodes": nodes,
        "links": [
            {
                "source": str(e.source_asset_id),
                "target": str(e.target_asset_id),
                "type": e.connection_type,
            }
            for e in edges
        ],
    }


@router.get("/attack-paths/impact")
def attack_path_impact(
    limit: int = Query(default=25, ge=1, le=200),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """How path context changed finding scores, bands and ranking (SC-9)."""
    return reports.attack_path_impact(db, user, limit)


@router.get("/attack-paths/export")
def attack_graph_export(
    format: Literal["cypher", "graphml"] = "cypher",
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Export the scoped asset graph and modeled paths for a graph database (Neo4j) or GraphML tools."""
    assets = db.scalars(_asset_scope(select(Asset), user)).all()
    ids = {a.id for a in assets}
    edges = [
        e
        for e in db.scalars(select(AssetConnection))
        if e.source_asset_id in ids and e.target_asset_id in ids
    ]
    paths = [p for p in db.scalars(select(AttackPath)) if p.entry_asset_id in ids]

    def q(value) -> str:
        return json.dumps(
            str(value)
        )  # JSON string escaping is valid Cypher string escaping

    if format == "graphml":
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        for key, kind in (
            ("name", "string"),
            ("crown_jewel", "boolean"),
            ("internet_exposed", "boolean"),
            ("tier", "int"),
        ):
            ET.SubElement(
                root,
                "key",
                id=key,
                attrib={"for": "node", "attr.name": key, "attr.type": kind},
            )
        graph = ET.SubElement(root, "graph", id="ivm", edgedefault="directed")
        for a in assets:
            node = ET.SubElement(graph, "node", id=str(a.id))
            for key, value in (
                ("name", a.name),
                ("crown_jewel", str(a.is_crown_jewel).lower()),
                ("internet_exposed", str(a.internet_exposed).lower()),
                ("tier", str(a.criticality_tier)),
            ):
                ET.SubElement(node, "data", key=key).text = value
        for e in edges:
            ET.SubElement(
                graph,
                "edge",
                source=str(e.source_asset_id),
                target=str(e.target_asset_id),
            )
        body = ET.tostring(root, encoding="unicode", xml_declaration=True)
        return Response(
            body,
            media_type="application/xml",
            headers={
                "Content-Disposition": "attachment; filename=ivm-attack-graph.graphml"
            },
        )
    lines = ["// IVM attack graph export (synthetic data). Load with cypher-shell."]
    for a in assets:
        lines.append(
            f"MERGE (:Asset {{id: {q(a.id)}, name: {q(a.name)}, crown_jewel: "
            f"{str(a.is_crown_jewel).lower()}, internet_exposed: {str(a.internet_exposed).lower()}, "
            f"tier: {int(a.criticality_tier)}}});"
        )
    for e in edges:
        lines.append(
            f"MATCH (s:Asset {{id: {q(e.source_asset_id)}}}), (t:Asset {{id: {q(e.target_asset_id)}}}) "
            f"MERGE (s)-[:CONNECTS_TO {{type: {q(e.connection_type)}}}]->(t);"
        )
    for p in paths:
        lines.append(
            f"MERGE (:AttackPath {{id: {q(p.id)}, name: {q(p.name)}, risk: {float(p.path_risk_score)}}});"
        )
    lines.append(
        "// Example: MATCH p=(e:Asset {internet_exposed:true})-[:CONNECTS_TO*..5]->"
        "(t:Asset {crown_jewel:true}) RETURN p LIMIT 25;"
    )
    return Response(
        "\n".join(lines) + "\n",
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=ivm-attack-graph.cypher"},
    )


@router.get("/attack-paths/{path_id}")
def attack_path_detail(
    path_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    path = db.get(AttackPath, path_id)
    if not path:
        raise HTTPException(status_code=404, detail="Attack path not found")
    _check_asset_scope(db.get(Asset, path.entry_asset_id), user, db)
    return {
        "id": str(path.id),
        "name": path.name,
        "entry_asset_id": str(path.entry_asset_id),
        "target_asset_id": str(path.target_asset_id),
        "path_asset_ids": path.path_asset_ids,
        "path_finding_ids": path.path_finding_ids,
        "path_risk_score": path.path_risk_score,
        **_path_score_values(db, path),
    }


@router.post("/attack-paths/recalculate")
def attack_paths_recalculate(
    db: Session = Depends(get_db),
    _: User = Depends(require_permission(Permission.RISK_MANAGE)),
):
    paths = recalculate_paths(db)
    return {"calculated": len(paths)}
