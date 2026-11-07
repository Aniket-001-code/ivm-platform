from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.api.v1.common import (
    settings,
    QuestionInput,
    _check_asset_scope,
    _limit,
    audit,
)
from app.api.v1.routes.findings import _finding_rows
from app.core.deps import get_current_user as current_user
from app.core.deps import get_db
from app.models.entities import (
    AiQueryLog,
    Asset,
    Finding,
    User,
)
from app.services import analytics
from app.services.ai_assistant import answer_question

router = APIRouter(prefix="/api/v1")


@router.post("/ai/ask")
def ai_ask(
    body: QuestionInput,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    _limit(request, "ai", settings.ai_rate_limit)
    if body.finding_id:
        finding = db.get(Finding, body.finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        _check_asset_scope(db.get(Asset, finding.asset_id), user, db)
    result = answer_question(
        db,
        body.question,
        user.role,
        user.business_unit_id,
        user.id,
        finding_id=body.finding_id,
        history=[q[:500] for q in body.history[-5:]],
    )
    db.add(
        AiQueryLog(
            user_id=user.id,
            question=body.question[:1000],
            detected_intent=result["intent"],
            answer_summary=str(result["answer"])[:2000],
            used_llm=result["used_llm"],
        )
    )
    audit(
        db,
        user,
        "ai_query",
        "ai_query",
        new={"intent": result["intent"], "used_llm": result["used_llm"]},
    )
    db.commit()
    return result


@router.get("/ai/recommendations")
def ai_recommendations(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    return _finding_rows(
        db,
        analytics.finding_query(user)
        .where(Finding.status == "open")
        .order_by(Finding.risk_score.desc())
        .limit(10),
    )


@router.post("/ai/explain/{finding_id}")
def ai_explain(
    finding_id: UUID, db: Session = Depends(get_db), user: User = Depends(current_user)
):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    _check_asset_scope(db.get(Asset, f.asset_id), user, db)
    factors = f.risk_breakdown or []
    parts = [factor.get("reason", "") for factor in factors if isinstance(factor, dict)]
    return {
        "answer": f"This finding has a {f.risk_band} contextual risk score of {f.risk_score:.1f}. "
        + " ".join(parts),
        "used_llm": False,
        "disclaimer": "AI-generated demo explanation; verify with evidence.",
    }


@router.post("/ai/executive-summary")
def ai_executive_summary(
    db: Session = Depends(get_db), user: User = Depends(current_user)
):
    result = answer_question(
        db, "Summarize highest priorities", user.role, user.business_unit_id, user.id
    )
    return {
        "summary": result["answer"],
        "used_llm": result["used_llm"],
        "label": "AI-generated demo summary",
    }
