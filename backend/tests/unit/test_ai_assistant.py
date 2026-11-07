from app.models.entities import Asset, BusinessUnit, Finding
from app.services.ai_assistant import answer_question


def test_finding_context_returns_selected_finding_and_risk_drivers(db_session):
    unit = BusinessUnit(name="Finding Assistant Unit")
    db_session.add(unit)
    db_session.flush()
    asset = Asset(
        name="Payments API",
        asset_type="server",
        environment="prod",
        business_unit_id=unit.id,
    )
    db_session.add(asset)
    db_session.flush()
    finding = Finding(
        asset_id=asset.id,
        finding_type="vulnerability",
        title="Critical remote code execution",
        description="Unauthenticated remote code execution on the payment service.",
        severity="critical",
        cvss_score=9.8,
        status="open",
        fingerprint="a" * 64,
        risk_score=94.5,
        risk_band="critical",
        risk_breakdown=[
            {
                "factor": "exploitability",
                "points": 17.5,
                "max_points": 20,
                "reason": "Public exploit is available.",
            }
        ],
    )
    db_session.add(finding)
    db_session.commit()

    result = answer_question(
        db_session,
        "Explain why this finding is prioritized.",
        "security_analyst",
        finding_id=finding.id,
    )

    assert result["intent"] == "explain_finding"
    assert "Critical remote code execution" in result["answer"]
    assert "94.5/100" in result["answer"]
    assert "Public exploit is available" in result["answer"]
    assert result["data"][0]["asset_name"] == "Payments API"
