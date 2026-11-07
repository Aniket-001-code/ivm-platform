"""Pure, explainable eight-factor contextual risk scoring."""

from dataclasses import dataclass

DEFAULT_MAX_POINTS = {
    "cvss_technical_severity": 25.0,
    "asset_criticality": 15.0,
    "internet_exposure": 10.0,
    "exploitability": 10.0,
    "threat_intelligence": 15.0,
    "data_sensitivity": 10.0,
    "regulatory_impact": 5.0,
    "attack_path_influence": 10.0,
}
DEFAULT_THRESHOLDS = {"critical": 80.0, "high": 60.0, "medium": 40.0}


@dataclass(frozen=True)
class RiskResult:
    score: float
    band: str
    breakdown: list[dict[str, object]]


def _get(obj, key: str, default=None):
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def score_finding(
    finding,
    asset,
    intel=None,
    on_attack_path: bool | float = False,
    weights: dict[str, float] | None = None,
    band_thresholds: dict[str, float] | None = None,
    reachable_from_exposed: bool = False,
) -> RiskResult:
    """Return a clamped score and reasons; configured values are factor max points."""
    maximums = {**DEFAULT_MAX_POINTS, **(weights or {})}
    intel = intel or {}
    cvss = max(0.0, min(10.0, float(_get(finding, "cvss_score", 0) or 0)))
    tier = max(1, min(5, int(_get(asset, "criticality_tier", 3) or 3)))
    base_tier = {1: 15.0, 2: 12.0, 3: 8.0, 4: 4.0, 5: 2.0}[tier]
    criticality = min(
        15.0,
        base_tier
        + (3.0 if _get(asset, "is_crown_jewel", False) else 0.0)
        + (2.0 if _get(asset, "is_customer_facing", False) else 0.0),
    )
    internet_exposed = bool(_get(asset, "internet_exposed", False))
    exposure = 10.0 if internet_exposed else (6.0 if reachable_from_exposed else 0.0)
    exploit_signal = str(_get(intel, "exploit_maturity", "none") or "none").lower()
    exploit_points = {
        "none": 0.0,
        "poc": 4.0,
        "functional": 7.0,
        "weaponized": 10.0,
    }.get(exploit_signal, 0.0)
    epss_points = max(0.0, min(1.0, float(_get(intel, "epss_score", 0) or 0))) * 10.0
    exploitability = max(exploit_points, epss_points)
    threat = min(
        15.0,
        (8.0 if _get(intel, "in_kev_list", False) else 0.0)
        + (4.0 if _get(intel, "actively_exploited", False) else 0.0)
        + (3.0 if _get(intel, "ransomware_used", False) else 0.0),
    )
    sensitivity = 10.0 if _get(asset, "has_sensitive_data", False) else 0.0
    tags = {str(tag).upper() for tag in (_get(asset, "regulatory_tags", []) or [])}
    regulatory = (
        5.0 if tags.intersection({"PCI-DSS", "SOX"}) else (3.0 if tags else 0.0)
    )
    path_fraction = (
        1.0 if on_attack_path is True else max(0.0, min(1.0, float(on_attack_path)))
    )
    values: list[tuple[str, float, str]] = [
        (
            "cvss_technical_severity",
            cvss / 10.0 * 25.0,
            f"CVSS {cvss:.1f} technical severity.",
        ),
        (
            "asset_criticality",
            criticality,
            f"Tier {tier}"
            + (", crown jewel" if _get(asset, "is_crown_jewel", False) else "")
            + (", customer-facing" if _get(asset, "is_customer_facing", False) else "")
            + ".",
        ),
        (
            "internet_exposure",
            exposure,
            (
                "Direct internet exposure."
                if internet_exposed
                else (
                    "One hop from an internet-exposed asset."
                    if reachable_from_exposed
                    else "No internet-reachability signal."
                )
            ),
        ),
        (
            "exploitability",
            exploitability,
            f"Exploit maturity {exploit_signal}; EPSS {float(_get(intel, 'epss_score', 0) or 0):.2f}.",
        ),
        (
            "threat_intelligence",
            threat,
            "KEV, active exploitation, and ransomware threat indicators.",
        ),
        (
            "data_sensitivity",
            sensitivity,
            "Sensitive data is present." if sensitivity else "No sensitive-data flag.",
        ),
        (
            "regulatory_impact",
            regulatory,
            f"Regulatory tags: {', '.join(sorted(tags)) or 'none'}.",
        ),
        (
            "attack_path_influence",
            path_fraction * 10.0,
            (
                "Finding lies on a modeled route toward a critical target."
                if path_fraction
                else "No modeled attack path contains this finding."
            ),
        ),
    ]
    breakdown: list[dict[str, object]] = []
    total = 0.0
    for factor, raw_points, reason in values:
        max_points = max(0.0, float(maximums.get(factor, DEFAULT_MAX_POINTS[factor])))
        points = min(max_points, raw_points / DEFAULT_MAX_POINTS[factor] * max_points)
        total += points
        breakdown.append(
            {
                "factor": factor,
                "points": round(points, 2),
                "max_points": max_points,
                "reason": reason,
            }
        )
    total = round(max(0.0, min(100.0, total)), 1)
    thresholds = {**DEFAULT_THRESHOLDS, **(band_thresholds or {})}
    band = (
        "critical"
        if total >= thresholds["critical"]
        else (
            "high"
            if total >= thresholds["high"]
            else "medium" if total >= thresholds["medium"] else "low"
        )
    )
    return RiskResult(total, band, breakdown)
