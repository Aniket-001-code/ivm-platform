from types import SimpleNamespace

import pytest

from app.services.normalization import (
    asset_key,
    finding_fingerprint,
    normalize_severity,
)
from app.services.risk_engine import DEFAULT_MAX_POINTS, score_finding


@pytest.mark.parametrize(
    "cvss,criticality,exposed",
    [
        (10, 1, True),
        (9.8, 1, True),
        (9, 2, True),
        (8, 1, False),
        (7, 3, True),
        (6, 3, False),
        (5, 2, False),
        (4, 4, True),
        (3, 4, False),
        (2, 5, False),
        (1, 5, False),
        (0, 5, False),
        (8, 5, True),
        (5, 1, True),
        (9.5, 1, True),
    ],
)
def test_risk_score_is_bounded_and_has_spec_factors(cvss, criticality, exposed):
    finding = SimpleNamespace(cvss_score=cvss)
    asset = SimpleNamespace(
        criticality_tier=criticality,
        internet_exposed=exposed,
        is_customer_facing=False,
        is_crown_jewel=False,
        has_sensitive_data=False,
        regulatory_tags=[],
    )
    result = score_finding(finding, asset, {"epss_score": 0.8, "in_kev_list": True})
    assert 0 <= result.score <= 100
    assert result.band in {"critical", "high", "medium", "low"}
    assert [row["factor"] for row in result.breakdown] == list(DEFAULT_MAX_POINTS)
    assert all(0 <= row["points"] <= row["max_points"] for row in result.breakdown)


def test_attack_path_signal_increases_score():
    finding = SimpleNamespace(cvss_score=7.5)
    asset = SimpleNamespace(
        criticality_tier=2,
        internet_exposed=False,
        is_customer_facing=False,
        is_crown_jewel=False,
        has_sensitive_data=False,
        regulatory_tags=[],
    )
    base = score_finding(finding, asset)
    on_path = score_finding(finding, asset, on_attack_path=True)
    assert on_path.score > base.score
    assert "modeled route" in on_path.breakdown[-1]["reason"]


@pytest.mark.parametrize(
    "raw,normalized",
    [
        ("Critical", "critical"),
        ("crit", "critical"),
        ("Severe", "high"),
        ("Moderate", "medium"),
        ("Informational", "low"),
        (None, "medium"),
    ],
)
def test_severity_aliases(raw, normalized):
    assert normalize_severity(raw) == normalized


def test_asset_aliases_correlate_fqdns_and_hostnames():
    assert asset_key("web01.bank.local") == asset_key("web01")


def test_fingerprint_is_stable_and_asset_scoped():
    one = finding_fingerprint("asset-a", "CVE-2021-1234", "ignored")
    assert one == finding_fingerprint("asset-a", "cve-2021-1234", "different title")
    assert one != finding_fingerprint("asset-b", "CVE-2021-1234", "ignored")


def test_seeded_owner_mapping_matches_generator_ground_truth():
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "data" / "synthetic" / "assets.json"
    if not path.exists():
        pytest.skip("Run the synthetic data generator first")
    assets = json.loads(path.read_text(encoding="utf-8"))
    matched = sum(
        row["owner_email"] == f"user{8 + ((row['id'] - 1) % 3)}@demo.bank"
        for row in assets
    )
    assert matched / len(assets) >= 0.90
