"""Create repeatable, fictional source exports for local demos (seed 42)."""

import csv
import json
import random
from datetime import date, timedelta
from pathlib import Path

from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)
OUT = Path(__file__).resolve().parents[1] / "data" / "synthetic"
OUT.mkdir(parents=True, exist_ok=True)
TODAY = date(2025, 1, 1)

units = [
    "Retail Banking",
    "Corporate Banking",
    "Treasury",
    "Cards and Payments",
    "Digital Channels",
]
services_by_unit = [
    ["Retail Payments", "Branch Banking", "Customer Identity"],
    ["Corporate Portal", "Trade Finance"],
    ["Treasury Trading", "Liquidity"],
    ["Card Authorization", "Settlement", "Fraud Platform"],
    ["Mobile Banking", "Online Banking"],
]
services = [
    {"name": name, "business_unit": unit, "description": f"Synthetic {name} service"}
    for unit, rows in zip(units, services_by_unit)
    for name in rows
]
assets = []
types = (
    ["server"] * 90
    + ["application"] * 60
    + ["database"] * 40
    + ["cloud_resource"] * 40
    + ["container"] * 40
    + ["network_device"] * 30
)
random.shuffle(types)
for index, asset_type in enumerate(types, 1):
    unit = units[(index - 1) % len(units)]
    assets.append(
        {
            "id": index,
            "name": f"{asset_type.replace('_', '-')}-{index:03d}",
            "hostname": f"host{index:03d}.bank.local",
            "ip_address": f"10.{index // 250}.{(index // 2500) % 250}.{(index % 250) + 1}",
            "asset_type": asset_type,
            "environment": random.choices(["prod", "uat", "dev"], [0.65, 0.2, 0.15])[0],
            "business_unit": unit,
            "business_service": random.choice(
                [x["name"] for x in services if x["business_unit"] == unit]
            ),
            "owner_email": f"user{8 + ((index - 1) % 3)}@demo.bank",
            "criticality_tier": random.choices(
                [1, 2, 3, 4, 5], [0.08, 0.2, 0.35, 0.25, 0.12]
            )[0],
            "is_customer_facing": random.random() < 0.25,
            "is_crown_jewel": random.random() < 0.08,
            "has_sensitive_data": random.random() < 0.30,
            "regulatory_tags": random.sample(
                ["PCI-DSS", "SOX", "GDPR"], random.randint(0, 2)
            ),
            "internet_exposed": random.random() < 0.20,
            "os_or_platform": random.choice(
                ["Linux", "Windows Server", "AWS", "Kubernetes"]
            ),
            "status": "active",
        }
    )

known_cves = [
    "CVE-2021-44228",
    "CVE-2021-34527",
    "CVE-2023-34362",
    "CVE-2023-27997",
    "CVE-2022-22965",
    "CVE-2024-3400",
    "CVE-2023-22515",
    "CVE-2021-26855",
    "CVE-2023-4966",
    "CVE-2024-21762",
    "CVE-2022-30190",
    "CVE-2023-20198",
]
catalog = []
for index in range(120):
    cve = (
        known_cves[index]
        if index < len(known_cves)
        else f"CVE-{2019 + index % 6}-{10000 + index}"
    )
    catalog.append(
        {
            "cve_id": cve,
            "title": f"Synthetic vulnerability record {index + 1}",
            "description": "Metadata is fictionalized for this academic demonstration; no exploit code is included.",
            "cvss_base_score": round(random.uniform(2.0, 10.0), 1),
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": f"CWE-{random.choice([79, 89, 287, 502, 611, 918])}",
            "published_date": str(
                date(2020, 1, 1) + timedelta(days=random.randint(0, 2300))
            ),
            "has_public_exploit": index % 4 == 0,
            "exploit_maturity": random.choice(
                ["none", "poc", "functional", "weaponized"]
            ),
            "epss_score": round(random.uniform(0.001, 0.97), 3),
            "in_kev_list": index % 7 == 0,
            "ransomware_used": index % 13 == 0,
            "actively_exploited": index % 9 == 0,
        }
    )
    if index < 12:
        catalog[-1]["cve_id"] = known_cves[index]

scanner, cspm, pentest, container = [], [], [], []
# Each source intentionally reports part of the same common population to exercise correlation.
for index in range(650):
    asset = assets[index % len(assets)]
    vuln = catalog[index % len(catalog)]
    base = {
        "host": asset["hostname"],
        "ip": asset["ip_address"],
        "cve": vuln["cve_id"],
        "plugin_name": vuln["title"],
        "cvss": vuln["cvss_base_score"],
        "severity": (
            "Critical"
            if vuln["cvss_base_score"] >= 9
            else "High" if vuln["cvss_base_score"] >= 7 else "Medium"
        ),
        "first_found": str(TODAY - timedelta(days=index % 180)),
        "port": random.choice([443, 8443, 22, 5432]),
    }
    scanner.append(base)
    if (
        index < 500
    ):  # Same issue with alternate naming is a deliberate cross-source duplicate.
        container.append(
            {
                "image_name": asset["name"],
                "namespace": "payments",
                "pod": asset["hostname"].split(".")[0],
                "cve_id": vuln["cve_id"],
                "package": "demo-package",
                "fixed_version": "2.4.1",
                "severity": base["severity"],
            }
        )
for index in range(600):
    asset = assets[(index * 7 + 19) % len(assets)]
    cspm.append(
        {
            "resource_id": asset["hostname"],
            "resource_type": asset["asset_type"],
            "rule_id": f"CSPM-{index:04d}",
            "rule_title": random.choice(
                [
                    "Storage is publicly readable",
                    "Encryption at rest is disabled",
                    "Security group permits broad access",
                ]
            ),
            "severity": random.choice(["critical", "high", "medium", "low"]),
            "region": "ap-south-1",
            "status": "open",
        }
    )
for index in range(600):
    asset = assets[(index * 11 + 31) % len(assets)]
    pentest.append(
        {
            "target": asset["hostname"],
            "finding_title": random.choice(
                [
                    "Authorization bypass",
                    "Weak session handling",
                    "Verbose error response",
                    "Missing rate limit",
                ]
            ),
            "risk_rating": random.choice(["Critical", "High", "Medium", "Low"]),
            "description": "Synthetic penetration test observation. No production target was tested.",
            "cwe": "CWE-" + str(random.choice([79, 285, 287, 693])),
            "tester": "Demo Security Team",
            "date": str(TODAY - timedelta(days=index % 90)),
        }
    )
# Add malformed records to make import error handling visible.
scanner.extend([{"host": "", "cve": "NOT-A-CVE", "severity": "???"} for _ in range(50)])
with (OUT / "scanner_export.csv").open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(
        stream, fieldnames=sorted({key for row in scanner for key in row})
    )
    writer.writeheader()
    writer.writerows(scanner)
for name, data in [
    ("cspm_findings.json", cspm),
    ("pentest_report.json", pentest),
    ("container_k8s_findings.json", container),
]:
    (OUT / name).write_text(json.dumps(data, indent=2), encoding="utf-8")
with (OUT / "identity_findings.csv").open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(
        stream, fieldnames=["account", "asset", "issue", "severity"]
    )
    writer.writeheader()
    writer.writerows(
        {
            "account": f"svc-demo-{i:03}",
            "asset": assets[i % len(assets)]["hostname"],
            "issue": random.choice(
                ["stale admin account", "MFA not enabled", "excessive privilege"]
            ),
            "severity": random.choice(["High", "Medium"]),
        }
        for i in range(100)
    )
(OUT / "assets.json").write_text(json.dumps(assets, indent=2), encoding="utf-8")
(OUT / "business_units.json").write_text(json.dumps(units, indent=2), encoding="utf-8")
(OUT / "business_services.json").write_text(
    json.dumps(services, indent=2), encoding="utf-8"
)
(OUT / "vulnerability_catalog.json").write_text(
    json.dumps(catalog, indent=2), encoding="utf-8"
)
(OUT / "threat_intel_feed.json").write_text(
    json.dumps(catalog, indent=2), encoding="utf-8"
)
connections = []
entry_assets = [asset for asset in assets if asset["internet_exposed"]]
app_assets = [
    asset for asset in assets if asset["asset_type"] in {"application", "server"}
]
targets = [asset for asset in assets if asset["is_crown_jewel"]]
databases = [asset for asset in assets if asset["asset_type"] == "database"]
for index, entry in enumerate(entry_assets):
    middle = app_assets[(index * 3) % len(app_assets)]
    target = (
        targets[index % len(targets)]
        if index % 2 == 0 and targets
        else databases[index % len(databases)]
    )
    connections.append(
        {
            "source": entry["id"],
            "target": middle["id"],
            "connection_type": "network",
            "port_or_protocol": "tcp/443",
        }
    )
    connections.append(
        {
            "source": middle["id"],
            "target": target["id"],
            "connection_type": "data_flow",
            "port_or_protocol": "tcp/5432",
        }
    )
for index in range(18):
    source = app_assets[(index * 5) % len(app_assets)]
    target = databases[(index * 7) % len(databases)]
    connections.append(
        {
            "source": source["id"],
            "target": target["id"],
            "connection_type": "data_flow",
            "port_or_protocol": "tcp/5432",
        }
    )
(OUT / "asset_connections.json").write_text(
    json.dumps(connections, indent=2), encoding="utf-8"
)
print(
    f"Wrote deterministic synthetic data to {OUT}; 300 assets, 120 CVEs and {len(scanner)+len(cspm)+len(pentest)+len(container)+100} raw rows."
)
