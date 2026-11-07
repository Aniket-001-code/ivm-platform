import hashlib
import re


def normalize_severity(value: str | None) -> str:
    value = (value or "medium").lower().strip()
    aliases = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "severe": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "informational": "low",
        "info": "low",
    }
    return aliases.get(value, "medium")


def asset_key(*values: str | None) -> str:
    normalized = []
    for value in values:
        token = (value or "").lower().strip().split(".")[0]
        if token:
            normalized.append(re.sub(r"[^a-z0-9]", "", token))
    return normalized[0] if normalized else "unknown"


def finding_fingerprint(asset_id: str, cve_id: str | None, title: str) -> str:
    key = f"{asset_id}|{(cve_id or title).lower().strip()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
