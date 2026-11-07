import hashlib
import re
from urllib.parse import urlparse


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


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def asset_key(*values: str | None) -> str:
    """Normalize a host, FQDN, URL or IP to the key used to match import rows to assets.

    Hostnames and FQDNs reduce to their first label ("host001.bank.local" -> "host001");
    URLs reduce to their host; IP addresses are kept whole so different hosts never collide.
    """
    for value in values:
        token = (value or "").lower().strip()
        if not token:
            continue
        if "://" in token:
            token = urlparse(token).hostname or ""
        token = token.split("/")[0].split(":")[0] if not _IPV4.match(token) else token
        if _IPV4.match(token):
            return token
        label = re.sub(r"[^a-z0-9]", "", token.split(".")[0])
        if label:
            return label
    return "unknown"


def finding_fingerprint(asset_id: str, cve_id: str | None, title: str) -> str:
    key = f"{asset_id}|{(cve_id or title).lower().strip()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
