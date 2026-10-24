"""External enrichment: VirusTotal (hash/domain lookups only), RDAP domain age, IOC list."""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from functools import lru_cache
from urllib.parse import urlparse

from pkgscan.config import DATA_DIR
from pkgscan.http import Http

VT_API = "https://www.virustotal.com/api/v3"


def vt_file(http: Http, sha256: str) -> dict | None:
    """VirusTotal file report by hash. Never uploads the file."""
    if not http.vt_key:
        return None
    try:
        r = http.get(f"{VT_API}/files/{sha256}", headers={"x-apikey": http.vt_key})
    except Exception:
        return None
    if r.status_code != 200:
        return {"not_found": True} if r.status_code == 404 else None
    a = r.json().get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {})
    ptc = a.get("popular_threat_classification") or {}
    return {
        "score": int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)),
        "total": sum(int(v) for v in stats.values()) if stats else 0,
        "popular_threat_classification": ptc.get("suggested_threat_label"),
        "popular_threat_category": [c.get("value") for c in ptc.get("popular_threat_category", [])][:3],
        "tags": a.get("tags", [])[:15],
        "exiftool": {k: v for k, v in (a.get("exiftool") or {}).items()
                     if k in ("FileType", "CompanyName", "ProductName", "OriginalFileName", "TimeStamp", "Author")},
        "has_pe_info": bool(a.get("pe_info")),
        "sandbox_verdicts": {k: v.get("category") for k, v in (a.get("sandbox_verdicts") or {}).items()},
    }


def vt_domain(http: Http, domain: str) -> dict | None:
    if not http.vt_key:
        return None
    try:
        r = http.get(f"{VT_API}/domains/{domain}", headers={"x-apikey": http.vt_key})
    except Exception:
        return None
    if r.status_code != 200:
        return None
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"malicious": int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)),
            "total": sum(int(v) for v in stats.values()) if stats else 0}


def registrable_domain(host: str) -> str:
    """Rough eTLD+1 (good enough for matching against curated domain lists)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "ac", "gov", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def domain_age_days(http: Http, domain: str) -> int | None:
    """Domain age from RDAP registration event."""
    status, data = http.get_json(f"https://rdap.org/domain/{registrable_domain(domain)}")
    if not data:
        return None
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                when = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - when).days
            except ValueError:
                return None
    return None


def domain_matches(host: str, domains: list[str]) -> str | None:
    host = host.lower().strip(".")
    for d in domains:
        d = d.lower()
        if host == d or host.endswith("." + d) or host.startswith(d + "/"):
            return d
    return None


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def ip_kind(s: str) -> str | None:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_multicast or ip.is_reserved:
        return "reserved"
    return "public"


@lru_cache(maxsize=1)
def load_iocs() -> dict:
    return json.loads((DATA_DIR / "iocs.json").read_text())
