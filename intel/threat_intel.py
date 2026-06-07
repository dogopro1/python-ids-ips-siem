"""
Threat Intelligence integration — Module 3.

Supports: VirusTotal (IP/domain/file hash), AbuseIPDB (IP reputation), Shodan (host info).
All results are cached in SQLite (intel_cache table, TTL from config).
API keys configured in config.yaml — leave empty string to skip that source.
"""
import time
import json
import logging

logger = logging.getLogger("ids_ips")


def _cfg():
    try:
        from utils.config_loader import Config
        return Config.load()
    except Exception:
        return {}


def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None


def _get(url: str, headers: dict = None, params: dict = None, timeout: int = 10) -> dict:
    try:
        import requests
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=timeout)
        return {"status": r.status_code, "json": r.json() if r.content else {}, "ok": r.ok}
    except Exception as e:
        return {"status": 0, "json": {}, "ok": False, "error": str(e)}


# ── VirusTotal ────────────────────────────────────────────────────────────────

def virustotal_ip(ip: str) -> dict:
    cfg = _cfg()
    key = cfg.get("virustotal_api_key", "")
    if not key:
        return {"error": "no VirusTotal API key configured"}
    result = _cached("vt_ip", ip)
    if result:
        return result
    r = _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": key},
    )
    if not r["ok"]:
        return {"error": f"VT error {r['status']}"}
    data = r["json"].get("data", {}).get("attributes", {})
    out = {
        "source": "VirusTotal",
        "ip": ip,
        "country": data.get("country", ""),
        "as_owner": data.get("as_owner", ""),
        "reputation": data.get("reputation", 0),
        "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
        "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
        "undetected": data.get("last_analysis_stats", {}).get("undetected", 0),
        "total_votes": data.get("total_votes", {}),
        "tags": data.get("tags", []),
    }
    _cache("vt_ip", ip, out)
    return out


def virustotal_domain(domain: str) -> dict:
    cfg = _cfg()
    key = cfg.get("virustotal_api_key", "")
    if not key:
        return {"error": "no VirusTotal API key configured"}
    result = _cached("vt_domain", domain)
    if result:
        return result
    r = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": key},
    )
    if not r["ok"]:
        return {"error": f"VT error {r['status']}"}
    data = r["json"].get("data", {}).get("attributes", {})
    out = {
        "source": "VirusTotal",
        "domain": domain,
        "reputation": data.get("reputation", 0),
        "registrar": data.get("registrar", ""),
        "creation_date": data.get("creation_date", ""),
        "categories": data.get("categories", {}),
        "malicious": data.get("last_analysis_stats", {}).get("malicious", 0),
        "suspicious": data.get("last_analysis_stats", {}).get("suspicious", 0),
        "harmless": data.get("last_analysis_stats", {}).get("harmless", 0),
        "tags": data.get("tags", []),
    }
    _cache("vt_domain", domain, out)
    return out


def virustotal_hash(file_hash: str) -> dict:
    cfg = _cfg()
    key = cfg.get("virustotal_api_key", "")
    if not key:
        return {"error": "no VirusTotal API key configured"}
    result = _cached("vt_hash", file_hash)
    if result:
        return result
    r = _get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": key},
    )
    if not r["ok"]:
        return {"error": f"VT error {r['status']}"}
    data = r["json"].get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    out = {
        "source": "VirusTotal",
        "hash": file_hash,
        "name": data.get("meaningful_name", ""),
        "size": data.get("size", 0),
        "type": data.get("type_description", ""),
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "popular_names": list((data.get("popular_threat_name") or {}).values())[:5],
        "first_seen": data.get("first_submission_date", 0),
        "last_seen": data.get("last_submission_date", 0),
    }
    _cache("vt_hash", file_hash, out)
    return out


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def abuseipdb_check(ip: str) -> dict:
    cfg = _cfg()
    key = cfg.get("abuseipdb_api_key", "")
    if not key:
        return {"error": "no AbuseIPDB API key configured"}
    result = _cached("abuseipdb", ip)
    if result:
        return result
    r = _get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )
    if not r["ok"]:
        return {"error": f"AbuseIPDB error {r['status']}"}
    data = r["json"].get("data", {})
    out = {
        "source": "AbuseIPDB",
        "ip": ip,
        "is_public": data.get("isPublic", False),
        "ip_version": data.get("ipVersion", 4),
        "is_whitelisted": data.get("isWhitelisted", False),
        "abuse_confidence": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode", ""),
        "isp": data.get("isp", ""),
        "domain": data.get("domain", ""),
        "total_reports": data.get("totalReports", 0),
        "last_reported": data.get("lastReportedAt", ""),
        "distinct_users": data.get("numDistinctUsers", 0),
    }
    _cache("abuseipdb", ip, out)
    return out


# ── Shodan ────────────────────────────────────────────────────────────────────

def shodan_host(ip: str) -> dict:
    cfg = _cfg()
    key = cfg.get("shodan_api_key", "")
    if not key:
        return {"error": "no Shodan API key configured"}
    result = _cached("shodan", ip)
    if result:
        return result
    r = _get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": key},
    )
    if not r["ok"]:
        return {"error": f"Shodan error {r['status']}"}
    data = r["json"]
    out = {
        "source": "Shodan",
        "ip": ip,
        "organization": data.get("org", ""),
        "country": data.get("country_name", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "os": data.get("os", ""),
        "open_ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "vulns": list(data.get("vulns", {}).keys()),
        "last_update": data.get("last_update", ""),
        "tags": data.get("tags", []),
        "services": [
            {
                "port": s.get("port"),
                "transport": s.get("transport"),
                "product": s.get("product", ""),
                "version": s.get("version", ""),
                "banner": (s.get("data") or "")[:256],
                "cpe": s.get("cpe", []),
            }
            for s in data.get("data", [])[:20]
        ],
    }
    _cache("shodan", ip, out)
    return out


# ── Combined lookup ───────────────────────────────────────────────────────────

def full_intel(target: str, target_type: str = "ip") -> dict:
    """Run all available TI sources for an IP or domain."""
    results = {}
    if target_type == "ip":
        results["virustotal"] = virustotal_ip(target)
        results["abuseipdb"] = abuseipdb_check(target)
        results["shodan"] = shodan_host(target)
    elif target_type == "domain":
        results["virustotal"] = virustotal_domain(target)
    elif target_type == "hash":
        results["virustotal"] = virustotal_hash(target)
    return results


# ── Cache helpers ─────────────────────────────────────────────────────────────

def _cache_key(source: str, target: str) -> str:
    return f"{source}:{target}"


def _cached(source: str, target: str):
    db = _db()
    if db is None:
        return None
    try:
        cfg = _cfg()
        ttl = int(cfg.get("intel_cache_ttl", 3600))
        return db.get_intel_cache(_cache_key(source, target), ttl)
    except Exception:
        return None


def _cache(source: str, target: str, data: dict):
    db = _db()
    if db is None:
        return
    try:
        db.set_intel_cache(_cache_key(source, target), data)
    except Exception:
        pass
