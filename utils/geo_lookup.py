import urllib.request
import urllib.error
import json
import threading
import time
import logging

logger = logging.getLogger("ids_ips")

_cache: dict = {}
_cache_lock = threading.Lock()
_CACHE_TTL = 3600 * 12  # 12 hours
_API = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query"


def lookup(ip: str) -> dict:
    """Return geolocation for an IP. Uses ip-api.com free tier (45 req/min)."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {"status": "private", "query": ip, "country": "Private Network",
                    "countryCode": "LAN", "isp": "Local", "org": "Local Network", "as": ""}
    except ValueError:
        return {"status": "error", "query": ip}

    with _cache_lock:
        entry = _cache.get(ip)
        if entry and time.time() - entry["_ts"] < _CACHE_TTL:
            return entry

    try:
        url = _API.format(ip=ip)
        req = urllib.request.Request(url, headers={"User-Agent": "IDS-Monitor/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        data["_ts"] = time.time()
        with _cache_lock:
            _cache[ip] = data
        try:
            from db.database import Database
            db = Database.get()
            db.cache_ip_analysis(ip, data)
        except Exception:
            pass
        return data
    except Exception as e:
        logger.debug("geo_lookup failed for %s: %s", ip, e)
        return {"status": "error", "query": ip, "error": str(e)}
