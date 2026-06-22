"""
Wayback Machine URL enumeration via CDX API.

Fetches all archived URLs for a domain from archive.org CDX index.
Useful for discovering old endpoints, parameters, backup files.
"""
import time
import logging
from urllib.parse import urlparse, urlencode

logger = logging.getLogger("ids_ips")

_CDX_URL = "http://web.archive.org/cdx/search/cdx"

_INTERESTING_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".bak", ".backup", ".sql", ".db",
    ".env", ".config", ".conf", ".cfg", ".xml", ".json", ".yaml", ".yml",
    ".log", ".txt", ".csv", ".xls", ".xlsx", ".pdf",
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl",
    ".js", ".ts", ".map",
    ".key", ".pem", ".crt", ".p12",
}

_INTERESTING_PATTERNS = [
    "admin", "login", "password", "passwd", "token", "secret", "api",
    "config", "setup", "install", "debug", "test", "backup", "dump",
    "upload", "download", "export", "import", "shell", ".git", ".svn",
]


def _classify_url(url: str) -> list:
    tags = []
    lower = url.lower()
    path = urlparse(url).path.lower()
    ext = "." + path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
    if ext in _INTERESTING_EXTENSIONS:
        tags.append("sensitive-ext")
    for pat in _INTERESTING_PATTERNS:
        if pat in lower:
            tags.append(pat)
            break
    return tags


def fetch(
    domain: str,
    limit: int = 5000,
    collapse_urlkey: bool = True,
    from_year: str = None,
    to_year: str = None,
    timeout: float = 30.0,
) -> dict:
    """
    Fetch archived URLs for domain from Wayback Machine CDX.

    Args:
        domain: target domain (e.g. example.com)
        limit: max URLs to return
        collapse_urlkey: deduplicate same URL regardless of params
        from_year: "2015" — restrict to years
        to_year: "2023"

    Returns:
        {domain, urls:[{url, timestamp, status, mimetype, tags}],
         total, interesting_count, elapsed_s}
    """
    try:
        import requests as _req
    except ImportError:
        return {"error": "requests library required", "domain": domain}

    t0 = time.time()
    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype",
        "limit": str(min(limit, 10000)),
    }
    if collapse_urlkey:
        params["collapse"] = "urlkey"
    if from_year:
        params["from"] = from_year
    if to_year:
        params["to"] = to_year

    try:
        r = _req.get(_CDX_URL, params=params, timeout=timeout,
                     headers={"User-Agent": "Mozilla/5.0 (WaybackRecon/1.0)"})
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return {"error": str(exc), "domain": domain, "elapsed_s": round(time.time() - t0, 2)}

    if not data or len(data) < 2:
        return {"domain": domain, "urls": [], "total": 0,
                "interesting_count": 0, "elapsed_s": round(time.time() - t0, 2)}

    header = data[0]  # ["original","timestamp","statuscode","mimetype"]
    urls = []
    interesting = 0
    seen = set()

    for row in data[1:]:
        if len(row) < len(header):
            continue
        entry = dict(zip(header, row))
        url = entry.get("original", "")
        if not url or url in seen:
            continue
        seen.add(url)
        tags = _classify_url(url)
        if tags:
            interesting += 1
        urls.append({
            "url": url,
            "timestamp": entry.get("timestamp", ""),
            "status": entry.get("statuscode", ""),
            "mimetype": entry.get("mimetype", ""),
            "tags": tags,
        })

    # Sort: interesting first, then alphabetical
    urls.sort(key=lambda u: (not bool(u["tags"]), u["url"]))

    return {
        "domain": domain,
        "urls": urls,
        "total": len(urls),
        "interesting_count": interesting,
        "elapsed_s": round(time.time() - t0, 2),
    }
