"""
JavaScript File Analyzer — extract and analyze JS files from a target.

Finds all .js files referenced by a webpage, fetches them, and scans for:
  - API endpoints (fetch/axios/XMLHttpRequest/REST URLs)
  - Secrets / credentials (API keys, tokens, passwords)
  - Internal hostnames and IP addresses
  - Interesting function/variable names
"""
import re
import time
import logging
import concurrent.futures
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("ids_ips")

_SECRET_PATTERNS = [
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,64})["\']'), "api_key"),
    (re.compile(r'(?i)(secret|secret[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-\/\+]{16,64})["\']'), "secret"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']'), "password"),
    (re.compile(r'(?i)(token|auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']'), "token"),
    (re.compile(r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']([A-Z0-9]{20})["\']'), "aws_key_id"),
    (re.compile(r'(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/]{40})["\']'), "aws_secret"),
    (re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "google_api_key"),
    (re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'), "jwt_token"),
    (re.compile(r'(?i)(private[_-]?key)\s*[=:]\s*["\']([^"\']{32,})["\']'), "private_key"),
    (re.compile(r'Basic\s+[A-Za-z0-9+/=]{20,}'), "basic_auth"),
]

_ENDPOINT_PATTERNS = [
    re.compile(r'["\'](/(?:api|v\d|rest|graphql|gql)[^\s"\'<>]{1,200})["\']'),
    re.compile(r'(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["\']([^"\']+)["\']'),
    re.compile(r'XMLHttpRequest[^;]*open\s*\(\s*["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']'),
    re.compile(r'(?:url|endpoint|baseURL|apiUrl)\s*[:=]\s*["\']([^"\']{5,200})["\']'),
]

_IP_PATTERN = re.compile(r'\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b')
_HOSTNAME_PATTERN = re.compile(r'https?://([a-zA-Z0-9][a-zA-Z0-9\-\.]{3,60}\.[a-zA-Z]{2,10})')


def _extract_js_urls(base_url: str, html: str) -> list:
    """Extract all JS file URLs from HTML."""
    urls = set()
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.I):
        urls.add(urljoin(base_url, m.group(1)))
    # Also inline fetch/import statements pointing to .js
    for m in re.finditer(r'import\s+[^"\']*["\']([^"\']+\.js)["\']', html):
        urls.add(urljoin(base_url, m.group(1)))
    return sorted(urls)


def _analyze_js(content: str, source_url: str) -> dict:
    """Analyze a single JS file for secrets and endpoints."""
    secrets = []
    endpoints = set()
    internal_ips = set()
    hostnames = set()

    # Secret scanning
    for pattern, kind in _SECRET_PATTERNS:
        for m in pattern.finditer(content):
            val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
            secrets.append({"type": kind, "value": val[:80] + ("..." if len(val) > 80 else ""),
                            "line": content[:m.start()].count("\n") + 1})

    # Endpoint extraction
    for pattern in _ENDPOINT_PATTERNS:
        for m in pattern.finditer(content):
            ep = m.group(1)
            if 3 < len(ep) < 300 and not any(skip in ep for skip in (".png", ".jpg", ".css", ".svg")):
                endpoints.add(ep)

    # Internal IPs
    for m in _IP_PATTERN.finditer(content):
        internal_ips.add(m.group(0))

    # Hostnames from URLs
    for m in _HOSTNAME_PATTERN.finditer(content):
        hostnames.add(m.group(1).lower())

    return {
        "source_url": source_url,
        "size_bytes": len(content.encode()),
        "lines": content.count("\n") + 1,
        "secrets": secrets,
        "endpoints": sorted(endpoints)[:100],
        "internal_ips": sorted(internal_ips),
        "hostnames": sorted(hostnames)[:50],
        "secrets_count": len(secrets),
        "endpoints_count": len(endpoints),
    }


def run(url: str, max_js: int = 30, timeout: float = 10.0) -> dict:
    """
    Fetch page, find all JS files, analyze each for secrets/endpoints.

    Returns:
        {url, js_files:[...], total_secrets, total_endpoints,
         all_secrets:[...], all_endpoints:[...], elapsed_s}
    """
    try:
        import requests as _req
    except ImportError:
        return {"error": "requests library required"}

    import warnings
    warnings.filterwarnings("ignore")
    t0 = time.time()

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = _req.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (JSAnalyzer/1.0)"

    # Fetch homepage to extract JS URLs
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        js_urls = _extract_js_urls(r.url, r.text)[:max_js]
    except Exception as exc:
        return {"url": url, "error": str(exc), "elapsed_s": round(time.time() - t0, 2)}

    analyzed = []
    all_secrets = []
    all_endpoints = set()

    def _fetch_and_analyze(js_url):
        try:
            r2 = session.get(js_url, timeout=timeout, verify=False)
            if r2.ok and "javascript" in r2.headers.get("Content-Type", "").lower() or js_url.endswith(".js"):
                result = _analyze_js(r2.text, js_url)
                return result
        except Exception:
            pass
        return {"source_url": js_url, "error": "fetch failed", "secrets": [], "endpoints": []}

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_fetch_and_analyze, u): u for u in js_urls}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 2):
            res = f.result()
            analyzed.append(res)
            all_secrets.extend(res.get("secrets", []))
            all_endpoints.update(res.get("endpoints", []))

    analyzed.sort(key=lambda x: x.get("secrets_count", 0), reverse=True)

    return {
        "url": url,
        "js_files": analyzed,
        "total_js": len(js_urls),
        "total_secrets": len(all_secrets),
        "total_endpoints": len(all_endpoints),
        "all_secrets": all_secrets[:200],
        "all_endpoints": sorted(all_endpoints)[:500],
        "elapsed_s": round(time.time() - t0, 2),
    }
