"""
Status Codes — bulk HTTP status check for a list of URLs/paths.

Useful for quickly checking which paths on a server return 200 vs 403/404/500.
Can also be used to test a wordlist against a base URL.
"""
import time
import logging
import concurrent.futures

logger = logging.getLogger("ids_ips")

_STATUS_LABELS = {
    200: "OK", 201: "Created", 204: "No Content", 301: "Moved Permanently",
    302: "Found", 303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
    308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
    403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 429: "Too Many Requests", 500: "Internal Server Error",
    502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}

_STATUS_CATEGORY = {
    2: "2xx Success", 3: "3xx Redirect", 4: "4xx Client Error", 5: "5xx Server Error"
}


def _check_one(session, url: str, timeout: float) -> dict:
    try:
        import time as _t
        t0 = _t.time()
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
        elapsed = round((_t.time() - t0) * 1000)
        status = r.status_code
        location = r.headers.get("Location", "")
        return {
            "url": url,
            "status": status,
            "label": _STATUS_LABELS.get(status, ""),
            "category": _STATUS_CATEGORY.get(status // 100, "Unknown"),
            "time_ms": elapsed,
            "size": len(r.content),
            "location": location[:200] if location else None,
            "server": r.headers.get("Server", ""),
            "content_type": r.headers.get("Content-Type", "").split(";")[0].strip(),
        }
    except Exception as exc:
        return {"url": url, "status": None, "label": "Error", "category": "Error",
                "error": str(exc)[:80], "time_ms": None, "size": 0}


def check(
    targets: list,
    base_url: str = None,
    concurrency: int = 20,
    timeout: float = 8.0,
) -> dict:
    """
    Check HTTP status for a list of URLs or paths.

    Args:
        targets: list of full URLs or paths (combined with base_url if given)
        base_url: optional base URL to prepend to paths
        concurrency: parallel workers
        timeout: per-request timeout

    Returns:
        {results:[...], stats:{200:N, 301:N, ...}, by_category:{...},
         total, elapsed_s}
    """
    try:
        import requests as _req
    except ImportError:
        return {"error": "requests library required"}

    import warnings
    warnings.filterwarnings("ignore")
    t0 = time.time()

    # Build full URLs
    urls = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if base_url and not t.startswith(("http://", "https://")):
            base = base_url.rstrip("/")
            path = t if t.startswith("/") else "/" + t
            urls.append(base + path)
        elif t.startswith(("http://", "https://")):
            urls.append(t)
        else:
            urls.append("https://" + t)

    session = _req.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (StatusChecker/1.0)"

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, len(urls) or 1)) as ex:
        futures = {ex.submit(_check_one, session, url, timeout): url for url in urls}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                results.append(f.result())
            except Exception:
                results.append({"url": futures[f], "status": None, "error": "timeout"})

    # Stats
    stats: dict = {}
    by_category: dict = {}
    for r in results:
        s = r.get("status")
        if s:
            stats[s] = stats.get(s, 0) + 1
            cat = r.get("category", "Unknown")
            by_category[cat] = by_category.get(cat, 0) + 1

    results.sort(key=lambda r: (r.get("status") or 999, r.get("url", "")))

    return {
        "results": results,
        "stats": {str(k): v for k, v in sorted(stats.items())},
        "by_category": by_category,
        "total": len(results),
        "elapsed_s": round(time.time() - t0, 2),
    }
