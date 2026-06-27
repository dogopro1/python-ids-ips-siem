"""
Response Headers — fetch and display all HTTP response headers for a URL.

Shows the full header dump with security analysis annotations.
"""
import time
import logging

logger = logging.getLogger("ids_ips")

_SECURITY_HEADERS = {
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "x-xss-protection", "cross-origin-embedder-policy", "cross-origin-opener-policy",
    "access-control-allow-origin", "access-control-allow-credentials",
}

_INFO_DISCLOSURE = {
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-wp-total",
}

_INTERESTING = {
    "set-cookie", "www-authenticate", "proxy-authenticate",
    "content-location", "link", "via", "x-forwarded-for",
    "x-real-ip", "cf-ray", "x-cache", "age",
}


def fetch(url: str, method: str = "GET", follow_redirects: bool = True,
          timeout: float = 10.0) -> dict:
    """
    Fetch HTTP response headers for URL.

    Returns:
        {url, final_url, status, method, headers:[{name, value, category}],
         redirect_chain, elapsed_s}
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
    session.headers["User-Agent"] = "Mozilla/5.0 (HeaderFetcher/1.0)"

    try:
        fn = getattr(session, method.lower(), session.get)
        r = fn(url, timeout=timeout, verify=False, allow_redirects=follow_redirects)
    except Exception as exc:
        return {"url": url, "error": str(exc), "elapsed_s": round(time.time() - t0, 2)}

    # Annotate each header
    annotated = []
    for name, value in r.headers.items():
        name_l = name.lower()
        if name_l in _SECURITY_HEADERS:
            category = "security"
        elif name_l in _INFO_DISCLOSURE:
            category = "disclosure"
        elif name_l in _INTERESTING:
            category = "interesting"
        elif name_l.startswith(("x-", "cf-", "x-amz", "fastly")):
            category = "custom"
        else:
            category = "standard"
        annotated.append({
            "name": name,
            "value": value[:500],
            "category": category,
        })

    # Redirect chain
    redirect_chain = [
        {"url": resp.url, "status": resp.status_code}
        for resp in getattr(r, "history", [])
    ]

    return {
        "url": url,
        "final_url": r.url,
        "status": r.status_code,
        "method": method.upper(),
        "headers": annotated,
        "header_count": len(annotated),
        "redirect_chain": redirect_chain,
        "elapsed_ms": round((time.time() - t0) * 1000),
        "elapsed_s": round(time.time() - t0, 2),
    }
