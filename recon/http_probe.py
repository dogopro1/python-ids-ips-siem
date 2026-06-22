"""
HTTP Probe — bulk status/title/server check for multiple hosts.

Probes each target: HTTP status code, page title, server header,
redirect chain, response time, content length.
"""
import time
import re
import logging
import concurrent.futures

logger = logging.getLogger("ids_ips")


def _probe_single(target: str, timeout: float = 8.0) -> dict:
    try:
        import requests as _req
    except ImportError:
        return {"target": target, "error": "requests required"}

    import warnings
    warnings.filterwarnings("ignore")

    if not target.startswith(("http://", "https://")):
        targets_to_try = [f"https://{target}", f"http://{target}"]
    else:
        targets_to_try = [target]

    for probe_url in targets_to_try:
        try:
            t0 = time.time()
            r = _req.get(
                probe_url, timeout=timeout, verify=False,
                allow_redirects=True,
                headers={
                    "User-Agent": "Mozilla/5.0 (HTTPProbe/1.0)",
                    "Accept": "text/html,application/xhtml+xml,*/*",
                },
            )
            elapsed = round((time.time() - t0) * 1000)

            # Extract title
            m = re.search(r"<title[^>]*>([^<]{1,200})</title>", r.text, re.I)
            title = m.group(1).strip()[:100] if m else ""

            # Redirect chain
            redirect_chain = [resp.url for resp in r.history]

            # Security headers present
            headers = dict(r.headers)
            has_hsts = "strict-transport-security" in {k.lower() for k in headers}
            has_csp = "content-security-policy" in {k.lower() for k in headers}

            return {
                "target": target,
                "url": r.url,
                "status": r.status_code,
                "title": title,
                "server": headers.get("Server", headers.get("server", "")),
                "x_powered_by": headers.get("X-Powered-By", headers.get("x-powered-by", "")),
                "content_type": headers.get("Content-Type", "").split(";")[0],
                "content_length": len(r.content),
                "response_time_ms": elapsed,
                "redirect_count": len(r.history),
                "redirect_chain": redirect_chain[:5],
                "has_hsts": has_hsts,
                "has_csp": has_csp,
                "live": True,
            }
        except Exception as exc:
            continue

    return {"target": target, "live": False, "error": "unreachable", "status": None}


def probe(
    targets: list,
    concurrency: int = 20,
    timeout: float = 8.0,
) -> dict:
    """
    Probe multiple hosts concurrently.

    Args:
        targets: list of hostnames or URLs
        concurrency: parallel workers
        timeout: per-request timeout

    Returns:
        {results:[...], total, live_count, elapsed_s}
    """
    t0 = time.time()
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, len(targets) or 1)) as ex:
        futures = {ex.submit(_probe_single, t, timeout): t for t in targets}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 3):
            try:
                results.append(f.result())
            except Exception:
                results.append({"target": futures[f], "error": "timeout", "live": False})

    results.sort(key=lambda r: (not r.get("live"), r.get("target", "")))
    return {
        "results": results,
        "total": len(results),
        "live_count": sum(1 for r in results if r.get("live")),
        "elapsed_s": round(time.time() - t0, 2),
    }
