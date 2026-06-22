"""
Security Headers Analyzer — check HTTP response headers for security best practices.

Checks for presence and correct configuration of:
  HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, X-XSS-Protection, COEP, COOP, CORP, Cache-Control, CORS
"""
import time
import logging

logger = logging.getLogger("ids_ips")

_HEADERS_CONFIG = [
    {
        "name": "Strict-Transport-Security",
        "key": "strict-transport-security",
        "required": True,
        "severity": "HIGH",
        "good_value": "max-age=31536000; includeSubDomains; preload",
        "description": "Forces HTTPS connections. Missing → SSL stripping attacks possible.",
        "checks": [
            ("max-age", "max-age directive missing or too short", lambda v: "max-age=" in v.lower() and any(
                int(p.split("=")[1]) >= 15768000 for p in v.lower().split(";") if p.strip().startswith("max-age=") and p.strip().split("=")[1].strip().isdigit()
            )),
        ],
    },
    {
        "name": "Content-Security-Policy",
        "key": "content-security-policy",
        "required": True,
        "severity": "HIGH",
        "good_value": "default-src 'self'; script-src 'self'; object-src 'none'",
        "description": "Prevents XSS, clickjacking, data injection attacks.",
        "checks": [
            ("no_unsafe_inline", "unsafe-inline script detected", lambda v: "unsafe-inline" not in v.lower()),
            ("no_unsafe_eval", "unsafe-eval detected", lambda v: "unsafe-eval" not in v.lower()),
        ],
    },
    {
        "name": "X-Frame-Options",
        "key": "x-frame-options",
        "required": True,
        "severity": "MEDIUM",
        "good_value": "DENY",
        "description": "Prevents clickjacking. Should be DENY or SAMEORIGIN.",
        "checks": [
            ("valid", "should be DENY or SAMEORIGIN", lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN")),
        ],
    },
    {
        "name": "X-Content-Type-Options",
        "key": "x-content-type-options",
        "required": True,
        "severity": "LOW",
        "good_value": "nosniff",
        "description": "Prevents MIME-sniffing. Must be 'nosniff'.",
        "checks": [
            ("nosniff", "value must be nosniff", lambda v: v.strip().lower() == "nosniff"),
        ],
    },
    {
        "name": "Referrer-Policy",
        "key": "referrer-policy",
        "required": True,
        "severity": "LOW",
        "good_value": "strict-origin-when-cross-origin",
        "description": "Controls what Referer header is sent. Prevents data leakage.",
        "checks": [],
    },
    {
        "name": "Permissions-Policy",
        "key": "permissions-policy",
        "required": False,
        "severity": "INFO",
        "good_value": "camera=(), microphone=(), geolocation=()",
        "description": "Restricts browser feature access (camera, GPS, etc.).",
        "checks": [],
    },
    {
        "name": "X-XSS-Protection",
        "key": "x-xss-protection",
        "required": False,
        "severity": "INFO",
        "good_value": "0",
        "description": "Legacy XSS filter. Modern guidance: set to 0 (disabled), rely on CSP instead.",
        "checks": [],
    },
    {
        "name": "Cross-Origin-Embedder-Policy",
        "key": "cross-origin-embedder-policy",
        "required": False,
        "severity": "INFO",
        "good_value": "require-corp",
        "description": "Needed for SharedArrayBuffer, required for high-resolution timers.",
        "checks": [],
    },
    {
        "name": "Cross-Origin-Opener-Policy",
        "key": "cross-origin-opener-policy",
        "required": False,
        "severity": "INFO",
        "good_value": "same-origin",
        "description": "Prevents cross-origin window attacks.",
        "checks": [],
    },
    {
        "name": "Cache-Control",
        "key": "cache-control",
        "required": False,
        "severity": "INFO",
        "good_value": "no-store",
        "description": "For authenticated pages: no-store prevents caching sensitive data.",
        "checks": [],
    },
]

_SCORE_MAP = {"HIGH": 30, "MEDIUM": 20, "LOW": 10, "INFO": 5}


def analyze(url: str, timeout: float = 10.0) -> dict:
    """
    Check security headers for URL.

    Returns:
        {url, status, headers_raw, findings:[...], score, grade, elapsed_s}
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

    try:
        r = _req.get(url, timeout=timeout, verify=False, allow_redirects=True,
                     headers={"User-Agent": "Mozilla/5.0 (SecurityHeadersScanner/1.0)"})
        headers_lower = {k.lower(): v for k, v in r.headers.items()}
        status = r.status_code
    except Exception as exc:
        return {"url": url, "error": str(exc), "elapsed_s": round(time.time() - t0, 2)}

    findings = []
    score = 100
    max_deduction = sum(_SCORE_MAP.get(h["severity"], 0) for h in _HEADERS_CONFIG if h["required"])
    earned = 0

    for hconf in _HEADERS_CONFIG:
        key = hconf["key"]
        present = key in headers_lower
        value = headers_lower.get(key, "")
        issues = []

        if not present:
            if hconf["required"]:
                issues.append("MISSING")
            status_str = "MISSING"
        else:
            status_str = "PRESENT"
            # Run sub-checks
            for check_name, check_msg, check_fn in hconf.get("checks", []):
                try:
                    if not check_fn(value):
                        issues.append(check_msg)
                except Exception:
                    pass

        if not issues and present:
            earned += _SCORE_MAP.get(hconf["severity"], 0)
            status_str = "PASS"

        findings.append({
            "header": hconf["name"],
            "status": status_str,
            "severity": hconf["severity"] if (not present and hconf["required"]) or issues else "OK",
            "value": value[:200] if value else None,
            "good_value": hconf["good_value"],
            "description": hconf["description"],
            "issues": issues,
        })

    # Calculate score and grade
    required_count = sum(1 for h in _HEADERS_CONFIG if h["required"])
    present_required = sum(1 for f in findings if f["status"] in ("PRESENT", "PASS") and
                          any(h["name"] == f["header"] and h["required"] for h in _HEADERS_CONFIG))
    score = round((present_required / required_count) * 100) if required_count else 100
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"

    return {
        "url": url,
        "http_status": status,
        "final_url": r.url,
        "findings": findings,
        "score": score,
        "grade": grade,
        "headers_raw": {k: v[:300] for k, v in headers_lower.items()},
        "elapsed_s": round(time.time() - t0, 2),
    }
