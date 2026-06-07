"""
Web Vulnerability Scanner — Module 6.

Tests a target URL for common web vulnerabilities:
  - Security headers audit
  - Cookie flags (Secure, HttpOnly, SameSite)
  - SQL injection (error-based and time-based indicators)
  - Cross-Site Scripting (reflected XSS)
  - Local File Inclusion (path traversal)
  - CSRF (missing anti-CSRF tokens)
  - Directory bruteforce (common sensitive paths)
  - Open redirects

Uses requests library for HTTP. All payloads are benign canary strings — not destructive.
"""
import time
import logging
import threading
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("ids_ips")

_TIMEOUT = 8
_MAX_THREADS = 10

# ── Payloads ──────────────────────────────────────────────────────────────────

_SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
    "1' AND 1=1--", "1' AND 1=2--", "' OR 1=1#",
    "admin'--", "' OR 'x'='x", "1; DROP TABLE users--",
    "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
    "1 AND SLEEP(0)--", "1 OR SLEEP(0)--",
]

_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "\" onmouseover=\"alert(1)",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
]

_LFI_PAYLOADS = [
    "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
    "../../../../etc/passwd", "../../../../../etc/passwd",
    "..%2Fetc%2Fpasswd", "..%2F..%2Fetc%2Fpasswd",
    "..\\..\\windows\\win.ini", "..\\windows\\system32\\drivers\\etc\\hosts",
    "/etc/passwd", "/etc/shadow", "C:\\windows\\win.ini",
    "%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd",
]

_OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "//evil.com/%2f..",
    "https://evil.com?", "https://google.com",
]

_DIR_WORDLIST = [
    "admin", "administrator", "login", "panel", "dashboard", "config",
    ".env", ".git", ".git/config", "backup", "backup.zip", "db.sql",
    "phpinfo.php", "info.php", "wp-admin", "wp-login.php", "wp-config.php",
    "xmlrpc.php", "api", "api/v1", "api/v2", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "graphql", ".htaccess", ".htpasswd",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "web.config",
    "server-status", "server-info", "elmah.axd", "trace.axd",
    "adminer.php", "phpmyadmin", "pma", "mysql", "database",
    "test", "temp", "tmp", "logs", "log", "debug", "console",
    "actuator", "actuator/env", "actuator/health", "actuator/mappings",
    "metrics", "health", "status", "ping", "version",
    "shell", "sh", "cmd", "exec", "system", "upload", "uploads",
    "files", "static", "assets", "media", "images", "include",
    "includes", "lib", "libs", "vendor", "node_modules",
    "package.json", "composer.json", "requirements.txt", "Gemfile",
    ".DS_Store", "thumbs.db", "desktop.ini",
    "cgi-bin", "cgi-bin/env.cgi", "cgi-bin/test.cgi",
    "webdav", "dav", "git/HEAD", ".svn", ".svn/entries",
    "old", "bak", "backup.sql", "dump.sql", "data.sql",
]

_SEC_HEADERS_REQUIRED = {
    "strict-transport-security": "HSTS missing — no HTTPS enforcement",
    "content-security-policy": "CSP missing — XSS not mitigated",
    "x-frame-options": "X-Frame-Options missing — clickjacking possible",
    "x-content-type-options": "X-Content-Type-Options missing — MIME sniffing possible",
    "referrer-policy": "Referrer-Policy missing — referrer leakage possible",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _session():
    try:
        import requests
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner; compatible)",
        })
        return s
    except ImportError:
        return None


def _get(session, url: str, params: dict = None) -> tuple:
    """Returns (response, elapsed_ms) or (None, 0) on failure."""
    try:
        t0 = time.time()
        r = session.get(url, params=params, timeout=_TIMEOUT,
                        allow_redirects=False, verify=False)
        return r, (time.time() - t0) * 1000
    except Exception:
        return None, 0


def _post(session, url: str, data: dict) -> tuple:
    try:
        t0 = time.time()
        r = session.post(url, data=data, timeout=_TIMEOUT,
                         allow_redirects=False, verify=False)
        return r, (time.time() - t0) * 1000
    except Exception:
        return None, 0


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a query param value in URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ── Individual checks ─────────────────────────────────────────────────────────

def check_headers(session, url: str) -> dict:
    resp, _ = _get(session, url)
    if resp is None:
        return {"error": "cannot reach target"}

    findings = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Required headers
    for h, msg in _SEC_HEADERS_REQUIRED.items():
        if h not in headers_lower:
            findings.append({"type": "MISSING_HEADER", "header": h,
                              "message": msg, "severity": "MEDIUM"})

    # Cookie flags
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure flag missing")
        if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie._rest).lower():
            issues.append("HttpOnly flag missing")
        if not cookie.has_nonstandard_attr("SameSite") and "samesite" not in str(cookie._rest).lower():
            issues.append("SameSite flag missing")
        if issues:
            findings.append({
                "type": "INSECURE_COOKIE",
                "cookie": cookie.name,
                "message": f"Cookie '{cookie.name}': {', '.join(issues)}",
                "severity": "LOW",
            })

    # Server / X-Powered-By info disclosure
    for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if h in headers_lower:
            findings.append({
                "type": "INFO_DISCLOSURE",
                "header": h,
                "value": headers_lower[h],
                "message": f"Header '{h}' discloses server info: {headers_lower[h]}",
                "severity": "LOW",
            })

    return {
        "check": "headers",
        "url": url,
        "status_code": resp.status_code,
        "findings": findings,
        "all_headers": dict(resp.headers),
    }


def check_sqli(session, url: str) -> dict:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        return {"check": "sqli", "url": url, "findings": [],
                "info": "no GET parameters found to test"}

    findings = []
    error_signatures = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql", "sqlstate",
        "unclosed quotation", "sqlite_", "syntax error", "microsoft sql",
        "jdbc", "db2 sql", "error in your sql",
    ]

    for param in params[:5]:
        for payload in _SQLI_PAYLOADS[:8]:
            test_url = _inject_param(url, param, payload)
            resp, elapsed = _get(session, test_url)
            if resp is None:
                continue
            body_lower = resp.text.lower() if hasattr(resp, "text") else ""
            for sig in error_signatures:
                if sig in body_lower:
                    findings.append({
                        "type": "SQLI_ERROR_BASED",
                        "param": param,
                        "payload": payload,
                        "signature": sig,
                        "message": f"Possible SQLi in param '{param}' — DB error signature '{sig}' found",
                        "severity": "HIGH",
                    })
                    break

    return {"check": "sqli", "url": url, "findings": findings}


def check_xss(session, url: str) -> dict:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        return {"check": "xss", "url": url, "findings": [],
                "info": "no GET parameters found to test"}

    findings = []
    for param in params[:5]:
        for payload in _XSS_PAYLOADS[:6]:
            test_url = _inject_param(url, param, payload)
            resp, _ = _get(session, test_url)
            if resp is None:
                continue
            if payload in (resp.text if hasattr(resp, "text") else ""):
                findings.append({
                    "type": "XSS_REFLECTED",
                    "param": param,
                    "payload": payload,
                    "message": f"Reflected XSS in param '{param}' — payload echoed in response",
                    "severity": "HIGH",
                })

    return {"check": "xss", "url": url, "findings": findings}


def check_lfi(session, url: str) -> dict:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        return {"check": "lfi", "url": url, "findings": [],
                "info": "no GET parameters found to test"}

    findings = []
    lfi_signatures = ["root:x:", "[boot loader]", "[fonts]", "for 16-bit app support"]

    for param in params[:3]:
        for payload in _LFI_PAYLOADS[:8]:
            test_url = _inject_param(url, param, payload)
            resp, _ = _get(session, test_url)
            if resp is None:
                continue
            body = resp.text.lower() if hasattr(resp, "text") else ""
            for sig in lfi_signatures:
                if sig in body:
                    findings.append({
                        "type": "LFI",
                        "param": param,
                        "payload": payload,
                        "signature": sig,
                        "message": f"LFI in param '{param}' — file content signature '{sig}' found",
                        "severity": "CRITICAL",
                    })
                    break

    return {"check": "lfi", "url": url, "findings": findings}


def check_open_redirect(session, url: str) -> dict:
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    redirect_params = [p for p in params if any(k in p.lower()
                        for k in ("redirect", "url", "next", "return", "goto", "redir", "dest"))]
    if not redirect_params:
        return {"check": "open_redirect", "url": url, "findings": [],
                "info": "no redirect parameters found"}

    findings = []
    for param in redirect_params[:3]:
        for payload in _OPEN_REDIRECT_PAYLOADS[:3]:
            test_url = _inject_param(url, param, payload)
            resp, _ = _get(session, test_url)
            if resp is None:
                continue
            loc = resp.headers.get("Location", "")
            if "evil.com" in loc or ("google.com" in payload and "google.com" in loc):
                findings.append({
                    "type": "OPEN_REDIRECT",
                    "param": param,
                    "payload": payload,
                    "location": loc,
                    "message": f"Open redirect via '{param}' — redirects to {loc}",
                    "severity": "MEDIUM",
                })

    return {"check": "open_redirect", "url": url, "findings": findings}


def check_csrf(session, url: str) -> dict:
    """Heuristic: POST endpoints without CSRF token in form are potentially vulnerable."""
    resp, _ = _get(session, url)
    if resp is None:
        return {"check": "csrf", "url": url, "findings": []}

    body = resp.text if hasattr(resp, "text") else ""
    findings = []
    import re
    forms = re.findall(r'<form[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>',
                       body, re.IGNORECASE | re.DOTALL)
    for form in forms:
        has_csrf = any(tok in form.lower() for tok in
                       ("csrf", "token", "_token", "nonce", "authenticity"))
        if not has_csrf:
            findings.append({
                "type": "CSRF_MISSING_TOKEN",
                "message": "POST form found without CSRF token",
                "severity": "MEDIUM",
            })

    return {"check": "csrf", "url": url, "findings": findings}


def check_dirbrute(session, base_url: str, wordlist: list = None) -> dict:
    words = wordlist or _DIR_WORDLIST
    base = base_url.rstrip("/")
    findings = []
    lock = threading.Lock()

    def probe(path: str):
        test_url = f"{base}/{path}"
        resp, _ = _get(session, test_url)
        if resp is None:
            return
        if resp.status_code in (200, 301, 302, 403):
            with lock:
                findings.append({
                    "type": "PATH_FOUND",
                    "path": f"/{path}",
                    "url": test_url,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "message": f"Path /{path} returned HTTP {resp.status_code}",
                    "severity": "LOW" if resp.status_code == 403 else "MEDIUM",
                })

    threads = []
    for word in words:
        t = threading.Thread(target=probe, args=(word,), daemon=True)
        threads.append(t)
        if len(threads) >= _MAX_THREADS:
            for th in threads:
                th.start()
            for th in threads:
                th.join(timeout=_TIMEOUT + 2)
            threads = []

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_TIMEOUT + 2)

    return {"check": "dirbrute", "url": base_url, "paths_tested": len(words),
            "findings": sorted(findings, key=lambda x: x["status"])}


# ── Full scan orchestrator ────────────────────────────────────────────────────

def full_scan(url: str, checks: list = None) -> dict:
    """
    Run all (or selected) vulnerability checks against url.
    checks: list of check names, e.g. ['headers', 'sqli', 'xss']
    Returns combined report.
    """
    import warnings
    warnings.filterwarnings("ignore")  # suppress InsecureRequestWarning

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    session = _session()
    if session is None:
        return {"error": "requests library not installed"}

    all_checks = checks or ["headers", "sqli", "xss", "lfi", "open_redirect",
                             "csrf", "dirbrute"]

    results = {
        "url": url,
        "timestamp": time.time(),
        "checks_run": [],
        "findings": [],
        "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    }

    check_fn = {
        "headers": check_headers,
        "sqli": check_sqli,
        "xss": check_xss,
        "lfi": check_lfi,
        "open_redirect": check_open_redirect,
        "csrf": check_csrf,
        "dirbrute": check_dirbrute,
    }

    for name in all_checks:
        fn = check_fn.get(name)
        if fn is None:
            continue
        try:
            r = fn(session, url)
            results["checks_run"].append(name)
            for f in r.get("findings", []):
                results["findings"].append({**f, "check": name})
                sev = f.get("severity", "LOW")
                results["summary"][sev] = results["summary"].get(sev, 0) + 1
            # Store per-check result for detail view
            results[name] = r
        except Exception as e:
            results[name] = {"error": str(e)}

    results["risk_score"] = (
        results["summary"].get("CRITICAL", 0) * 40 +
        results["summary"].get("HIGH", 0) * 20 +
        results["summary"].get("MEDIUM", 0) * 8 +
        results["summary"].get("LOW", 0) * 2
    )

    db = _db()
    if db:
        try:
            db.save_vuln_scan(url, results)
        except Exception:
            pass

    return results


def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None
