"""
Web Technology Detector — fingerprint the technology stack of a web application.

Detects from:
  - HTTP response headers (Server, X-Powered-By, Set-Cookie, Via, X-Generator)
  - HTML meta tags (generator, framework hints)
  - Script/link src patterns (jQuery, React, Angular, Vue, Bootstrap, etc.)
  - Cookie names (PHPSESSID → PHP, ASP.NET_SessionId → .NET, etc.)
  - Page HTML patterns (WordPress comments, Drupal classes, etc.)
"""
import re
import time
import logging

logger = logging.getLogger("ids_ips")

# Each entry: (name, category, match_fn or None, patterns)
_FINGERPRINTS = [
    # Web servers
    {"name": "Nginx", "cat": "Web Server",
     "header": {"server": r"nginx"}},
    {"name": "Apache", "cat": "Web Server",
     "header": {"server": r"apache"}},
    {"name": "IIS", "cat": "Web Server",
     "header": {"server": r"Microsoft-IIS"}},
    {"name": "Caddy", "cat": "Web Server",
     "header": {"server": r"Caddy"}},
    {"name": "LiteSpeed", "cat": "Web Server",
     "header": {"server": r"LiteSpeed"}},
    {"name": "OpenResty", "cat": "Web Server",
     "header": {"server": r"openresty"}},
    {"name": "Cloudflare", "cat": "CDN",
     "header": {"server": r"cloudflare", "cf-ray": r".+"}},
    {"name": "AWS CloudFront", "cat": "CDN",
     "header": {"x-amz-cf-id": r".+", "via": r"CloudFront"}},
    {"name": "Fastly", "cat": "CDN",
     "header": {"x-served-by": r"cache", "x-cache": r"HIT|MISS"}},
    # Programming languages / runtime
    {"name": "PHP", "cat": "Language",
     "header": {"x-powered-by": r"PHP"},
     "cookie": r"PHPSESSID"},
    {"name": "ASP.NET", "cat": "Language",
     "header": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".+"},
     "cookie": r"ASP\.NET_SessionId|\.ASPXAUTH"},
    {"name": "Node.js / Express", "cat": "Language",
     "header": {"x-powered-by": r"Express"}},
    {"name": "Python / Django", "cat": "Framework",
     "cookie": r"csrftoken|sessionid",
     "html": r'csrfmiddlewaretoken|django'},
    {"name": "Ruby on Rails", "cat": "Framework",
     "header": {"x-powered-by": r"Phusion Passenger"},
     "cookie": r"_session_id|_rails"},
    # CMS
    {"name": "WordPress", "cat": "CMS",
     "html": r'wp-content|wp-includes|WordPress',
     "header": {"x-pingback": r".+"}},
    {"name": "Drupal", "cat": "CMS",
     "html": r'Drupal\.settings|drupal\.js|/sites/default/files',
     "cookie": r"SESS[a-f0-9]+|Drupal\.visitor"},
    {"name": "Joomla", "cat": "CMS",
     "html": r'/media/jui/|Joomla!|/components/com_'},
    {"name": "Magento", "cat": "CMS",
     "html": r'Mage\.Cookies|/skin/frontend/|/js/mage/'},
    {"name": "Shopify", "cat": "E-Commerce",
     "html": r'cdn\.shopify\.com|Shopify\.theme',
     "header": {"x-shopify-stage": r".+"}},
    {"name": "WooCommerce", "cat": "E-Commerce",
     "html": r'woocommerce|wc-ajax'},
    {"name": "PrestaShop", "cat": "E-Commerce",
     "html": r'prestashop|/themes/[^/]+/js/'},
    # JS Frameworks
    {"name": "React", "cat": "JS Framework",
     "html": r'react\.development\.js|react\.production\.min\.js|__reactFiber|data-reactroot'},
    {"name": "Vue.js", "cat": "JS Framework",
     "html": r'vue\.min\.js|vue@\d|__vue__|v-bind:|:class='},
    {"name": "Angular", "cat": "JS Framework",
     "html": r'ng-version|angular\.min\.js|angular/core'},
    {"name": "Next.js", "cat": "JS Framework",
     "html": r'__NEXT_DATA__|/_next/static/'},
    {"name": "Nuxt.js", "cat": "JS Framework",
     "html": r'__NUXT__|/_nuxt/'},
    {"name": "jQuery", "cat": "JS Library",
     "html": r'jquery\.min\.js|jquery-\d+\.\d+'},
    {"name": "Bootstrap", "cat": "CSS Framework",
     "html": r'bootstrap\.min\.css|bootstrap\.min\.js|bootstrap@\d'},
    {"name": "Tailwind CSS", "cat": "CSS Framework",
     "html": r'tailwind|tailwindcss'},
    # Security / Analytics
    {"name": "Cloudflare WAF", "cat": "WAF",
     "header": {"cf-chl-bypass": r".+", "server": r"cloudflare"}},
    {"name": "AWS WAF", "cat": "WAF",
     "header": {"x-amzn-requestid": r".+"}},
    {"name": "Google Analytics", "cat": "Analytics",
     "html": r'google-analytics\.com/analytics\.js|gtag\(|UA-\d+-\d+|G-[A-Z0-9]+'},
    {"name": "Google Tag Manager", "cat": "Analytics",
     "html": r'googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]+'},
    {"name": "Matomo", "cat": "Analytics",
     "html": r'matomo\.js|piwik\.js'},
    # Hosting
    {"name": "GitHub Pages", "cat": "Hosting",
     "header": {"server": r"GitHub\.com"}},
    {"name": "Vercel", "cat": "Hosting",
     "header": {"x-vercel-id": r".+", "server": r"Vercel"}},
    {"name": "Netlify", "cat": "Hosting",
     "header": {"server": r"Netlify", "x-nf-request-id": r".+"}},
    {"name": "Heroku", "cat": "Hosting",
     "header": {"via": r"1\.1 vegur"}},
]


def _match_fingerprint(fp: dict, headers: dict, cookies: str, html: str) -> bool:
    matched = False
    if "header" in fp:
        for hkey, pattern in fp["header"].items():
            val = headers.get(hkey.lower(), "")
            if val and re.search(pattern, val, re.I):
                matched = True
                break
    if not matched and "cookie" in fp:
        if re.search(fp["cookie"], cookies, re.I):
            matched = True
    if not matched and "html" in fp:
        if re.search(fp["html"], html, re.I):
            matched = True
    return matched


def detect(url: str, timeout: float = 12.0) -> dict:
    """
    Detect web technologies used by the target URL.

    Returns:
        {url, technologies:[{name, cat}], by_category:{cat:[names]},
         http_status, server, powered_by, elapsed_s}
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
                     headers={"User-Agent": "Mozilla/5.0 (TechDetector/1.0)"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        cookies = "; ".join(f"{c.name}={c.value}" for c in r.cookies)
        html = r.text[:200_000]
        status = r.status_code
    except Exception as exc:
        return {"url": url, "error": str(exc), "elapsed_s": round(time.time() - t0, 2)}

    detected = []
    for fp in _FINGERPRINTS:
        if _match_fingerprint(fp, headers, cookies, html):
            detected.append({"name": fp["name"], "category": fp["cat"]})

    by_category: dict = {}
    for tech in detected:
        by_category.setdefault(tech["category"], []).append(tech["name"])

    return {
        "url": url,
        "final_url": r.url,
        "http_status": status,
        "technologies": detected,
        "by_category": by_category,
        "total": len(detected),
        "server": headers.get("server", ""),
        "powered_by": headers.get("x-powered-by", ""),
        "generator": re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I) and
                     re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.I).group(1) or "",
        "elapsed_s": round(time.time() - t0, 2),
    }
