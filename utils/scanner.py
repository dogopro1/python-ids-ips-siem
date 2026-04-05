import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket
import time
import html.parser
import logging
import random

logger = logging.getLogger("ids_ips")

_BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

_TECH_SIGS = [
    ("React",          ["react.min.js", "react.development.js", "reactdom", "/react/"]),
    ("Vue.js",         ["vue.min.js", "vue.js", "__vue__", "/vue@"]),
    ("Angular",        ["angular.min.js", "ng-app=", "ng-controller", "/angular/"]),
    ("jQuery",         ["jquery.min.js", "jquery.js", "/jquery-", "/jquery@"]),
    ("Bootstrap",      ["bootstrap.min.css", "bootstrap.css", "bootstrap.min.js"]),
    ("Tailwind CSS",   ["tailwind.min.css", "tailwindcss", "cdn.tailwindcss.com"]),
    ("Next.js",        ["/_next/", "__next", "next/dist"]),
    ("Nuxt.js",        ["/_nuxt/", "__nuxt"]),
    ("Gatsby",         ["/gatsby-", "___gatsby"]),
    ("WordPress",      ["wp-content/", "wp-includes/", "wp-json", "/wp-login"]),
    ("Drupal",         ["sites/default/files", "drupal.js", "/drupal/"]),
    ("Joomla",         ["/components/com_", "/media/jui/"]),
    ("WooCommerce",    ["woocommerce", "/woo-"]),
    ("Shopify",        ["cdn.shopify.com", "shopify.theme"]),
    ("Google Analytics", ["google-analytics.com/analytics.js", "gtag('config", "ga('send"]),
    ("Google Tag Manager", ["googletagmanager.com/gtm.js", "gtm.js"]),
    ("Cloudflare",     ["cloudflare.com/cdn-cgi/", "__cf_", "cf_clearance"]),
    ("Font Awesome",   ["font-awesome", "fontawesome", "fa-solid", "fa-brands"]),
    ("Webpack",        ["/webpack.js", "webpackJsonp", "__webpack_require__"]),
]

_SEC_HEADERS = [
    ("strict-transport-security",   "HSTS",                   True),
    ("content-security-policy",     "Content-Security-Policy", True),
    ("x-frame-options",             "X-Frame-Options",         True),
    ("x-content-type-options",      "X-Content-Type-Options",  True),
    ("referrer-policy",             "Referrer-Policy",         True),
    ("permissions-policy",          "Permissions-Policy",      False),
    ("x-xss-protection",            "X-XSS-Protection",        False),
    ("cross-origin-opener-policy",  "COOP",                    False),
]


class _LinkParser(html.parser.HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: list = []
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "a" and "href" in attrs_d:
            href = attrs_d["href"].strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full = urllib.parse.urljoin(self.base, href)
                self.links.append({"href": href, "full": full, "text": ""})
        if tag == "title":
            self._in_title = True

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False


def _make_ctx(verify: bool = True) -> ssl.SSLContext:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get_tls_info(hostname: str, port: int = 443) -> dict:
    try:
        ctx = _make_ctx(verify=True)
        with socket.create_connection((hostname, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as s:
                cert = s.getpeercert()
                cipher = s.cipher()
                version = s.version()
        subject = {k: v for kv in cert.get("subject", []) for k, v in kv}
        issuer = {k: v for kv in cert.get("issuer", []) for k, v in kv}
        san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        return {
            "valid": True,
            "version": version,
            "cipher": cipher[0] if cipher else None,
            "bits": cipher[2] if cipher else None,
            "subject": subject,
            "issuer": issuer,
            "cn": subject.get("commonName", ""),
            "issuer_cn": issuer.get("organizationName", ""),
            "not_after": cert.get("notAfter", ""),
            "san": san,
        }
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": f"Invalid certificate: {e}"}
    except Exception as e:
        return {"valid": None, "error": str(e)}


def analyze(url: str, crawl: bool = True, save_html: bool = False) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""

    result = {
        "url": url, "final_url": url, "hostname": hostname,
        "status_code": None, "response_time_ms": None,
        "server": None, "content_type": None, "content_length": None,
        "title": None,
        "redirect_chain": [],
        "tls": {},
        "security_headers": {},
        "missing_critical": [],
        "risk_score": 0,
        "links": [],
        "html_preview": None,
        "robots_txt": None,
        "error": None,
    }

    # TLS
    if parsed.scheme == "https":
        result["tls"] = _get_tls_info(hostname, parsed.port or 443)

    # HTTP request
    ctx = _make_ctx(parsed.scheme == "https")
    t0 = time.time()
    try:
        opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (IDS-Scanner/1.0; Security Research)"},
        )
        with opener.open(req, timeout=10) as resp:
            elapsed = int((time.time() - t0) * 1000)
            body = resp.read(1_048_576)  # max 1 MB
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            result.update({
                "status_code": resp.status,
                "response_time_ms": elapsed,
                "final_url": resp.url,
                "server": hdrs.get("server", ""),
                "content_type": hdrs.get("content-type", ""),
                "content_length": hdrs.get("content-length") or str(len(body)),
            })

        # Security headers
        missing = []
        for hdr, label, important in _SEC_HEADERS:
            present = hdr in hdrs
            result["security_headers"][label] = {
                "present": present,
                "value": hdrs.get(hdr, ""),
                "important": important,
            }
            if important and not present:
                missing.append(label)
        result["missing_critical"] = missing
        # Risk: missing critical headers + HTTP instead of HTTPS
        result["risk_score"] = min(100, len(missing) * 15 + (20 if parsed.scheme == "http" else 0))

        # Parse HTML
        if "html" in result["content_type"].lower():
            try:
                encoding = "utf-8"
                for part in result["content_type"].split(";"):
                    if "charset=" in part:
                        encoding = part.split("=", 1)[1].strip()
                html_text = body.decode(encoding, errors="replace")
                if save_html:
                    result["html_preview"] = html_text[:50000]
                parser = _LinkParser(result["final_url"])
                parser.feed(html_text)
                result["title"] = parser.title.strip()
                if crawl:
                    result["links"] = parser.links[:200]
            except Exception as e:
                result["links"] = []
                logger.debug("HTML parse error: %s", e)

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = str(e)
    except Exception as e:
        result["error"] = str(e)

    # robots.txt
    try:
        robots_url = f"{parsed.scheme}://{hostname}/robots.txt"
        req2 = urllib.request.Request(robots_url, headers={"User-Agent": "IDS-Scanner/1.0"})
        with urllib.request.urlopen(req2, timeout=5, context=ctx) as r:
            result["robots_txt"] = r.read(16384).decode(errors="replace")
    except Exception:
        result["robots_txt"] = None

    return result


def detect_tech(html_body: str, headers: dict) -> list:
    """Detect technology stack from HTML content and response headers."""
    detected = []
    body_lower = (html_body or "").lower()
    server = (headers.get("server") or "").lower()
    x_powered = (headers.get("x-powered-by") or "").lower()
    ct = (headers.get("content-type") or "").lower()

    # Server header
    for name, kws in [("Apache", ["apache"]), ("Nginx", ["nginx"]), ("IIS", ["iis", "microsoft-iis"]),
                      ("LiteSpeed", ["litespeed"]), ("Caddy", ["caddy"]), ("Cloudflare", ["cloudflare"])]:
        if any(k in server for k in kws):
            detected.append({"name": name, "source": "Server header", "value": server})

    # X-Powered-By
    if x_powered:
        for name, kws in [("PHP", ["php"]), ("ASP.NET", ["asp.net"]), ("Express.js", ["express"]),
                          ("Ruby on Rails", ["phusion passenger", "ruby"])]:
            if any(k in x_powered for k in kws):
                detected.append({"name": name, "source": "X-Powered-By", "value": x_powered})

    # HTML body
    for tech, sigs in _TECH_SIGS:
        if any(s in body_lower for s in sigs):
            if not any(d["name"] == tech for d in detected):
                detected.append({"name": tech, "source": "HTML signature", "value": ""})

    return detected


class _AssetParser(html.parser.HTMLParser):
    """Extracts all links, images, scripts, and stylesheets from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base = base_url
        self.links: list = []
        self.images: list = []
        self.scripts: list = []
        self.stylesheets: list = []
        self.title: str = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "a" and "href" in attrs_d:
            href = (attrs_d["href"] or "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                full = urllib.parse.urljoin(self.base, href)
                if full not in self.links:
                    self.links.append(full)
        elif tag == "img" and "src" in attrs_d:
            src = (attrs_d["src"] or "").strip()
            if src and not src.startswith("data:"):
                full = urllib.parse.urljoin(self.base, src)
                if full not in self.images:
                    self.images.append(full)
        elif tag == "script" and "src" in attrs_d:
            src = (attrs_d["src"] or "").strip()
            if src:
                full = urllib.parse.urljoin(self.base, src)
                if full not in self.scripts:
                    self.scripts.append(full)
        elif tag == "link":
            rel = (attrs_d.get("rel") or "").lower()
            href = (attrs_d.get("href") or "").strip()
            if "stylesheet" in rel and href:
                full = urllib.parse.urljoin(self.base, href)
                if full not in self.stylesheets:
                    self.stylesheets.append(full)
        if tag == "title":
            self._in_title = True

    def handle_data(self, data):
        if self._in_title:
            self.title += data

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False


def _download_asset(url: str, dest_dir: str, ua: str) -> dict:
    """Download one asset file into dest_dir. Returns result metadata."""
    import os
    import re as _re

    try:
        parsed = urllib.parse.urlparse(url)
        ctx = _make_ctx(verify=False)  # lenient for cross-origin assets
        req = urllib.request.Request(url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            data = resp.read(2 * 1024 * 1024)  # 2 MB per asset
        raw_name = os.path.basename(parsed.path) or "asset"
        filename = _re.sub(r"[^\w.\-]", "_", raw_name)[:80]
        if not filename or filename == "_":
            filename = f"asset_{abs(hash(url)) % 9999999}"
        filepath = os.path.join(dest_dir, filename)
        if os.path.exists(filepath):
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{abs(hash(url)) % 9999}{ext}"
            filepath = os.path.join(dest_dir, filename)
        with open(filepath, "wb") as f:
            f.write(data)
        return {"url": url, "filename": filename, "size": len(data), "ok": True}
    except Exception as e:
        return {"url": url, "error": str(e), "ok": False}


def scrape_page(url: str, save_dir: str, include_assets: bool = False) -> dict:
    """
    Scrape a single page: saves raw HTML + manifest.json to save_dir.
    Extracts all links, images, scripts, stylesheets.
    If include_assets=True, also downloads CSS/JS/images.
    """
    import os
    import json as _json

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urllib.parse.urlparse(url)
    ua = random.choice(_BROWSER_UAS)
    ctx = _make_ctx(verify=False)

    try:
        os.makedirs(save_dir, exist_ok=True)
    except Exception as e:
        return {"error": f"Cannot create directory: {e}", "url": url}

    t0 = time.time()
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "close",
        })
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            status_code = resp.status
            elapsed = int((time.time() - t0) * 1000)
            final_url = resp.url
            hdrs = dict(resp.headers)
            content_type = hdrs.get("Content-Type", "")
            raw = resp.read(5 * 1024 * 1024)  # 5 MB page limit
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}

    # Decode
    encoding = "utf-8"
    for part in content_type.split(";"):
        part = part.strip()
        if part.lower().startswith("charset="):
            encoding = part.split("=", 1)[1].strip().strip('"')
    html_text = raw.decode(encoding, errors="replace")

    # Parse all assets
    asset_parser = _AssetParser(final_url)
    try:
        asset_parser.feed(html_text)
    except Exception:
        pass

    # Save HTML
    html_path = os.path.join(save_dir, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_text)
    files_saved = ["index.html"]

    # Optionally download assets
    asset_results = []
    if include_assets:
        assets_dir = os.path.join(save_dir, "assets")
        os.makedirs(assets_dir, exist_ok=True)
        all_asset_urls = (asset_parser.stylesheets + asset_parser.scripts + asset_parser.images)[:50]
        for asset_url in all_asset_urls:
            res = _download_asset(asset_url, assets_dir, ua)
            asset_results.append(res)
            if res.get("ok"):
                files_saved.append(f"assets/{res['filename']}")

    # Build and save manifest
    manifest = {
        "url": url,
        "final_url": final_url,
        "scraped_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status_code": status_code,
        "response_ms": elapsed,
        "size_bytes": len(raw),
        "content_type": content_type,
        "title": asset_parser.title.strip(),
        "links_count": len(asset_parser.links),
        "links": asset_parser.links[:500],
        "images": asset_parser.images[:100],
        "scripts": asset_parser.scripts[:100],
        "stylesheets": asset_parser.stylesheets[:50],
        "assets_downloaded": sum(1 for r in asset_results if r.get("ok")),
        "asset_results": asset_results,
        "save_dir": save_dir,
        "files_saved": files_saved,
    }

    manifest_path = os.path.join(save_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        _json.dump(manifest, f, indent=2, ensure_ascii=False)
    manifest["files_saved"].append("manifest.json")

    return manifest


def crawl_anon(url: str, max_pages: int = 8, fake_ua: bool = True) -> dict:
    """Crawl a site anonymously using a browser-spoofed user agent."""
    ua = random.choice(_BROWSER_UAS) if fake_ua else "Mozilla/5.0"
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    ctx = _make_ctx(parsed.scheme == "https")

    visited: dict = {}
    queue = [url]
    errors = []

    while queue and len(visited) < max_pages:
        cur_url = queue.pop(0)
        if cur_url in visited:
            continue

        page = {"url": cur_url, "status": None, "title": None, "links_found": 0,
                "size_bytes": 0, "response_ms": None, "error": None}
        t0 = time.time()
        try:
            req = urllib.request.Request(cur_url, headers={
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "DNT": "1",
            })
            with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                page["status"] = resp.status
                page["response_ms"] = int((time.time() - t0) * 1000)
                ct_h = resp.headers.get("Content-Type", "")
                if "html" in ct_h:
                    body = resp.read(512 * 1024)
                    page["size_bytes"] = len(body)
                    text = body.decode(errors="replace")
                    parser = _LinkParser(cur_url)
                    parser.feed(text)
                    page["title"] = parser.title.strip()
                    page["links_found"] = len(parser.links)
                    for lnk in parser.links:
                        full = lnk["full"]
                        if full.startswith(base) and full not in visited and full not in queue:
                            queue.append(full)
        except Exception as e:
            page["error"] = str(e)
            errors.append(f"{cur_url}: {e}")
        visited[cur_url] = page

    return {
        "base_url": url,
        "user_agent": ua,
        "pages_crawled": len(visited),
        "pages": list(visited.values()),
        "errors": errors,
    }
