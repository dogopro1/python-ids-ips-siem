"""
Email Harvester — extract contact email addresses from web pages.

Crawls target site (BFS, same-origin), extracts emails from:
  - Page text and HTML
  - mailto: links
  - JavaScript strings
  - Meta tags (contact, author)
"""
import re
import time
import logging
from collections import deque
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("ids_ips")

_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b'
)

_IGNORED_DOMAINS = {
    "example.com", "test.com", "sentry.io", "wixpress.com",
    "schema.org", "w3.org", "openid.net", "facebook.com",
    "google.com", "twitter.com", "linkedin.com", "github.com",
    "googleapis.com", "cloudflare.com", "jquery.com", "bootstrap.com",
}

_IGNORED_PREFIXES = ("noreply", "no-reply", "donotreply", "mailer-daemon", "bounce")

_FILLER_PATTERN = re.compile(r'\.(png|jpg|jpeg|gif|svg|ico|css|js|woff|woff2|ttf|map)$', re.I)


def _extract_emails(html: str, source_domain: str) -> set:
    found = set()
    for m in _EMAIL_RE.finditer(html):
        email = m.group(0).lower().strip(".,;:\"'")
        domain = email.split("@")[-1]
        if domain in _IGNORED_DOMAINS:
            continue
        local = email.split("@")[0]
        if any(local.startswith(p) for p in _IGNORED_PREFIXES):
            continue
        if len(email) < 6 or len(email) > 80:
            continue
        found.add(email)
    return found


def run(
    url: str,
    max_pages: int = 20,
    max_depth: int = 2,
    timeout: float = 10.0,
) -> dict:
    """
    Crawl site and harvest email addresses.

    Returns:
        {url, emails:[{email, sources:[url]}], total, pages_crawled, elapsed_s}
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

    parsed = urlparse(url)
    base_domain = parsed.netloc.lower()

    session = _req.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (EmailHarvester/1.0)"

    visited = set()
    queue = deque([(url, 0)])
    email_sources: dict = {}  # email → set of source URLs
    pages_crawled = 0

    while queue and pages_crawled < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            r = session.get(current_url, timeout=timeout, verify=False, allow_redirects=True)
            if not r.ok:
                continue
            if "text" not in r.headers.get("Content-Type", ""):
                continue

            pages_crawled += 1
            html = r.text

            # Extract emails
            for email in _extract_emails(html, base_domain):
                if email not in email_sources:
                    email_sources[email] = set()
                email_sources[email].add(current_url)

            # Enqueue links (same-origin only)
            if depth < max_depth:
                for m in re.finditer(r'href=["\']([^"\'#?]+)["\']', html, re.I):
                    href = m.group(1).strip()
                    if _FILLER_PATTERN.search(href):
                        continue
                    abs_url = urljoin(current_url, href)
                    link_parsed = urlparse(abs_url)
                    if link_parsed.netloc.lower().endswith(base_domain):
                        if abs_url not in visited:
                            queue.append((abs_url, depth + 1))

        except Exception:
            continue

    emails = sorted([
        {"email": e, "sources": sorted(srcs), "count": len(srcs)}
        for e, srcs in email_sources.items()
    ], key=lambda x: -x["count"])

    return {
        "url": url,
        "emails": emails,
        "total": len(emails),
        "pages_crawled": pages_crawled,
        "elapsed_s": round(time.time() - t0, 2),
    }
