"""
Web Crawler (Recon) — BFS crawler that maps all pages and resources of a site.

Distinct from the Proxy Spider: this one is for recon — it focuses on
collecting URLs, forms, external links, and page metadata.
"""
import re
import time
import logging
from collections import deque
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("ids_ips")

_SKIP_EXT = re.compile(
    r'\.(jpg|jpeg|png|gif|svg|ico|webp|mp4|mp3|pdf|zip|gz|woff|woff2|ttf|eot|css)$', re.I
)
_LINK_RE = re.compile(r'href=["\']([^"\'#\s]{1,500})["\']', re.I)
_FORM_RE = re.compile(r'<form[^>]*action=["\']([^"\']*)["\']', re.I)
_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,10}\b')
_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.S)


def crawl(
    url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    include_external: bool = True,
    timeout: float = 8.0,
) -> dict:
    """
    BFS web crawl from start URL.

    Returns:
        {url, pages:[{url, status, title, forms, links_count, depth, internal}],
         external_links:[str], emails:[str], comments:[str],
         total_pages, total_internal, total_external, elapsed_s}
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
    session.headers["User-Agent"] = "Mozilla/5.0 (WebCrawler/1.0)"

    visited = set()
    queue = deque([(url, 0)])
    pages = []
    external_links = set()
    all_emails = set()
    all_comments = []

    while queue and len(pages) < max_pages:
        current_url, depth = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)

        try:
            r = session.get(current_url, timeout=timeout, verify=False, allow_redirects=True)
            content_type = r.headers.get("Content-Type", "")
            if "text" not in content_type and "html" not in content_type:
                continue

            html = r.text
            final_url = r.url

            # Title
            tm = re.search(r"<title[^>]*>([^<]{1,200})</title>", html, re.I)
            title = tm.group(1).strip()[:100] if tm else ""

            # Forms
            forms = []
            for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
                attrs = fm.group(1)
                body2 = fm.group(2)
                action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
                method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
                inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body2, re.I)
                forms.append({
                    "action": urljoin(final_url, action_m.group(1)) if action_m else final_url,
                    "method": (method_m.group(1) if method_m else "get").upper(),
                    "inputs": inputs,
                })

            # Links
            internal_links = set()
            for lm in _LINK_RE.finditer(html):
                href = lm.group(1).strip()
                if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                    continue
                abs_url = urljoin(final_url, href)
                link_parsed = urlparse(abs_url)
                if not abs_url.startswith(("http://", "https://")):
                    continue
                if _SKIP_EXT.search(link_parsed.path):
                    continue
                if link_parsed.netloc.lower() == base_domain:
                    internal_links.add(abs_url)
                    if depth < max_depth and abs_url not in visited:
                        queue.append((abs_url, depth + 1))
                else:
                    external_links.add(abs_url)

            # Emails
            for em in _EMAIL_RE.findall(html):
                all_emails.add(em.lower())

            # HTML comments (may contain dev notes)
            for c in _COMMENT_RE.findall(html):
                c = c.strip()
                if len(c) > 10 and len(c) < 500:
                    all_comments.append({"comment": c[:300], "page": final_url})

            pages.append({
                "url": final_url,
                "status": r.status_code,
                "title": title,
                "depth": depth,
                "internal_links": len(internal_links),
                "forms": forms,
                "size_bytes": len(r.content),
                "content_type": content_type.split(";")[0].strip(),
            })

        except Exception:
            continue

    return {
        "url": url,
        "pages": pages,
        "external_links": sorted(external_links)[:200],
        "emails": sorted(all_emails),
        "comments": all_comments[:50],
        "total_pages": len(pages),
        "total_internal": len(pages),
        "total_external": len(external_links),
        "elapsed_s": round(time.time() - t0, 2),
    }
