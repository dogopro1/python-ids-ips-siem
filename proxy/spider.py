"""
Web Spider/Crawler — BurpSuite Spider equivalent.

Discovers URLs by:
  - Following <a href> links
  - Parsing <form action> endpoints
  - Extracting src/action attributes from all tags
  - Checking robots.txt and sitemap.xml
  - Extracting URLs from inline JavaScript
  - Respecting scope (same origin only by default)

Results stored in spider_results DB table.
"""
import threading
import time
import re
import logging
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

logger = logging.getLogger("ids_ips")

_TIMEOUT = 10
_MAX_PAGES_HARD = 500
_LINK_RE = re.compile(r'href=["\']([^"\'#>]{3,})', re.IGNORECASE)
_SRC_RE = re.compile(r'src=["\']([^"\'#>]{3,})', re.IGNORECASE)
_ACTION_RE = re.compile(r'action=["\']([^"\'#>]{3,})', re.IGNORECASE)
_JS_URL_RE = re.compile(r'''(?:url|href|src|endpoint|path)\s*[:=]\s*["\']([/][^"\'<>]{2,})["\']''',
                         re.IGNORECASE)
_FORM_RE = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
_INPUT_RE = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)


def _normalize_url(base: str, href: str, scope_netloc: str) -> str | None:
    try:
        url = urljoin(base, href)
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return None
        if p.netloc != scope_netloc:
            return None
        # Strip fragment
        clean = urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))
        return clean
    except Exception:
        return None


def _extract_links(html: str, base_url: str, scope_netloc: str) -> set:
    found = set()
    for pattern in (_LINK_RE, _SRC_RE, _ACTION_RE):
        for m in pattern.finditer(html):
            url = _normalize_url(base_url, m.group(1), scope_netloc)
            if url:
                found.add(url)
    for m in _JS_URL_RE.finditer(html):
        url = _normalize_url(base_url, m.group(1), scope_netloc)
        if url:
            found.add(url)
    return found


def _extract_forms(html: str, base_url: str) -> list:
    forms = []
    for m in _FORM_RE.finditer(html):
        form_html = m.group(0)
        method_m = re.search(r'method=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        action_m = re.search(r'action=["\']([^"\']+)["\']', form_html, re.IGNORECASE)
        method = method_m.group(1).upper() if method_m else "GET"
        action = urljoin(base_url, action_m.group(1)) if action_m else base_url
        inputs = _INPUT_RE.findall(m.group(1))
        forms.append({"method": method, "action": action, "inputs": inputs})
    return forms


def _session():
    try:
        import requests
        import warnings
        warnings.filterwarnings("ignore")
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Spider/1.0; Security-Audit)",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        s.verify = False
        return s
    except ImportError:
        return None


def crawl(
    start_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    follow_external: bool = False,
    timeout: float = 10.0,
    concurrency: int = 5,
) -> dict:
    """
    Crawl start_url up to max_pages / max_depth.

    Returns {
        base_url, pages_found, pages_crawled,
        results: [{url, status, depth, method, content_type, title, forms, links_found}],
        errors: [str],
        robots_txt: str,
        sitemap_urls: [str],
    }
    """
    if not start_url.startswith(("http://", "https://")):
        start_url = "https://" + start_url

    max_pages = min(max_pages, _MAX_PAGES_HARD)
    session = _session()
    if session is None:
        return {"error": "requests library required"}

    parsed_start = urlparse(start_url)
    scope_netloc = parsed_start.netloc

    visited = set()
    results = []
    errors = []
    queue = [(start_url, 0)]  # (url, depth)
    lock = threading.Lock()
    sem = threading.Semaphore(concurrency)

    # Fetch robots.txt
    robots_txt = ""
    sitemap_urls = []
    try:
        robots_url = f"{parsed_start.scheme}://{scope_netloc}/robots.txt"
        r = session.get(robots_url, timeout=timeout, allow_redirects=True)
        if r.status_code == 200:
            robots_txt = r.text[:4096]
            for line in robots_txt.splitlines():
                if line.lower().startswith("sitemap:"):
                    sitemap_urls.append(line.split(":", 1)[1].strip())
    except Exception as e:
        errors.append(f"robots.txt: {e}")

    # Fetch sitemap.xml if not found in robots.txt
    if not sitemap_urls:
        try:
            sitemap_url = f"{parsed_start.scheme}://{scope_netloc}/sitemap.xml"
            r = session.get(sitemap_url, timeout=timeout)
            if r.status_code == 200:
                sitemap_urls.append(sitemap_url)
                for loc_m in re.finditer(r'<loc>(.*?)</loc>', r.text, re.IGNORECASE):
                    url = _normalize_url(sitemap_url, loc_m.group(1).strip(), scope_netloc)
                    if url:
                        with lock:
                            if url not in visited and len(queue) < max_pages:
                                queue.append((url, 1))
        except Exception as e:
            errors.append(f"sitemap.xml: {e}")

    def fetch_page(url: str, depth: int):
        sem.acquire()
        try:
            with lock:
                if url in visited or len(results) >= max_pages:
                    return
                visited.add(url)

            t0 = time.time()
            try:
                r = session.get(url, timeout=timeout, allow_redirects=True,
                                stream=False)
                elapsed_ms = round((time.time() - t0) * 1000)
                content_type = r.headers.get("content-type", "")
                body = ""
                if "text/html" in content_type or "application/xhtml" in content_type:
                    body = r.text[:65536]

                # Extract title
                title = ""
                t_m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if t_m:
                    title = re.sub(r"\s+", " ", t_m.group(1).strip())[:120]

                # Extract forms
                forms = _extract_forms(body, url)

                # Extract links for further crawling
                new_links = _extract_links(body, url, scope_netloc)

                entry = {
                    "url": url,
                    "status": r.status_code,
                    "depth": depth,
                    "method": "GET",
                    "content_type": content_type.split(";")[0].strip(),
                    "title": title,
                    "forms": forms,
                    "forms_count": len(forms),
                    "links_found": len(new_links),
                    "response_ms": elapsed_ms,
                    "size_bytes": len(r.content),
                }

                with lock:
                    results.append(entry)
                    if depth < max_depth:
                        for link in new_links:
                            if link not in visited and len(queue) + len(results) < max_pages * 2:
                                queue.append((link, depth + 1))

                # Save to DB per-page
                try:
                    from db.database import Database
                    Database.get().save_spider_result({
                        "base_url": start_url,
                        "found_url": url,
                        "method": "GET",
                        "status_code": r.status_code,
                        "depth": depth,
                        "content_type": content_type.split(";")[0].strip(),
                        "forms_count": len(forms),
                        "title": title,
                    })
                except Exception:
                    pass

            except Exception as exc:
                with lock:
                    errors.append(f"{url}: {exc}")
        finally:
            sem.release()

    # BFS crawl loop
    while queue and len(results) < max_pages:
        # Take up to concurrency items from queue
        batch = []
        with lock:
            while queue and len(batch) < concurrency:
                batch.append(queue.pop(0))

        threads = [threading.Thread(target=fetch_page, args=(u, d), daemon=True)
                   for u, d in batch]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 5)

    return {
        "base_url": start_url,
        "scope": scope_netloc,
        "pages_found": len(visited),
        "pages_crawled": len(results),
        "results": results,
        "errors": errors[:20],
        "robots_txt": robots_txt,
        "sitemap_urls": sitemap_urls,
        "all_forms": [f for page in results for f in page.get("forms", [])],
    }
