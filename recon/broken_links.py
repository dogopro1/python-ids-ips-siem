"""
Broken Links Checker — crawl site and find dead/broken links.

Crawls a website (same-origin BFS), checks every href/src for HTTP errors,
and reports broken links (4xx/5xx/timeout) with their source page.
"""
import re
import time
import logging
import concurrent.futures
from collections import deque
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("ids_ips")

_SKIP_EXT = re.compile(r'\.(jpg|jpeg|png|gif|svg|ico|webp|mp4|mp3|pdf|zip|gz|woff|woff2|ttf)$', re.I)
_LINK_RE = re.compile(r'(?:href|src|action)=["\']([^"\'#\s]{2,500})["\']', re.I)


def _get_links(html: str, base_url: str) -> list:
    links = []
    for m in _LINK_RE.finditer(html):
        href = m.group(1).strip()
        if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        abs_url = urljoin(base_url, href)
        if abs_url.startswith(("http://", "https://")):
            links.append(abs_url)
    return links


def _check_url(session, url: str, timeout: float) -> dict:
    try:
        r = session.head(url, timeout=timeout, verify=False, allow_redirects=True)
        status = r.status_code
        if status == 405:
            r = session.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True)
            status = r.status_code
            r.close()
        return {"url": url, "status": status, "broken": status >= 400}
    except Exception as exc:
        return {"url": url, "status": None, "broken": True, "error": str(exc)[:60]}


def run(
    url: str,
    max_pages: int = 30,
    max_links_per_page: int = 100,
    check_external: bool = True,
    concurrency: int = 20,
    timeout: float = 8.0,
) -> dict:
    """
    Crawl site and check all links for broken status.

    Returns:
        {url, broken_links:[{url, status, found_on:[pages]}],
         total_checked, broken_count, pages_crawled, elapsed_s}
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
    session.headers["User-Agent"] = "Mozilla/5.0 (BrokenLinkChecker/1.0)"

    visited_pages = set()
    queue = deque([url])
    # link_url → set of pages where found
    all_links: dict = {}
    pages_crawled = 0

    # Crawl phase (same-origin)
    while queue and pages_crawled < max_pages:
        current = queue.popleft()
        if current in visited_pages:
            continue
        visited_pages.add(current)

        try:
            r = session.get(current, timeout=timeout, verify=False, allow_redirects=True)
            if "text" not in r.headers.get("Content-Type", ""):
                continue
            pages_crawled += 1
            links = _get_links(r.text, r.url)[:max_links_per_page]
            for link in links:
                if _SKIP_EXT.search(urlparse(link).path):
                    continue
                if link not in all_links:
                    all_links[link] = set()
                all_links[link].add(current)
                # Enqueue same-origin links for crawling
                link_domain = urlparse(link).netloc.lower()
                if link_domain == base_domain and link not in visited_pages:
                    queue.append(link)
        except Exception:
            pages_crawled += 1
            continue

    # Check phase — check ALL collected links (incl. external if requested)
    links_to_check = [
        lnk for lnk in all_links
        if check_external or urlparse(lnk).netloc.lower() == base_domain
    ]

    check_results: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(_check_url, session, lnk, timeout): lnk for lnk in links_to_check}
        for f in concurrent.futures.as_completed(futures, timeout=timeout * 5):
            res = f.result()
            check_results[res["url"]] = res

    broken = []
    for lnk, res in check_results.items():
        if res.get("broken"):
            broken.append({
                "url": lnk,
                "status": res.get("status"),
                "error": res.get("error"),
                "found_on": sorted(all_links.get(lnk, [])),
                "external": urlparse(lnk).netloc.lower() != base_domain,
            })

    broken.sort(key=lambda x: (x.get("status") or 999, x["url"]))

    return {
        "url": url,
        "broken_links": broken,
        "total_checked": len(check_results),
        "broken_count": len(broken),
        "pages_crawled": pages_crawled,
        "elapsed_s": round(time.time() - t0, 2),
    }
