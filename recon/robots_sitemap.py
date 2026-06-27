"""
Robots.txt & Sitemap parser — fetch and analyze robots.txt and sitemap.xml.

Extracts:
  - Disallowed paths (potential hidden endpoints)
  - Allowed paths
  - Sitemap references
  - All URLs from sitemap (recursively follows sitemap indexes)
"""
import re
import time
import logging
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("ids_ips")


def _fetch(session, url: str, timeout: float) -> str:
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        if r.ok and r.text:
            return r.text
    except Exception:
        pass
    return ""


def _parse_robots(text: str) -> dict:
    """Parse robots.txt into structured data."""
    agents: dict = {}
    current_agent = "*"
    sitemaps = []

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()

        if key == "user-agent":
            current_agent = val
            if current_agent not in agents:
                agents[current_agent] = {"disallow": [], "allow": []}
        elif key == "disallow":
            if val:
                agents.setdefault(current_agent, {"disallow": [], "allow": []})["disallow"].append(val)
        elif key == "allow":
            if val:
                agents.setdefault(current_agent, {"disallow": [], "allow": []})["allow"].append(val)
        elif key == "sitemap":
            sitemaps.append(val)

    # Interesting disallowed paths (potential hidden content)
    all_disallow = []
    for a in agents.values():
        all_disallow.extend(a["disallow"])
    interesting = [p for p in set(all_disallow) if any(
        kw in p.lower() for kw in (
            "admin", "api", "login", "dashboard", "config", "backup",
            "db", "secret", "private", "internal", "test", "dev",
            "staging", "upload", "panel", "manage", "console",
        )
    )]

    return {
        "agents": agents,
        "sitemaps": sitemaps,
        "all_disallowed": sorted(set(all_disallow)),
        "interesting_paths": sorted(set(interesting)),
    }


def _parse_sitemap_xml(text: str) -> list:
    """Extract URLs from sitemap XML (handles sitemap index and urlset)."""
    urls = []
    # urlset: <loc>...</loc>
    for m in re.finditer(r"<loc>\s*(https?://[^\s<]+)\s*</loc>", text, re.I):
        urls.append(m.group(1).strip())
    return urls


def fetch(url: str, max_sitemap_urls: int = 500, timeout: float = 10.0) -> dict:
    """
    Fetch and parse robots.txt and sitemap(s) for target.

    Returns:
        {url, robots:{agents, sitemaps, all_disallowed, interesting_paths},
         sitemap_urls:[str], sitemap_count, robots_raw, elapsed_s}
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
    base = f"{parsed.scheme}://{parsed.netloc}"

    session = _req.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (RobotsFetcher/1.0)"

    # Fetch robots.txt
    robots_raw = _fetch(session, f"{base}/robots.txt", timeout)
    robots = _parse_robots(robots_raw) if robots_raw else {
        "agents": {}, "sitemaps": [], "all_disallowed": [], "interesting_paths": []
    }

    # Collect sitemap URLs
    sitemap_sources = list(robots.get("sitemaps", []))
    if not sitemap_sources:
        # Common sitemap locations
        for path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap/sitemap.xml"):
            sitemap_sources.append(urljoin(base, path))

    sitemap_urls = []
    visited_sitemaps = set()

    def _process_sitemap(sm_url):
        if sm_url in visited_sitemaps or len(sitemap_urls) >= max_sitemap_urls:
            return
        visited_sitemaps.add(sm_url)
        sm_text = _fetch(session, sm_url, timeout)
        if not sm_text:
            return
        urls = _parse_sitemap_xml(sm_text)
        for u in urls:
            if u.endswith(".xml") and "sitemap" in u.lower():
                _process_sitemap(u)
            elif len(sitemap_urls) < max_sitemap_urls:
                sitemap_urls.append(u)

    for sm in sitemap_sources[:10]:
        _process_sitemap(sm)

    return {
        "url": url,
        "base": base,
        "robots_found": bool(robots_raw),
        "robots_raw": robots_raw[:3000] if robots_raw else "",
        "robots": robots,
        "sitemap_urls": sitemap_urls[:max_sitemap_urls],
        "sitemap_count": len(sitemap_urls),
        "sitemaps_checked": sorted(visited_sitemaps),
        "elapsed_s": round(time.time() - t0, 2),
    }
