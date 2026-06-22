"""
Favicon Hash — fingerprint web servers by their favicon.

Computes MD5 and MurmurHash3 (Shodan convention) of the favicon.
The MMH3 hash can be used in Shodan: http.favicon.hash:<value>
"""
import base64
import hashlib
import struct
import logging
import re
import time

logger = logging.getLogger("ids_ips")


def _mmh3_32(data: bytes) -> int:
    """MurmurHash3 32-bit signed — Shodan favicon standard."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = 0
    blocks = length >> 2
    for i in range(blocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[blocks * 4:]
    k1 = 0
    rem = length & 3
    if rem >= 3: k1 ^= tail[2] << 16
    if rem >= 2: k1 ^= tail[1] << 8
    if rem >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 > 0x7FFFFFFF else h1


def _find_favicon_urls(base_url: str, html: str) -> list:
    """Extract favicon URLs from HTML <link> tags."""
    urls = []
    for m in re.finditer(
        r'<link[^>]+rel=["\']?[^"\']*icon[^"\']*["\']?[^>]+href=["\']([^"\']+)["\']',
        html, re.I
    ):
        urls.append(m.group(1))
    for m in re.finditer(
        r'<link[^>]+href=["\']([^"\']+)["\'][^>]+rel=["\']?[^"\']*icon[^"\']*["\']?',
        html, re.I
    ):
        href = m.group(1)
        if href not in urls:
            urls.append(href)
    return urls


def _abs_url(base_url: str, href: str) -> str:
    from urllib.parse import urljoin
    return urljoin(base_url, href)


def fetch(url: str, timeout: float = 10.0) -> dict:
    """
    Fetch favicon for URL and compute hashes.

    Returns:
        {url, favicon_url, md5, mmh3, base64_preview, size_bytes,
         content_type, shodan_query, elapsed_s}
    """
    try:
        import requests as _req
    except ImportError:
        return {"error": "requests library required"}

    import warnings
    warnings.filterwarnings("ignore")
    t0 = time.time()

    session = _req.Session()
    session.headers["User-Agent"] = "Mozilla/5.0 (FaviconScanner/1.0)"

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Step 1: Try to get favicon URLs from homepage HTML
    favicon_urls = []
    try:
        r = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        base = f"{urlparse(r.url).scheme}://{urlparse(r.url).netloc}"
        for href in _find_favicon_urls(base, r.text):
            favicon_urls.append(_abs_url(base, href))
    except Exception:
        pass

    # Always try /favicon.ico as fallback
    favicon_urls.append(f"{base}/favicon.ico")

    # Deduplicate
    seen = set()
    unique_favicons = [u for u in favicon_urls if u not in seen and not seen.add(u)]

    # Step 2: Fetch favicons and compute hashes
    results = []
    for fav_url in unique_favicons[:5]:
        try:
            r = session.get(fav_url, timeout=timeout, verify=False)
            if r.ok and len(r.content) > 0:
                raw = r.content
                b64 = base64.encodebytes(raw).decode()
                mmh3 = _mmh3_32(b64.encode())
                md5 = hashlib.md5(raw).hexdigest()
                results.append({
                    "favicon_url": fav_url,
                    "md5": md5,
                    "mmh3": mmh3,
                    "shodan_query": f"http.favicon.hash:{mmh3}",
                    "size_bytes": len(raw),
                    "content_type": r.headers.get("Content-Type", ""),
                    "base64_preview": b64[:200],
                })
        except Exception:
            continue

    if not results:
        return {
            "url": url,
            "error": "No favicon found",
            "elapsed_s": round(time.time() - t0, 2),
        }

    primary = results[0]
    primary["url"] = url
    primary["all_favicons"] = results
    primary["elapsed_s"] = round(time.time() - t0, 2)
    return primary
