"""
ASN Lookup — find Autonomous System Number and routing info for an IP or domain.

Uses ipinfo.io (free tier, no key needed) + bgp.he.net scraping.
"""
import time
import socket
import logging

logger = logging.getLogger("ids_ips")


def _ipinfo(ip: str, timeout: float = 10.0) -> dict:
    try:
        import requests as _req
        r = _req.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (ASNLookup/1.0)"},
        )
        if r.ok:
            d = r.json()
            return {
                "ip": d.get("ip"),
                "asn": d.get("org", "").split(" ")[0] if d.get("org") else None,
                "org": " ".join(d.get("org", "").split(" ")[1:]) if d.get("org") else None,
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "hostname": d.get("hostname"),
                "timezone": d.get("timezone"),
                "source": "ipinfo.io",
            }
    except Exception as exc:
        logger.debug("ipinfo error: %s", exc)
    return {}


def _bgp_he_prefixes(asn: str, timeout: float = 10.0) -> list:
    """Try to get BGP prefixes for ASN from bgp.he.net."""
    try:
        import requests as _req
        import re
        asn_num = asn.lstrip("ASas")
        r = _req.get(
            f"https://bgp.he.net/AS{asn_num}",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.ok:
            prefixes = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})', r.text)
            return sorted(set(prefixes))[:50]
    except Exception:
        pass
    return []


def lookup(ip_or_domain: str, include_prefixes: bool = True, timeout: float = 12.0) -> dict:
    """
    ASN and routing info lookup.

    Args:
        ip_or_domain: IP address or domain name
        include_prefixes: fetch BGP prefix list (slower)

    Returns:
        {ip, asn, org, country, region, city, hostname, timezone,
         prefixes, isp, source, elapsed_s}
    """
    t0 = time.time()
    original = ip_or_domain.strip()

    # Resolve to IP
    ip = original
    try:
        socket.inet_aton(ip)
    except Exception:
        try:
            ip = socket.gethostbyname(original)
        except Exception:
            return {"error": f"Cannot resolve: {original}", "elapsed_s": 0}

    result = _ipinfo(ip, timeout)
    if not result:
        result = {"ip": ip, "error": "ipinfo.io unavailable"}

    result["original_query"] = original

    # Fetch BGP prefixes if ASN known
    if include_prefixes and result.get("asn"):
        result["prefixes"] = _bgp_he_prefixes(result["asn"], timeout)
    else:
        result["prefixes"] = []

    result["elapsed_s"] = round(time.time() - t0, 2)
    return result
