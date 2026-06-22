"""
Reverse IP Lookup — find all domains hosted on the same IP.

Uses HackerTarget API (free, no key) + optional ViewDNS fallback.
Also performs reverse PTR lookup via DNS.
"""
import time
import socket
import logging

logger = logging.getLogger("ids_ips")


def _ptr_lookup(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def _hackertarget(ip: str, timeout: float = 15.0) -> list:
    try:
        import requests as _req
        r = _req.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (ReverseIPScanner/1.0)"},
        )
        if r.ok and "error" not in r.text.lower()[:50]:
            domains = [line.strip() for line in r.text.splitlines() if line.strip()]
            return domains
    except Exception as exc:
        logger.debug("hackertarget reverseip error: %s", exc)
    return []


def lookup(ip_or_domain: str, timeout: float = 15.0) -> dict:
    """
    Reverse IP lookup.

    Args:
        ip_or_domain: IP address or domain name

    Returns:
        {ip, ptr, domains:[str], total, source, elapsed_s}
    """
    t0 = time.time()

    # Resolve domain → IP if needed
    ip = ip_or_domain.strip()
    try:
        socket.inet_aton(ip)
    except Exception:
        try:
            ip = socket.gethostbyname(ip_or_domain)
        except Exception:
            return {"error": f"Cannot resolve: {ip_or_domain}", "elapsed_s": 0}

    ptr = _ptr_lookup(ip)
    domains = _hackertarget(ip, timeout)

    # Deduplicate and clean
    seen = set()
    clean_domains = []
    for d in domains:
        d = d.strip().lower()
        if d and d not in seen:
            seen.add(d)
            clean_domains.append(d)

    return {
        "ip": ip,
        "original_query": ip_or_domain,
        "ptr": ptr,
        "domains": clean_domains,
        "total": len(clean_domains),
        "source": "hackertarget.com + PTR",
        "elapsed_s": round(time.time() - t0, 2),
    }
