"""
WHOIS / Domain Info — query WHOIS registration data for a domain or IP.

Uses python-whois library with fallback to raw socket WHOIS query.
"""
import time
import socket
import re
import logging

logger = logging.getLogger("ids_ips")


def _raw_whois(query: str, server: str = "whois.iana.org", port: int = 43, timeout: float = 10.0) -> str:
    """Low-level WHOIS socket query."""
    try:
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            return data.decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("raw_whois error: %s", exc)
        return ""


def _find_whois_server(tld: str) -> str:
    """Return WHOIS server for a TLD."""
    _KNOWN = {
        "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
        "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
        "uk": "whois.nic.uk", "de": "whois.denic.de", "fr": "whois.nic.fr",
        "nl": "whois.domain-registry.nl", "ru": "whois.tcinet.ru",
        "pl": "whois.dns.pl", "eu": "whois.eu", "info": "whois.afilias.net",
        "biz": "whois.biz", "us": "whois.nic.us", "ca": "whois.cira.ca",
        "au": "whois.auda.org.au", "jp": "whois.jprs.jp", "cn": "whois.cnnic.cn",
        "br": "whois.registro.br", "in": "whois.registry.in",
    }
    return _KNOWN.get(tld.lower(), "whois.iana.org")


def _parse_whois(raw: str) -> dict:
    """Extract key fields from raw WHOIS text."""
    fields = {}
    patterns = {
        "registrar": r"(?:Registrar|Registrar Name):\s*(.+)",
        "creation_date": r"(?:Creation Date|Created On|Created):\s*(.+)",
        "expiry_date": r"(?:Registry Expiry Date|Expiration Date|Expires On):\s*(.+)",
        "updated_date": r"(?:Updated Date|Last Updated|Last Modified):\s*(.+)",
        "registrant": r"Registrant (?:Name|Organization):\s*(.+)",
        "registrant_country": r"Registrant Country:\s*(.+)",
        "registrant_email": r"Registrant Email:\s*(.+)",
        "admin_email": r"Admin Email:\s*(.+)",
        "name_servers": r"Name Server:\s*(.+)",
        "status": r"Domain Status:\s*(.+)",
        "dnssec": r"DNSSEC:\s*(.+)",
    }
    for key, pattern in patterns.items():
        matches = re.findall(pattern, raw, re.I)
        if matches:
            val = [m.strip() for m in matches if m.strip()]
            fields[key] = val if len(val) > 1 else val[0] if val else None
    return fields


def lookup(domain: str, timeout: float = 15.0) -> dict:
    """
    WHOIS lookup for domain or IP.

    Returns:
        {query, raw, parsed:{registrar, creation_date, expiry_date, ...},
         source, elapsed_s}
    """
    t0 = time.time()
    query = domain.strip().lower()

    # Try python-whois first (most reliable)
    try:
        import whois as _whois
        w = _whois.whois(query)
        raw = str(w.text) if hasattr(w, "text") else ""

        def _fmt(v):
            if v is None:
                return None
            if isinstance(v, list):
                return [str(x) for x in v]
            return str(v)

        parsed = {
            "registrar": _fmt(w.registrar),
            "creation_date": _fmt(w.creation_date),
            "expiry_date": _fmt(w.expiration_date),
            "updated_date": _fmt(w.updated_date),
            "registrant": _fmt(getattr(w, "name", None)),
            "registrant_org": _fmt(getattr(w, "org", None)),
            "registrant_country": _fmt(getattr(w, "country", None)),
            "registrant_email": _fmt(getattr(w, "emails", None)),
            "name_servers": _fmt(w.name_servers),
            "status": _fmt(w.status),
            "dnssec": _fmt(getattr(w, "dnssec", None)),
        }
        return {
            "query": query,
            "raw": raw[:5000],
            "parsed": parsed,
            "source": "python-whois",
            "elapsed_s": round(time.time() - t0, 2),
        }
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("python-whois failed: %s", exc)

    # Fallback: raw socket WHOIS
    parts = query.rstrip(".").split(".")
    tld = parts[-1] if parts else "com"
    server = _find_whois_server(tld)

    raw = _raw_whois(query, server, timeout=timeout)
    if not raw and server != "whois.iana.org":
        # IANA may redirect us to correct server
        iana_raw = _raw_whois(query, "whois.iana.org", timeout=timeout)
        refer_match = re.search(r"refer:\s*(\S+)", iana_raw, re.I)
        if refer_match:
            server = refer_match.group(1)
            raw = _raw_whois(query, server, timeout=timeout)

    parsed = _parse_whois(raw)
    return {
        "query": query,
        "raw": raw[:5000],
        "parsed": parsed,
        "source": f"raw socket → {server}",
        "elapsed_s": round(time.time() - t0, 2),
    }
