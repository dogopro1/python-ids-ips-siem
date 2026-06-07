"""
RDAP + BGP/ASN lookup — Module 3.

RDAP (Registration Data Access Protocol) is the modern replacement for WHOIS.
Provides structured JSON responses with full registrar, contact, and domain info.
BGP/ASN lookup via RIPE NCC API.
"""
import time
import logging
import ipaddress

logger = logging.getLogger("ids_ips")

# RDAP bootstrap servers (IANA provides the authoritative list)
_RDAP_IP_BOOTSTRAP = "https://rdap.iana.org/ip/{}"
_RDAP_DOMAIN_BOOTSTRAP = "https://rdap.iana.org/domain/{}"
_RIPE_BGP = "https://stat.ripe.net/data/prefix-overview/data.json?resource={}"
_RIPE_ASN = "https://stat.ripe.net/data/as-overview/data.json?resource=AS{}"


def _get(url: str, timeout: int = 10) -> dict:
    try:
        import requests
        r = requests.get(url, timeout=timeout,
                         headers={"Accept": "application/rdap+json, application/json"})
        return {"ok": r.ok, "status": r.status_code, "json": r.json()}
    except Exception as e:
        return {"ok": False, "status": 0, "json": {}, "error": str(e)}


def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None


def rdap_ip(ip: str) -> dict:
    db = _db()
    if db:
        cached = db.get_intel_cache(f"rdap_ip:{ip}", ttl=7200)
        if cached:
            return cached

    r = _get(_RDAP_IP_BOOTSTRAP.format(ip))
    if not r["ok"]:
        return {"error": f"RDAP error {r['status']}", "source": "RDAP"}

    data = r["json"]
    out = _parse_rdap_ip(data, ip)
    if db:
        db.set_intel_cache(f"rdap_ip:{ip}", out)
    return out


def _parse_rdap_ip(data: dict, ip: str) -> dict:
    entities = data.get("entities", [])
    contacts = []
    for ent in entities:
        vcard = ent.get("vcardArray", [None, []])[1]
        name = ""
        email = ""
        for field in vcard:
            if field[0] == "fn":
                name = field[3]
            if field[0] == "email":
                email = field[3]
        contacts.append({
            "role": ent.get("roles", []),
            "name": name,
            "email": email,
            "handle": ent.get("handle", ""),
        })

    remarks = []
    for r in data.get("remarks", []):
        for d in r.get("description", []):
            remarks.append(d)

    return {
        "source": "RDAP",
        "ip": ip,
        "handle": data.get("handle", ""),
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "start_address": data.get("startAddress", ""),
        "end_address": data.get("endAddress", ""),
        "cidr": [str(c) for c in data.get("cidr0_cidrs", [])],
        "parent_handle": data.get("parentHandle", ""),
        "entities": contacts,
        "remarks": remarks[:5],
        "links": [l.get("href", "") for l in data.get("links", [])],
        "events": [
            {"action": e.get("eventAction"), "date": e.get("eventDate")}
            for e in data.get("events", [])
        ],
    }


def rdap_domain(domain: str) -> dict:
    db = _db()
    if db:
        cached = db.get_intel_cache(f"rdap_domain:{domain}", ttl=7200)
        if cached:
            return cached

    r = _get(_RDAP_DOMAIN_BOOTSTRAP.format(domain))
    if not r["ok"]:
        # Try direct lookup at common RDAP servers
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else "com"
        direct_servers = {
            "com": "https://rdap.verisign.com/com/v1/domain/",
            "net": "https://rdap.verisign.com/net/v1/domain/",
            "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
            "io": "https://rdap.nic.io/domain/",
            "co": "https://rdap.nic.co/domain/",
        }
        url = direct_servers.get(tld, f"https://rdap.iana.org/domain/") + domain
        r = _get(url)
        if not r["ok"]:
            return {"error": f"RDAP error {r['status']}", "source": "RDAP"}

    data = r["json"]
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    entities = []
    for ent in data.get("entities", []):
        vcard = ent.get("vcardArray", [None, []])[1]
        info = {"role": ent.get("roles", []), "handle": ent.get("handle", "")}
        for field in vcard:
            if field[0] == "fn":
                info["name"] = field[3]
            elif field[0] == "email":
                info["email"] = field[3]
            elif field[0] == "org":
                info["org"] = field[3]
        entities.append(info)

    out = {
        "source": "RDAP",
        "domain": domain,
        "handle": data.get("handle", ""),
        "ldhName": data.get("ldhName", ""),
        "status": data.get("status", []),
        "nameservers": nameservers,
        "entities": entities,
        "events": [
            {"action": e.get("eventAction"), "date": e.get("eventDate")}
            for e in data.get("events", [])
        ],
        "secureDNS": data.get("secureDNS", {}),
        "links": [l.get("href", "") for l in data.get("links", [])],
    }
    if db:
        db.set_intel_cache(f"rdap_domain:{domain}", out)
    return out


def bgp_lookup(ip: str) -> dict:
    """BGP prefix and ASN info for an IP via RIPE NCC stat API."""
    db = _db()
    if db:
        cached = db.get_intel_cache(f"bgp:{ip}", ttl=3600)
        if cached:
            return cached

    r = _get(_RIPE_BGP.format(ip))
    if not r["ok"]:
        return {"error": f"RIPE error {r['status']}", "source": "BGP"}

    data = r["json"].get("data", {})
    asns = data.get("asns", [])
    out = {
        "source": "BGP/RIPE",
        "ip": ip,
        "prefix": data.get("resource", ""),
        "is_less_specific": data.get("is_less_specific", False),
        "asns": [
            {
                "asn": a.get("asn"),
                "holder": a.get("holder", ""),
            }
            for a in asns[:5]
        ],
    }
    if asns:
        asn = asns[0].get("asn")
        if asn:
            asn_r = _get(_RIPE_ASN.format(asn))
            if asn_r["ok"]:
                asn_data = asn_r["json"].get("data", {})
                out["asn_details"] = {
                    "asn": asn,
                    "holder": asn_data.get("holder", ""),
                    "announced": asn_data.get("announced", False),
                    "resource": asn_data.get("resource", ""),
                }
    if db:
        db.set_intel_cache(f"bgp:{ip}", out)
    return out
