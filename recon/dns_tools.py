"""
DNS Tools — full record lookup + zone transfer attempt.

Record types: A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, SRV, CAA, DMARC, SPF
Zone transfer: AXFR attempt on each NS (rarely succeeds on patched servers)
"""
import logging
import time

logger = logging.getLogger("ids_ips")

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV"]


def _rdata_str(rdata) -> str:
    try:
        return rdata.to_text()
    except Exception:
        return str(rdata)


def lookup(domain: str, record_types: list = None, timeout: float = 8.0) -> dict:
    """
    Query DNS records for domain.
    Returns {domain, records: {type: [values...]}, errors: {type: msg}, elapsed_s}
    """
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return {"error": "dnspython not installed — pip install dnspython", "domain": domain}

    types = record_types or _RECORD_TYPES
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    records: dict = {}
    errors: dict = {}
    t0 = time.time()

    for rtype in types:
        try:
            answers = resolver.resolve(domain, rtype)
            values = []
            for rd in answers:
                text = _rdata_str(rd)
                # Extra parsing for common types
                if rtype == "MX":
                    values.append({"priority": rd.preference, "host": rd.exchange.to_text().rstrip(".")})
                elif rtype == "SOA":
                    values.append({
                        "mname": rd.mname.to_text().rstrip("."),
                        "rname": rd.rname.to_text().rstrip("."),
                        "serial": rd.serial, "refresh": rd.refresh,
                        "retry": rd.retry, "expire": rd.expire, "minimum": rd.minimum,
                    })
                elif rtype == "SRV":
                    values.append({
                        "priority": rd.priority, "weight": rd.weight,
                        "port": rd.port, "target": rd.target.to_text().rstrip("."),
                    })
                elif rtype == "NS":
                    values.append(rd.target.to_text().rstrip("."))
                elif rtype == "CNAME":
                    values.append(rd.target.to_text().rstrip("."))
                else:
                    values.append(text)
            if values:
                records[rtype] = values
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
        except dns.exception.Timeout:
            errors[rtype] = "timeout"
        except Exception as exc:
            errors[rtype] = str(exc)[:80]

    # Extract SPF from TXT records
    spf = [t for t in records.get("TXT", []) if "v=spf1" in str(t).lower()]
    dmarc_domain = f"_dmarc.{domain}"
    try:
        dmarc_ans = resolver.resolve(dmarc_domain, "TXT")
        records["DMARC"] = [_rdata_str(rd) for rd in dmarc_ans]
    except Exception:
        pass

    if spf:
        records["SPF"] = spf

    return {
        "domain": domain,
        "records": records,
        "errors": errors,
        "elapsed_s": round(time.time() - t0, 2),
    }


def zone_transfer(domain: str, timeout: float = 10.0) -> dict:
    """
    Attempt DNS zone transfer (AXFR) on all NS servers.
    Returns {domain, nameservers, results: {ns: [records]}, success: bool}
    """
    try:
        import dns.resolver
        import dns.query
        import dns.zone
        import dns.exception
    except ImportError:
        return {"error": "dnspython not installed", "domain": domain}

    t0 = time.time()
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout

    # Get nameservers
    nameservers = []
    try:
        ns_answers = resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_host = ns.target.to_text().rstrip(".")
            # Resolve NS to IP
            try:
                ip_ans = resolver.resolve(ns_host, "A")
                nameservers.append({"host": ns_host, "ip": ip_ans[0].to_text()})
            except Exception:
                nameservers.append({"host": ns_host, "ip": None})
    except Exception as exc:
        return {"domain": domain, "nameservers": [], "results": {}, "success": False,
                "error": str(exc), "elapsed_s": round(time.time() - t0, 2)}

    results = {}
    success = False
    for ns_info in nameservers:
        ns_ip = ns_info["ip"]
        ns_host = ns_info["host"]
        if not ns_ip:
            results[ns_host] = {"error": "could not resolve NS IP"}
            continue
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout))
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            "name": str(name),
                            "type": dns.rdatatype.to_text(rdataset.rdtype),
                            "value": _rdata_str(rdata),
                        })
            results[ns_host] = {"records": records, "count": len(records)}
            success = True
            logger.warning("ZONE TRANSFER SUCCEEDED on %s for %s — %d records", ns_host, domain, len(records))
        except Exception as exc:
            results[ns_host] = {"error": str(exc)[:120]}

    return {
        "domain": domain,
        "nameservers": nameservers,
        "results": results,
        "success": success,
        "elapsed_s": round(time.time() - t0, 2),
    }
