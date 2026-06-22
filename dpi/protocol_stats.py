"""
Wireshark-style protocol statistics.

Functions:
  protocol_hierarchy(packets) — % breakdown by protocol
  conversations(packets)      — top IP pairs with packet/byte counts
  endpoints(packets)          — all unique IPs with stats
  io_graph(packets, interval) — packets/bytes per time bucket
  service_stats(packets)      — port/service distribution
"""
import time
from collections import defaultdict


def protocol_hierarchy(packets: list) -> list:
    """
    Return protocol hierarchy statistics.
    Each entry: {protocol, count, bytes, pct_packets, pct_bytes}
    """
    total_pkts = len(packets)
    total_bytes = sum(p.get("size", 0) or 0 for p in packets)

    counts: dict = defaultdict(lambda: {"count": 0, "bytes": 0})
    for p in packets:
        proto = (p.get("protocol") or "UNKNOWN").upper()
        sz = p.get("size", 0) or 0
        counts[proto]["count"] += 1
        counts[proto]["bytes"] += sz

    result = []
    for proto, data in sorted(counts.items(), key=lambda x: -x[1]["count"]):
        result.append({
            "protocol": proto,
            "count": data["count"],
            "bytes": data["bytes"],
            "pct_packets": round(data["count"] / total_pkts * 100, 1) if total_pkts else 0,
            "pct_bytes": round(data["bytes"] / total_bytes * 100, 1) if total_bytes else 0,
        })
    return result


def conversations(packets: list, limit: int = 50) -> list:
    """
    Top IP-pair conversations.
    Each entry: {src_ip, dst_ip, packets_a_b, packets_b_a, bytes_a_b, bytes_b_a,
                 total_packets, total_bytes, protocols}
    """
    conv: dict = defaultdict(lambda: {
        "packets_a_b": 0, "packets_b_a": 0,
        "bytes_a_b": 0, "bytes_b_a": 0,
        "protocols": set(),
    })

    for p in packets:
        src = p.get("src_ip", "")
        dst = p.get("dst_ip", "")
        if not src or not dst:
            continue
        proto = (p.get("protocol") or "").upper()
        sz = p.get("size", 0) or 0
        key = (min(src, dst), max(src, dst))
        c = conv[key]
        if src <= dst:
            c["packets_a_b"] += 1
            c["bytes_a_b"] += sz
        else:
            c["packets_b_a"] += 1
            c["bytes_b_a"] += sz
        if proto:
            c["protocols"].add(proto)

    result = []
    for (a, b), c in conv.items():
        result.append({
            "src_ip": a,
            "dst_ip": b,
            "packets_a_b": c["packets_a_b"],
            "packets_b_a": c["packets_b_a"],
            "bytes_a_b": c["bytes_a_b"],
            "bytes_b_a": c["bytes_b_a"],
            "total_packets": c["packets_a_b"] + c["packets_b_a"],
            "total_bytes": c["bytes_a_b"] + c["bytes_b_a"],
            "protocols": sorted(c["protocols"]),
        })

    result.sort(key=lambda x: -x["total_packets"])
    return result[:limit]


def endpoints(packets: list, limit: int = 100) -> list:
    """
    Unique IP endpoints with statistics.
    Each entry: {ip, packets_sent, packets_recv, bytes_sent, bytes_recv,
                 total_packets, total_bytes, protocols, ports_used}
    """
    eps: dict = defaultdict(lambda: {
        "packets_sent": 0, "packets_recv": 0,
        "bytes_sent": 0, "bytes_recv": 0,
        "protocols": set(), "ports_used": set(),
    })

    for p in packets:
        src = p.get("src_ip", "")
        dst = p.get("dst_ip", "")
        proto = (p.get("protocol") or "").upper()
        sz = p.get("size", 0) or 0
        dport = p.get("dst_port")
        sport = p.get("src_port")
        if src:
            e = eps[src]
            e["packets_sent"] += 1
            e["bytes_sent"] += sz
            if proto:
                e["protocols"].add(proto)
            if dport:
                e["ports_used"].add(dport)
        if dst:
            e = eps[dst]
            e["packets_recv"] += 1
            e["bytes_recv"] += sz
            if sport:
                e["ports_used"].add(sport)

    result = []
    for ip, e in eps.items():
        result.append({
            "ip": ip,
            "packets_sent": e["packets_sent"],
            "packets_recv": e["packets_recv"],
            "bytes_sent": e["bytes_sent"],
            "bytes_recv": e["bytes_recv"],
            "total_packets": e["packets_sent"] + e["packets_recv"],
            "total_bytes": e["bytes_sent"] + e["bytes_recv"],
            "protocols": sorted(e["protocols"]),
            "ports_used": sorted(list(e["ports_used"]))[:20],
        })

    result.sort(key=lambda x: -x["total_packets"])
    return result[:limit]


def io_graph(packets: list, interval: float = 1.0) -> list:
    """
    I/O graph — packets and bytes per time bucket.
    Returns list of {t, packets, bytes} sorted by time.
    interval: seconds per bucket (default 1s)
    """
    if not packets:
        return []

    buckets: dict = defaultdict(lambda: {"packets": 0, "bytes": 0})
    for p in packets:
        ts = p.get("timestamp", 0) or 0
        bucket = int(ts / interval) * interval
        sz = p.get("size", 0) or 0
        buckets[bucket]["packets"] += 1
        buckets[bucket]["bytes"] += sz

    result = [{"t": t, **data} for t, data in buckets.items()]
    result.sort(key=lambda x: x["t"])
    return result


def service_stats(packets: list) -> list:
    """
    Port/service distribution for TCP/UDP traffic.
    Returns [{port, service, count}] sorted by count desc.
    """
    from utils.service_detector import get_service  # lazy import
    port_counts: dict = defaultdict(int)
    for p in packets:
        dport = p.get("dst_port")
        if dport and dport > 0:
            port_counts[dport] += 1

    result = []
    for port, count in sorted(port_counts.items(), key=lambda x: -x[1])[:50]:
        try:
            svc = get_service(port)
        except Exception:
            svc = ""
        result.append({"port": port, "service": svc, "count": count})
    return result


def expert_info(packets: list) -> list:
    """
    Expert information — Wireshark-style anomaly detection on packet stream.
    Detects: port scan, SYN flood, ARP spoof indicator, ICMP flood,
             DNS amplification, small packet storm, duplicate IPs.
    Returns list of {severity, category, detail, count}.
    """
    from collections import Counter
    alerts = []
    now = time.time()

    src_ports: dict = defaultdict(set)
    syn_counts: dict = defaultdict(int)
    arp_ips: dict = {}
    icmp_per_src: dict = defaultdict(int)
    dns_responses: list = []
    small_pkts: dict = defaultdict(int)

    for p in packets:
        src = p.get("src_ip", "")
        dst = p.get("dst_ip", "")
        proto = (p.get("protocol") or "").upper()
        flags = p.get("tcp", {}).get("flags", "") if isinstance(p.get("tcp"), dict) else ""
        sz = p.get("size", 0) or 0
        dport = p.get("dst_port", 0) or 0

        # Port scan detection
        if src and dport:
            src_ports[src].add(dport)

        # SYN flood
        if "S" in str(flags) and "A" not in str(flags):
            syn_counts[src] += 1

        # ARP spoof indicator
        if proto == "ARP" and isinstance(p.get("arp"), dict):
            arp = p["arp"]
            ip = arp.get("sender_ip", "")
            mac = arp.get("sender_mac", "")
            if ip and mac:
                if ip in arp_ips and arp_ips[ip] != mac:
                    alerts.append({
                        "severity": "ERROR",
                        "category": "ARP",
                        "detail": f"ARP MAC conflict for {ip}: {arp_ips[ip]} vs {mac}",
                        "count": 1,
                    })
                arp_ips[ip] = mac

        # ICMP flood
        if proto == "ICMP":
            icmp_per_src[src] += 1

        # DNS amplification (large UDP DNS responses > 512 bytes)
        if proto == "UDP" and dport == 53 and sz > 512:
            dns_responses.append(sz)

        # Small packet storm (< 64 bytes TCP/UDP)
        if proto in ("TCP", "UDP") and 0 < sz < 64:
            small_pkts[src] += 1

    # Port scan alert
    for src, ports in src_ports.items():
        if len(ports) > 15:
            alerts.append({
                "severity": "WARNING",
                "category": "Port Scan",
                "detail": f"{src} scanned {len(ports)} unique ports",
                "count": len(ports),
            })

    # SYN flood alert
    for src, cnt in syn_counts.items():
        if cnt > 50:
            alerts.append({
                "severity": "ERROR",
                "category": "SYN Flood",
                "detail": f"{src} sent {cnt} SYN packets (no ACK)",
                "count": cnt,
            })

    # ICMP flood
    for src, cnt in icmp_per_src.items():
        if cnt > 30:
            alerts.append({
                "severity": "WARNING",
                "category": "ICMP Flood",
                "detail": f"{src} sent {cnt} ICMP packets",
                "count": cnt,
            })

    # DNS amplification
    if len(dns_responses) > 5:
        avg_sz = sum(dns_responses) / len(dns_responses)
        alerts.append({
            "severity": "NOTE",
            "category": "DNS",
            "detail": f"{len(dns_responses)} large DNS responses (avg {avg_sz:.0f} bytes) — possible amplification",
            "count": len(dns_responses),
        })

    # Small packet storm
    for src, cnt in small_pkts.items():
        if cnt > 100:
            alerts.append({
                "severity": "NOTE",
                "category": "Small Packet Storm",
                "detail": f"{src} sent {cnt} small packets (<64 bytes)",
                "count": cnt,
            })

    alerts.sort(key=lambda x: {"ERROR": 0, "WARNING": 1, "NOTE": 2}.get(x["severity"], 3))
    return alerts
