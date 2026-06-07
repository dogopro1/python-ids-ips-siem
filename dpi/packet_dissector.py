"""
Deep Packet Inspection — Module 2.

Dissects raw Scapy packets into structured dicts with full protocol details.
Supports: Ethernet, IP, IPv6, TCP, UDP, ICMP, HTTP (plain), DNS, ARP, DHCP, TLS (header only).
"""
import logging
import time

logger = logging.getLogger("ids_ips")


def dissect(pkt) -> dict:
    """
    Takes a Scapy packet object and returns a fully dissected dict.
    Returns {} if dissection fails.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.dns import DNS
        from scapy.packet import Raw
    except ImportError:
        return {}

    result = {
        "timestamp": time.time(),
        "layers": [],
        "summary": pkt.summary() if hasattr(pkt, "summary") else "",
    }

    # ── Ethernet ──────────────────────────────────────────────────────────────
    if pkt.haslayer(Ether):
        eth = pkt[Ether]
        result["eth"] = {"src": eth.src, "dst": eth.dst, "type": hex(eth.type)}
        result["layers"].append("Ethernet")

    # ── ARP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        ops = {1: "who-has", 2: "is-at"}
        result["arp"] = {
            "op": ops.get(arp.op, str(arp.op)),
            "sender_mac": arp.hwsrc, "sender_ip": arp.psrc,
            "target_mac": arp.hwdst, "target_ip": arp.pdst,
        }
        result["layers"].append("ARP")
        result["protocol"] = "ARP"
        return result

    # ── IP ────────────────────────────────────────────────────────────────────
    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["ip"] = {
            "src": ip.src, "dst": ip.dst,
            "ttl": ip.ttl, "tos": ip.tos,
            "id": ip.id, "flags": str(ip.flags),
            "frag": ip.frag, "len": ip.len,
            "proto": ip.proto,
        }
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ttl"] = ip.ttl
        result["layers"].append("IP")

    # ── ICMP ──────────────────────────────────────────────────────────────────
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request",
                 11: "Time Exceeded", 5: "Redirect"}
        result["icmp"] = {
            "type": icmp.type, "type_name": types.get(icmp.type, f"type-{icmp.type}"),
            "code": icmp.code, "id": getattr(icmp, "id", None),
            "seq": getattr(icmp, "seq", None),
        }
        result["protocol"] = "ICMP"
        result["layers"].append("ICMP")
        return result

    # ── TCP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        flags_map = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
                     "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}
        flag_str = str(tcp.flags)
        active_flags = [name for ch, name in flags_map.items() if ch in flag_str]
        result["tcp"] = {
            "src_port": tcp.sport, "dst_port": tcp.dport,
            "flags": flag_str, "flags_decoded": active_flags,
            "seq": tcp.seq, "ack": tcp.ack,
            "window": tcp.window, "urgptr": tcp.urgptr,
        }
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        result["protocol"] = "TCP"
        result["layers"].append("TCP")

        # ── TLS detection (first byte 0x16 = handshake, 0x17 = data) ─────────
        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw])
            if raw and raw[0] in (0x14, 0x15, 0x16, 0x17, 0x18):
                tls_types = {0x14: "ChangeCipherSpec", 0x15: "Alert",
                             0x16: "Handshake", 0x17: "ApplicationData",
                             0x18: "Heartbeat"}
                result["tls"] = {
                    "content_type": tls_types.get(raw[0], hex(raw[0])),
                    "version_major": raw[1] if len(raw) > 1 else 0,
                    "version_minor": raw[2] if len(raw) > 2 else 0,
                }
                if raw[0] == 0x16 and len(raw) > 5:
                    hs_types = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
                                12: "ServerKeyExchange", 14: "ServerHelloDone",
                                16: "ClientKeyExchange", 20: "Finished"}
                    result["tls"]["handshake_type"] = hs_types.get(raw[5], f"type-{raw[5]}")
                result["layers"].append("TLS")

            # ── HTTP detection ────────────────────────────────────────────────
            elif tcp.dport in (80, 8080, 8000, 8888) or tcp.sport in (80, 8080, 8000, 8888):
                try:
                    text = raw.decode(errors="ignore")
                    if text.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                        lines = text.split("\r\n")
                        method, path, *_ = (lines[0].split(" ") + ["", ""])[:3]
                        headers = {}
                        for line in lines[1:]:
                            if ":" in line:
                                k, v = line.split(":", 1)
                                headers[k.strip().lower()] = v.strip()
                        result["http"] = {
                            "type": "request", "method": method,
                            "path": path, "headers": headers,
                            "body_preview": text[text.find("\r\n\r\n")+4:][:256],
                        }
                        result["layers"].append("HTTP")
                    elif text.startswith("HTTP/"):
                        lines = text.split("\r\n")
                        status = lines[0]
                        result["http"] = {
                            "type": "response", "status": status,
                            "body_preview": text[text.find("\r\n\r\n")+4:][:256],
                        }
                        result["layers"].append("HTTP")
                except Exception:
                    pass
        return result

    # ── UDP ───────────────────────────────────────────────────────────────────
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        result["udp"] = {
            "src_port": udp.sport, "dst_port": udp.dport, "len": udp.len,
        }
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport
        result["protocol"] = "UDP"
        result["layers"].append("UDP")

        # ── DNS ───────────────────────────────────────────────────────────────
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            qnames = []
            try:
                for i in range(dns.qdcount):
                    q = dns.qd
                    for _ in range(i):
                        q = q.payload
                    qnames.append(q.qname.decode(errors="replace").rstrip("."))
            except Exception:
                pass
            answers = []
            try:
                an = dns.an
                while an and an.type != 0:
                    answers.append({"name": str(an.rrname.decode(errors="replace")),
                                    "type": an.type, "rdata": str(an.rdata)})
                    an = an.payload
            except Exception:
                pass
            result["dns"] = {
                "id": dns.id, "qr": dns.qr,
                "opcode": dns.opcode, "rcode": dns.rcode,
                "questions": qnames, "answers": answers,
                "is_query": dns.qr == 0,
            }
            result["layers"].append("DNS")

    return result
