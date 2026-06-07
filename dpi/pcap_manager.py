"""
PCAP Import / Export — Module 2.

Export: takes packets from the DB and writes a .pcap file using Scapy wrpcap.
Import: reads a .pcap file using Scapy rdpcap, dissects each packet, inserts into DB.
The exported file can be opened directly in Wireshark.
"""
import os
import time
import logging

logger = logging.getLogger("ids_ips")

_EXPORT_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "pcap",
)


def _scapy():
    try:
        import scapy.all as sc
        return sc
    except ImportError:
        return None


def export_pcap(packets: list, filename: str = None) -> dict:
    """
    packets: list of dicts from db.get_packets().
    Returns {"path": str, "count": int} or {"error": str}.
    """
    sc = _scapy()
    if sc is None:
        return {"error": "scapy not available"}

    os.makedirs(_EXPORT_DIR, exist_ok=True)
    if not filename:
        filename = f"export_{int(time.time())}.pcap"
    if not filename.endswith(".pcap"):
        filename += ".pcap"
    # Sanitise
    filename = os.path.basename(filename)
    path = os.path.join(_EXPORT_DIR, filename)

    scapy_pkts = []
    for p in packets:
        try:
            src_ip = p.get("src_ip") or "0.0.0.0"
            dst_ip = p.get("dst_ip") or "0.0.0.0"
            dst_port = int(p.get("dst_port") or 0)
            proto = (p.get("protocol") or "TCP").upper()
            size = int(p.get("size") or 64)
            if proto == "TCP":
                pkt = sc.IP(src=src_ip, dst=dst_ip) / sc.TCP(dport=dst_port)
            elif proto == "UDP":
                pkt = sc.IP(src=src_ip, dst=dst_ip) / sc.UDP(dport=dst_port)
            elif proto == "ICMP":
                pkt = sc.IP(src=src_ip, dst=dst_ip) / sc.ICMP()
            else:
                pkt = sc.IP(src=src_ip, dst=dst_ip)
            scapy_pkts.append(pkt)
        except Exception:
            continue

    if not scapy_pkts:
        return {"error": "no valid packets to export"}

    try:
        sc.wrpcap(path, scapy_pkts)
        return {"path": path, "count": len(scapy_pkts)}
    except Exception as e:
        return {"error": str(e)}


def import_pcap(path: str) -> dict:
    """
    Import a .pcap file, dissect each packet, insert into DB.
    Returns {"imported": int, "errors": int}.
    """
    sc = _scapy()
    if sc is None:
        return {"error": "scapy not available"}
    if not os.path.exists(path):
        return {"error": f"file not found: {path}"}

    try:
        pkts = sc.rdpcap(path)
    except Exception as e:
        return {"error": f"rdpcap failed: {e}"}

    from dpi.packet_dissector import dissect
    try:
        from db.database import Database
        db = Database.get()
    except Exception:
        db = None

    imported = 0
    errors = 0
    for pkt in pkts:
        try:
            d = dissect(pkt)
            if db and d:
                db.queue_packet({
                    "src_ip": d.get("src_ip", ""),
                    "dst_ip": d.get("dst_ip", ""),
                    "dst_port": d.get("dst_port") or d.get("tcp", {}).get("dst_port") or 0,
                    "protocol": d.get("protocol", "OTHER"),
                    "tcp_flags": 0,
                    "size": len(bytes(pkt)),
                    "timestamp": d.get("timestamp", time.time()),
                })
            imported += 1
        except Exception:
            errors += 1

    return {"imported": imported, "errors": errors, "total": len(pkts)}


def list_pcap_files() -> list:
    os.makedirs(_EXPORT_DIR, exist_ok=True)
    files = []
    for fn in os.listdir(_EXPORT_DIR):
        if fn.endswith(".pcap"):
            full = os.path.join(_EXPORT_DIR, fn)
            files.append({
                "filename": fn,
                "path": full,
                "size": os.path.getsize(full),
                "modified": os.path.getmtime(full),
            })
    files.sort(key=lambda x: x["modified"], reverse=True)
    return files
