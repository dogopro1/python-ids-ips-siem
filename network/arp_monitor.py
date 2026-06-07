"""
ARP Spoof / Poisoning Monitor — Module 5.

Sniffs ARP packets using Scapy. Maintains an ARP table (IP→MAC mapping).
Raises an alert when a known IP changes its MAC address (ARP spoofing indicator).
Also detects gratuitous ARP (unsolicited ARP reply) which is commonly used in attacks.
"""
import threading
import time
import logging
from collections import deque

logger = logging.getLogger("ids_ips")

_arp_table: dict = {}          # ip → {"mac": str, "first_seen": float, "last_seen": float}
_arp_events: deque = deque(maxlen=500)
_lock = threading.Lock()
_running = False
_sniffer_thread = None


def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None


def _scapy():
    try:
        import scapy.all as sc
        return sc
    except ImportError:
        return None


def _process_arp(pkt):
    sc = _scapy()
    if sc is None:
        return
    try:
        if not pkt.haslayer(sc.ARP):
            return
        arp = pkt[sc.ARP]
        if arp.op not in (1, 2):  # who-has or is-at
            return

        sender_ip = arp.psrc
        sender_mac = arp.hwsrc.lower()

        if not sender_ip or sender_ip == "0.0.0.0":
            return

        now = time.time()
        with _lock:
            known = _arp_table.get(sender_ip)
            if known is None:
                _arp_table[sender_ip] = {
                    "mac": sender_mac, "first_seen": now, "last_seen": now,
                    "change_count": 0,
                }
                return

            known["last_seen"] = now
            if known["mac"] == sender_mac:
                return

            # MAC changed — potential ARP spoofing
            old_mac = known["mac"]
            known["mac"] = sender_mac
            known["change_count"] = known.get("change_count", 0) + 1

        # Gratuitous ARP check (ARP reply with target = sender)
        is_gratuitous = (arp.op == 2 and arp.pdst == sender_ip)
        event = {
            "type": "ARP_SPOOF",
            "severity": "HIGH",
            "ip": sender_ip,
            "old_mac": old_mac,
            "new_mac": sender_mac,
            "is_gratuitous": is_gratuitous,
            "timestamp": now,
            "message": (
                f"ARP SPOOF detected: {sender_ip} changed MAC "
                f"{old_mac} → {sender_mac}"
                + (" [gratuitous]" if is_gratuitous else "")
            ),
        }
        _arp_events.appendleft(event)
        logger.alert("ARP SPOOF: %s changed MAC %s → %s", sender_ip, old_mac, sender_mac)

        db = _db()
        if db:
            db.save_arp_event(event)
    except Exception as e:
        logger.debug("arp_monitor: process error — %s", e)


def start():
    global _running, _sniffer_thread
    if _running:
        return
    sc = _scapy()
    if sc is None:
        logger.warning("arp_monitor: scapy not available")
        return

    _running = True
    _sniffer_thread = threading.Thread(target=_sniff_loop, daemon=True, name="ARP-Monitor")
    _sniffer_thread.start()
    logger.info("ARP monitor started")


def _sniff_loop():
    sc = _scapy()
    while _running:
        try:
            sc.sniff(filter="arp", prn=_process_arp, store=False, timeout=5)
        except Exception as e:
            logger.debug("arp_monitor: sniff error — %s", e)
            time.sleep(5)


def stop():
    global _running
    _running = False


def get_arp_table() -> list:
    with _lock:
        return [
            {"ip": ip, **info}
            for ip, info in sorted(_arp_table.items())
        ]


def get_events(limit: int = 50) -> list:
    return list(_arp_events)[:limit]
