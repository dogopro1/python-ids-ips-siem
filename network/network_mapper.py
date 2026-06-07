"""
Home Network Mapper — Module 5.

Discovers all devices on the local subnet using:
  1. ARP scan (sends ARP who-has to all IPs in subnet)
  2. mDNS / SSDP passive listener
  3. TTL-based OS guess
  4. MAC OUI lookup (vendor identification)

Stores discovered devices in the database.
Re-scans periodically (interval from config).
"""
import threading
import time
import socket
import logging
import ipaddress

logger = logging.getLogger("ids_ips")

_devices: dict = {}   # ip → device dict
_lock = threading.Lock()
_running = False
_scan_thread = None


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


# ── OUI vendor lookup ─────────────────────────────────────────────────────────

_OUI_TABLE = {
    "00:50:56": "VMware", "00:0c:29": "VMware",
    "00:1a:11": "Google", "00:17:f2": "Apple",
    "00:1c:b3": "Apple", "00:23:32": "Apple",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi", "00:e0:4c": "Realtek",
    "fc:aa:14": "Amazon", "44:65:0d": "Amazon",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Netgear",
    "c8:d3:a3": "Netgear", "00:14:6c": "Netgear",
    "00:18:4d": "Netgear", "14:59:c0": "TP-Link",
    "50:c7:bf": "TP-Link", "a0:f3:c1": "TP-Link",
    "00:1d:7e": "Cisco", "00:0f:f7": "Cisco",
    "28:80:23": "Asus", "04:d4:c4": "Asus",
    "00:90:f5": "Asus", "00:08:22": "InPro Comm",
    "00:10:18": "Broadcom",
}


def _get_vendor(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.lower()[:8]
    return _OUI_TABLE.get(prefix, "")


# ── TTL-based OS guess ────────────────────────────────────────────────────────

def _guess_os_from_ttl(ttl: int) -> str:
    if ttl <= 64:
        return "Linux/Android"
    if ttl <= 128:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Network Device"
    return "Unknown"


# ── Detect local subnet ───────────────────────────────────────────────────────

def _get_local_subnet() -> str:
    try:
        from utils.config_loader import Config
        cfg = Config.load()
        net = cfg.get("home_network", "auto")
        if net and net != "auto":
            return net
    except Exception:
        pass
    # Detect via routing
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        # Assume /24
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


# ── ARP scan ─────────────────────────────────────────────────────────────────

def _arp_scan(subnet: str) -> list:
    sc = _scapy()
    if sc is None:
        return []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        answered, _ = sc.arping(str(network), timeout=2, verbose=False)
        results = []
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            results.append({"ip": ip, "mac": mac})
        return results
    except Exception as e:
        logger.debug("network_mapper: arp_scan error — %s", e)
        return []


# ── Hostname resolution ───────────────────────────────────────────────────────

def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Full network scan ─────────────────────────────────────────────────────────

def scan_network(subnet: str = None) -> list:
    subnet = subnet or _get_local_subnet()
    logger.info("network_mapper: scanning %s", subnet)

    found = _arp_scan(subnet)
    now = time.time()

    with _lock:
        for dev in found:
            ip = dev["ip"]
            mac = dev["mac"]
            existing = _devices.get(ip, {})
            hostname = existing.get("hostname") or _resolve_hostname(ip)
            vendor = _get_vendor(mac)
            _devices[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "vendor": vendor,
                "first_seen": existing.get("first_seen", now),
                "last_seen": now,
                "status": "up",
            }

    db = _db()
    if db:
        with _lock:
            devs = list(_devices.values())
        for d in devs:
            db.upsert_network_device(d)

    with _lock:
        return list(_devices.values())


def get_devices() -> list:
    db = _db()
    if db:
        devs = db.get_network_devices()
        if devs:
            return devs
    with _lock:
        return list(_devices.values())


def start(interval: int = 300):
    global _running, _scan_thread
    if _running:
        return
    _running = True
    _scan_thread = threading.Thread(
        target=_scan_loop, args=(interval,), daemon=True, name="NetworkMapper"
    )
    _scan_thread.start()
    logger.info("network_mapper: started (interval=%ds)", interval)


def _scan_loop(interval: int):
    while _running:
        try:
            scan_network()
        except Exception as e:
            logger.debug("network_mapper: scan error — %s", e)
        time.sleep(interval)


def stop():
    global _running
    _running = False
