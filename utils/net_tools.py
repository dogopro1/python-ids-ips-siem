"""
Enhanced network tools — Module 4 (Nmap-like scanner).

New features vs original:
  - banner_grab()      read first N bytes from open port → service version
  - os_fingerprint()   TTL + TCP window heuristic → OS guess
  - udp_scan()         UDP port probing (ICMP unreachable = closed/filtered)
  - arp_scan()         ARP who-has on local subnet
  - port_scan()        now includes banner + service + timing presets
  - enhanced whois()   now includes RDAP fallback
"""
import subprocess
import socket
import ssl
import platform
import time
import threading
import ipaddress
import logging

logger = logging.getLogger("ids_ips")

_OS = platform.system().lower()

# Timing presets: (connect_timeout, thread_count)
_TIMING = {
    1: (2.0, 20),    # sneaky
    2: (1.5, 50),    # polite
    3: (0.5, 150),   # normal (default)
    4: (0.3, 300),   # aggressive
    5: (0.1, 500),   # insane
}


# ── Ping ──────────────────────────────────────────────────────────────────────

def ping(host: str, count: int = 4) -> dict:
    count = min(max(1, count), 20)
    if _OS == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), "-W", "2", host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


# ── Traceroute ────────────────────────────────────────────────────────────────

def traceroute(host: str) -> dict:
    if _OS == "windows":
        cmd = ["tracert", "-h", "20", "-w", "1000", host]
    else:
        cmd = ["traceroute", "-m", "20", "-w", "2", host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"stdout": r.stdout, "stderr": r.stderr, "returncode": r.returncode}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "Timeout after 60s", "returncode": -1}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "traceroute/tracert not found.", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


# ── DNS ───────────────────────────────────────────────────────────────────────

def nslookup(host: str, record_type: str = "A") -> dict:
    record_type = record_type.upper()
    results = []
    errors = []
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, record_type)
        for rdata in answers:
            results.append(str(rdata))
        return {"host": host, "type": record_type, "results": results, "errors": errors}
    except ImportError:
        pass
    except Exception as e:
        errors.append(str(e))
    if record_type in ("A", "AAAA"):
        try:
            family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
            addrs = socket.getaddrinfo(host, None, family)
            results = list({a[4][0] for a in addrs})
        except Exception as e2:
            errors.append(str(e2))
    return {"host": host, "type": record_type, "results": results, "errors": errors}


def dns_lookup_all(host: str) -> dict:
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]
    out = {}
    for rt in record_types:
        r = nslookup(host, rt)
        if r["results"]:
            out[rt] = r["results"]
    return out


# ── WHOIS + RDAP ──────────────────────────────────────────────────────────────

def whois(host: str) -> dict:
    # subprocess whois
    try:
        cmd = ["whois", host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            return {"output": r.stdout, "source": "subprocess"}
    except (FileNotFoundError, Exception):
        pass

    # socket whois
    try:
        output = _socket_whois(host)
        return {"output": output, "source": "socket"}
    except Exception:
        pass

    # RDAP fallback
    try:
        from intel.rdap_lookup import rdap_ip, rdap_domain
        try:
            ipaddress.ip_address(host)
            data = rdap_ip(host)
        except ValueError:
            data = rdap_domain(host)
        import json
        return {"output": json.dumps(data, indent=2), "source": "rdap", "structured": data}
    except Exception as e:
        return {"output": f"Whois unavailable: {e}", "source": "error"}


def _socket_whois(query: str) -> str:
    server = "whois.iana.org"
    port = 43
    with socket.create_connection((server, port), timeout=10) as s:
        s.sendall(f"{query}\r\n".encode())
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
    text = raw.decode(errors="replace")
    for line in text.splitlines():
        if line.lower().startswith("whois:") or line.lower().startswith("refer:"):
            ref_server = line.split(":", 1)[1].strip()
            if ref_server and ref_server != server:
                with socket.create_connection((ref_server, port), timeout=10) as s2:
                    s2.sendall(f"{query}\r\n".encode())
                    raw2 = b""
                    while True:
                        chunk = s2.recv(4096)
                        if not chunk:
                            break
                        raw2 += chunk
                return raw2.decode(errors="replace")
    return text


# ── Banner grabbing ───────────────────────────────────────────────────────────

def banner_grab(host: str, port: int, timeout: float = 2.0, use_ssl: bool = False) -> str:
    """
    Connect to host:port, optionally wrap in SSL, send a minimal probe,
    read up to 512 bytes, return decoded banner.
    """
    probes = {
        21: b"",              # FTP sends banner immediately
        22: b"",              # SSH sends banner immediately
        25: b"",              # SMTP sends banner immediately
        80: b"HEAD / HTTP/1.0\r\n\r\n",
        110: b"",             # POP3
        143: b"",             # IMAP
        443: b"HEAD / HTTP/1.0\r\n\r\n",
        3306: b"",            # MySQL sends banner
        5432: b"",            # PostgreSQL
        6379: b"PING\r\n",   # Redis
        27017: b"",           # MongoDB
    }
    probe = probes.get(port, b"HEAD / HTTP/1.0\r\n\r\n")
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl or port == 443:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if probe:
            sock.sendall(probe)
        sock.settimeout(timeout)
        banner = b""
        try:
            while len(banner) < 512:
                chunk = sock.recv(512 - len(banner))
                if not chunk:
                    break
                banner += chunk
        except (socket.timeout, OSError):
            pass
        sock.close()
        return banner.decode(errors="replace").strip()
    except Exception:
        return ""


# ── OS fingerprinting (heuristic) ─────────────────────────────────────────────

def os_fingerprint(host: str) -> dict:
    """
    Send ICMP ping (via subprocess) and check TTL, TCP window.
    Returns a best-guess OS string with confidence.
    """
    # Get TTL from ping output
    ttl = _get_ping_ttl(host)
    result = {
        "host": host,
        "ttl": ttl,
        "tcp_window": None,
        "guess": "Unknown",
        "confidence": "low",
        "details": "",
    }
    if ttl is None:
        result["details"] = "Host unreachable or ping blocked"
        return result

    # TTL heuristics (initial TTL — reduced by each hop)
    if ttl <= 64:
        result["guess"] = "Linux / Android / macOS"
        result["confidence"] = "medium"
    elif ttl <= 128:
        result["guess"] = "Windows"
        result["confidence"] = "medium"
    elif ttl <= 255:
        result["guess"] = "Cisco IOS / Network Device"
        result["confidence"] = "low"

    # TCP window size heuristic (connect to port 80 or 443)
    win = _get_tcp_window(host)
    result["tcp_window"] = win
    if win:
        if win == 65535:
            result["guess"] = "macOS / FreeBSD"
            result["confidence"] = "medium"
        elif win == 8192:
            result["guess"] = "Windows XP / 2003"
            result["confidence"] = "medium"
        elif win in (64240, 29200):
            result["guess"] = "Linux 4.x+"
            result["confidence"] = "medium"
        elif win == 65535 and ttl == 128:
            result["guess"] = "Windows 7/8/10"
            result["confidence"] = "medium"

    result["details"] = (
        f"TTL={ttl}, TCP-window={win or 'N/A'}. "
        f"Note: TTL decreases by 1 per hop — actual initial TTL may be higher."
    )
    return result


def _get_ping_ttl(host: str) -> int | None:
    try:
        if _OS == "windows":
            cmd = ["ping", "-n", "1", host]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        import re
        m = re.search(r"TTL[=:](\d+)", r.stdout, re.IGNORECASE)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None


def _get_tcp_window(host: str) -> int | None:
    for port in (80, 443, 22, 21):
        try:
            with socket.create_connection((host, port), timeout=1) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                win = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                return win
        except Exception:
            continue
    return None


# ── UDP scan ──────────────────────────────────────────────────────────────────

_UDP_PROBES = {
    53:  b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    67:  b"\x01" + b"\x00" * 235,   # DHCP discover (minimal)
    123: b"\x1b" + b"\x00" * 47,    # NTP client request
    161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
    500: b"\x00" * 28,              # IKE
    1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
}

def udp_scan(host: str, ports: str = "53,67,123,161,500,1900") -> dict:
    port_list = _parse_ports(ports)
    if len(port_list) > 200:
        return {"error": "Max 200 UDP ports per scan"}

    open_filtered = []
    closed = []
    lock = threading.Lock()

    def scan_port(p: int):
        probe = _UDP_PROBES.get(p, b"\x00\x00")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(probe, (host, p))
            try:
                data, _ = sock.recvfrom(512)
                with lock:
                    from utils.service_detector import get_service
                    open_filtered.append({
                        "port": p, "state": "open",
                        "service": get_service(p),
                        "response": data[:64].hex(),
                    })
            except socket.timeout:
                # No response could mean open|filtered
                with lock:
                    open_filtered.append({
                        "port": p, "state": "open|filtered",
                        "service": _udp_service(p),
                    })
            sock.close()
        except Exception:
            with lock:
                closed.append(p)

    threads = [threading.Thread(target=scan_port, args=(p,), daemon=True) for p in port_list]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    return {
        "host": host,
        "scanned": len(port_list),
        "results": open_filtered,
        "closed": len(closed),
        "protocol": "UDP",
    }


def _udp_service(port: int) -> str:
    services = {53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP",
                123: "NTP", 161: "SNMP", 162: "SNMPTRAP",
                500: "IKE/IPSec", 1900: "SSDP/UPnP", 5353: "mDNS"}
    return services.get(port, "")


# ── ARP scan ──────────────────────────────────────────────────────────────────

def arp_scan(subnet: str = None) -> dict:
    """
    Discover all live hosts in the local subnet using ARP.
    Uses Scapy arping. Falls back to ICMP ping sweep if Scapy unavailable.
    """
    if subnet is None:
        subnet = _detect_subnet()

    try:
        import scapy.all as sc
        network = ipaddress.ip_network(subnet, strict=False)
        answered, _ = sc.arping(str(network), timeout=2, verbose=False)
        hosts = [
            {
                "ip": rcv.psrc,
                "mac": rcv.hwsrc,
                "vendor": _oui_vendor(rcv.hwsrc),
            }
            for _, rcv in answered
        ]
        return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "method": "ARP"}
    except Exception:
        pass

    # Fallback: ICMP ping sweep (slow)
    hosts = _ping_sweep(subnet)
    return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "method": "ICMP"}


def _detect_subnet() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    except Exception:
        return "192.168.1.0/24"


def _ping_sweep(subnet: str) -> list:
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = []
    lock = threading.Lock()

    def check(ip):
        try:
            sock = socket.create_connection((str(ip), 80), timeout=0.5)
            sock.close()
            with lock:
                hosts.append({"ip": str(ip), "mac": "", "vendor": ""})
        except Exception:
            pass

    threads = [threading.Thread(target=check, args=(ip,), daemon=True)
               for ip in list(network.hosts())[:254]]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)
    return hosts


_OUI = {
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
    "00:50:56": "VMware", "00:0c:29": "VMware",
    "00:17:88": "Philips Hue", "14:59:c0": "TP-Link",
    "50:c7:bf": "TP-Link", "fc:aa:14": "Amazon",
    "00:1d:7e": "Cisco", "28:80:23": "Asus",
}


def _oui_vendor(mac: str) -> str:
    return _OUI.get(mac.lower()[:8], "")


# ── Enhanced port scan with banner grabbing ───────────────────────────────────

def port_scan(host: str, ports: str = "1-1024", timing: int = 3,
              banner: bool = True, os_detect: bool = False) -> dict:
    """
    TCP connect scan with optional banner grabbing and OS detection.
    timing: 1-5 (like nmap -T)
    """
    port_list = _parse_ports(ports)
    cfg_max = 10000
    try:
        from utils.config_loader import Config
        cfg_max = int(Config.load().get("scan_max_ports", 10000))
    except Exception:
        pass
    if len(port_list) > cfg_max:
        return {"error": f"Max {cfg_max} ports per scan"}

    timeout, max_threads = _TIMING.get(timing, (0.5, 150))
    open_ports = []
    closed = 0
    lock = threading.Lock()
    sem = threading.Semaphore(max_threads)

    def scan_port(p: int):
        nonlocal closed
        try:
            with socket.create_connection((host, p), timeout=timeout):
                pass
            # Port is open
            from utils.service_detector import get_service
            entry = {"port": p, "state": "open", "service": get_service(p)}
            if banner:
                b = banner_grab(host, p, timeout=timeout)
                entry["banner"] = b[:200] if b else ""
                if b:
                    entry["version"] = _parse_version_from_banner(b)
            with lock:
                open_ports.append(entry)
        except (ConnectionRefusedError, OSError):
            with lock:
                closed += 1
        except Exception:
            pass
        finally:
            sem.release()

    threads = []
    for p in port_list:
        sem.acquire()
        t = threading.Thread(target=scan_port, args=(p,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join(timeout=30)

    result = {
        "host": host,
        "scanned": len(port_list),
        "open": sorted(open_ports, key=lambda x: x["port"]),
        "closed": closed,
        "timing": timing,
    }

    if os_detect:
        result["os"] = os_fingerprint(host)

    return result


def _parse_version_from_banner(banner: str) -> str:
    """Extract version strings from common service banners."""
    import re
    patterns = [
        r"SSH-[\d.]+-([^\r\n]+)",           # SSH: OpenSSH_9.2
        r"Server:\s*([^\r\n]+)",             # HTTP Server header
        r"(\w[\w._-]+[\d]+[\w._-]*)",        # Generic version token
        r"FTP[^)]+\(([^)]+)\)",             # FTP server info
        r"220[- ]([^\r\n]+)",               # SMTP/FTP 220 banner
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group(1).strip()[:80]
    return ""


# ── Port parser ───────────────────────────────────────────────────────────────

def _parse_ports(ports_str: str) -> list:
    result = set()
    for part in ports_str.replace(" ", "").split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                result.update(range(int(a), int(b) + 1))
            except ValueError:
                pass
        else:
            try:
                result.add(int(part))
            except ValueError:
                pass
    return [p for p in result if 1 <= p <= 65535]
