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

# ── Nmap Top Ports list (from nmap-services) ──────────────────────────────────

_TOP_PORTS_1000 = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080,
    1723, 111, 995, 993, 5900, 1025, 587, 8888, 199, 1720, 465, 548, 113,
    81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
    26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000,
    513, 990, 5357, 427, 49156, 543, 544, 5101, 144, 7, 389, 8009, 3128,
    444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9,
    5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
]

_TOP_PORTS_100 = _TOP_PORTS_1000[:100]


def top_ports_scan(host: str, n: int = 100, timing: int = 3,
                   banner: bool = True, os_detect: bool = False) -> dict:
    """Scan the N most common TCP ports (Nmap --top-ports equivalent)."""
    ports = list(dict.fromkeys(_TOP_PORTS_1000[:max(1, min(n, 1000))]))
    ports_str = ",".join(str(p) for p in ports)
    return port_scan(host, ports_str, timing=timing, banner=banner, os_detect=os_detect)


# ── Stealth / raw-socket scans (Scapy-based, require root/Administrator) ──────

def _scapy_scan(host: str, ports: list, flags: str, timeout: float = 2.0) -> dict:
    """Generic Scapy TCP scan with custom flags."""
    try:
        from scapy.all import IP, TCP, sr, conf
        conf.verb = 0
    except ImportError:
        return {"error": "Scapy not installed"}
    except Exception as e:
        return {"error": str(e)}

    import socket
    try:
        host_ip = socket.gethostbyname(host)
    except Exception as e:
        return {"error": f"DNS lookup failed: {e}"}

    open_ports = []
    closed_ports = []
    filtered_ports = []

    try:
        pkts = [IP(dst=host_ip) / TCP(dport=p, flags=flags) for p in ports[:500]]
        answered, unanswered = sr(pkts, timeout=timeout, verbose=False)

        for sent, received in answered:
            tcp = received.getlayer(TCP) if received.haslayer(TCP) else None
            if tcp is None:
                continue
            port = sent[TCP].dport
            tcp_flags = str(tcp.flags)
            if "S" in tcp_flags and "A" in tcp_flags:
                open_ports.append(port)
            elif "R" in tcp_flags:
                closed_ports.append(port)

        for pkt in unanswered:
            filtered_ports.append(pkt[TCP].dport)

        from utils.service_detector import get_service
        result = {
            "host": host, "host_ip": host_ip,
            "scan_type": flags,
            "open": [{"port": p, "service": get_service(p)} for p in sorted(open_ports)],
            "closed": len(closed_ports),
            "filtered": len(filtered_ports),
            "scanned": len(ports),
        }
        return result
    except PermissionError:
        return {"error": "Raw socket scans require Administrator/root privileges"}
    except Exception as exc:
        return {"error": str(exc)}


def syn_scan(host: str, ports: str = "1-1024", timing: int = 3) -> dict:
    """Stealth SYN scan (-sS equivalent). Requires root/Administrator."""
    timeout, _ = _TIMING.get(timing, (0.5, 150))
    port_list = _parse_ports(ports)
    if len(port_list) > 10000:
        return {"error": "Max 10000 ports per scan"}
    return _scapy_scan(host, port_list, "S", timeout)


def null_scan(host: str, ports: str = "1-1024") -> dict:
    """TCP NULL scan (no flags, -sN). Requires root/Administrator."""
    return _scapy_scan(host, _parse_ports(ports), "", 2.0)


def fin_scan(host: str, ports: str = "1-1024") -> dict:
    """TCP FIN scan (-sF). Requires root/Administrator."""
    return _scapy_scan(host, _parse_ports(ports), "F", 2.0)


def xmas_scan(host: str, ports: str = "1-1024") -> dict:
    """TCP Xmas scan (FIN+PSH+URG, -sX). Requires root/Administrator."""
    return _scapy_scan(host, _parse_ports(ports), "FPU", 2.0)


def ack_scan(host: str, ports: str = "1-1024") -> dict:
    """
    TCP ACK scan (-sA). Detects firewall rules.
    Unfiltered ports return RST. Filtered ports drop the packet.
    """
    try:
        from scapy.all import IP, TCP, sr, conf
        conf.verb = 0
        import socket
        host_ip = socket.gethostbyname(host)
        port_list = _parse_ports(ports)[:500]
        pkts = [IP(dst=host_ip) / TCP(dport=p, flags="A") for p in port_list]
        answered, unanswered = sr(pkts, timeout=2.0, verbose=False)
        unfiltered = []
        filtered = []
        for sent, recv in answered:
            if recv.haslayer(TCP) and "R" in str(recv[TCP].flags):
                unfiltered.append(sent[TCP].dport)
        for pkt in unanswered:
            filtered.append(pkt[TCP].dport)
        return {
            "host": host, "scan_type": "ACK",
            "unfiltered": sorted(unfiltered),
            "filtered": sorted(filtered),
            "note": "Unfiltered=firewall rule allows port, Filtered=firewall drops ACK packet",
        }
    except PermissionError:
        return {"error": "ACK scan requires Administrator/root privileges"}
    except ImportError:
        return {"error": "Scapy not installed"}
    except Exception as exc:
        return {"error": str(exc)}


def window_scan(host: str, ports: str = "1-1024") -> dict:
    """TCP Window scan (-sW). Like ACK scan but checks TCP window size."""
    try:
        from scapy.all import IP, TCP, sr, conf
        conf.verb = 0
        import socket
        host_ip = socket.gethostbyname(host)
        port_list = _parse_ports(ports)[:500]
        pkts = [IP(dst=host_ip) / TCP(dport=p, flags="A") for p in port_list]
        answered, _ = sr(pkts, timeout=2.0, verbose=False)
        open_ports = []
        closed_ports = []
        for sent, recv in answered:
            if recv.haslayer(TCP):
                tcp = recv[TCP]
                if "R" in str(tcp.flags):
                    if tcp.window > 0:
                        open_ports.append(sent[TCP].dport)
                    else:
                        closed_ports.append(sent[TCP].dport)
        from utils.service_detector import get_service
        return {
            "host": host, "scan_type": "Window",
            "open": [{"port": p, "service": get_service(p)} for p in sorted(open_ports)],
            "closed": len(closed_ports),
        }
    except PermissionError:
        return {"error": "Window scan requires Administrator/root privileges"}
    except ImportError:
        return {"error": "Scapy not installed"}
    except Exception as exc:
        return {"error": str(exc)}


def ping_sweep(subnet: str = None) -> dict:
    """ICMP ping sweep for host discovery (-sn/-sP equivalent). Uses Scapy if available."""
    if subnet is None:
        subnet = _detect_subnet()
    try:
        import ipaddress as _ip
        network = _ip.ip_network(subnet, strict=False)
    except ValueError as e:
        return {"error": str(e)}

    hosts = []

    # Scapy ICMP method (accurate)
    try:
        from scapy.all import IP, ICMP, sr, conf
        conf.verb = 0
        targets = [str(ip) for ip in list(network.hosts())[:254]]
        pkts = [IP(dst=t) / ICMP() for t in targets]
        answered, _ = sr(pkts, timeout=1.5, verbose=False)
        for sent, recv in answered:
            hosts.append({
                "ip": recv[IP].src,
                "ttl": recv[IP].ttl,
                "method": "ICMP",
            })
        return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "method": "ICMP"}
    except Exception:
        pass

    # TCP SYN fallback on port 80/443
    lock = threading.Lock()
    import ipaddress as _ip2
    network2 = _ip2.ip_network(subnet, strict=False)

    def check_host(ip_str):
        for port in (80, 443, 22):
            try:
                sock = socket.create_connection((ip_str, port), timeout=0.5)
                sock.close()
                with lock:
                    hosts.append({"ip": ip_str, "ttl": None, "method": "TCP"})
                return
            except Exception:
                pass

    all_hosts = [str(ip) for ip in list(network2.hosts())[:254]]
    threads = [threading.Thread(target=check_host, args=(ip,), daemon=True) for ip in all_hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)

    return {"subnet": subnet, "hosts": hosts, "count": len(hosts), "method": "TCP-fallback"}


# ── IPv6 scanning ─────────────────────────────────────────────────────────────

def ipv6_scan(host: str, ports: str = "1-1024", timing: int = 3,
              banner: bool = True) -> dict:
    """TCP connect scan for IPv6 addresses."""
    port_list = _parse_ports(ports)
    timeout, max_threads = _TIMING.get(timing, (0.5, 150))
    open_ports = []
    closed = 0
    lock = threading.Lock()
    sem = threading.Semaphore(max_threads)

    def scan_port(p: int):
        nonlocal closed
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, p, 0, 0))
            sock.close()
            if result == 0:
                from utils.service_detector import get_service
                entry = {"port": p, "state": "open", "service": get_service(p)}
                if banner:
                    b = banner_grab(host, p, timeout=timeout)
                    entry["banner"] = b[:200] if b else ""
                with lock:
                    open_ports.append(entry)
            else:
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

    return {
        "host": host, "protocol": "IPv6",
        "scanned": len(port_list),
        "open": sorted(open_ports, key=lambda x: x["port"]),
        "closed": closed,
    }


# ── NSE script equivalents ────────────────────────────────────────────────────

def nse_run(host: str, scripts: list, open_ports: list = None) -> dict:
    """
    Run NSE-like service scripts.

    Available scripts:
      http-title        — fetch / and extract page title
      http-headers      — fetch response headers from port 80/443
      http-server-header — extract Server: header
      http-robots       — fetch robots.txt
      ssl-cert          — TLS certificate details (subject, issuer, expiry)
      ftp-anon          — test anonymous FTP login
      smtp-commands     — EHLO and list SMTP commands
      ssh-hostkey       — get SSH host key fingerprint
      smb-os-discovery  — NetBIOS/SMB OS info
      vnc-info          — VNC version banner
      http-auth-finder  — detect HTTP auth methods
    """
    results = {}
    if not open_ports:
        open_ports = []

    def _http(port, use_ssl):
        try:
            import urllib.request as _ur
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            scheme = "https" if use_ssl else "http"
            req = _ur.Request(f"{scheme}://{host}:{port}/",
                              headers={"User-Agent": "Mozilla/5.0 (NSE/1.0)"})
            with _ur.urlopen(req, timeout=5, context=ctx if use_ssl else None) as resp:
                body = resp.read(16384).decode(errors="replace")
                hdrs = dict(resp.headers)
                return body, hdrs, resp.status
        except Exception:
            return "", {}, 0

    for script in scripts:
        script = script.lower().strip()
        try:
            if script == "http-title":
                import re as _re
                for port in [p for p in (open_ports or [80, 443, 8080, 8443]) if p in (80, 443, 8080, 8443, 8000)]:
                    use_ssl = port in (443, 8443)
                    body, hdrs, status = _http(port, use_ssl)
                    if body:
                        m = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.IGNORECASE | _re.DOTALL)
                        title = m.group(1).strip()[:200] if m else "(no title)"
                        results["http-title"] = {"port": port, "title": title, "status": status}
                        break

            elif script == "http-headers":
                for port in [p for p in (open_ports or [80, 443]) if p in (80, 443, 8080, 8443, 8000)]:
                    use_ssl = port in (443, 8443)
                    _, hdrs, status = _http(port, use_ssl)
                    if hdrs:
                        results["http-headers"] = {"port": port, "headers": hdrs, "status": status}
                        break

            elif script == "http-server-header":
                for port in [p for p in (open_ports or [80, 443]) if p in (80, 443, 8080, 8443)]:
                    _, hdrs, _ = _http(port, port in (443, 8443))
                    if hdrs:
                        server = hdrs.get("Server") or hdrs.get("server") or ""
                        results["http-server-header"] = {"port": port, "server": server}
                        break

            elif script == "http-robots":
                for port in [p for p in (open_ports or [80, 443]) if p in (80, 443, 8080)]:
                    use_ssl = port in (443, 8443)
                    try:
                        import urllib.request as _ur2
                        import ssl as _ssl2
                        ctx2 = _ssl2.create_default_context()
                        ctx2.check_hostname = False
                        ctx2.verify_mode = _ssl2.CERT_NONE
                        scheme = "https" if use_ssl else "http"
                        req = _ur2.Request(f"{scheme}://{host}:{port}/robots.txt")
                        with _ur2.urlopen(req, timeout=5, context=ctx2 if use_ssl else None) as r:
                            robots = r.read(4096).decode(errors="replace")
                            results["http-robots"] = {"port": port, "robots_txt": robots}
                            break
                    except Exception:
                        pass

            elif script == "ssl-cert":
                for port in [p for p in (open_ports or [443, 8443]) if p in (443, 8443, 636, 993, 995, 465)]:
                    try:
                        import ssl as _ssl3
                        ctx3 = _ssl3.create_default_context()
                        ctx3.check_hostname = False
                        ctx3.verify_mode = _ssl3.CERT_NONE
                        with _ssl3.create_connection((host, port), timeout=5) as raw:
                            with ctx3.wrap_socket(raw, server_hostname=host) as s:
                                cert = s.getpeercert(binary_form=False)
                                der = s.getpeercert(binary_form=True)
                                import hashlib
                                sha1 = hashlib.sha1(der).hexdigest().upper()
                                sha256 = hashlib.sha256(der).hexdigest().upper()
                                results["ssl-cert"] = {
                                    "port": port,
                                    "subject": dict(x[0] for x in cert.get("subject", [])),
                                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                                    "notBefore": cert.get("notBefore", ""),
                                    "notAfter": cert.get("notAfter", ""),
                                    "sha1": ":".join(sha1[i:i+2] for i in range(0, 40, 2)),
                                    "sha256": sha256[:20] + "...",
                                    "san": [v for t, v in cert.get("subjectAltName", [])],
                                }
                                break
                    except Exception as e:
                        results["ssl-cert"] = {"port": port, "error": str(e)}

            elif script == "ftp-anon":
                port = next((p for p in (open_ports or [21]) if p == 21), 21)
                try:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=8)
                    banner = ftp.getwelcome()
                    try:
                        ftp.login("anonymous", "anon@example.com")
                        listing = []
                        ftp.retrlines("LIST", listing.append)
                        results["ftp-anon"] = {"port": port, "anonymous": True,
                                               "banner": banner, "listing": listing[:10]}
                        ftp.quit()
                    except Exception:
                        results["ftp-anon"] = {"port": port, "anonymous": False, "banner": banner}
                except Exception as e:
                    results["ftp-anon"] = {"error": str(e)}

            elif script == "smtp-commands":
                port = next((p for p in (open_ports or [25, 587]) if p in (25, 587, 465)), 25)
                try:
                    with socket.create_connection((host, port), timeout=8) as s:
                        s.settimeout(5)
                        banner = s.recv(1024).decode(errors="replace").strip()
                        s.sendall(f"EHLO probe.local\r\n".encode())
                        ehlo_resp = s.recv(4096).decode(errors="replace")
                        s.sendall(b"QUIT\r\n")
                    cmds = [line[4:] for line in ehlo_resp.splitlines() if line.startswith("250-") or line.startswith("250 ")]
                    results["smtp-commands"] = {"port": port, "banner": banner,
                                                "commands": cmds, "ehlo_response": ehlo_resp[:500]}
                except Exception as e:
                    results["smtp-commands"] = {"error": str(e)}

            elif script == "ssh-hostkey":
                port = next((p for p in (open_ports or [22]) if p == 22), 22)
                b = banner_grab(host, port, timeout=5)
                if b:
                    results["ssh-hostkey"] = {"port": port, "banner": b,
                                              "version": b.split("\n")[0] if b else ""}

            elif script == "smb-os-discovery":
                for port in [p for p in (open_ports or [445, 139]) if p in (445, 139)]:
                    b = banner_grab(host, port, timeout=5)
                    results["smb-os-discovery"] = {"port": port, "banner": b[:200] if b else ""}
                    break

            elif script == "vnc-info":
                port = next((p for p in (open_ports or [5900]) if p == 5900), 5900)
                b = banner_grab(host, port, timeout=5)
                if b and "RFB" in b:
                    results["vnc-info"] = {"port": port, "version": b.split("\n")[0]}
                elif b:
                    results["vnc-info"] = {"port": port, "banner": b[:100]}

            elif script == "http-auth-finder":
                for port in [p for p in (open_ports or [80, 443]) if p in (80, 443, 8080)]:
                    _, hdrs, status = _http(port, port in (443, 8443))
                    auth = hdrs.get("WWW-Authenticate") or hdrs.get("www-authenticate") or ""
                    results["http-auth-finder"] = {"port": port, "status": status, "auth": auth}
                    break

        except Exception as exc:
            results[script] = {"error": str(exc)}

    return results


# ── Scan output format converters ─────────────────────────────────────────────

def scan_to_xml(scan_result: dict) -> str:
    """Convert port scan result to Nmap-compatible XML format."""
    import xml.etree.ElementTree as ET
    import time as _time

    root = ET.Element("nmaprun")
    root.set("scanner", "ids-ips-scanner")
    root.set("start", str(int(_time.time())))
    root.set("version", "1.0")

    host_el = ET.SubElement(root, "host")
    addr = ET.SubElement(host_el, "address")
    addr.set("addr", scan_result.get("host", ""))
    addr.set("addrtype", "ipv4")

    ports_el = ET.SubElement(host_el, "ports")
    for p in scan_result.get("open", []):
        port_el = ET.SubElement(ports_el, "port")
        port_el.set("protocol", "tcp")
        port_el.set("portid", str(p.get("port", 0)))
        state_el = ET.SubElement(port_el, "state")
        state_el.set("state", "open")
        svc_el = ET.SubElement(port_el, "service")
        svc_el.set("name", p.get("service", ""))
        if p.get("banner"):
            svc_el.set("banner", p["banner"][:100])
        if p.get("version"):
            svc_el.set("version", p["version"])

    if scan_result.get("os"):
        os_el = ET.SubElement(host_el, "os")
        osmatch = ET.SubElement(os_el, "osmatch")
        osmatch.set("name", scan_result["os"].get("guess", "Unknown"))
        osmatch.set("accuracy", "medium")

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode", xml_declaration=True)


def scan_to_grepable(scan_result: dict) -> str:
    """Convert port scan result to Nmap grepable format (-oG)."""
    import time as _time
    host = scan_result.get("host", "unknown")
    open_ports = scan_result.get("open", [])
    ports_str = ", ".join(
        f"{p['port']}/open/tcp//{p.get('service', '')}/"
        for p in open_ports
    )
    ts = _time.strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# IDS/IPS Scanner grepable output — {ts}",
        f"Host: {host}\tPorts: {ports_str}\t",
    ]
    if scan_result.get("os"):
        lines.append(f"# OS: {scan_result['os'].get('guess', 'Unknown')}")
    return "\n".join(lines)


def scan_to_normal(scan_result: dict) -> str:
    """Convert port scan result to Nmap normal format (-oN)."""
    import time as _time
    host = scan_result.get("host", "unknown")
    open_ports = scan_result.get("open", [])
    lines = [
        f"IDS/IPS Scanner Report",
        f"Scan time: {_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"",
        f"Nmap scan report for {host}",
        f"",
        f"PORT     STATE SERVICE   VERSION",
    ]
    for p in open_ports:
        port_s = f"{p['port']}/tcp"
        svc = p.get("service", "")[:12]
        ver = (p.get("version") or p.get("banner") or "")[:40]
        lines.append(f"{port_s:<9} open  {svc:<10} {ver}")

    lines.append("")
    lines.append(f"Open: {len(open_ports)}, Closed: {scan_result.get('closed', 0)}, "
                 f"Scanned: {scan_result.get('scanned', 0)}")
    if scan_result.get("os"):
        lines.append(f"OS guess: {scan_result['os'].get('guess', 'Unknown')} "
                     f"(confidence: {scan_result['os'].get('confidence', 'low')})")
    return "\n".join(lines)


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
