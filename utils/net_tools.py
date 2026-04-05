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
        return {"stdout": "", "stderr": "traceroute/tracert not found. On Windows use: tracert", "returncode": -1}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "returncode": -1}


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

    # Fallback: socket for A/AAAA only
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


def whois(host: str) -> dict:
    # Try subprocess whois first
    try:
        cmd = ["whois", host]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            return {"output": r.stdout, "source": "subprocess"}
    except (FileNotFoundError, Exception):
        pass

    # Fallback: socket whois
    try:
        output = _socket_whois(host)
        return {"output": output, "source": "socket"}
    except Exception as e:
        return {"output": f"Whois unavailable: {e}\n\nTip: On Windows install: winget install -e --id Geekflare.WHOIS",
                "source": "error"}


def _socket_whois(query: str) -> str:
    server = "whois.iana.org"
    port = 43
    # First query IANA to find authoritative whois server
    with socket.create_connection((server, port), timeout=10) as s:
        s.sendall(f"{query}\r\n".encode())
        raw = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw += chunk
    text = raw.decode(errors="replace")
    # Look for refer: line
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


def port_scan(host: str, ports: str = "1-1024") -> dict:
    """TCP connect scan. ports can be '80,443,8080' or '1-1024'."""
    port_list = _parse_ports(ports)
    if len(port_list) > 2000:
        return {"error": "Max 2000 ports per scan"}

    open_ports = []
    closed_ports = []
    errors = []
    lock = threading.Lock()

    def scan_port(p: int):
        try:
            with socket.create_connection((host, p), timeout=0.5):
                with lock:
                    open_ports.append(p)
        except (ConnectionRefusedError, OSError):
            with lock:
                closed_ports.append(p)
        except Exception as e:
            with lock:
                errors.append(f":{p} {e}")

    threads = [threading.Thread(target=scan_port, args=(p,), daemon=True) for p in port_list]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    from utils.service_detector import get_service
    open_with_svc = [{"port": p, "service": get_service(p)} for p in sorted(open_ports)]
    return {
        "host": host, "scanned": len(port_list),
        "open": open_with_svc, "closed": len(closed_ports),
        "errors": errors[:10],
    }


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
