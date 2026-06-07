"""
Intercepting HTTP/HTTPS proxy — Module 1.

Runs a standard HTTP CONNECT proxy on proxy_port (default 8080).
For plain HTTP: reads request, forwards, logs request+response.
For HTTPS: does SSL MITM with per-host certs signed by local CA.

Configure your browser / OS to use HTTP proxy 127.0.0.1:8080.
Import data/proxy/ca.crt into the browser's trusted CA list once.
"""
import socket
import ssl
import threading
import time
import logging
import re
import json

logger = logging.getLogger("ids_ips")

_PROXY_VERSION = "IDS-IPS-Proxy/1.0"
_TIMEOUT = 15
_BUFSIZE = 65536

_running = False
_server_sock = None
_request_count = 0
_intercept_lock = threading.Lock()
_interceptors: list = []  # list of callables(req_dict) -> req_dict (for future Repeater)


def _db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None


# ── HTTP request / response helpers ──────────────────────────────────────────

def _recv_headers(sock) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _parse_request_line(raw: bytes) -> dict:
    try:
        header_part = raw.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
        lines = header_part.split("\r\n")
        method, path, version = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        return {"method": method, "path": path, "version": version,
                "headers": headers, "body": body, "raw": raw}
    except Exception:
        return {}


def _forward(src, dst):
    try:
        while True:
            data = src.recv(_BUFSIZE)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass


# ── HTTPS tunnel with MITM ────────────────────────────────────────────────────

def _handle_https(client_sock, host: str, port: int, client_addr: tuple):
    try:
        from proxy.cert_manager import get_host_cert
        crt_path, key_path = get_host_cert(host)
    except Exception as e:
        logger.debug("proxy: cert gen failed for %s: %s", host, e)
        client_sock.close()
        return

    # Connect to real server
    try:
        remote = socket.create_connection((host, port), timeout=_TIMEOUT)
        ctx_remote = ssl.create_default_context()
        ctx_remote.check_hostname = False
        ctx_remote.verify_mode = ssl.CERT_NONE
        remote_ssl = ctx_remote.wrap_socket(remote, server_hostname=host)
    except Exception as e:
        logger.debug("proxy: cannot connect to %s:%d — %s", host, port, e)
        client_sock.close()
        return

    # Wrap client in SSL using fake cert
    try:
        ctx_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx_client.load_cert_chain(crt_path, key_path)
        client_ssl = ctx_client.wrap_socket(client_sock, server_side=True)
    except Exception as e:
        logger.debug("proxy: SSL wrap client failed: %s", e)
        remote_ssl.close()
        client_sock.close()
        return

    # Read decrypted request
    try:
        raw_req = _recv_headers(client_ssl)
        # Read body if Content-Length present
        req = _parse_request_line(raw_req)
        cl = int(req.get("headers", {}).get("content-length", 0) or 0)
        while len(req.get("body", b"")) < cl:
            chunk = client_ssl.recv(_BUFSIZE)
            if not chunk:
                break
            raw_req += chunk
            req = _parse_request_line(raw_req)

        # Forward to real server
        remote_ssl.sendall(raw_req)

        # Read response
        raw_resp = _recv_headers(remote_ssl)
        # Forward response to client
        client_ssl.sendall(raw_resp)

        # Continue piping rest of data
        t1 = threading.Thread(target=_forward, args=(client_ssl, remote_ssl), daemon=True)
        t2 = threading.Thread(target=_forward, args=(remote_ssl, client_ssl), daemon=True)
        t1.start(); t2.start()
        t1.join(timeout=30); t2.join(timeout=30)

        _log_request(req, raw_resp, host, port, "HTTPS", client_addr)
    except Exception as e:
        logger.debug("proxy: HTTPS intercept error %s:%d — %s", host, port, e)
    finally:
        try: client_ssl.close()
        except Exception: pass
        try: remote_ssl.close()
        except Exception: pass


# ── Plain HTTP handler ────────────────────────────────────────────────────────

def _handle_http(client_sock, raw_req: bytes, client_addr: tuple):
    req = _parse_request_line(raw_req)
    path = req.get("path", "")
    host_hdr = req.get("headers", {}).get("host", "")
    host, port = (host_hdr.split(":", 1) + ["80"])[:2]
    port = int(port)

    try:
        remote = socket.create_connection((host, port), timeout=_TIMEOUT)
        # Rewrite absolute URI to relative
        relative_path = re.sub(r"^https?://[^/]+", "", path) or "/"
        new_req = raw_req.replace(
            f"{req['method']} {path}".encode(),
            f"{req['method']} {relative_path}".encode(), 1
        )
        remote.sendall(new_req)
        raw_resp = b""
        while True:
            chunk = remote.recv(_BUFSIZE)
            if not chunk:
                break
            raw_resp += chunk
            client_sock.sendall(chunk)
        remote.close()
        _log_request(req, raw_resp, host, port, "HTTP", client_addr)
    except Exception as e:
        logger.debug("proxy: HTTP forward error — %s", e)
        try: client_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception: pass
    finally:
        client_sock.close()


# ── Log to DB ─────────────────────────────────────────────────────────────────

def _log_request(req: dict, raw_resp: bytes, host: str, port: int,
                 scheme: str, client_addr: tuple):
    global _request_count
    db = _db()
    if db is None:
        return
    try:
        resp_headers_raw = raw_resp.split(b"\r\n\r\n", 1)[0].decode(errors="replace") if raw_resp else ""
        resp_body = raw_resp.split(b"\r\n\r\n", 1)[1][:4096] if b"\r\n\r\n" in raw_resp else b""
        status_line = resp_headers_raw.splitlines()[0] if resp_headers_raw else ""
        status_code = 0
        try:
            status_code = int(status_line.split(" ", 2)[1])
        except Exception:
            pass
        db.save_proxy_request({
            "method": req.get("method", ""),
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": req.get("path", ""),
            "req_headers": json.dumps(req.get("headers", {})),
            "req_body": (req.get("body", b"") or b"")[:4096].decode(errors="replace"),
            "resp_status": status_code,
            "resp_headers": resp_headers_raw[:2048],
            "resp_body": resp_body.decode(errors="replace"),
            "client_ip": client_addr[0] if client_addr else "",
            "timestamp": time.time(),
        })
        with _intercept_lock:
            _request_count += 1
    except Exception as e:
        logger.debug("proxy: log error — %s", e)


# ── Connection dispatcher ─────────────────────────────────────────────────────

def _handle_client(client_sock, client_addr):
    try:
        client_sock.settimeout(_TIMEOUT)
        raw = _recv_headers(client_sock)
        if not raw:
            client_sock.close()
            return

        first_line = raw.split(b"\r\n", 1)[0].decode(errors="replace")
        if first_line.startswith("CONNECT "):
            # HTTPS tunnel
            target = first_line.split(" ", 2)[1]
            host, port = (target.rsplit(":", 1) + ["443"])[:2]
            port = int(port)
            client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _handle_https(client_sock, host, port, client_addr)
        else:
            _handle_http(client_sock, raw, client_addr)
    except Exception as e:
        logger.debug("proxy: client handler error — %s", e)
        try: client_sock.close()
        except Exception: pass


# ── Server lifecycle ──────────────────────────────────────────────────────────

def start(host: str = "127.0.0.1", port: int = 8080, ca_dir: str = None) -> bool:
    global _running, _server_sock

    from proxy.cert_manager import init_ca, _DEFAULT_CA_DIR
    if not init_ca(ca_dir or _DEFAULT_CA_DIR):
        logger.warning("proxy: CA init failed — proxy not started")
        return False

    try:
        _server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _server_sock.bind((host, port))
        _server_sock.listen(128)
        _running = True
        t = threading.Thread(target=_accept_loop, daemon=True, name="Proxy-Accept")
        t.start()
        logger.info("proxy: listening on %s:%d  (import data/proxy/ca.crt into browser)", host, port)
        return True
    except Exception as e:
        logger.error("proxy: start failed — %s", e)
        return False


def _accept_loop():
    global _running
    while _running:
        try:
            _server_sock.settimeout(1.0)
            client, addr = _server_sock.accept()
            t = threading.Thread(target=_handle_client, args=(client, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except Exception:
            break


def stop():
    global _running, _server_sock
    _running = False
    if _server_sock:
        try: _server_sock.close()
        except Exception: pass
    logger.info("proxy: stopped")


def get_stats() -> dict:
    return {"running": _running, "requests_intercepted": _request_count}
