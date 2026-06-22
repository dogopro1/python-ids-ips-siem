"""
TCP Stream Reassembler — Module 2.

Tracks TCP conversations and reassembles payload bytes in sequence-number order.
Provides "Follow TCP Stream" capability similar to Wireshark.
Streams are stored in memory (max 200 active) and flushed to DB.
"""
import threading
import time
import logging
from collections import OrderedDict

logger = logging.getLogger("ids_ips")

_MAX_STREAMS = 200
_STREAM_TTL = 120        # seconds of inactivity before closing stream
_MAX_PAYLOAD = 65536     # max bytes kept per stream direction


class TCPStream:
    def __init__(self, key: tuple):
        self.key = key           # (src_ip, dst_ip, src_port, dst_port)
        self.created = time.time()
        self.updated = time.time()
        self.client_data = b""   # src→dst direction
        self.server_data = b""   # dst→src direction
        self._seqs_client: dict = {}
        self._seqs_server: dict = {}
        self.state = "SYN_SENT"
        self.packets = 0
        self.bytes_total = 0

    def add_segment(self, is_client: bool, seq: int, payload: bytes, flags_str: str):
        self.updated = time.time()
        self.packets += 1
        self.bytes_total += len(payload)
        if "S" in flags_str and not payload:
            self.state = "SYN" if is_client else "SYN_ACK"
            return
        if "F" in flags_str:
            self.state = "FIN"
        if "R" in flags_str:
            self.state = "RST"
        if not payload:
            return
        store = self._seqs_client if is_client else self._seqs_server
        store[seq] = payload
        # Reassemble in order (simple: just sort by seq)
        ordered = b"".join(v for _, v in sorted(store.items()))
        if is_client:
            self.client_data = ordered[-_MAX_PAYLOAD:]
        else:
            self.server_data = ordered[-_MAX_PAYLOAD:]

    def to_dict(self) -> dict:
        src_ip, dst_ip, src_port, dst_port = self.key
        return {
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "state": self.state,
            "packets": self.packets,
            "bytes_total": self.bytes_total,
            "created": self.created,
            "updated": self.updated,
            "client_payload": self.client_data.decode(errors="replace"),
            "server_payload": self.server_data.decode(errors="replace"),
            "client_bytes": len(self.client_data),
            "server_bytes": len(self.server_data),
        }


class TCPReassembler:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._streams: OrderedDict = OrderedDict()
        self._stream_lock = threading.Lock()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="TCP-Reassembler"
        )
        self._cleanup_thread.start()

    @classmethod
    def get(cls) -> "TCPReassembler":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def process_packet(self, pkt_info: dict):
        """Feed a dissected packet dict into the reassembler."""
        if pkt_info.get("protocol") != "TCP":
            return
        tcp = pkt_info.get("tcp", {})
        if not tcp:
            return
        src_ip = pkt_info.get("src_ip", "")
        dst_ip = pkt_info.get("dst_ip", "")
        src_port = tcp.get("src_port", 0)
        dst_port = tcp.get("dst_port", 0)
        if not src_ip or not dst_ip:
            return

        # Canonical key: always smaller tuple first
        fwd_key = (src_ip, dst_ip, src_port, dst_port)
        rev_key = (dst_ip, src_ip, dst_port, src_port)

        with self._stream_lock:
            is_client = True
            if fwd_key in self._streams:
                key = fwd_key
            elif rev_key in self._streams:
                key = rev_key
                is_client = False
            else:
                # New stream
                key = fwd_key
                if len(self._streams) >= _MAX_STREAMS:
                    self._streams.popitem(last=False)
                self._streams[key] = TCPStream(key)

            stream = self._streams[key]
            payload = b""
            http = pkt_info.get("http", {})
            if http:
                body = http.get("body_preview", "")
                payload = body.encode(errors="replace") if body else b""
            stream.add_segment(
                is_client=is_client,
                seq=tcp.get("seq", 0),
                payload=payload,
                flags_str=tcp.get("flags", ""),
            )

    def get_stream(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> dict:
        key = (src_ip, dst_ip, src_port, dst_port)
        rev = (dst_ip, src_ip, dst_port, src_port)
        with self._stream_lock:
            if key in self._streams:
                return self._streams[key].to_dict()
            if rev in self._streams:
                return self._streams[rev].to_dict()
        return {}

    def get_all_streams(self, limit: int = 50) -> list:
        with self._stream_lock:
            streams = list(self._streams.values())
        streams.sort(key=lambda s: s.updated, reverse=True)
        return [s.to_dict() for s in streams[:limit]]

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            cutoff = time.time() - _STREAM_TTL
            with self._stream_lock:
                stale = [k for k, s in self._streams.items() if s.updated < cutoff]
                for k in stale:
                    del self._streams[k]


# ── UDP Stream Tracker ────────────────────────────────────────────────────────

_MAX_UDP_STREAMS = 500
_UDP_TTL = 60


class UDPStream:
    def __init__(self, key: tuple):
        self.key = key       # (src_ip, dst_ip, src_port, dst_port)
        self.created = time.time()
        self.updated = time.time()
        self.datagrams: list = []
        self.bytes_total = 0

    def add_datagram(self, direction: str, payload: bytes, dns_info: dict = None):
        self.updated = time.time()
        self.bytes_total += len(payload)
        entry = {
            "direction": direction,
            "timestamp": self.updated,
            "length": len(payload),
            "data": payload.decode(errors="replace")[:256],
            "hex": payload.hex()[:64],
        }
        if dns_info:
            entry["dns"] = dns_info
        self.datagrams.append(entry)
        # Keep last 200 datagrams per stream
        if len(self.datagrams) > 200:
            self.datagrams = self.datagrams[-200:]

    def to_dict(self) -> dict:
        src_ip, dst_ip, src_port, dst_port = self.key
        return {
            "src_ip": src_ip, "dst_ip": dst_ip,
            "src_port": src_port, "dst_port": dst_port,
            "datagrams": len(self.datagrams),
            "bytes_total": self.bytes_total,
            "created": self.created,
            "updated": self.updated,
            "payload": self.datagrams,
        }


class UDPTracker:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self._streams: OrderedDict = OrderedDict()
        self._stream_lock = threading.Lock()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True, name="UDP-Tracker"
        )
        self._cleanup_thread.start()

    @classmethod
    def get(cls) -> "UDPTracker":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def process_packet(self, pkt_info: dict):
        """Feed a dissected UDP packet dict."""
        if pkt_info.get("protocol") != "UDP":
            return
        udp = pkt_info.get("udp", {})
        if not udp:
            return
        src_ip = pkt_info.get("src_ip", "")
        dst_ip = pkt_info.get("dst_ip", "")
        src_port = udp.get("src_port", 0)
        dst_port = udp.get("dst_port", 0)
        if not src_ip or not dst_ip:
            return

        fwd = (src_ip, dst_ip, src_port, dst_port)
        rev = (dst_ip, src_ip, dst_port, src_port)

        with self._stream_lock:
            if fwd in self._streams:
                key, direction = fwd, "client"
            elif rev in self._streams:
                key, direction = rev, "server"
            else:
                key, direction = fwd, "client"
                if len(self._streams) >= _MAX_UDP_STREAMS:
                    self._streams.popitem(last=False)
                self._streams[key] = UDPStream(key)

            dns = pkt_info.get("dns")
            payload = b""
            if dns:
                q = dns.get("questions", [])
                a = dns.get("answers", [])
                payload_str = f"Q:{q} A:{a}"
                payload = payload_str.encode()
            self._streams[key].add_datagram(direction, payload, dns_info=dns)

    def get_all_streams(self, limit: int = 100) -> list:
        with self._stream_lock:
            streams = list(self._streams.values())
        streams.sort(key=lambda s: s.updated, reverse=True)
        return [s.to_dict() for s in streams[:limit]]

    def get_stream(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> dict:
        key = (src_ip, dst_ip, src_port, dst_port)
        rev = (dst_ip, src_ip, dst_port, src_port)
        with self._stream_lock:
            if key in self._streams:
                return self._streams[key].to_dict()
            if rev in self._streams:
                return self._streams[rev].to_dict()
        return {}

    def _cleanup_loop(self):
        while True:
            time.sleep(30)
            cutoff = time.time() - _UDP_TTL
            with self._stream_lock:
                stale = [k for k, s in self._streams.items() if s.updated < cutoff]
                for k in stale:
                    del self._streams[k]
