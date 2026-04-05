import time
import threading
from collections import OrderedDict

from utils.service_detector import get_service


class _Conn:
    __slots__ = ("src_ip", "dst_ip", "dst_port", "protocol", "service",
                 "first_seen", "last_seen", "packets", "bytes_total", "state")

    def __init__(self, src_ip, dst_ip, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.protocol = protocol
        self.service = get_service(dst_port)
        now = time.time()
        self.first_seen = now
        self.last_seen = now
        self.packets = 0
        self.bytes_total = 0
        self.state = "ACTIVE"

    def to_dict(self, now: float) -> dict:
        return {
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "dst_port": self.dst_port, "protocol": self.protocol,
            "service": self.service, "first_seen": self.first_seen,
            "last_seen": self.last_seen, "duration": int(now - self.first_seen),
            "packets": self.packets, "bytes": self.bytes_total, "state": self.state,
        }


class ConnectionTracker:
    def __init__(self, maxsize: int = 1000, idle_timeout: int = 120):
        self._conns: OrderedDict = OrderedDict()
        self._maxsize = maxsize
        self._idle_timeout = idle_timeout
        self._lock = threading.Lock()
        self._total = 0

    def update(self, packet: dict):
        src = packet.get("src_ip", "")
        dst = packet.get("dst_ip", "")
        port = packet.get("dst_port", 0)
        proto = packet.get("protocol", "OTHER")
        size = packet.get("size", 0)
        key = (src, dst, port, proto)
        now = time.time()

        with self._lock:
            if key in self._conns:
                c = self._conns[key]
                c.packets += 1
                c.bytes_total += size
                c.last_seen = now
                self._conns.move_to_end(key)
            else:
                c = _Conn(src, dst, port, proto)
                c.packets = 1
                c.bytes_total = size
                self._conns[key] = c
                self._total += 1
                while len(self._conns) > self._maxsize:
                    self._conns.popitem(last=False)

            for conn in self._conns.values():
                conn.state = "ACTIVE" if now - conn.last_seen < self._idle_timeout else "IDLE"

    def get_connections(self, limit: int = 100) -> list:
        now = time.time()
        with self._lock:
            items = sorted(self._conns.values(), key=lambda c: c.last_seen, reverse=True)
        return [c.to_dict(now) for c in items[:limit]]

    def get_top_talkers(self, limit: int = 10) -> list:
        agg: dict = {}
        with self._lock:
            for c in self._conns.values():
                ip = c.src_ip
                if ip not in agg:
                    agg[ip] = {"ip": ip, "packets": 0, "bytes": 0, "connections": 0}
                agg[ip]["packets"] += c.packets
                agg[ip]["bytes"] += c.bytes_total
                agg[ip]["connections"] += 1
        return sorted(agg.values(), key=lambda x: x["packets"], reverse=True)[:limit]

    def get_active_count(self) -> int:
        now = time.time()
        with self._lock:
            return sum(1 for c in self._conns.values() if now - c.last_seen < self._idle_timeout)

    @property
    def total_seen(self) -> int:
        return self._total
