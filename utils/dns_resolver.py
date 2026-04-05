import socket
import threading
import logging
from collections import OrderedDict

logger = logging.getLogger("ids_ips")


class DNSResolver:
    _instance = None
    _lock = threading.Lock()

    def __init__(self, maxsize: int = 2000):
        self._cache: OrderedDict = OrderedDict()
        self._maxsize = maxsize
        self._pending: set = set()
        self._cache_lock = threading.Lock()

    @classmethod
    def get(cls) -> "DNSResolver":
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def resolve_async(self, ip: str) -> str:
        """Return cached hostname immediately; start background resolution if not cached."""
        with self._cache_lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
            if ip in self._pending:
                return ip
            self._pending.add(ip)
        threading.Thread(target=self._resolve, args=(ip,), daemon=True, name=f"DNS-{ip}").start()
        return ip

    def resolve_sync(self, ip: str) -> str:
        """Blocking resolve — use only in background threads."""
        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]
        self._resolve(ip)
        with self._cache_lock:
            return self._cache.get(ip, ip)

    def _resolve(self, ip: str):
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = ip
        with self._cache_lock:
            self._pending.discard(ip)
            self._cache[ip] = hostname
            self._cache.move_to_end(ip)
            while len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)
        try:
            from db.database import Database
            Database.get().cache_hostname(ip, hostname)
        except Exception:
            pass
