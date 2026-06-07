"""
Per-device bandwidth monitor — Module 5.

Tracks bytes and packets per source IP across 1-second buckets.
Provides: current rate, total bytes, top talkers, 60-second history per IP.
Integrates with ConnectionTracker to get per-device totals.
"""
import threading
import time
import logging
from collections import defaultdict, deque

logger = logging.getLogger("ids_ips")

_HISTORY_SECONDS = 60

# ip → deque of (timestamp, bytes) tuples
_buckets: dict = defaultdict(lambda: deque(maxlen=_HISTORY_SECONDS))
_totals: dict = defaultdict(lambda: {"bytes": 0, "packets": 0})
_lock = threading.Lock()


def record(src_ip: str, byte_count: int, packet_count: int = 1):
    """Call this whenever a packet is seen from src_ip."""
    now = time.time()
    bucket_ts = int(now)
    with _lock:
        hist = _buckets[src_ip]
        # Append to deque; last element is most recent second
        if hist and hist[-1][0] == bucket_ts:
            old_ts, old_bytes = hist[-1]
            hist[-1] = (bucket_ts, old_bytes + byte_count)
        else:
            hist.append((bucket_ts, byte_count))
        _totals[src_ip]["bytes"] += byte_count
        _totals[src_ip]["packets"] += packet_count


def get_current_rate(ip: str) -> dict:
    """Bytes/sec and packets for an IP (averaged over last 5 seconds)."""
    now = int(time.time())
    with _lock:
        hist = list(_buckets.get(ip, []))
        total = dict(_totals.get(ip, {"bytes": 0, "packets": 0}))
    recent = [b for ts, b in hist if ts >= now - 5]
    rate = sum(recent) / max(1, len(recent))
    return {
        "ip": ip,
        "rate_bps": rate,
        "rate_kbps": round(rate / 1024, 2),
        "total_bytes": total["bytes"],
        "total_packets": total["packets"],
    }


def get_top_talkers(limit: int = 10) -> list:
    """Return top IPs by total bytes in last 60 seconds."""
    now = int(time.time())
    with _lock:
        summary = {}
        for ip, hist in _buckets.items():
            recent = sum(b for ts, b in hist if ts >= now - 60)
            summary[ip] = {
                "ip": ip,
                "bytes_60s": recent,
                "rate_kbps": round(recent / 60 / 1024, 2),
                "total_bytes": _totals[ip]["bytes"],
                "total_packets": _totals[ip]["packets"],
            }
    ranked = sorted(summary.values(), key=lambda x: x["bytes_60s"], reverse=True)
    return ranked[:limit]


def get_history(ip: str) -> list:
    """Returns list of (timestamp, bytes) for the last 60 seconds."""
    with _lock:
        return list(_buckets.get(ip, []))


def get_all_stats() -> list:
    """All tracked IPs with their stats."""
    now = int(time.time())
    with _lock:
        result = []
        for ip in set(list(_buckets.keys()) + list(_totals.keys())):
            hist = list(_buckets.get(ip, []))
            recent = sum(b for ts, b in hist if ts >= now - 60)
            tot = _totals.get(ip, {"bytes": 0, "packets": 0})
            result.append({
                "ip": ip,
                "bytes_60s": recent,
                "rate_kbps": round(recent / 60 / 1024, 2),
                "total_bytes": tot["bytes"],
                "total_packets": tot["packets"],
            })
    return sorted(result, key=lambda x: x["bytes_60s"], reverse=True)
