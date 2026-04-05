import time
import pytest
from core.rules import RuleEngine


def make_config(overrides=None):
    defaults = {
        "dos_threshold": 100,
        "portscan_threshold": 20,
        "syn_flood_threshold": 80,
        "icmp_flood_threshold": 50,
        "time_window": 10,
        "blacklist": ["10.0.0.99"],
        "suspicious_ports": [4444, 5555, 6666, 31337, 12345],
    }
    if overrides:
        defaults.update(overrides)
    return defaults


class DictConfig:
    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        return self._d[k]

    def get(self, k, default=None):
        return self._d.get(k, default)

    def __contains__(self, k):
        return k in self._d


def make_packet(src_ip="192.168.1.1", dst_port=80, protocol="TCP",
                tcp_flags=0, ts=None):
    return {
        "src_ip": src_ip,
        "dst_ip": "10.0.0.1",
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_flags": tcp_flags,
        "size": 64,
        "timestamp": ts if ts is not None else time.time(),
    }


def test_dos_detection():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for _ in range(150):
        alerts.extend(engine.evaluate(make_packet()))
    assert "DOS_FLOOD" in [a["type"] for a in alerts]


def test_portscan_detection():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for port in range(1, 26):
        alerts.extend(engine.evaluate(make_packet(dst_port=port)))
    assert "PORT_SCAN" in [a["type"] for a in alerts]


def test_portscan_sliding_window():
    """Sliding window must detect scans that span a bucket boundary."""
    cfg = make_config({"time_window": 10, "portscan_threshold": 5})
    engine = RuleEngine(DictConfig(cfg))
    base = 1_000_000.0
    alerts = []
    # 3 ports at t=5, 3 ports at t=9 — all within 10s of t=9 → 6 unique ports > 5
    for port in range(1, 4):
        alerts.extend(engine.evaluate(make_packet(dst_port=port, ts=base + 5)))
    for port in range(4, 7):
        alerts.extend(engine.evaluate(make_packet(dst_port=port, ts=base + 9)))
    assert "PORT_SCAN" in [a["type"] for a in alerts], \
        "Sliding window should detect scan spanning a bucket boundary"


def test_blacklist_detection():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = engine.evaluate(make_packet(src_ip="10.0.0.99"))
    assert "BLACKLIST" in [a["type"] for a in alerts]


def test_syn_flood():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for _ in range(90):
        alerts.extend(engine.evaluate(make_packet(protocol="TCP", tcp_flags=0x02)))
    assert "SYN_FLOOD" in [a["type"] for a in alerts]


def test_syn_with_ack_not_flagged():
    """SYN+ACK (normal handshake reply) must NOT trigger SYN flood."""
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for _ in range(90):
        alerts.extend(engine.evaluate(
            make_packet(protocol="TCP", tcp_flags=0x12)  # SYN=0x02 | ACK=0x10
        ))
    assert "SYN_FLOOD" not in [a["type"] for a in alerts]


def test_icmp_flood():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for _ in range(60):
        alerts.extend(engine.evaluate(make_packet(protocol="ICMP", tcp_flags=0)))
    assert "ICMP_FLOOD" in [a["type"] for a in alerts]


def test_suspicious_port():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = engine.evaluate(make_packet(src_ip="1.2.3.4", dst_port=4444))
    assert "SUSPICIOUS_PORT" in [a["type"] for a in alerts]


def test_no_false_positive():
    engine = RuleEngine(DictConfig(make_config()))
    alerts = []
    for _ in range(5):
        alerts.extend(engine.evaluate(make_packet(src_ip="172.16.0.1", dst_port=80)))
    assert len(alerts) == 0


def test_rate_limiter():
    """
    Same (ip, type) alert must not fire more than once per 30 seconds.

    Strategy:
      Burst 1 @ T+0  → first DOS_FLOOD alert emitted, rate-limit set to T+0
      Burst 2 @ T+15 → rate-limit blocks (15 < 30), no alert
      Burst 3 @ T+31 → rate-limit expired (31 >= 30), second alert emitted
    """
    engine = RuleEngine(DictConfig(make_config()))
    base = 1_000_000.0
    alerts = []

    for _ in range(150):
        alerts.extend(engine.evaluate(make_packet(ts=base)))

    for _ in range(150):
        alerts.extend(engine.evaluate(make_packet(ts=base + 15)))

    for _ in range(150):
        alerts.extend(engine.evaluate(make_packet(ts=base + 31)))

    dos = [a for a in alerts if a["type"] == "DOS_FLOOD"]
    assert len(dos) == 2, (
        f"Expected exactly 2 DOS_FLOOD alerts (burst 1 and burst 3), got {len(dos)}"
    )
    gap = dos[1]["timestamp"] - dos[0]["timestamp"]
    assert gap >= 30, f"Rate limiter violated: second alert only {gap:.1f}s after first"


def test_rate_limiter_cleanup():
    """Internal _rate_limit dict must not grow unboundedly."""
    engine = RuleEngine(DictConfig(make_config()))
    base = 1_000_000.0
    # Trigger cleanup cycle by advancing time > 60s
    for i in range(5):
        engine.evaluate(make_packet(src_ip=f"10.1.1.{i}", ts=base + i))
    # Advance past cleanup threshold
    engine.evaluate(make_packet(src_ip="10.1.1.100", ts=base + 200))
    # Entries older than 120s should be gone; only recent entry remains
    with engine._lock:
        assert all(v > base + 200 - 120 for v in engine._rate_limit.values())
