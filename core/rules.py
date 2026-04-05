import time
import threading
from collections import defaultdict


class RuleEngine:
    def __init__(self, config):
        self._config = config
        self._lock = threading.Lock()

        # Sliding-window packet counters  {ip: [timestamp, ...]}
        self._packet_counts: defaultdict = defaultdict(list)
        # Port-scan sliding window        {ip: [(port, timestamp), ...]}
        self._port_timestamps: defaultdict = defaultdict(list)
        # SYN-flood counters              {ip: [timestamp, ...]}
        self._syn_counts: defaultdict = defaultdict(list)
        # ICMP-flood counters             {ip: [timestamp, ...]}
        self._icmp_counts: defaultdict = defaultdict(list)

        # Rate-limiter: (ip, alert_type) → last_alert_timestamp
        self._rate_limit: dict = {}
        self._last_cleanup: float = 0.0

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def evaluate(self, packet_info: dict) -> list:
        src_ip: str = packet_info.get("src_ip", "")
        dst_port: int = packet_info.get("dst_port", 0)
        protocol: str = packet_info.get("protocol", "OTHER")
        tcp_flags: int = packet_info.get("tcp_flags", 0)
        now: float = packet_info.get("timestamp", time.time())

        # Read config outside the lock — config is read-only after init
        window: int = self._config["time_window"]
        blacklist: list = self._config["blacklist"]
        dos_threshold: int = self._config["dos_threshold"]
        portscan_threshold: int = self._config["portscan_threshold"]
        syn_threshold: int = self._config["syn_flood_threshold"]
        icmp_threshold: int = self._config["icmp_flood_threshold"]
        suspicious_ports: list = self._config["suspicious_ports"]

        alerts = []

        with self._lock:
            # ── 1. Blacklist ──────────────────────────────────────────────
            if src_ip in blacklist:
                alerts.append(self._make_alert(
                    "BLACKLIST", src_ip,
                    f"Packet from blacklisted IP {src_ip}",
                    "HIGH", now,
                ))

            # ── 2. DoS flood — sliding window ─────────────────────────────
            self._packet_counts[src_ip].append(now)
            self._packet_counts[src_ip] = self._clean_window(
                self._packet_counts[src_ip], now, window
            )
            if len(self._packet_counts[src_ip]) > dos_threshold:
                alerts.append(self._make_alert(
                    "DOS_FLOOD", src_ip,
                    f"DoS flood: {len(self._packet_counts[src_ip])} pkts/{window}s",
                    "HIGH", now,
                ))

            # ── 3. Port scan — true sliding window ────────────────────────
            # Previous implementation used tumbling buckets (int(now/window))
            # which missed scans that crossed a bucket boundary. Fixed here.
            if dst_port:
                self._port_timestamps[src_ip].append((dst_port, now))
            self._port_timestamps[src_ip] = [
                (p, t) for p, t in self._port_timestamps[src_ip] if t > now - window
            ]
            unique_ports = len(set(p for p, _ in self._port_timestamps[src_ip]))
            if unique_ports > portscan_threshold:
                alerts.append(self._make_alert(
                    "PORT_SCAN", src_ip,
                    f"Port scan: {unique_ports} unique ports/{window}s",
                    "MEDIUM", now,
                ))

            # ── 4. SYN flood — SYN without ACK ───────────────────────────
            is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
            if protocol == "TCP" and is_syn:
                self._syn_counts[src_ip].append(now)
                self._syn_counts[src_ip] = self._clean_window(
                    self._syn_counts[src_ip], now, window
                )
                if len(self._syn_counts[src_ip]) > syn_threshold:
                    alerts.append(self._make_alert(
                        "SYN_FLOOD", src_ip,
                        f"SYN flood: {len(self._syn_counts[src_ip])} SYN pkts/{window}s",
                        "HIGH", now,
                    ))

            # ── 5. ICMP flood ─────────────────────────────────────────────
            if protocol == "ICMP":
                self._icmp_counts[src_ip].append(now)
                self._icmp_counts[src_ip] = self._clean_window(
                    self._icmp_counts[src_ip], now, window
                )
                if len(self._icmp_counts[src_ip]) > icmp_threshold:
                    alerts.append(self._make_alert(
                        "ICMP_FLOOD", src_ip,
                        f"ICMP flood: {len(self._icmp_counts[src_ip])} pkts/{window}s",
                        "MEDIUM", now,
                    ))

            # ── 6. Suspicious port ────────────────────────────────────────
            if dst_port in suspicious_ports:
                alerts.append(self._make_alert(
                    "SUSPICIOUS_PORT", src_ip,
                    f"Connection to suspicious port {dst_port}",
                    "LOW", now,
                ))

            # ── Rate limiting ─────────────────────────────────────────────
            # Suppress repeated alerts for the same (ip, type) within 30s.
            filtered = []
            for alert in alerts:
                key = (alert["src_ip"], alert["type"])
                if now - self._rate_limit.get(key, 0.0) >= 30:
                    self._rate_limit[key] = now
                    filtered.append(alert)

            # ── Periodic cleanup (every 60 s) ─────────────────────────────
            # Evicts stale state for IPs that have gone quiet to prevent
            # unbounded memory growth when many unique source IPs are seen.
            if now - self._last_cleanup > 60:
                self._periodic_cleanup(now, window)
                self._last_cleanup = now

        return filtered

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _periodic_cleanup(self, now: float, window: int) -> None:
        """Remove stale entries; called inside self._lock."""
        rate_cutoff = now - 120
        self._rate_limit = {
            k: v for k, v in self._rate_limit.items() if v > rate_cutoff
        }

        # Use 2× window as the eviction threshold so a short-burst IP is kept
        # around long enough to be correctly counted if it resumes activity.
        evict_cutoff = now - window * 2

        for store in (self._packet_counts, self._syn_counts, self._icmp_counts):
            for ip in list(store.keys()):
                store[ip] = [t for t in store[ip] if t > evict_cutoff]
                if not store[ip]:
                    del store[ip]

        for ip in list(self._port_timestamps.keys()):
            self._port_timestamps[ip] = [
                (p, t) for p, t in self._port_timestamps[ip] if t > evict_cutoff
            ]
            if not self._port_timestamps[ip]:
                del self._port_timestamps[ip]

    def _make_alert(self, alert_type: str, src_ip: str, message: str,
                    severity: str, timestamp: float) -> dict:
        return {
            "type": alert_type,
            "src_ip": src_ip,
            "message": message,
            "severity": severity,
            "timestamp": timestamp,
        }

    def _clean_window(self, entries: list, now: float, window: int) -> list:
        cutoff = now - window
        return [t for t in entries if t > cutoff]
