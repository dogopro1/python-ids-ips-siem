import time
import threading
import logging
from collections import deque
from queue import Queue

# Suppress Scapy's runtime/version warnings before any Scapy import
import logging as _log
_log.getLogger("scapy.runtime").setLevel(_log.ERROR)

logger = logging.getLogger("ids_ips")


class PacketSniffer:
    def __init__(self, config, packet_queue: Queue,
                 conn_tracker=None, traffic_series=None):
        self._config = config
        self._queue = packet_queue
        self._conn_tracker = conn_tracker
        self._traffic_series = traffic_series
        self._packets: deque = deque(maxlen=config["packet_buffer_size"])
        self._stop_event = threading.Event()
        self._thread = None
        self.degraded = False
        self._dropped = 0
        self._total_captured = 0
        # Scapy layer classes resolved once in _run(), reused in _handle_packet()
        self._IP = self._TCP = self._UDP = self._ICMP = None
        self._db = None

    def _get_db(self):
        if self._db is None:
            try:
                from db.database import Database
                self._db = Database.get()
            except Exception:
                pass
        return self._db

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="Sniffer", daemon=True)
        self._thread.start()
        logger.info("PacketSniffer started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info(
            "PacketSniffer stopped (captured=%d, dropped=%d)",
            self._total_captured, self._dropped,
        )

    def _run(self) -> None:
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP, conf  # noqa: F401
            self._IP = IP
            self._TCP = TCP
            self._UDP = UDP
            self._ICMP = ICMP
        except ImportError:
            logger.error("Scapy not installed — sniffer degraded. Run: pip install scapy")
            self.degraded = True
            return

        iface = self._config.get("interface", "auto")
        if iface == "auto":
            try:
                # Use Scapy's auto-detected default interface (handles Windows GUIDs)
                iface = str(conf.iface)
            except Exception:
                iface = None

        logger.info("Capturing on interface: %s", iface or "<default>")

        # Loop with timeout=1 instead of stop_filter:
        # stop_filter is only called AFTER a packet arrives — on an idle network
        # the thread would hang indefinitely. timeout=1 makes sniff() return
        # every second so the stop event is checked promptly.
        consecutive_errors = 0
        while not self._stop_event.is_set():
            try:
                sniff(
                    iface=iface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                )
                consecutive_errors = 0
            except PermissionError:
                logger.error(
                    "Insufficient privileges for packet capture — "
                    "run as Administrator (Windows) or with sudo (Linux/macOS)"
                )
                self.degraded = True
                return
            except OSError as e:
                consecutive_errors += 1
                if consecutive_errors >= 3:
                    logger.error(
                        "Sniffer: %d consecutive OS errors — degraded mode. Last: %s",
                        consecutive_errors, e,
                    )
                    self.degraded = True
                    return
                logger.warning(
                    "Sniffer transient OS error (%d/3): %s — retrying", consecutive_errors, e
                )
                self._stop_event.wait(1)
            except Exception as e:
                logger.error("Sniffer unexpected error: %s — degraded mode", e, exc_info=True)
                self.degraded = True
                return

    def _handle_packet(self, pkt) -> None:
        try:
            IP, TCP, UDP, ICMP = self._IP, self._TCP, self._UDP, self._ICMP
            if IP is None or not pkt.haslayer(IP):
                return

            ip_layer = pkt[IP]
            protocol = "OTHER"
            dst_port = 0
            tcp_flags = 0

            if pkt.haslayer(TCP):
                protocol = "TCP"
                dst_port = pkt[TCP].dport
                tcp_flags = int(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                dst_port = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            packet_info = {
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_flags": tcp_flags,
                "size": len(pkt),
                "timestamp": time.time(),
            }

            self._total_captured += 1
            self._packets.append(packet_info)

            # Feed auxiliary components
            if self._conn_tracker is not None:
                try:
                    self._conn_tracker.update(packet_info)
                except Exception:
                    pass

            if self._traffic_series is not None:
                try:
                    self._traffic_series.record()
                except Exception:
                    pass

            # Queue packet to DB (batch-flushed every 10s)
            db = self._get_db()
            if db is not None:
                try:
                    db.queue_packet(packet_info)
                except Exception:
                    pass

            try:
                self._queue.put_nowait(packet_info)
            except Exception:
                # Queue is full — IDS thread falling behind (flood attack?)
                self._dropped += 1
                if self._dropped % 1000 == 0:
                    logger.warning(
                        "IDS queue full: %d packets dropped — "
                        "IDS thread cannot keep up with capture rate",
                        self._dropped,
                    )
        except Exception as e:
            logger.debug("Packet parse error: %s", e)

    def get_recent_packets(self, limit: int = 20) -> list:
        packets = list(self._packets)
        return packets[-limit:]
