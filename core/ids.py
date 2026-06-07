import threading
import time
import logging
from collections import deque
from queue import Queue, Empty

from core.rules import RuleEngine

logger = logging.getLogger("ids_ips")


class IDS:
    def __init__(self, config, packet_queue: Queue, ips=None):
        self._config = config
        self._queue = packet_queue
        self._ips = ips
        self._engine = RuleEngine(config)
        self._alerts: deque = deque(maxlen=500)
        self._stop_event = threading.Event()
        self._thread = None
        self._stats = {
            "total_packets": 0,
            "total_alerts": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "alert_types": {},
            "start_time": time.time(),
        }
        self._stats_lock = threading.Lock()
        # Lazy DB reference — avoids import-time circular dependency
        self._db = None

    def _get_db(self):
        if self._db is None:
            try:
                from db.database import Database
                self._db = Database.get()
            except Exception:
                pass
        return self._db

    def start(self):
        self._thread = threading.Thread(target=self._run, name="IDS-Worker", daemon=True)
        self._thread.start()
        logger.info("IDS started")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("IDS stopped")

    def _run(self):
        while not self._stop_event.is_set():
            try:
                packet_info = self._queue.get(timeout=0.5)
            except Empty:
                continue

            # Guard entire processing block — a bug must not kill the worker thread
            try:
                self._update_stats(packet_info)
                alerts = self._engine.evaluate(packet_info)

                for alert in alerts:
                    self._alerts.append(alert)
                    with self._stats_lock:
                        self._stats["total_alerts"] += 1
                        self._stats["alert_types"][alert["type"]] = (
                            self._stats["alert_types"].get(alert["type"], 0) + 1
                        )

                    # Persist to DB (fire-and-forget, non-blocking)
                    db = self._get_db()
                    if db is not None:
                        try:
                            db.insert_alert(alert)
                        except Exception:
                            pass

                    if alert["severity"] in ("HIGH", "MEDIUM"):
                        logger.alert(
                            "[%s] %s — %s", alert["severity"], alert["type"], alert["message"]
                        )
                        if self._ips:
                            self._ips.handle_alert(alert)
                    else:
                        logger.info(
                            "[%s] %s — %s", alert["severity"], alert["type"], alert["message"]
                        )
            except Exception as e:
                logger.error("IDS processing error: %s", e, exc_info=True)

    def _update_stats(self, packet_info: dict):
        proto = packet_info.get("protocol", "OTHER")
        with self._stats_lock:
            self._stats["total_packets"] += 1
            if proto == "TCP":
                self._stats["tcp"] += 1
            elif proto == "UDP":
                self._stats["udp"] += 1
            elif proto == "ICMP":
                self._stats["icmp"] += 1
            else:
                self._stats["other"] += 1

    def get_stats(self) -> dict:
        with self._stats_lock:
            # Deep-copy nested alert_types dict to prevent external mutation
            stats = {**self._stats, "alert_types": dict(self._stats["alert_types"])}
        stats["uptime"] = time.time() - stats["start_time"]
        return stats

    def get_alerts(self, limit: int = 50) -> list:
        alerts = list(self._alerts)
        return alerts[-limit:]




        
