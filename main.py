import sys
import os
import signal
import logging
from queue import Queue

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config_loader import Config
from utils.logger import setup_logger
from core.ids import IDS
from core.ips import IPS
from core.connection_tracker import ConnectionTracker
from core.traffic_series import TrafficSeries
from sniffer.packet_sniffer import PacketSniffer
from db.database import Database
from web.app import app, init_app

logger = logging.getLogger("ids_ips")

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

_ids: "IDS" = None
_ips: "IPS" = None
_sniffer: "PacketSniffer" = None
_db: "Database" = None


def _cleanup() -> None:
    if _sniffer:
        _sniffer.stop()
    if _ids:
        _ids.stop()
    if _ips:
        _ips.stop()

    # Stop new modules
    try:
        from proxy.intercepting_proxy import stop as proxy_stop
        proxy_stop()
    except Exception:
        pass
    try:
        from network.arp_monitor import stop as arp_stop
        arp_stop()
    except Exception:
        pass
    try:
        from network.network_mapper import stop as nm_stop
        nm_stop()
    except Exception:
        pass

    if _db:
        _db.close()
    logger.info("Shutdown complete")


def main() -> None:
    global _ids, _ips, _sniffer, _db

    config = Config.load()

    log_file: str = config["log_file"]
    if not os.path.isabs(log_file):
        log_file = os.path.join(_PROJECT_ROOT, log_file)

    setup_logger(log_file, config["log_level"])

    logger.info("=" * 60)
    logger.info("IDS/IPS Security Console starting  (Python %s)", sys.version.split()[0])
    logger.info("Project root: %s", _PROJECT_ROOT)
    logger.info("=" * 60)

    _db = Database.get()

    conn_tracker = ConnectionTracker()
    traffic_series = TrafficSeries(window=60)
    packet_queue: Queue = Queue(maxsize=10_000)

    _ips = IPS(config)
    _ids = IDS(config, packet_queue, ips=_ips)
    _sniffer = PacketSniffer(
        config, packet_queue,
        conn_tracker=conn_tracker,
        traffic_series=traffic_series,
    )

    init_app(_sniffer, _ids, _ips, conn_tracker, traffic_series)

    # ── Module 1: Intercepting Proxy ──────────────────────────────────────────
    if config.get("proxy_enabled", True):
        try:
            from proxy.intercepting_proxy import start as proxy_start
            ca_dir = config.get("proxy_ca_dir", "data/proxy")
            if not os.path.isabs(ca_dir):
                ca_dir = os.path.join(_PROJECT_ROOT, ca_dir)
            proxy_start(
                host=config.get("proxy_host", "127.0.0.1"),
                port=int(config.get("proxy_port", 8080)),
                ca_dir=ca_dir,
            )
            logger.info("Proxy → http://%s:%d  (configure browser to use this proxy)",
                        config.get("proxy_host", "127.0.0.1"),
                        int(config.get("proxy_port", 8080)))
        except Exception as e:
            logger.warning("proxy: could not start — %s", e)

    # ── Module 5: ARP Monitor ─────────────────────────────────────────────────
    if config.get("arp_monitor_enabled", True):
        try:
            from network.arp_monitor import start as arp_start
            arp_start()
        except Exception as e:
            logger.warning("arp_monitor: could not start — %s", e)

    # ── Module 5: Network Mapper ──────────────────────────────────────────────
    try:
        from network.network_mapper import start as nm_start
        nm_start(interval=int(config.get("network_map_interval", 300)))
    except Exception as e:
        logger.warning("network_mapper: could not start — %s", e)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    _ips.start()
    _ids.start()
    _sniffer.start()

    host: str = config["web_host"]
    port: int = config["web_port"]
    logger.info("Dashboard → http://%s:%s", host, port)

    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        logger.info("Shutdown signal received — stopping components...")
        _cleanup()


if __name__ == "__main__":
    main()
