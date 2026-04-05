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
    """Stop all components in reverse start order."""
    if _sniffer:
        _sniffer.stop()
    if _ids:
        _ids.stop()
    if _ips:
        _ips.stop()
    if _db:
        _db.close()
    logger.info("Shutdown complete")


def main() -> None:
    global _ids, _ips, _sniffer, _db

    config = Config.load()

    # Resolve log file relative to project root regardless of working directory
    log_file: str = config["log_file"]
    if not os.path.isabs(log_file):
        log_file = os.path.join(_PROJECT_ROOT, log_file)

    setup_logger(log_file, config["log_level"])

    logger.info("=" * 60)
    logger.info("IDS/IPS System starting  (Python %s)", sys.version.split()[0])
    logger.info("Project root: %s", _PROJECT_ROOT)
    logger.info("=" * 60)

    # Initialize database singleton early so all components share it
    _db = Database.get()

    conn_tracker = ConnectionTracker()
    traffic_series = TrafficSeries(window=60)

    # Bounded queue: if IDS falls behind under a flood attack, packets are
    # dropped with a warning rather than consuming all available RAM.
    packet_queue: Queue = Queue(maxsize=10_000)

    _ips = IPS(config)
    _ids = IDS(config, packet_queue, ips=_ips)
    _sniffer = PacketSniffer(
        config, packet_queue,
        conn_tracker=conn_tracker,
        traffic_series=traffic_series,
    )

    init_app(_sniffer, _ids, _ips, conn_tracker, traffic_series)

    # SIGTERM (systemd, docker stop, kill): raise SystemExit in main thread
    # so the finally block below runs clean shutdown.
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    _ips.start()
    _ids.start()
    _sniffer.start()

    host: str = config["web_host"]
    port: int = config["web_port"]
    logger.info("Dashboard → http://%s:%s", host, port)

    try:
        # threaded=True: Flask handles concurrent API requests from the dashboard
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        logger.info("Shutdown signal received — stopping components...")
        _cleanup()


if __name__ == "__main__":
    main()
