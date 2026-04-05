import threading
import time
import logging

from utils.platform_utils import block_ip, unblock_ip

logger = logging.getLogger("ids_ips")


class IPS:
    def __init__(self, config):
        self._config = config
        self._enabled: bool = config["ips_enabled"]
        self._block_timeout: int = config["block_timeout"]
        self._blocked_ips: dict = {}   # {ip: blocked_at_timestamp}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
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
        if self._block_timeout > 0:
            self._thread = threading.Thread(
                target=self._unblock_loop, name="IPS-Unblock", daemon=True
            )
            self._thread.start()
        logger.info(
            "IPS started (enabled=%s, block_timeout=%ss)",
            self._enabled, self._block_timeout,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("IPS stopped")

    def handle_alert(self, alert: dict) -> None:
        if not self._enabled:
            return
        ip: str = alert.get("src_ip", "")
        if not ip:
            return

        # Check whitelist before blocking
        db = self._get_db()
        if db is not None:
            try:
                if db.is_whitelisted(ip):
                    logger.debug("IPS: %s is whitelisted — skip block", ip)
                    return
            except Exception:
                pass

        # Atomic check-and-reserve: both operations happen under the lock so
        # concurrent alerts for the same IP cannot both pass the "not blocked" check.
        with self._lock:
            if ip in self._blocked_ips:
                return
            # Reserve the slot before releasing the lock. This prevents TOCTOU.
            self._blocked_ips[ip] = time.time()

        reason = alert.get("message", alert.get("type", "auto"))

        # Persist to DB
        if db is not None:
            try:
                db.insert_blocked(ip, reason=reason, block_type="auto",
                                  timeout=self._block_timeout)
            except Exception:
                pass

        # Fire-and-forget: block_ip() calls subprocess.run(timeout=10) which can
        # stall for up to 10 seconds. Running it in a daemon thread ensures the
        # IDS worker thread (caller) is NEVER blocked by firewall I/O.
        threading.Thread(
            target=self._apply_block,
            args=(ip,),
            name=f"IPS-Block-{ip}",
            daemon=True,
        ).start()

    def block_manual(self, ip: str, reason: str = "manual") -> bool:
        """Block an IP manually from the dashboard. Returns False if already blocked."""
        db = self._get_db()
        if db is not None:
            try:
                if db.is_whitelisted(ip):
                    return False
            except Exception:
                pass

        with self._lock:
            if ip in self._blocked_ips:
                return False
            self._blocked_ips[ip] = time.time()

        if db is not None:
            try:
                db.insert_blocked(ip, reason=reason, block_type="manual",
                                  timeout=self._block_timeout)
            except Exception:
                pass

        threading.Thread(
            target=self._apply_block,
            args=(ip,),
            name=f"IPS-ManualBlock-{ip}",
            daemon=True,
        ).start()
        return True

    def unblock_manual(self, ip: str) -> bool:
        """Unblock an IP manually from the dashboard. Returns False if not blocked."""
        with self._lock:
            if ip not in self._blocked_ips:
                return False

        unblock_ip(ip)
        with self._lock:
            self._blocked_ips.pop(ip, None)

        db = self._get_db()
        if db is not None:
            try:
                db.mark_unblocked(ip)
            except Exception:
                pass

        logger.info("Manually unblocked IP: %s", ip)
        return True

    def _apply_block(self, ip: str) -> None:
        success = block_ip(ip)
        if not success:
            logger.warning(
                "Firewall block failed for %s — tracking in memory only "
                "(check privileges / firewall status)",
                ip,
            )
        logger.blocked("Blocked IP: %s", ip)

    def _unblock_loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            to_unblock = []
            with self._lock:
                for ip, blocked_at in list(self._blocked_ips.items()):
                    if now - blocked_at >= self._block_timeout:
                        to_unblock.append(ip)

            for ip in to_unblock:
                unblock_ip(ip)
                with self._lock:
                    self._blocked_ips.pop(ip, None)
                db = self._get_db()
                if db is not None:
                    try:
                        db.mark_unblocked(ip)
                    except Exception:
                        pass
                logger.info("Auto-unblocked IP: %s (after %ds)", ip, self._block_timeout)

            self._stop_event.wait(30)

    def get_blocked(self) -> list:
        now = time.time()
        with self._lock:
            return [
                {"ip": ip, "blocked_at": blocked_at, "age": int(now - blocked_at)}
                for ip, blocked_at in self._blocked_ips.items()
            ]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips
