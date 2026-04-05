import logging
import os

ALERT = 35
BLOCKED = 36

logging.addLevelName(ALERT, "ALERT")
logging.addLevelName(BLOCKED, "BLOCKED")


def _alert(self, message, *args, **kwargs):
    if self.isEnabledFor(ALERT):
        self._log(ALERT, message, args, stacklevel=2, **kwargs)


def _blocked(self, message, *args, **kwargs):
    if self.isEnabledFor(BLOCKED):
        self._log(BLOCKED, message, args, stacklevel=2, **kwargs)


logging.Logger.alert = _alert
logging.Logger.blocked = _blocked


def setup_logger(log_file: str = "logs/system.log", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("ids_ips")
    if logger.handlers:
        return logger

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(min(numeric_level, ALERT))

    fmt = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)-8s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else ".", exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # Route Flask/Werkzeug HTTP request logs to the same file
    wz = logging.getLogger("werkzeug")
    if not any(isinstance(h, logging.FileHandler) for h in wz.handlers):
        wz.addHandler(fh)

    return logger
