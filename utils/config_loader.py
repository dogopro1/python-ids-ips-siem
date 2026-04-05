import yaml
import os

_DEFAULTS: dict = {
    "interface": "auto",
    "dos_threshold": 100,
    "portscan_threshold": 20,
    "syn_flood_threshold": 80,
    "icmp_flood_threshold": 50,
    "time_window": 10,
    "blacklist": [],
    "suspicious_ports": [4444, 5555, 6666, 31337, 12345],
    "ips_enabled": True,
    "block_timeout": 600,
    "web_host": "127.0.0.1",
    "web_port": 5000,
    "log_file": "logs/system.log",
    "log_level": "INFO",
    "packet_buffer_size": 1000,
}

# Keys that must be non-negative integers, with optional (min, max) bounds
_INT_BOUNDS: dict = {
    "dos_threshold":       (1, None),
    "portscan_threshold":  (1, None),
    "syn_flood_threshold": (1, None),
    "icmp_flood_threshold":(1, None),
    "time_window":         (1, 3600),
    "block_timeout":       (0, None),
    "web_port":            (1, 65535),
    "packet_buffer_size":  (10, 1_000_000),
}

_instance: "Config | None" = None


class Config:
    def __init__(self, data: dict):
        self._data = data

    @classmethod
    def load(cls, path: str = None) -> "Config":
        global _instance
        if _instance is not None:
            return _instance

        if path is None:
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            path = os.path.join(base, "config", "config.yaml")

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
        except FileNotFoundError:
            raise FileNotFoundError(
                f"Config file not found: {path}\n"
                "Create config/config.yaml or run from the ids_ips_system/ directory."
            )

        merged = {**_DEFAULTS, **raw}
        instance = cls(merged)
        instance._validate()
        _instance = instance
        return _instance

    @classmethod
    def reset(cls) -> None:
        """Reset singleton — intended for tests only."""
        global _instance
        _instance = None

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def __getitem__(self, key: str):
        if key in self._data:
            return self._data[key]
        if key in _DEFAULTS:
            return _DEFAULTS[key]
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return key in self._data

    # ------------------------------------------------------------------
    def _validate(self) -> None:
        """
        Validate critical config values early so YAML typos surface with a
        clear message rather than a cryptic AttributeError deep in rules.py.
        """
        errors = []
        for key, (lo, hi) in _INT_BOUNDS.items():
            val = self._data.get(key)
            if not isinstance(val, int) or isinstance(val, bool):
                errors.append(
                    f"'{key}' must be an integer, got {type(val).__name__}: {val!r}"
                )
                continue
            if lo is not None and val < lo:
                errors.append(f"'{key}' must be >= {lo}, got {val}")
            if hi is not None and val > hi:
                errors.append(f"'{key}' must be <= {hi}, got {val}")

        if not isinstance(self._data.get("blacklist", []), list):
            errors.append("'blacklist' must be a list of IP strings")
        if not isinstance(self._data.get("suspicious_ports", []), list):
            errors.append("'suspicious_ports' must be a list of port numbers")
        if not isinstance(self._data.get("ips_enabled"), bool):
            errors.append("'ips_enabled' must be true or false")

        if errors:
            raise ValueError(
                "config/config.yaml validation failed:\n"
                + "\n".join(f"  [!] {e}" for e in errors)
            )
