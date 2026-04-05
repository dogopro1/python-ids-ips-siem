import time
import threading
from collections import deque


class TrafficSeries:
    """Per-second packet counters for sparkline charts."""

    def __init__(self, window: int = 60):
        self._window = window
        self._buckets: deque = deque(maxlen=window)
        self._cur_ts: int = 0
        self._cur_count: int = 0
        self._lock = threading.Lock()

    def record(self):
        ts = int(time.time())
        with self._lock:
            if ts == self._cur_ts:
                self._cur_count += 1
            else:
                if self._cur_ts:
                    self._buckets.append({"ts": self._cur_ts, "count": self._cur_count})
                self._cur_ts = ts
                self._cur_count = 1

    def get_series(self) -> list:
        with self._lock:
            result = list(self._buckets)
            if self._cur_ts:
                result.append({"ts": self._cur_ts, "count": self._cur_count})
        return result
