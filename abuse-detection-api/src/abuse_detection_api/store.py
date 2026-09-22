"""Bounded, in-memory sliding-window store.

The API is stateless in the sense that it has no database and nothing
survives a restart. To detect velocity (brute force, stuffing, spray) it keeps
a short-lived window of recent events in memory:

* No entry is ever kept longer than ``max_age_seconds`` (capped at 1 hour).
* The number of tracked keys is capped; the least recently touched key is
  evicted first when the cap is hit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

MAX_RETENTION_SECONDS = 3600


class WindowStore:
    def __init__(
        self,
        max_age_seconds: int = MAX_RETENTION_SECONDS,
        max_keys: int = 100_000,
        max_events_per_key: int = 1_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_age_seconds > MAX_RETENTION_SECONDS:
            raise ValueError(f"retention may not exceed {MAX_RETENTION_SECONDS}s")
        self.max_age = max_age_seconds
        self.max_keys = max_keys
        self.max_events_per_key = max_events_per_key
        self._clock = clock
        self._data: OrderedDict[str, deque[tuple[float, str]]] = OrderedDict()
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[tuple[float, str]] | None:
        events = self._data.get(key)
        if events is None:
            return None
        cutoff = now - self.max_age
        while events and events[0][0] < cutoff:
            events.popleft()
        if not events:
            del self._data[key]
            return None
        return events

    def record(self, key: str, value: str = "") -> None:
        now = self._clock()
        with self._lock:
            events = self._prune(key, now)
            if events is None:
                events = deque(maxlen=self.max_events_per_key)
                self._data[key] = events
            events.append((now, value))
            self._data.move_to_end(key)
            while len(self._data) > self.max_keys:
                self._data.popitem(last=False)

    def _window(self, key: str, window_seconds: int) -> list[tuple[float, str]]:
        now = self._clock()
        with self._lock:
            events = self._prune(key, now)
            if events is None:
                return []
            cutoff = now - min(window_seconds, self.max_age)
            return [e for e in events if e[0] >= cutoff]

    def count(self, key: str, window_seconds: int) -> int:
        return len(self._window(key, window_seconds))

    def values(self, key: str, window_seconds: int) -> set[str]:
        return {v for _, v in self._window(key, window_seconds)}

    def distinct(self, key: str, window_seconds: int) -> int:
        return len(self.values(key, window_seconds))

    def sweep(self) -> None:
        """Drop every expired event; called periodically by the app."""
        now = self._clock()
        with self._lock:
            for key in list(self._data):
                self._prune(key, now)

    def __len__(self) -> int:
        return len(self._data)
