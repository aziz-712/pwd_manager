"""In-process sliding-window rate limiting.

Honest about its limits: this is per-process state. Behind more than one worker
it under-counts, and it is not a defence against a distributed attacker. It is
here so the endpoint shape and the 429 contract are right from day one; swap the
backing store for Redis before production (see docs/SECURITY_CHECKLIST.md).
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, window_seconds: int = 60, max_entries: int = 100_000):
        self.window = window_seconds
        self.max_entries = max_entries
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int) -> tuple[bool, int, float]:
        """(allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self.max_entries:
                self._evict(now)
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= limit:
                return False, 0, max(0.0, self.window - (now - bucket[0]))
            bucket.append(now)
            return True, limit - len(bucket), 0.0

    def _evict(self, now: float) -> None:
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] > self.window]:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()
