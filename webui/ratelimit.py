"""A small in-process token bucket, used to throttle live DNS audits.

Not a distributed rate limiter: state lives in one process, so N instances
permit N times the configured rate. That is honest for the single-instance
deployment this app documents, and the README says so. Anything larger wants a
shared store.

Buckets are evicted once they have been idle long enough to have fully
refilled, because an unbounded per-IP dictionary is itself a memory-exhaustion
vector — the exact thing a rate limiter is supposed to prevent.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = ["RateLimiter", "RateLimit"]

#: Never track more clients than this. On overflow the oldest-seen bucket is
#: dropped, which at worst grants one extra request to a client that has not
#: been seen for a while.
_MAX_TRACKED_CLIENTS = 10_000


@dataclass(frozen=True)
class RateLimit:
    """The outcome of one rate-limit check."""

    allowed: bool
    retry_after: int = 0


class RateLimiter:
    """Token bucket: ``burst`` tokens, refilled at ``per_minute`` a minute."""

    def __init__(
        self,
        per_minute: int,
        burst: int,
        *,
        clock=time.monotonic,
        max_clients: int = _MAX_TRACKED_CLIENTS,
    ) -> None:
        if per_minute <= 0 or burst <= 0:
            raise ValueError("per_minute and burst must both be positive")
        if max_clients <= 0:
            raise ValueError("max_clients must be positive")
        self.per_minute = per_minute
        self.burst = burst
        self.max_clients = max_clients
        self._refill_per_second = per_minute / 60.0
        self._clock = clock
        self._lock = threading.Lock()
        # client -> (tokens, last_seen)
        self._buckets: dict[str, tuple[float, float]] = {}

    def __len__(self) -> int:
        """How many clients are currently tracked. Used to assert the cap holds."""

        with self._lock:
            return len(self._buckets)

    def check(self, client: str, cost: float = 1.0) -> RateLimit:
        """Spend ``cost`` tokens for ``client`` if it can afford them."""

        now = self._clock()
        with self._lock:
            self._evict(now, incoming=client)
            tokens, last_seen = self._buckets.get(client, (float(self.burst), now))
            tokens = min(
                float(self.burst),
                tokens + (now - last_seen) * self._refill_per_second,
            )
            if tokens >= cost:
                self._buckets[client] = (tokens - cost, now)
                return RateLimit(allowed=True)
            self._buckets[client] = (tokens, now)
            deficit = cost - tokens
            # Round up: a Retry-After of 0 invites an immediate retry that
            # would fail again.
            retry_after = max(1, int(deficit / self._refill_per_second) + 1)
            return RateLimit(allowed=False, retry_after=retry_after)

    def _evict(self, now: float, incoming: str) -> None:
        """Drop buckets that have refilled; they are indistinguishable from new."""

        full_after = self.burst / self._refill_per_second
        stale = [
            client
            for client, (_, last_seen) in self._buckets.items()
            if now - last_seen >= full_after
        ]
        for client in stale:
            del self._buckets[client]

        # Reserve a slot for the caller so the dictionary never exceeds the
        # cap, rather than settling one above it.
        needed = 0 if incoming in self._buckets else 1
        overflow = len(self._buckets) + needed - self.max_clients
        if overflow > 0:
            oldest = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
            for client, _ in oldest[:overflow]:
                del self._buckets[client]
