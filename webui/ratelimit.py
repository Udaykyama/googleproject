"""Token buckets for live DNS audits.

Memory/file deployments use an in-process bucket. SQLite deployments use the
same arithmetic against shared transactional rows, so adding workers does not
multiply the configured allowance.

Buckets are evicted once they have been idle long enough to have fully
refilled, because an unbounded per-IP dictionary is itself a memory-exhaustion
vector — the exact thing a rate limiter is supposed to prevent.
"""

from __future__ import annotations

import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from fake_review_detector.sqlite_store import SQLiteStore

__all__ = ["RateLimiter", "SQLiteRateLimiter", "RateLimit"]

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
        for name, value in (
            ("per_minute", per_minute), ("burst", burst), ("max_clients", max_clients)
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        self.per_minute = per_minute
        self.burst = burst
        self.max_clients = max_clients
        self._refill_per_second = per_minute / 60.0
        self._clock = clock
        self._lock = threading.Lock()
        # client -> (tokens, last_seen)
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def __len__(self) -> int:
        """How many clients are currently tracked. Used to assert the cap holds."""

        with self._lock:
            return len(self._buckets)

    def check(self, client: str, cost: float = 1.0) -> RateLimit:
        """Spend ``cost`` tokens for ``client`` if it can afford them."""

        self._validate_cost(cost)
        with self._lock:
            now = self._clock()
            self._evict(now, incoming=client)
            tokens, last_seen = self._buckets.get(client, (float(self.burst), now))
            tokens, verdict = self._spend(tokens, last_seen, now, cost)
            self._buckets[client] = (tokens, max(now, last_seen))
            self._buckets.move_to_end(client)
            return verdict

    def _validate_cost(self, cost: float) -> None:
        if not math.isfinite(cost) or not 0 < cost <= self.burst:
            raise ValueError("cost must be finite, positive, and no greater than burst")

    def _spend(
        self, tokens: float, last_seen: float, now: float, cost: float
    ) -> tuple[float, RateLimit]:
        tokens = min(
            float(self.burst),
            tokens + max(0.0, now - last_seen) * self._refill_per_second,
        )
        if tokens >= cost:
            return tokens - cost, RateLimit(allowed=True)
        wait = math.ceil((cost - tokens) / self._refill_per_second)
        return tokens, RateLimit(allowed=False, retry_after=max(1, wait))

    def _evict(self, now: float, incoming: str) -> None:
        """Drop buckets that have refilled; they are indistinguishable from new."""

        full_after = self.burst / self._refill_per_second
        while self._buckets:
            _, (_, last_seen) = next(iter(self._buckets.items()))
            if now - last_seen < full_after:
                break
            self._buckets.popitem(last=False)

        # Reserve a slot for the caller so the dictionary never exceeds the
        # cap, rather than settling one above it.
        needed = 0 if incoming in self._buckets else 1
        overflow = len(self._buckets) + needed - self.max_clients
        for _ in range(max(0, overflow)):
            self._buckets.popitem(last=False)


class SQLiteRateLimiter(RateLimiter):
    """One token allowance across processes and restarts on the same host."""

    def __init__(
        self, store: SQLiteStore, per_minute: int, burst: int, *,
        clock=time.time, max_clients: int = _MAX_TRACKED_CLIENTS,
    ) -> None:
        super().__init__(per_minute, burst, clock=clock, max_clients=max_clients)
        self.store = store

    def __len__(self) -> int:
        with self.store.transaction() as connection:
            return connection.execute("SELECT COUNT(*) FROM rate_limits").fetchone()[0]

    def check(self, client: str, cost: float = 1.0) -> RateLimit:
        self._validate_cost(cost)
        with self.store.transaction(write=True) as connection:
            now = self._clock()
            full_after = self.burst / self._refill_per_second
            connection.execute(
                "DELETE FROM rate_limits WHERE last_seen <= ?", (now - full_after,)
            )
            row = connection.execute(
                "SELECT tokens, last_seen FROM rate_limits WHERE client = ?", (client,)
            ).fetchone()
            if row is None:
                count = connection.execute("SELECT COUNT(*) FROM rate_limits").fetchone()[0]
                overflow = count + 1 - self.max_clients
                if overflow > 0:
                    connection.execute(
                        "DELETE FROM rate_limits WHERE client IN "
                        "(SELECT client FROM rate_limits ORDER BY last_seen, client LIMIT ?)",
                        (overflow,),
                    )
                tokens, last_seen = float(self.burst), now
            else:
                tokens, last_seen = row["tokens"], row["last_seen"]
            tokens, verdict = self._spend(tokens, last_seen, now, cost)
            connection.execute(
                """INSERT INTO rate_limits (client, tokens, last_seen) VALUES (?, ?, ?)
                   ON CONFLICT(client) DO UPDATE SET
                   tokens = excluded.tokens, last_seen = excluded.last_seen""",
                (client, tokens, max(now, last_seen)),
            )
            return verdict
