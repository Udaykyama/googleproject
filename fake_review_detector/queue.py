"""Human review queue.

Automated heuristics decide what is *suspicious*; people decide what is
*actionable*. Everything the engine is not confident enough to allow outright
lands here.

The queue records moderator outcomes, and that is the point: an ``overturned``
outcome is a measured false positive. Without it, precision is a guess. With it,
:mod:`fake_review_detector.evaluation` can report the real-world false-positive
rate from the queue rather than only from a static labelled set.

State is a single JSON document written atomically. That is appropriate for a
single-process operator tool; a multi-writer deployment needs a database, and
:meth:`ReviewQueue.save` is where that swap would happen.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable

from .errors import ModerationError
from .models import ModerationDecision, utc_now_iso

__all__ = ["ReviewQueue", "QueueItem", "QueueSnapshot", "QueueState", "Outcome"]


class QueueState(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    RESOLVED = "resolved"


class Outcome(str, Enum):
    """A moderator's verdict on a queued item."""

    UPHELD = "upheld"  # the signal was right; content violates policy
    OVERTURNED = "overturned"  # false positive; content is legitimate
    UNCLEAR = "unclear"  # insufficient evidence either way


@dataclass
class QueueItem:
    """One decision awaiting or having received human judgement."""

    decision: ModerationDecision
    state: QueueState = QueueState.PENDING
    queued_at: str = field(default_factory=utc_now_iso)
    claimed_by: str | None = None
    claimed_at: str | None = None
    resolved_by: str | None = None
    resolved_at: str | None = None
    outcome: Outcome | None = None
    note: str = ""

    @property
    def review_id(self) -> str:
        return self.decision.review_id

    @property
    def priority(self) -> int:
        return self.decision.score

    def claim(self, moderator: str) -> None:
        validate_claim(moderator, 1)
        if self.state is not QueueState.PENDING:
            raise ModerationError(f"{self.review_id} is not pending")
        self.state = QueueState.CLAIMED
        self.claimed_by = moderator
        self.claimed_at = utc_now_iso()

    def release(self) -> None:
        if self.state is not QueueState.CLAIMED:
            raise ModerationError(f"{self.review_id} is not claimed")
        self.state = QueueState.PENDING
        self.claimed_by = None
        self.claimed_at = None

    def resolve(self, moderator: str, outcome: Outcome | str, note: str = "") -> None:
        if not isinstance(moderator, str) or not moderator.strip():
            raise ModerationError("a moderator identifier is required to resolve items")
        if self.state is QueueState.RESOLVED:
            raise ModerationError(f"{self.review_id} is already resolved")
        try:
            parsed = Outcome(outcome)
        except ValueError as exc:
            raise ModerationError(
                f"unknown outcome {outcome!r}; expected one of "
                f"{', '.join(o.value for o in Outcome)}"
            ) from exc
        self.outcome = parsed
        self.state = QueueState.RESOLVED
        self.resolved_by = moderator
        self.resolved_at = utc_now_iso()
        self.note = note

    def to_dict(self) -> dict:
        return {
            "decision": self.decision.to_dict(),
            "state": self.state.value,
            "queued_at": self.queued_at,
            "claimed_by": self.claimed_by,
            "claimed_at": self.claimed_at,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at,
            "outcome": self.outcome.value if self.outcome else None,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "QueueItem":
        return cls(
            decision=ModerationDecision.from_dict(payload["decision"]),
            state=QueueState(payload.get("state", "pending")),
            queued_at=payload.get("queued_at", utc_now_iso()),
            claimed_by=payload.get("claimed_by"),
            claimed_at=payload.get("claimed_at"),
            resolved_by=payload.get("resolved_by"),
            resolved_at=payload.get("resolved_at"),
            outcome=Outcome(payload["outcome"]) if payload.get("outcome") else None,
            note=payload.get("note", ""),
        )


@dataclass(frozen=True)
class QueueSnapshot:
    """One bounded page and queue-wide counts from the same storage snapshot."""

    items: list[QueueItem]
    stats: dict
    limit: int = 50
    offset: int = 0
    state: QueueState | None = None

    @property
    def total(self) -> int:
        return self.stats["states"][self.state.value] if self.state else self.stats["total"]

    @property
    def has_next(self) -> bool:
        return self.offset + len(self.items) < self.total


def validate_page(limit: int, offset: int, state: QueueState | str | None) -> QueueState | None:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ModerationError("page size must be a positive integer")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ModerationError("page offset must be a non-negative integer")
    try:
        return QueueState(state) if state is not None else None
    except ValueError as exc:
        raise ModerationError("queue state must be pending, claimed, or resolved") from exc


def validate_claim(moderator: str, limit: int) -> None:
    if not isinstance(moderator, str) or not moderator.strip():
        raise ModerationError("a moderator identifier is required to claim items")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ModerationError("claim limit must be a positive integer")


def summarize_counts(counts: dict[str, int], outcomes: dict[str, int]) -> dict:
    decided = outcomes["upheld"] + outcomes["overturned"]
    return {
        "total": sum(counts.values()),
        "states": counts,
        "outcomes": outcomes,
        "overturn_rate": round(outcomes["overturned"] / decided, 4) if decided else None,
    }


class ReviewQueue:
    """A persistent, priority-ordered queue of items needing human judgement."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._items: dict[str, QueueItem] = {}
        self.load()

    # -- persistence -----------------------------------------------------

    def load(self) -> None:
        if not self.path.exists():
            self._items = {}
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError, RecursionError) as exc:
            raise ModerationError(f"cannot read queue {self.path}: {exc}") from exc
        try:
            if not isinstance(payload, dict) or not isinstance(payload.get("items", []), list):
                raise ValueError("queue must be an object with an items array")
            if payload.get("version", 1) != 1:
                raise ValueError("unsupported queue version")
            items = {}
            for raw in payload.get("items", []):
                item = QueueItem.from_dict(raw)
                if item.review_id in items:
                    raise ValueError(f"duplicate queue item {item.review_id!r}")
                items[item.review_id] = item
        except (KeyError, TypeError, ValueError) as exc:
            raise ModerationError(f"invalid queue {self.path}: {exc}") from exc
        self._items = items

    def save(self) -> None:
        """Write atomically so an interrupted save cannot truncate the queue."""

        payload = {
            "version": 1,
            "saved_at": utc_now_iso(),
            "items": [item.to_dict() for item in self._ordered()],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            )
            with handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(handle.name, self.path)
        except OSError as exc:
            raise ModerationError(f"cannot write queue {self.path}: {exc}") from exc

    # -- queue operations ------------------------------------------------

    def _ordered(self) -> list[QueueItem]:
        # Highest score first, then oldest first so low-scoring items still get
        # worked rather than starving behind a stream of high-scoring ones.
        return sorted(
            self._items.values(), key=lambda i: (-i.priority, i.queued_at, i.review_id)
        )

    def enqueue(self, decisions: Iterable[ModerationDecision]) -> int:
        """Add decisions that require human review. Existing ids are skipped."""

        added = 0
        for decision in decisions:
            if not decision.requires_human_review:
                continue
            if decision.review_id in self._items:
                continue
            self._items[decision.review_id] = QueueItem(decision=decision)
            added += 1
        return added

    def items(self) -> list[QueueItem]:
        """Every item, highest priority first, whatever its state."""

        return self._ordered()

    def pending(self) -> list[QueueItem]:
        return [i for i in self._ordered() if i.state is QueueState.PENDING]

    def snapshot(
        self, *, limit: int = 50, offset: int = 0, state: QueueState | str | None = None
    ) -> QueueSnapshot:
        state = validate_page(limit, offset, state)
        items = [i for i in self._ordered() if state is None or i.state is state]
        return QueueSnapshot(
            items=[QueueItem.from_dict(i.to_dict()) for i in items[offset : offset + limit]],
            stats=self.stats(),
            limit=limit,
            offset=offset,
            state=state,
        )

    def claim(self, moderator: str, limit: int = 1) -> list[QueueItem]:
        """Assign the highest-priority pending items to a moderator."""

        validate_claim(moderator, limit)
        claimed: list[QueueItem] = []
        for item in self.pending():
            if len(claimed) >= limit:
                break
            item.claim(moderator)
            claimed.append(item)
        return claimed

    def release(self, review_id: str) -> None:
        """Return a claimed item to the pending pool."""

        self._require(review_id).release()

    def resolve(
        self, review_id: str, moderator: str, outcome: Outcome | str, note: str = ""
    ) -> QueueItem:
        """Record a moderator's verdict."""

        item = self._require(review_id)
        item.resolve(moderator, outcome, note)
        return item

    def _require(self, review_id: str) -> QueueItem:
        item = self._items.get(review_id)
        if item is None:
            raise ModerationError(f"{review_id} is not in the queue")
        return item

    def get(self, review_id: str) -> QueueItem | None:
        return self._items.get(review_id)

    def __len__(self) -> int:
        return len(self._items)

    # -- reporting -------------------------------------------------------

    def stats(self) -> dict:
        """Queue depth and, crucially, the observed overturn rate.

        ``overturn_rate`` is the share of resolved items moderators judged to be
        false positives — the production precision signal that a static test set
        cannot provide.
        """

        counts = {state.value: 0 for state in QueueState}
        outcomes = {outcome.value: 0 for outcome in Outcome}
        for item in self._items.values():
            counts[item.state.value] += 1
            if item.outcome:
                outcomes[item.outcome.value] += 1

        return summarize_counts(counts, outcomes)
