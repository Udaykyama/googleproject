"""The review-moderation half of the UI, and where its state lives.

Every backend uses the library's queue transitions and overturn-rate
arithmetic. Storage modes explicitly distinguish demo state from durability:

:class:`MemoryStore`
    A queue that never touches disk, and no audit log at all. Restarting loses
    everything, which the UI states rather than leaving to be discovered.
:class:`FileStore`
    The queue on disk, plus the hash-chained
    :class:`~fake_review_detector.audit.AuditLog` and its anchor.
:class:`DatabaseStore`
    Transactional SQLite queue and decision history, safe across workers.

Both serialise writes behind a lock, because a WSGI server handles requests on
several threads while the underlying files assume a single writer. The lock is
process-local: it makes one instance safe and does nothing for two, which is
why ``STORAGE=file`` is documented as single-instance only.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Protocol, Sequence

from fake_review_detector.audit import AuditLog, ChainStatus
from fake_review_detector.engine import BatchResult, moderate_batch
from fake_review_detector.errors import ModerationError, StorageError
from fake_review_detector.models import ModerationDecision
from fake_review_detector.policy import Policy
from fake_review_detector.queue import Outcome, QueueSnapshot, QueueState, ReviewQueue
from fake_review_detector.sqlite_store import SQLiteStore

from .config import SQLITE, AppConfig

__all__ = [
    "BatchProblem",
    "ModerationService",
    "MemoryStore",
    "FileStore",
    "DatabaseStore",
    "Snapshot",
    "Outcome",
]

#: Moderator names are shown back to other moderators and stored in the queue.
_MAX_MODERATOR_LENGTH = 64
_MAX_NOTE_LENGTH = 500
#: Most items one request may claim at once.
_MAX_CLAIM = 25


class BatchProblem(ValueError):
    """A user-facing problem with a submitted batch or queue action."""


Snapshot = QueueSnapshot


class ModerationStore(Protocol):
    def enqueue(self, decisions: Sequence[ModerationDecision]) -> int: ...
    def snapshot(self, *, limit: int, offset: int, state: QueueState | None) -> Snapshot: ...
    def claim(self, moderator: str, limit: int) -> int: ...
    def resolve(self, review_id: str, moderator: str, outcome: Outcome, note: str) -> None: ...
    def release(self, review_id: str) -> None: ...
    def integrity(self) -> str | None: ...
    def verify(self) -> ChainStatus | None: ...
    def healthcheck(self) -> None: ...


class _EphemeralQueue(ReviewQueue):
    """The library's queue behaviour with the persistence removed.

    ``ReviewQueue.save`` is documented as the seam where a different backing
    store would go; this is that seam used to mean "no store at all".
    """

    def load(self) -> None:
        self._items = getattr(self, "_items", {})

    def save(self) -> None:
        return None


class MemoryStore:
    """Non-durable queue. Deliberately writes no audit log."""

    persistent = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._queue = _EphemeralQueue(Path("memory"))

    def enqueue(self, decisions: Sequence[ModerationDecision]) -> int:
        with self._lock:
            return self._queue.enqueue(decisions)

    def snapshot(self, *, limit=50, offset=0, state=None) -> Snapshot:
        with self._lock:
            return self._queue.snapshot(limit=limit, offset=offset, state=state)

    def claim(self, moderator: str, limit: int) -> int:
        with self._lock:
            return len(self._queue.claim(moderator, limit=limit))

    def resolve(
        self, review_id: str, moderator: str, outcome: Outcome, note: str
    ) -> None:
        with self._lock:
            try:
                self._queue.resolve(review_id, moderator, outcome, note)
            except ModerationError as exc:
                raise BatchProblem(str(exc)) from exc

    def integrity(self) -> str | None:
        return None

    def release(self, review_id: str) -> None:
        with self._lock:
            self._queue.release(review_id)

    def verify(self) -> ChainStatus | None:
        return None

    def healthcheck(self) -> None:
        pass


class FileStore:
    """Durable queue plus a hash-chained, anchored audit log."""

    persistent = True

    def __init__(self, data_dir: Path) -> None:
        self._lock = threading.Lock()
        data_dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = data_dir / "queue.json"
        self._log_path = data_dir / "decisions.jsonl"

    def _open(self) -> ReviewQueue:
        # Re-read on every operation so an operator working the same files
        # from the CLI is not silently clobbered by a stale in-memory copy.
        return ReviewQueue(self._queue_path)

    def enqueue(self, decisions: Sequence[ModerationDecision]) -> int:
        with self._lock:
            queue = self._open()
            added = queue.enqueue(decisions)
            # Every decision is logged, not only the queued ones: an "allow"
            # is as much a decision as a removal, and appeals turn on it.
            AuditLog(self._log_path).append(decisions)
            queue.save()
            return added

    def snapshot(self, *, limit=50, offset=0, state=None) -> Snapshot:
        with self._lock:
            queue = self._open()
            return queue.snapshot(limit=limit, offset=offset, state=state)

    def claim(self, moderator: str, limit: int) -> int:
        with self._lock:
            queue = self._open()
            claimed = queue.claim(moderator, limit=limit)
            queue.save()
            return len(claimed)

    def resolve(
        self, review_id: str, moderator: str, outcome: Outcome, note: str
    ) -> None:
        with self._lock:
            queue = self._open()
            try:
                queue.resolve(review_id, moderator, outcome, note)
            except ModerationError as exc:
                raise BatchProblem(str(exc)) from exc
            queue.save()

    def release(self, review_id: str) -> None:
        with self._lock:
            queue = self._open()
            queue.release(review_id)
            queue.save()

    def integrity(self) -> str | None:
        """The audit log's own verdict on itself, shown on the queue page."""

        with self._lock:
            log = AuditLog(self._log_path)
            if not self._log_path.exists() and not log.anchor_path.exists():
                return "No decisions logged yet."
            try:
                anchor = log.read_anchor()
                if anchor is None:
                    return "No anchor found. Run an integrity check before trusting this history."
                return f"{anchor.records} decision record(s) anchored. Full history not checked on page load."
            except ModerationError as exc:  # pragma: no cover - unreadable log
                return f"Audit log could not be read: {exc}"

    def verify(self) -> ChainStatus:
        with self._lock:
            return AuditLog(self._log_path).verify()

    def healthcheck(self) -> None:
        with self._lock:
            self._open()


class DatabaseStore:
    """Web adapter; the same SQLite database can also be worked from the CLI."""

    persistent = True

    def __init__(self, data_dir: Path, *, timeout: float = 5.0) -> None:
        self.database = SQLiteStore(data_dir / "moderation.sqlite3", timeout=timeout)

    def enqueue(self, decisions: Sequence[ModerationDecision]) -> int:
        return self.database.enqueue(decisions)

    def snapshot(self, *, limit=50, offset=0, state=None) -> Snapshot:
        return self.database.snapshot(limit=limit, offset=offset, state=state)

    def claim(self, moderator: str, limit: int) -> int:
        return len(self.database.claim(moderator, limit))

    def resolve(self, review_id: str, moderator: str, outcome: Outcome, note: str) -> None:
        self.database.resolve(review_id, moderator, outcome, note)

    def release(self, review_id: str) -> None:
        self.database.release(review_id)

    def integrity(self) -> str:
        anchor = self.database.read_anchor()
        return (
            f"{anchor.records} decision record(s) stored. "
            "Full history not checked on page load."
        )

    def verify(self) -> ChainStatus:
        return self.database.verify()

    def healthcheck(self) -> None:
        self.database.healthcheck()


class ModerationService:
    """Parses submitted batches, scores them, and owns the queue."""

    def __init__(self, config: AppConfig, store: ModerationStore | None = None) -> None:
        self.config = config
        self.policy = Policy()
        self.store: ModerationStore
        if store is not None:
            self.store = store
        elif config.persistent:
            if config.data_dir is None:  # pragma: no cover - AppConfig forbids it
                raise ValueError("persistent storage requires a data directory")
            self.store = (
                DatabaseStore(config.data_dir, timeout=config.sqlite_timeout)
                if config.storage == SQLITE else FileStore(config.data_dir)
            )
        else:
            self.store = MemoryStore()

    # -- input ------------------------------------------------------------

    def parse(self, raw: str | bytes) -> list[dict]:
        """Turn submitted JSON into review dicts, or explain why it will not."""

        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise BatchProblem(
                    "That file is not UTF-8 text. Upload the JSON export, not a "
                    "spreadsheet or an archive."
                ) from None
        raw = raw.strip()
        if not raw:
            raise BatchProblem("Paste a JSON array of reviews, or upload a file.")

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise BatchProblem(
                f"That is not valid JSON (line {exc.lineno}, column {exc.colno}: "
                f"{exc.msg})."
            ) from None
        except (ValueError, RecursionError):
            raise BatchProblem("That JSON is nested too deeply or contains an unsupported value.") from None

        if isinstance(payload, dict) and isinstance(payload.get("reviews"), list):
            payload = payload["reviews"]
        if not isinstance(payload, list):
            raise BatchProblem(
                "Expected a JSON array of review objects, or an object with a "
                '"reviews" array.'
            )
        if not payload:
            raise BatchProblem("That batch is empty.")
        if len(payload) > self.config.max_reviews:
            raise BatchProblem(
                f"This deployment accepts {self.config.max_reviews} reviews per "
                f"batch; that one has {len(payload)}. The command-line tool has "
                "no such limit."
            )
        if not all(isinstance(item, dict) for item in payload):
            raise BatchProblem("Every entry in the array must be a review object.")
        return payload

    def sample(self) -> str:
        """The bundled example batch, for the "load the sample" button."""

        path = self.config.sample_reviews
        return path.read_text(encoding="utf-8") if path else ""

    # -- scoring ----------------------------------------------------------

    def moderate(self, reviews: list[dict]) -> BatchResult:
        return moderate_batch(
            reviews, policy=self.policy, max_items=self.config.max_reviews
        )

    def enqueue(self, result: BatchResult) -> int:
        return self.store.enqueue(result.decisions)

    # -- queue ------------------------------------------------------------

    def snapshot(self, page=1, state: str = "") -> Snapshot:
        try:
            page = int(page)
        except (TypeError, ValueError):
            raise BatchProblem("Queue page must be a positive whole number.") from None
        if not 1 <= page <= 1_000_000_000:
            raise BatchProblem("Queue page is outside the supported range.")
        try:
            parsed_state = QueueState(state) if state else None
        except ValueError:
            raise BatchProblem("Choose pending, claimed, resolved, or all queue items.") from None
        return self.store.snapshot(
            limit=self.config.queue_page_size,
            offset=(page - 1) * self.config.queue_page_size,
            state=parsed_state,
        )

    def integrity(self) -> str | None:
        return self.store.integrity()

    def verify(self) -> ChainStatus | None:
        return self.store.verify()

    def healthcheck(self) -> None:
        self.store.healthcheck()

    def claim(self, moderator: str, limit) -> int:
        return self.store.claim(_clean_moderator(moderator), _clean_limit(limit))

    def resolve(self, review_id: str, moderator: str, outcome: str, note: str) -> None:
        try:
            parsed = Outcome(outcome)
        except ValueError:
            raise BatchProblem("Choose upheld, overturned, or unclear.") from None
        note = (note or "").strip()
        if len(note) > _MAX_NOTE_LENGTH:
            raise BatchProblem(f"Notes must be at most {_MAX_NOTE_LENGTH} characters.")
        try:
            self.store.resolve(
                _clean_review_id(review_id), _clean_moderator(moderator), parsed, note
            )
        except StorageError:
            raise
        except ModerationError as exc:
            raise BatchProblem(str(exc)) from exc

    def release(self, review_id: str) -> None:
        try:
            self.store.release(_clean_review_id(review_id))
        except StorageError:
            raise
        except ModerationError as exc:
            raise BatchProblem(str(exc)) from exc


def _clean_moderator(raw: str) -> str:
    moderator = (raw or "").strip()
    if not moderator:
        raise BatchProblem(
            "Enter who is working this item — an unattributed decision cannot "
            "be audited."
        )
    if len(moderator) > _MAX_MODERATOR_LENGTH:
        raise BatchProblem("That moderator name is too long.")
    return moderator


def _clean_review_id(raw: str) -> str:
    review_id = (raw or "").strip()
    if not review_id:
        raise BatchProblem("No review was selected.")
    return review_id


def _clean_limit(raw) -> int:
    try:
        limit = int(raw)
    except (TypeError, ValueError):
        raise BatchProblem("How many items to claim must be a number.") from None
    if limit < 1:
        raise BatchProblem("Claim at least one item.")
    if limit > _MAX_CLAIM:
        raise BatchProblem(f"Claim at most {_MAX_CLAIM} items at once.")
    return limit
