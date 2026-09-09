"""Transactional moderation storage for multiple workers on one host.

Queue mutations, decision records, and the audit head commit together. Each
operation opens its own connection, so no connection is shared across threads
or inherited by a forked worker. WAL permits readers during a write; SQLite
still serializes writers. Use a local persistent disk, not a network share.

The audit head detects accidental edits/truncation, not an administrator who
can rewrite the entire database. Keep independent backups for that threat.
"""

from __future__ import annotations

import json
import math
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .audit import GENESIS_HASH, Anchor, AuditRecord, ChainStatus, verify_records
from .errors import AuditLogError, ModerationError, StorageBusyError, StorageError
from .models import ModerationDecision, utc_now_iso
from .queue import (
    Outcome,
    QueueItem,
    QueueSnapshot,
    QueueState,
    summarize_counts,
    validate_claim,
    validate_page,
)

__all__ = ["SQLiteStore"]

_SCHEMA_VERSION = 1
_SCHEMA = (
    """CREATE TABLE queue_items (
        review_id TEXT PRIMARY KEY,
        decision TEXT NOT NULL,
        priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 100),
        state TEXT NOT NULL CHECK (state IN ('pending', 'claimed', 'resolved')),
        queued_at TEXT NOT NULL,
        claimed_by TEXT,
        claimed_at TEXT,
        resolved_by TEXT,
        resolved_at TEXT,
        outcome TEXT CHECK (outcome IN ('upheld', 'overturned', 'unclear')),
        note TEXT NOT NULL
    )""",
    """CREATE INDEX queue_priority
       ON queue_items (priority DESC, queued_at, review_id)""",
    """CREATE INDEX queue_state_priority
       ON queue_items (state, priority DESC, queued_at, review_id)""",
    "CREATE INDEX queue_counts ON queue_items (state, outcome)",
    """CREATE TABLE audit_records (
        sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
        record TEXT NOT NULL
    )""",
    """CREATE TABLE audit_head (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        records INTEGER NOT NULL CHECK (records >= 0),
        head_hash TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE rate_limits (
        client TEXT PRIMARY KEY,
        tokens REAL NOT NULL,
        last_seen REAL NOT NULL
    )""",
    "CREATE INDEX rate_limits_last_seen ON rate_limits (last_seen, client)",
)


class SQLiteStore:
    """Durable queue and hash-chained decision log with atomic operations."""

    persistent = True

    def __init__(
        self, path: str | Path, *, timeout: float = 5.0, create: bool = True
    ) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SQLite timeout must be finite and greater than zero")
        self.path = Path(path).expanduser().resolve()
        self.timeout = timeout
        if create:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise StorageError(f"cannot create storage directory: {exc}") from exc
        self._initialize(create=create)

    @contextmanager
    def _connection(
        self, *, create: bool = False, timeout: float | None = None
    ) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            mode = "rwc" if create else "rw"
            connection = sqlite3.connect(
                self.path.as_uri() + f"?mode={mode}",
                uri=True,
                timeout=self.timeout if timeout is None else timeout,
                isolation_level=None,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA synchronous = FULL")
            yield connection
        except sqlite3.Error as exc:
            # sqlite_errorcode was added in Python 3.11; retain the 3.10 floor.
            code = getattr(exc, "sqlite_errorcode", None)
            if (code is not None and code & 0xFF in (5, 6)) or str(exc) in {
                "database is locked", "database table is locked",
            }:
                raise StorageBusyError("moderation storage is busy; retry shortly") from exc
            raise StorageError(f"cannot use moderation database {self.path}: {exc}") from exc
        finally:
            if connection is not None:
                connection.close()

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        """A consistent read or serialized write, also used by shared rate limits."""

        with self._connection() as connection, connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection

    def _initialize(self, *, create: bool) -> None:
        deadline = time.monotonic() + self.timeout
        remaining = self.timeout
        while True:
            try:
                self._initialize_once(create=create, timeout=remaining)
                return
            except StorageBusyError:
                # WAL lock upgrades can bypass busy_timeout. A new connection
                # releases the failed attempt's locks before another try.
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise
                time.sleep(min(0.01, remaining))
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise

    def _initialize_once(self, *, create: bool, timeout: float) -> None:
        with self._connection(create=create, timeout=timeout) as connection:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise StorageError("moderation storage requires SQLite WAL on a local disk")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, _SCHEMA_VERSION):
                    raise StorageError(f"unsupported moderation database version {version}")
                if version == 0:
                    if not create:
                        raise StorageError("moderation database has not been initialized")
                    tables = connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table' "
                        "AND name NOT LIKE 'sqlite_%' LIMIT 1"
                    ).fetchone()
                    if tables:
                        raise StorageError("refusing to initialize a non-empty unknown database")
                    for statement in _SCHEMA:
                        connection.execute(statement)
                    connection.execute(
                        "INSERT INTO audit_head VALUES (1, 0, ?, ?)",
                        (GENESIS_HASH, utc_now_iso()),
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
                self._head(connection)

    @staticmethod
    def _head(connection: sqlite3.Connection) -> Anchor:
        row = connection.execute(
            "SELECT records, head_hash, updated_at FROM audit_head WHERE id = 1"
        ).fetchone()
        if row is None:
            raise AuditLogError("audit anchor is missing from the database")
        return Anchor.from_dict(dict(row))

    def read_anchor(self) -> Anchor:
        with self.transaction() as connection:
            return self._head(connection)

    @staticmethod
    def _record(row: sqlite3.Row) -> AuditRecord:
        try:
            record = AuditRecord.from_dict(json.loads(row["record"]))
            if record.sequence != row["sequence"]:
                raise ValueError("sequence does not match the stored row")
            return record
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise AuditLogError(f"invalid audit record at sequence {row['sequence']}: {exc}") from exc

    def _check_head(self, connection: sqlite3.Connection, anchor: Anchor) -> None:
        row = connection.execute(
            "SELECT sequence, record FROM audit_records ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        record = self._record(row) if row is not None else None
        sequence = record.sequence if record else 0
        head_hash = record.record_hash if record else GENESIS_HASH
        if sequence != anchor.records or head_hash != anchor.head_hash:
            raise AuditLogError("refusing to append: audit log does not match its anchor")

    def enqueue(self, decisions: Iterable[ModerationDecision]) -> int:
        """Log every decision and enqueue new flagged IDs in one transaction.

        Repeated submissions produce new audit records, but never reset an
        existing queue item or overwrite a moderator's outcome.
        """

        with self.transaction(write=True) as connection:
            anchor = self._head(connection)
            self._check_head(connection, anchor)
            sequence, head_hash = anchor.records, anchor.head_hash
            added = 0
            for decision in decisions:
                sequence += 1
                record = AuditRecord.create(sequence, decision, head_hash)
                head_hash = record.record_hash
                connection.execute(
                    "INSERT INTO audit_records (sequence, record) VALUES (?, ?)",
                    (sequence, json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True)),
                )
                if decision.requires_human_review:
                    item = QueueItem(decision=decision)
                    cursor = connection.execute(
                        """INSERT INTO queue_items
                           (review_id, decision, priority, state, queued_at, note)
                           VALUES (?, ?, ?, ?, ?, '')
                           ON CONFLICT(review_id) DO NOTHING""",
                        (
                            item.review_id,
                            json.dumps(decision.to_dict(), ensure_ascii=False, sort_keys=True),
                            item.priority,
                            item.state.value,
                            item.queued_at,
                        ),
                    )
                    added += cursor.rowcount
            if sequence != anchor.records:
                connection.execute(
                    "UPDATE audit_head SET records = ?, head_hash = ?, updated_at = ? WHERE id = 1",
                    (sequence, head_hash, utc_now_iso()),
                )
            return added

    @staticmethod
    def _item(row: sqlite3.Row) -> QueueItem:
        try:
            payload = dict(row)
            payload["decision"] = json.loads(payload["decision"])
            return QueueItem.from_dict(payload)
        except (KeyError, TypeError, ValueError, RecursionError) as exc:
            raise StorageError(f"invalid stored queue item {row['review_id']!r}") from exc

    @staticmethod
    def _stats(connection: sqlite3.Connection) -> dict:
        counts = {state.value: 0 for state in QueueState}
        outcomes = {outcome.value: 0 for outcome in Outcome}
        for row in connection.execute(
            "SELECT state, outcome, COUNT(*) AS count FROM queue_items GROUP BY state, outcome"
        ):
            counts[row["state"]] += row["count"]
            if row["outcome"]:
                outcomes[row["outcome"]] += row["count"]
        return summarize_counts(counts, outcomes)

    def stats(self) -> dict:
        with self.transaction() as connection:
            return self._stats(connection)

    def __len__(self) -> int:
        with self.transaction() as connection:
            return connection.execute("SELECT COUNT(*) FROM queue_items").fetchone()[0]

    def snapshot(
        self, *, limit: int = 50, offset: int = 0, state: QueueState | str | None = None
    ) -> QueueSnapshot:
        state = validate_page(limit, offset, state)
        where = "WHERE state = ?" if state else ""
        parameters = (state.value, limit, offset) if state else (limit, offset)
        with self.transaction() as connection:
            rows = connection.execute(
                f"SELECT * FROM queue_items {where} "
                "ORDER BY priority DESC, queued_at, review_id LIMIT ? OFFSET ?",
                parameters,
            )
            items = [self._item(row) for row in rows]
            return QueueSnapshot(items, self._stats(connection), limit, offset, state)

    def _require(self, connection: sqlite3.Connection, review_id: str) -> QueueItem:
        row = connection.execute(
            "SELECT * FROM queue_items WHERE review_id = ?", (review_id,)
        ).fetchone()
        if row is None:
            raise ModerationError(f"{review_id} is not in the queue")
        return self._item(row)

    def get(self, review_id: str) -> QueueItem | None:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM queue_items WHERE review_id = ?", (review_id,)
            ).fetchone()
            return self._item(row) if row is not None else None

    @staticmethod
    def _save_item(connection: sqlite3.Connection, item: QueueItem) -> None:
        connection.execute(
            """UPDATE queue_items SET state = ?, claimed_by = ?, claimed_at = ?,
               resolved_by = ?, resolved_at = ?, outcome = ?, note = ?
               WHERE review_id = ?""",
            (
                item.state.value, item.claimed_by, item.claimed_at,
                item.resolved_by, item.resolved_at,
                item.outcome.value if item.outcome else None,
                item.note, item.review_id,
            ),
        )

    def claim(self, moderator: str, limit: int = 1) -> list[QueueItem]:
        validate_claim(moderator, limit)
        with self.transaction(write=True) as connection:
            items = [
                self._item(row)
                for row in connection.execute(
                    "SELECT * FROM queue_items WHERE state = 'pending' "
                    "ORDER BY priority DESC, queued_at, review_id LIMIT ?", (limit,)
                )
            ]
            for item in items:
                item.claim(moderator)
                self._save_item(connection, item)
            return items

    def release(self, review_id: str) -> None:
        with self.transaction(write=True) as connection:
            item = self._require(connection, review_id)
            item.release()
            self._save_item(connection, item)

    def resolve(
        self, review_id: str, moderator: str, outcome: Outcome | str, note: str = ""
    ) -> QueueItem:
        with self.transaction(write=True) as connection:
            item = self._require(connection, review_id)
            item.resolve(moderator, outcome, note)
            self._save_item(connection, item)
            return item

    def read(self) -> Iterator[AuditRecord]:
        with self.transaction() as connection:
            for row in connection.execute(
                "SELECT sequence, record FROM audit_records ORDER BY sequence"
            ):
                yield self._record(row)

    def verify(self) -> ChainStatus:
        """Stream the history and its anchor from a single read transaction."""

        try:
            with self.transaction() as connection:
                anchor = self._head(connection)
                rows = connection.execute(
                    "SELECT sequence, record FROM audit_records ORDER BY sequence"
                )
                return verify_records((self._record(row) for row in rows), anchor)
        except AuditLogError as exc:
            return ChainStatus(valid=False, records=0, reason=str(exc))

    def check_integrity(self) -> None:
        """Run SQLite's full structural integrity check."""

        with self.transaction() as connection:
            results = [
                str(row[0])
                for row in connection.execute("PRAGMA integrity_check").fetchall()
            ]
        if results != ["ok"]:
            detail = "; ".join(results[:3]) or "no result"
            raise StorageError(f"SQLite integrity check failed: {detail}")

    def healthcheck(self) -> None:
        """Check the schema is readable without scanning the decision history."""

        with self.transaction() as connection:
            self._head(connection)
            connection.execute("SELECT review_id FROM queue_items LIMIT 1").fetchone()
