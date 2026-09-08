"""Storage guarantees across independent processes, not just WSGI threads."""

import json
import multiprocessing
import sqlite3
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from types import SimpleNamespace

import pytest

import fake_review_detector.sqlite_store as sqlite_store
from fake_review_detector import SQLiteStore, moderate_batch
from fake_review_detector.audit import replay
from fake_review_detector.errors import AuditLogError, ModerationError, StorageBusyError, StorageError
from fake_review_detector.models import Action
from fake_review_detector.queue import Outcome, QueueState


def decisions(count=3):
    return moderate_batch([
        {
            "review_id": f"r{i}", "author": f"a{i}", "rating": 5,
            "text": "Best product ever!!!", "verified_purchase": False,
            "account_age_days": 1,
        }
        for i in range(count)
    ]).decisions


def _writer(arguments):
    path, worker = arguments
    store = SQLiteStore(path)
    batch = [replace(d, review_id=f"{worker}-{d.review_id}") for d in decisions(10)]
    added = store.enqueue(batch)
    claimed = store.claim(str(worker), limit=10)
    return added, [i.review_id for i in claimed]


def _wait_for_bootstrap(barrier):
    barrier.wait(timeout=20)


def test_concurrent_bootstrap_and_writes_never_lose_decisions_or_double_claim(tmp_path):
    path = tmp_path / "moderation.sqlite3"
    context = multiprocessing.get_context("spawn")
    assert not path.exists()
    with ProcessPoolExecutor(
        max_workers=4, mp_context=context,
        initializer=_wait_for_bootstrap, initargs=(context.Barrier(4),),
    ) as pool:
        results = list(pool.map(_writer, [(path, i) for i in range(4)]))
    store = SQLiteStore(path, create=False)
    claimed = [review_id for _, ids in results for review_id in ids]
    assert sum(added for added, _ in results) == 40
    assert len(claimed) == len(set(claimed)) == 40
    assert store.stats()["states"] == {"pending": 0, "claimed": 40, "resolved": 0}
    status = store.verify()
    assert status.valid and status.anchor_checked and status.records == 40


def test_wal_bootstrap_retries_with_a_fresh_connection(tmp_path, monkeypatch):
    connections = []
    timeouts = []
    connect = sqlite3.connect

    class BusyFirstConnection(sqlite3.Connection):
        closed = False

        def execute(self, sql, parameters=()):
            if sql == "PRAGMA journal_mode = WAL" and self is connections[0]:
                # A WAL lock upgrade can fail immediately despite busy_timeout.
                raise sqlite3.OperationalError("database is locked")
            return super().execute(sql, parameters)

        def close(self):
            super().close()
            self.closed = True

    def counted_connect(*args, **kwargs):
        assert all(connection.closed for connection in connections)
        connection = connect(*args, **kwargs, factory=BusyFirstConnection)
        connections.append(connection)
        timeouts.append(kwargs["timeout"])
        return connection

    monkeypatch.setattr(sqlite3, "connect", counted_connect)
    store = SQLiteStore(tmp_path / "db", timeout=1)
    assert len(connections) == 2
    assert all(connection.closed for connection in connections)
    assert 0 < timeouts[1] < timeouts[0] <= 1
    assert store.verify().valid


def test_bootstrap_retries_stop_at_the_configured_deadline(tmp_path, monkeypatch):
    now = 0.0
    attempts = []

    def sleep(seconds):
        nonlocal now
        now += seconds

    def busy(self, *, create, timeout):
        attempts.append(timeout)
        raise StorageBusyError("moderation storage is busy")

    monkeypatch.setattr(
        sqlite_store, "time", SimpleNamespace(monotonic=lambda: now, sleep=sleep)
    )
    monkeypatch.setattr(SQLiteStore, "_initialize_once", busy)
    with pytest.raises(StorageBusyError, match="busy"):
        SQLiteStore(tmp_path / "db", timeout=0.025)
    assert now == pytest.approx(0.025)
    assert attempts == pytest.approx([0.025, 0.015, 0.005])


def test_queue_and_audit_roll_back_together(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    batch = decisions()
    batch[-1] = replace(batch[-1], score=101)
    with pytest.raises(StorageError):
        store.enqueue(batch)
    assert len(store) == 0
    assert list(store.read()) == []
    assert store.read_anchor().records == 0
    assert store.verify().valid


def test_all_decisions_are_logged_but_only_flagged_ones_are_queued(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    batch = decisions(2)
    batch[1] = replace(batch[1], action=Action.ALLOW)
    assert store.enqueue(batch) == 1
    assert store.verify().records == 2
    assert [item.review_id for item in store.snapshot().items] == [batch[0].review_id]


def test_duplicate_submission_preserves_moderator_outcomes(tmp_path):
    path = tmp_path / "db"
    first = SQLiteStore(path)
    batch = decisions()
    assert first.enqueue(batch) == 3
    first.claim("alice")
    first.resolve("r0", "alice", Outcome.OVERTURNED, "genuine customer")
    second = SQLiteStore(path)
    assert second.enqueue(batch) == 0
    restored = second.get("r0")
    assert restored.state is QueueState.RESOLVED
    assert restored.note == "genuine customer"
    assert second.stats()["overturn_rate"] == 1
    assert second.verify().records == 6


def test_queue_paging_uses_global_counts_and_stable_order(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    batch = decisions(12)
    store.enqueue(batch)
    store.claim("alice", 2)
    page = store.snapshot(limit=3, offset=3, state="pending")
    assert len(page.items) == 3
    assert page.stats["total"] == 12
    assert page.total == 10
    assert page.has_next
    assert all(item.state is QueueState.PENDING for item in page.items)
    first = store.snapshot(limit=3, state="pending")
    assert {i.review_id for i in first.items}.isdisjoint(i.review_id for i in page.items)
    assert not store.snapshot(limit=3, offset=9, state="pending").has_next
    assert store.snapshot(limit=3, offset=30).items == []


def test_only_page_items_are_deserialized(tmp_path, monkeypatch):
    store = SQLiteStore(tmp_path / "db")
    seed = decisions(1)[0]
    store.enqueue(replace(seed, review_id=f"r{i:04}") for i in range(1000))
    original = store._item
    read = []

    def counted(row):
        read.append(row["review_id"])
        return original(row)

    monkeypatch.setattr(store, "_item", counted)
    assert store.snapshot(limit=5, offset=400).stats["total"] == 1000
    assert len(read) == 5


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_claim_limit_does_not_change_storage(tmp_path, limit):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions())
    with pytest.raises(ModerationError):
        store.claim("alice", limit)
    assert store.stats()["states"]["pending"] == 3


def test_release_and_resolve_share_queue_rules(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions())
    with pytest.raises(ModerationError):
        store.release("r0")
    claimed = store.claim("alice")[0]
    store.release(claimed.review_id)
    assert store.get(claimed.review_id).state is QueueState.PENDING
    store.resolve("r0", "alice", "unclear")
    assert store.stats()["overturn_rate"] is None
    with pytest.raises(ModerationError):
        store.resolve("r0", "bob", "upheld")
    with pytest.raises(ModerationError):
        store.resolve("absent", "alice", "upheld")
    assert store.get("absent") is None


def test_truncation_is_detected_and_cannot_be_laundered_by_enqueue(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions())
    with store.transaction(write=True) as connection:
        connection.execute("DELETE FROM audit_records WHERE sequence = 3")
    status = store.verify()
    assert not status.valid and "truncated" in status.reason
    with pytest.raises(AuditLogError, match="does not match its anchor"):
        store.enqueue([replace(decisions(1)[0], review_id="new")])
    assert store.get("new") is None
    assert store.read_anchor().records == 3


def test_editing_a_record_breaks_the_chain(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions())
    with store.transaction(write=True) as connection:
        payload = json.loads(connection.execute(
            "SELECT record FROM audit_records WHERE sequence = 1"
        ).fetchone()[0])
        payload["decision"]["score"] = 0
        connection.execute(
            "UPDATE audit_records SET record = ? WHERE sequence = 1",
            (json.dumps(payload),),
        )
    status = store.verify()
    assert not status.valid and status.broken_at == 1


def test_replay_accepts_sqlite_history(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    reviews = [{
        "review_id": "r1", "author": "alice", "rating": 4,
        "text": "An ordinary product with a durable case and a useful handle.",
    }]
    store.enqueue(moderate_batch(reviews).decisions)
    assert replay(store, reviews) == []


def test_lock_contention_is_a_retryable_storage_error(tmp_path):
    store = SQLiteStore(tmp_path / "db", timeout=0.01)
    with store.transaction(write=True):
        with pytest.raises(StorageBusyError):
            store.enqueue(decisions())
    assert store.enqueue(decisions()) == 3


def test_opening_missing_history_does_not_create_a_database(tmp_path):
    path = tmp_path / "absent.sqlite3"
    with pytest.raises(StorageError):
        SQLiteStore(path, create=False)
    assert not path.exists()


def test_deleting_an_open_database_never_silently_reinitializes_it(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions())
    store.path.unlink()
    with pytest.raises(StorageError):
        store.stats()
    assert not store.path.exists()


def test_future_schema_is_refused(tmp_path):
    path = tmp_path / "db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 99")
    with pytest.raises(StorageError, match="unsupported"):
        SQLiteStore(path)


def test_missing_anchor_is_not_recreated_on_startup(tmp_path):
    path = tmp_path / "db"
    store = SQLiteStore(path)
    store.enqueue(decisions())
    with store.transaction(write=True) as connection:
        connection.execute("DELETE FROM audit_head")
    with pytest.raises(AuditLogError, match="missing"):
        SQLiteStore(path)


def test_read_snapshot_does_not_block_a_writer(tmp_path):
    store = SQLiteStore(tmp_path / "db")
    store.enqueue(decisions(1))
    with store.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM queue_items").fetchone()[0] == 1
        store.enqueue([replace(decisions(1)[0], review_id="later")])
        assert connection.execute("SELECT COUNT(*) FROM queue_items").fetchone()[0] == 1
    assert len(store) == 2
