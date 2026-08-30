"""Tests for the human review queue."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.engine import moderate_batch  # noqa: E402
from fake_review_detector.errors import ModerationError  # noqa: E402
from fake_review_detector.queue import (  # noqa: E402
    Outcome,
    QueueState,
    ReviewQueue,
)


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=5,
        text="Best product ever!!!",
        verified_purchase=False,
        account_age_days=1,
        date="2024-05-01",
    )
    base.update(overrides)
    return base


def flagged(count=3):
    items = [payload(review_id=f"f{i}", author=f"a{i}") for i in range(count)]
    return moderate_batch(items).decisions


def test_only_items_needing_review_are_queued(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    decisions = moderate_batch(
        [
            payload(review_id="fake"),
            payload(review_id="clean", rating=4, text="A calm, ordinary and quite detailed review.",
                    verified_purchase=True, account_age_days=900),
        ]
    ).decisions
    assert queue.enqueue(decisions) == 1
    assert [i.review_id for i in queue.pending()] == ["fake"]


def test_enqueue_is_idempotent(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    decisions = flagged()
    assert queue.enqueue(decisions) == 3
    assert queue.enqueue(decisions) == 0
    assert len(queue) == 3


def test_pending_is_ordered_by_priority(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(
        moderate_batch(
            [
                payload(review_id="low", rating=5, text="Fine.", verified_purchase=True,
                        account_age_days=900),
                payload(review_id="high"),
            ]
        ).decisions
    )
    ordered = [i.review_id for i in queue.pending()]
    assert ordered[0] == "high"


def test_claim_marks_items_and_records_the_moderator(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    claimed = queue.claim("alice", limit=2)
    assert len(claimed) == 2
    for item in claimed:
        assert item.state is QueueState.CLAIMED
        assert item.claimed_by == "alice"
        assert item.claimed_at
    assert len(queue.pending()) == 1


def test_claim_does_not_return_already_claimed_items(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    first = {i.review_id for i in queue.claim("alice", limit=2)}
    second = {i.review_id for i in queue.claim("bob", limit=2)}
    assert first & second == set()


def test_claim_requires_a_moderator(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    with pytest.raises(ModerationError):
        queue.claim("")


def test_release_returns_an_item_to_the_pool(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    claimed = queue.claim("alice")[0]
    queue.release(claimed.review_id)
    assert claimed.state is QueueState.PENDING
    assert claimed.claimed_by is None


def test_release_rejects_unclaimed_items(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    with pytest.raises(ModerationError):
        queue.release("f0")


def test_resolve_records_the_verdict(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    item = queue.resolve("f0", "alice", Outcome.UPHELD, note="clear template farm")
    assert item.state is QueueState.RESOLVED
    assert item.outcome is Outcome.UPHELD
    assert item.resolved_by == "alice"
    assert item.note == "clear template farm"


def test_resolve_accepts_a_string_outcome(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    assert queue.resolve("f0", "alice", "overturned").outcome is Outcome.OVERTURNED


def test_resolve_rejects_unknown_outcomes(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    with pytest.raises(ModerationError):
        queue.resolve("f0", "alice", "maybe")


def test_resolve_rejects_unknown_ids_and_double_resolution(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    with pytest.raises(ModerationError):
        queue.resolve("absent", "alice", Outcome.UPHELD)
    queue.resolve("f0", "alice", Outcome.UPHELD)
    with pytest.raises(ModerationError):
        queue.resolve("f0", "alice", Outcome.UPHELD)


def test_resolve_requires_a_moderator(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    with pytest.raises(ModerationError):
        queue.resolve("f0", "", Outcome.UPHELD)


def test_overturn_rate_measures_false_positives(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged(4))
    queue.resolve("f0", "alice", Outcome.UPHELD)
    queue.resolve("f1", "alice", Outcome.UPHELD)
    queue.resolve("f2", "alice", Outcome.OVERTURNED)
    # 'unclear' is deliberately excluded from the denominator.
    queue.resolve("f3", "alice", Outcome.UNCLEAR)
    assert queue.stats()["overturn_rate"] == pytest.approx(1 / 3, abs=1e-4)


def test_overturn_rate_is_none_before_any_verdict(tmp_path):
    queue = ReviewQueue(tmp_path / "q.json")
    queue.enqueue(flagged())
    assert queue.stats()["overturn_rate"] is None


def test_state_survives_a_save_and_reload(tmp_path):
    path = tmp_path / "q.json"
    queue = ReviewQueue(path)
    queue.enqueue(flagged())
    queue.claim("alice", limit=1)
    queue.resolve("f1", "bob", Outcome.OVERTURNED, note="genuine customer")
    queue.save()

    reloaded = ReviewQueue(path)
    assert len(reloaded) == 3
    resolved = reloaded.get("f1")
    assert resolved.outcome is Outcome.OVERTURNED
    assert resolved.resolved_by == "bob"
    assert resolved.note == "genuine customer"
    assert reloaded.get("f0").state is QueueState.CLAIMED


def test_signals_survive_the_round_trip(tmp_path):
    path = tmp_path / "q.json"
    queue = ReviewQueue(path)
    queue.enqueue(flagged(1))
    queue.save()
    original = queue.get("f0").decision
    restored = ReviewQueue(path).get("f0").decision
    assert restored.codes == original.codes
    assert restored.policy_digest == original.policy_digest
    assert restored.content_digest == original.content_digest


def test_corrupt_queue_file_is_reported(tmp_path):
    path = tmp_path / "q.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ModerationError):
        ReviewQueue(path)


def test_missing_queue_file_starts_empty(tmp_path):
    assert len(ReviewQueue(tmp_path / "absent.json")) == 0


def test_save_creates_missing_directories(tmp_path):
    queue = ReviewQueue(tmp_path / "nested" / "q.json")
    queue.enqueue(flagged(1))
    queue.save()
    assert (tmp_path / "nested" / "q.json").exists()
