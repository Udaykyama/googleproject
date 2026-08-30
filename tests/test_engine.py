"""Tests for the moderation engine and its enforcement decisions."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.engine import (  # noqa: E402
    moderate,
    moderate_batch,
    score_batch,
)
from fake_review_detector.models import Action, Review, RiskLevel  # noqa: E402
from fake_review_detector.policy import Policy  # noqa: E402


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=4,
        text="A perfectly ordinary review of a perfectly ordinary product.",
        verified_purchase=True,
        account_age_days=500,
        date="2024-05-01",
    )
    base.update(overrides)
    return base


def test_clean_review_is_allowed():
    decision = moderate(payload())
    assert decision.action is Action.ALLOW
    assert decision.risk_level is RiskLevel.LOW
    assert decision.score == 0


def test_obvious_fake_goes_to_human_review():
    decision = moderate(
        payload(rating=5, text="Best product ever!!!", verified_purchase=False, account_age_days=1)
    )
    assert decision.action is Action.ENQUEUE
    assert decision.risk_level is RiskLevel.HIGH
    assert decision.requires_human_review


def test_heuristics_alone_never_remove_content():
    # The single most important safety property: a false positive here would
    # delete a real person's writing.
    for score_payload in (
        payload(rating=5, text="Best product ever!!!", verified_purchase=False, account_age_days=0),
        payload(rating=1, text="DON'T WASTE YOUR MONEY!!!", verified_purchase=False, account_age_days=0),
    ):
        assert moderate(score_payload).action is not Action.REMOVE


def test_removal_requires_explicit_configuration():
    policy = Policy(
        allow_auto_removal=True,
        actions={"low": "allow", "medium": "enqueue", "high": "remove"},
        auto_removal_threshold=60,
    )
    decision = moderate(
        payload(rating=5, text="Best product ever!!!", verified_purchase=False, account_age_days=1),
        policy,
    )
    assert decision.action is Action.REMOVE


def test_invalid_items_do_not_abort_the_batch():
    result = moderate_batch([payload(review_id="good"), payload(review_id="bad", rating=99)])
    assert result.accepted == 1
    assert result.rejected == 1
    assert result.decisions[0].review_id == "good"


def test_batch_records_policy_provenance():
    policy = Policy()
    result = moderate_batch([payload()], policy)
    assert result.policy_version == policy.version
    assert result.policy_digest == policy.digest()
    assert result.decisions[0].policy_digest == policy.digest()


def test_decision_records_content_digest():
    decision = moderate(payload())
    assert decision.content_digest == moderate(payload()).content_digest
    assert decision.content_digest != moderate(payload(text="Different text entirely.")).content_digest


def test_duplicate_detection_is_a_batch_signal():
    result = moderate_batch(
        [
            payload(review_id="a", author="x", text="Identical wording in both of these reviews"),
            payload(review_id="b", author="y", text="Identical wording in both of these reviews"),
            payload(review_id="c", author="z", text="A totally different observation about shipping"),
        ]
    )
    by_id = {d.review_id: d for d in result.decisions}
    assert "NEAR_DUPLICATE_TEXT" in by_id["a"].codes
    assert "NEAR_DUPLICATE_TEXT" in by_id["b"].codes
    assert "NEAR_DUPLICATE_TEXT" not in by_id["c"].codes


def test_duplicate_evidence_names_the_other_review():
    result = moderate_batch(
        [
            payload(review_id="a", author="x", text="Identical wording in both of these reviews"),
            payload(review_id="b", author="y", text="Identical wording in both of these reviews"),
        ]
    )
    decision = next(d for d in result.decisions if d.review_id == "a")
    signal = next(s for s in decision.signals if s.code == "NEAR_DUPLICATE_TEXT")
    assert signal.evidence["matches"][0]["review_id"] == "b"


def test_same_author_duplicate_scores_higher_than_cross_author():
    same = moderate_batch(
        [
            payload(review_id="a", author="one", text="Identical wording in both of these reviews"),
            payload(review_id="b", author="one", text="Identical wording in both of these reviews"),
        ]
    )
    cross = moderate_batch(
        [
            payload(review_id="a", author="one", text="Identical wording in both of these reviews"),
            payload(review_id="b", author="two", text="Identical wording in both of these reviews"),
        ]
    )
    assert "REPEATED_AUTHOR_TEMPLATE" in same.decisions[0].codes
    assert "REPEATED_AUTHOR_TEMPLATE" not in cross.decisions[0].codes
    assert same.decisions[0].score > cross.decisions[0].score


def test_author_burst_detected():
    result = moderate_batch(
        [
            payload(review_id=f"r{i}", author="prolific", date="2024-05-01",
                    text=f"Observation number {i} about a different aspect of the item.")
            for i in range(3)
        ]
    )
    for decision in result.decisions:
        assert "AUTHOR_BURST" in decision.codes


def test_burst_needs_the_same_day():
    result = moderate_batch(
        [
            payload(review_id=f"r{i}", author="prolific", date=f"2024-05-0{i + 1}",
                    text=f"Observation number {i} about a different aspect of the item.")
            for i in range(3)
        ]
    )
    for decision in result.decisions:
        assert "AUTHOR_BURST" not in decision.codes


def test_results_are_ordered_by_score():
    result = moderate_batch(
        [
            payload(review_id="clean"),
            payload(review_id="fake", rating=5, text="Best product ever!!!",
                    verified_purchase=False, account_age_days=1),
        ]
    )
    assert [d.review_id for d in result.decisions] == ["fake", "clean"]


def test_score_is_clamped_to_one_hundred():
    decision = moderate(
        payload(rating=5, text="Best product ever!!! Highly recommend!!!",
                verified_purchase=False, account_age_days=0)
    )
    assert decision.score == 100


def test_batch_summary_counts_actions():
    result = moderate_batch(
        [
            payload(review_id="clean"),
            payload(review_id="fake", rating=5, text="Best product ever!!!",
                    verified_purchase=False, account_age_days=1),
        ]
    )
    assert result.by_action() == {"allow": 1, "monitor": 0, "enqueue": 1, "remove": 0}
    assert [d.review_id for d in result.needing_review()] == ["fake"]


def test_batch_result_is_json_serialisable():
    result = moderate_batch([payload(review_id="a"), payload(review_id="b", rating=99)])
    json.dumps(result.to_dict())


def test_empty_batch():
    result = moderate_batch([])
    assert result.accepted == 0 and result.rejected == 0


def test_score_batch_accepts_validated_reviews():
    scores, report = score_batch([Review(**payload())])
    assert scores[0].score == 0
    assert report.pairs == ()


def test_reasons_and_codes_stay_in_step():
    decision = moderate(
        payload(rating=5, text="Best product ever!!!", verified_purchase=False, account_age_days=1)
    )
    assert len(decision.reasons) == len(decision.codes) == len(decision.signals)


def test_batch_is_deterministic():
    items = [payload(review_id=f"r{i}", text=f"Review number {i} with some ordinary text.") for i in range(20)]
    first = moderate_batch(items).to_dict()
    second = moderate_batch(items).to_dict()
    for decisions in (first["decisions"], second["decisions"]):
        for decision in decisions:
            decision.pop("decided_at")
    assert first == second
