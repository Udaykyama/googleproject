"""Tests for the evaluation harness.

These check the maths and the loader. The measured numbers themselves live in
``README.md``; asserting exact scores here would make the tests a change
detector rather than a correctness check.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.evaluation import (  # noqa: E402
    LabelledReview,
    Metrics,
    evaluate,
    load_labelled,
    threshold_sweep,
)
from fake_review_detector.models import Review  # noqa: E402
from fake_review_detector.policy import Policy  # noqa: E402

DATA = Path(__file__).resolve().parents[1] / "data" / "labelled_reviews.json"


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=4,
        text="A perfectly ordinary review of a perfectly ordinary product.",
        verified_purchase=True,
        account_age_days=500,
        date="2024-05-01",
        is_fake=False,
    )
    base.update(overrides)
    return base


def test_metrics_arithmetic():
    metrics = Metrics(true_positives=8, false_positives=2, true_negatives=85, false_negatives=5, threshold=30)
    assert metrics.precision == pytest.approx(0.8)
    assert metrics.recall == pytest.approx(8 / 13)
    assert metrics.false_positive_rate == pytest.approx(2 / 87)
    assert metrics.accuracy == pytest.approx(93 / 100)
    assert metrics.f1 == pytest.approx(2 * 0.8 * (8 / 13) / (0.8 + 8 / 13))


def test_metrics_handle_empty_denominators():
    empty = Metrics(0, 0, 0, 0, threshold=30)
    assert empty.precision == 0.0
    assert empty.recall == 0.0
    assert empty.f1 == 0.0
    assert empty.false_positive_rate == 0.0
    assert empty.accuracy == 0.0


def test_metrics_serialise():
    json.dumps(Metrics(1, 2, 3, 4, threshold=30).to_dict())
    assert "precision" in Metrics(1, 2, 3, 4, threshold=30).format_table()


def test_load_labelled_strips_the_label():
    labelled, errors = load_labelled([payload(review_id="a", is_fake=True)])
    assert errors == []
    assert labelled[0].is_fake is True
    assert isinstance(labelled[0].review, Review)


def test_missing_label_is_an_error():
    payload_without_label = payload()
    payload_without_label.pop("is_fake")
    labelled, errors = load_labelled([payload_without_label])
    assert labelled == []
    assert any(e.field == "is_fake" for e in errors)


def test_non_boolean_label_is_an_error():
    labelled, errors = load_labelled([payload(is_fake="yes")])
    assert labelled == []
    assert errors


def test_invalid_review_is_skipped_not_fatal():
    labelled, errors = load_labelled(
        [payload(review_id="good"), payload(review_id="bad", rating=99)]
    )
    assert [item.review.review_id for item in labelled] == ["good"]
    assert len(errors) == 1


def test_labels_stay_attached_when_rows_are_dropped():
    # A dropped invalid row must not shift labels onto the wrong reviews.
    labelled, _ = load_labelled(
        [
            payload(review_id="a", is_fake=False),
            payload(review_id="bad", rating=99, is_fake=True),
            payload(review_id="c", is_fake=True),
        ]
    )
    assert {item.review.review_id: item.is_fake for item in labelled} == {"a": False, "c": True}


def test_perfect_separation_scores_perfectly():
    labelled = [
        LabelledReview(
            review=Review(review_id="fake", author="bot", rating=5, text="Best product ever!!!",
                          verified_purchase=False, account_age_days=1),
            is_fake=True,
        ),
        LabelledReview(
            review=Review(review_id="real", author="human", rating=4,
                          text="A thorough and specific account of using this for a month.",
                          verified_purchase=True, account_age_days=900),
            is_fake=False,
        ),
    ]
    metrics = evaluate(labelled)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.false_positive_rate == 0.0


def test_threshold_moves_the_operating_point():
    labelled, _ = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    permissive = evaluate(labelled, threshold=0)
    strict = evaluate(labelled, threshold=100)
    # Flagging everything catches everything, at maximum collateral damage.
    assert permissive.recall == 1.0
    assert permissive.false_positive_rate > strict.false_positive_rate
    assert strict.precision >= permissive.precision


def test_threshold_defaults_to_the_policy():
    labelled, _ = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    assert evaluate(labelled).threshold == Policy().medium_threshold
    assert evaluate(labelled, Policy(medium_threshold=45)).threshold == 45


def test_sweep_covers_the_range_and_is_monotonic_in_recall():
    labelled, _ = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    rows = threshold_sweep(labelled, step=10)
    assert [m.threshold for m in rows] == list(range(0, 101, 10))
    recalls = [m.recall for m in rows]
    # Raising the bar can only ever catch fewer items.
    assert recalls == sorted(recalls, reverse=True)


def test_sweep_agrees_with_single_evaluation():
    labelled, _ = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    row = next(m for m in threshold_sweep(labelled, step=10) if m.threshold == 30)
    assert row.to_dict() == evaluate(labelled, threshold=30).to_dict()


def test_sweep_rejects_a_zero_step():
    with pytest.raises(ValueError):
        threshold_sweep([], step=0)


def test_bundled_dataset_loads_cleanly():
    labelled, errors = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    assert errors == []
    assert len(labelled) > 30
    assert any(item.is_fake for item in labelled)
    assert any(not item.is_fake for item in labelled)


def test_bundled_dataset_contains_hard_negatives():
    # Without genuine reviews that trip the heuristics, the measured precision
    # would be meaningless.
    labelled, _ = load_labelled(json.loads(DATA.read_text(encoding="utf-8")))
    metrics = evaluate(labelled)
    assert metrics.false_positives > 0, "dataset is too easy to be informative"
    assert metrics.precision < 1.0
