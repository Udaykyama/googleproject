"""Regression tests for the specific gaps that made this a demo, not a system.

Each test here corresponds to a failure measured against the original
implementation. They exist so the fixes cannot quietly regress.
"""

import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import fake_review_detector as package  # noqa: E402
from fake_review_detector.dedupe import find_duplicates  # noqa: E402
from fake_review_detector.detector import (  # noqa: E402
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    Review,
    ReviewScore,
    score_review,
    score_reviews,
)
from fake_review_detector.engine import moderate, moderate_batch  # noqa: E402
from fake_review_detector.errors import ValidationError  # noqa: E402
from fake_review_detector.models import Action  # noqa: E402


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=5,
        text="A perfectly ordinary review of a perfectly ordinary product.",
        verified_purchase=True,
        account_age_days=500,
        date="2024-05-01",
    )
    base.update(overrides)
    return base


# --- the original API keeps working ------------------------------------


def test_legacy_names_are_still_importable():
    assert Review and ReviewScore and score_review and score_reviews
    assert (RISK_HIGH, RISK_MEDIUM, RISK_LOW) == ("high", "medium", "low")


def test_legacy_score_review_signature():
    score, reasons = score_review(Review(**payload()))
    assert isinstance(score, int) and isinstance(reasons, list)
    assert score == 0 and reasons == []


def test_legacy_score_reviews_returns_sorted_review_scores():
    scores = score_reviews(
        [
            Review(**payload(review_id="clean")),
            Review(**payload(review_id="fake", text="Best product ever!!!",
                             verified_purchase=False, account_age_days=1)),
        ]
    )
    assert [s.review_id for s in scores] == ["fake", "clean"]
    assert scores[0].score >= scores[1].score
    assert scores[0].risk_level in (RISK_HIGH, RISK_MEDIUM)


def test_risk_level_still_compares_as_a_string():
    scores = score_reviews([Review(**payload())])
    assert scores[0].risk_level == "low"


def test_package_exports_the_documented_surface():
    for name in (
        "moderate", "moderate_batch", "Policy", "ReviewQueue", "AuditLog",
        "evaluate", "threshold_sweep", "score_review", "score_reviews",
        "Review", "ReviewScore", "Action", "RiskLevel", "ValidationError",
    ):
        assert hasattr(package, name), name


# --- gap 1: phrase matching was trivially evaded ------------------------


@pytest.mark.parametrize(
    "text",
    [
        "Bеst prоduct еver",  # Cyrillic homoglyphs
        "Ｂｅｓｔ ｐｒｏｄｕｃｔ ｅｖｅｒ",  # fullwidth forms
        "Best pro\u200bduct ever",  # zero-width space
        "Best prodddduct everrr",  # character stretching
        "Best  product   ever",  # repeated spaces
        "B-e-s-t p-r-o-d-u-c-t e-v-e-r",  # letter spacing
    ],
)
def test_known_evasions_are_caught(text):
    _, reasons = score_review(Review(**payload(text=text)))
    assert any("generic" in reason for reason in reasons), text


def test_non_english_reviews_are_not_penalised_for_their_script():
    # The evasion fix must not turn into a tax on writing in another language.
    for text in (
        "Отличный товар, доставка заняла три дня, качество хорошее",
        "この製品は思ったより小さいですが、品質は良いです",
        "منتج جيد جدا ولكن الشحن تأخر أسبوعين",
    ):
        decision = moderate(payload(rating=4, text=text))
        assert decision.action is Action.ALLOW, text


def test_distinct_non_latin_reviews_are_not_duplicates_of_each_other():
    result = moderate_batch(
        [
            payload(review_id="a", rating=4, text="Отличный товар, рекомендую всем"),
            payload(review_id="b", rating=4, text="Плохой продукт, не советую никому"),
            payload(review_id="c", rating=4, text="この製品は良いです、また買います"),
        ]
    )
    for decision in result.decisions:
        assert "NEAR_DUPLICATE_TEXT" not in decision.codes


# --- gap 2: batch scoring was quadratic ---------------------------------


def test_large_batches_stay_fast():
    # The original took ~104s for 800 reviews and grew 4x per doubling,
    # extrapolating to roughly 19 days for 100k reviews.
    rnd = random.Random(7)
    words = "battery bracket washer manual firmware screen cable hinge latch grip".split()
    reviews = [
        Review(review_id=f"r{i}", author=f"a{i}", rating=4,
               text=" ".join(rnd.choice(words) for _ in range(12)) + f" unit {i}.")
        for i in range(2000)
    ]
    started = time.perf_counter()
    find_duplicates(reviews, exact_max_batch=200)
    elapsed = time.perf_counter() - started
    assert elapsed < 30, f"2000 distinct reviews took {elapsed:.1f}s"


def test_review_bomb_is_bounded_and_still_detected():
    """A bomb of near-identical reviews contains a quadratic number of true
    duplicate pairs, so enumerating them all is inherently quadratic. The
    partner cap bounds the work while still flagging the reviews."""
    reviews = [
        Review(review_id=f"r{i}", author=f"a{i}", rating=4,
               text=f"Review number {i} discussing battery life and build quality in detail.")
        for i in range(2000)
    ]
    started = time.perf_counter()
    report = find_duplicates(reviews, exact_max_batch=200)
    elapsed = time.perf_counter() - started

    assert elapsed < 30, f"2000 near-identical reviews took {elapsed:.1f}s"
    # Detection is what matters, not the exhaustive pair list.
    assert len(report.ids()) > 1900
    assert report.truncated is True
    # No review keeps an unbounded partner list.
    assert all(len(report.partners(f"r{i}")) <= 25 for i in range(0, 2000, 97))


def test_blocking_does_not_lose_duplicates():
    # Background texts are distinct, so the planted pair is the only true
    # duplicate and blocking recall is measured without the confound of a
    # corpus that is already dense with mutual duplicates.
    rnd = random.Random(11)
    words = "battery bracket washer manual firmware screen cable hinge latch grip".split()
    reviews = [
        Review(review_id=f"r{i}", author=f"a{i}", rating=4,
               text=" ".join(rnd.choice(words) for _ in range(14)) + f" unit {i}.")
        for i in range(300)
    ]
    reviews.append(Review(review_id="copy", author="z", rating=4, text=reviews[7].text))
    pairs = {
        tuple(sorted((p.left_id, p.right_id)))
        for p in find_duplicates(reviews, exact_max_batch=1).pairs
    }
    assert ("copy", "r7") in pairs


def test_dense_cluster_flags_every_member_even_when_pairs_are_capped():
    """In a dense cluster the partner cap makes the recorded pair list
    incomplete, but membership of the cluster is still reported."""
    reviews = [
        Review(review_id=f"r{i}", author=f"a{i}", rating=4,
               text=f"Review number {i} discussing battery life and build quality in detail.")
        for i in range(300)
    ]
    reviews.append(Review(review_id="copy", author="z", rating=4, text=reviews[7].text))
    report = find_duplicates(reviews, exact_max_batch=1)
    assert "copy" in report.ids()
    assert report.partners("copy")


# --- gap 3: input was never validated -----------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        {"rating": "5"},        # accepted as a string before
        {"rating": 99},         # out of range
        {"account_age_days": -5},  # negative age
        {"text": None},         # raised a bare AttributeError before
    ],
)
def test_previously_accepted_bad_input_is_now_rejected(bad):
    with pytest.raises(ValidationError):
        moderate(payload(**bad))


def test_one_bad_item_no_longer_takes_down_the_batch():
    result = moderate_batch(
        [payload(review_id="a"), payload(review_id="b", text=None), payload(review_id="c")]
    )
    assert {d.review_id for d in result.decisions} == {"a", "c"}
    assert result.rejected == 1


# --- gap 4: there was no enforcement, audit or measurement --------------


def test_every_decision_carries_provenance_and_evidence():
    decision = moderate(
        payload(text="Best product ever!!!", verified_purchase=False, account_age_days=1)
    )
    assert decision.policy_version and decision.policy_digest
    assert decision.content_digest and decision.decided_at
    for signal in decision.signals:
        assert signal.code and signal.message
    assert decision.appealable


def test_default_configuration_never_removes_content():
    for text in ("Best product ever!!!", "DON'T WASTE YOUR MONEY!!!", "FIVE STARS!!!"):
        decision = moderate(
            payload(text=text, verified_purchase=False, account_age_days=0)
        )
        assert decision.action is Action.ENQUEUE
        assert decision.requires_human_review
