import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.detector import (  # noqa: E402
    Review,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    score_review,
    score_reviews,
)


def make_review(**overrides):
    defaults = dict(
        review_id="r1",
        author="someone",
        rating=5,
        text="This is a genuinely useful product that solved my problem well.",
        verified_purchase=True,
        account_age_days=500,
        date="2024-01-01",
    )
    defaults.update(overrides)
    return Review(**defaults)


def test_genuine_review_scores_low():
    review = make_review()
    score, reasons = score_review(review)
    assert score < 30
    assert reasons == []


def test_generic_phrase_detected():
    review = make_review(text="Best product ever! Highly recommend to everyone.")
    score, reasons = score_review(review)
    assert score > 0
    assert any("generic" in r for r in reasons)


def test_extreme_rating_with_short_text_flagged():
    review = make_review(rating=1, text="Bad.")
    score, reasons = score_review(review)
    assert any("low-effort" in r for r in reasons)


def test_unverified_purchase_flagged():
    review = make_review(verified_purchase=False)
    score, reasons = score_review(review)
    assert any("unverified purchase" in r for r in reasons)


def test_new_account_flagged():
    review = make_review(account_age_days=1)
    score, reasons = score_review(review)
    assert any("account created only 1 day" in r for r in reasons)


def test_shouty_text_flagged():
    review = make_review(text="AMAZING!!! WILL BUY AGAIN!!!")
    score, reasons = score_review(review)
    assert any("CAPS" in r for r in reasons)


def test_duplicate_reviews_flagged_in_batch():
    reviews = [
        make_review(review_id="r1", author="a1", text="Best product ever! Highly recommend!"),
        make_review(review_id="r2", author="a2", text="Best product ever! Highly recommend!"),
        make_review(
            review_id="r3",
            author="a3",
            text="Solid, well-made item that has held up fine for daily use over several months.",
        ),
    ]
    scores = {s.review_id: s for s in score_reviews(reviews)}
    assert any("near-duplicate" in reason for reason in scores["r1"].reasons)
    assert any("near-duplicate" in reason for reason in scores["r2"].reasons)
    assert not any("near-duplicate" in reason for reason in scores["r3"].reasons)


def test_review_burst_flagged():
    reviews = [
        make_review(review_id=f"r{i}", author="burst_author", date="2024-01-01", text=f"Item {i} works fine for daily use over time.")
        for i in range(3)
    ]
    scores = {s.review_id: s for s in score_reviews(reviews)}
    for review_id in ("r0", "r1", "r2"):
        assert any("burst" in reason for reason in scores[review_id].reasons)


def test_risk_levels_are_ordered_high_to_low():
    reviews = [
        make_review(
            review_id="fake",
            author="bot",
            rating=5,
            text="Best product ever!!! Highly recommend!!!",
            verified_purchase=False,
            account_age_days=1,
        ),
        make_review(review_id="genuine"),
    ]
    scores = score_reviews(reviews)
    assert scores[0].review_id == "fake"
    assert scores[0].score >= scores[1].score
    assert scores[0].risk_level in (RISK_HIGH, RISK_MEDIUM)
    assert scores[1].risk_level in (RISK_LOW, RISK_MEDIUM)
