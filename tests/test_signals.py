"""Tests for detection signals and their evidence."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.models import Review  # noqa: E402
from fake_review_detector.policy import Policy  # noqa: E402
from fake_review_detector.signals import (  # noqa: E402
    evaluate_review,
    is_generic,
    is_shouty,
    matched_phrases,
)


def review(**overrides):
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
    return Review(**base)


def codes(hits):
    return {hit.code for hit in hits}


def test_plain_generic_phrase_detected():
    assert is_generic("This is the best product ever, truly")


def test_every_known_evasion_is_detected():
    for text in (
        "Bеst prоduct еver",
        "Ｂｅｓｔ ｐｒｏｄｕｃｔ ｅｖｅｒ",
        "Best pro\u200bduct ever",
        "Best prodddduct everrr",
        "B-e-s-t product ever",
        "BEST PRODUCT EVER",
    ):
        assert is_generic(text), text


def test_ordinary_reviews_are_not_generic():
    for text in (
        "The battery lasted about six hours in my testing.",
        "I recommend reading the manual before assembly.",
        "Отличный товар, доставка быстрая",
        "この製品は良いです",
    ):
        assert not is_generic(text), text


def test_matched_phrases_are_reported_as_evidence():
    hits = evaluate_review(review(text="Best product ever! Highly recommend!"), Policy())
    generic = next(h for h in hits if h.code == "GENERIC_PHRASE")
    assert "best product ever" in generic.evidence["phrases"]
    assert "highly recommend" in generic.evidence["phrases"]


def test_shouty_detects_exclamations_and_caps():
    assert is_shouty("WOW!!! AMAZING!!!")[0]
    assert is_shouty("THIS IS ENTIRELY CAPITALISED TEXT")[0]
    assert not is_shouty("A calm and measured review.")[0]
    assert not is_shouty("")[0]


def test_shouty_evidence_includes_the_counts_used():
    _, evidence = is_shouty("WOW!!!")
    assert evidence["exclamation_count"] == 3
    assert evidence["caps_ratio"] == 1.0


def test_low_effort_extreme_rating():
    assert "LOW_EFFORT_EXTREME_RATING" in codes(evaluate_review(review(rating=1, text="Bad."), Policy()))
    assert "LOW_EFFORT_EXTREME_RATING" in codes(evaluate_review(review(rating=5, text="Great."), Policy()))
    # A three-star rating is not extreme, however short.
    assert "LOW_EFFORT_EXTREME_RATING" not in codes(evaluate_review(review(rating=3, text="Fine."), Policy()))


def test_long_extreme_rating_is_not_low_effort():
    text = "I have used this every day for a year and it still works perfectly well."
    assert "LOW_EFFORT_EXTREME_RATING" not in codes(evaluate_review(review(rating=5, text=text), Policy()))


def test_unverified_and_new_account_signals():
    hits = evaluate_review(review(verified_purchase=False, account_age_days=1), Policy())
    assert {"UNVERIFIED_PURCHASE", "NEW_ACCOUNT"} <= codes(hits)
    new_account = next(h for h in hits if h.code == "NEW_ACCOUNT")
    assert new_account.evidence["account_age_days"] == 1
    assert "1 day" in new_account.message


def test_unknown_account_age_does_not_fire():
    assert "NEW_ACCOUNT" not in codes(evaluate_review(review(account_age_days=None), Policy()))


def test_mixed_script_signal_fires_on_evasion_only():
    assert "MIXED_SCRIPT_TEXT" in codes(evaluate_review(review(text="Bеst prоduct"), Policy()))
    # Genuine non-English writing must not be penalised.
    assert "MIXED_SCRIPT_TEXT" not in codes(
        evaluate_review(review(text="Отличный товар, рекомендую"), Policy())
    )


def test_clean_review_produces_no_signals():
    assert evaluate_review(review(), Policy()) == []


def test_zero_weight_suppresses_a_signal():
    policy = Policy(weights={"SHOUTY_TEXT": 0})
    assert "SHOUTY_TEXT" not in codes(evaluate_review(review(text="WOW!!! AMAZING!!!"), policy))


def test_policy_controls_signal_thresholds():
    lenient = Policy(new_account_days=0)
    assert "NEW_ACCOUNT" not in codes(evaluate_review(review(account_age_days=2), lenient))
    strict = Policy(new_account_days=30)
    assert "NEW_ACCOUNT" in codes(evaluate_review(review(account_age_days=2), strict))


def test_signal_weights_come_from_the_policy():
    policy = Policy(weights={"UNVERIFIED_PURCHASE": 7})
    hits = evaluate_review(review(verified_purchase=False), policy)
    assert next(h for h in hits if h.code == "UNVERIFIED_PURCHASE").weight == 7


def test_phrase_evidence_is_json_safe():
    import json

    for hit in evaluate_review(review(text="Best product ever!!!", rating=5), Policy()):
        json.dumps(hit.to_dict())
