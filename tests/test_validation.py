"""Tests for input validation.

Each rejection here corresponds to something the original demo accepted
silently, or crashed on.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.errors import ValidationError  # noqa: E402
from fake_review_detector.models import Review  # noqa: E402
from fake_review_detector.validation import (  # noqa: E402
    MAX_TEXT_LENGTH,
    validate_batch,
    validate_review,
)


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


def test_valid_payload_round_trips():
    review = validate_review(payload())
    assert isinstance(review, Review)
    assert review.review_id == "r1"
    assert review.rating == 5


def test_accepts_a_review_object():
    review = validate_review(Review(**payload()))
    assert review.review_id == "r1"


def test_rating_must_be_an_integer():
    # The demo accepted the string "5".
    with pytest.raises(ValidationError) as exc:
        validate_review(payload(rating="5"))
    assert exc.value.field == "rating"


def test_rating_must_be_in_range():
    # The demo accepted 99.
    for bad in (0, 6, 99, -1):
        with pytest.raises(ValidationError):
            validate_review(payload(rating=bad))


def test_boolean_rating_rejected():
    # bool subclasses int, so True would otherwise pass as rating 1.
    with pytest.raises(ValidationError):
        validate_review(payload(rating=True))


def test_account_age_cannot_be_negative():
    # The demo accepted -5.
    with pytest.raises(ValidationError) as exc:
        validate_review(payload(account_age_days=-5))
    assert exc.value.field == "account_age_days"


def test_account_age_may_be_absent():
    assert validate_review(payload(account_age_days=None)).account_age_days is None


def test_absurd_account_age_rejected():
    with pytest.raises(ValidationError):
        validate_review(payload(account_age_days=10**9))


def test_missing_text_raises_validation_error_not_attribute_error():
    # The demo raised a bare AttributeError from deep inside scoring.
    with pytest.raises(ValidationError) as exc:
        validate_review(payload(text=None))
    assert exc.value.field == "text"


def test_blank_text_rejected():
    for blank in ("", "   ", "\u200b\u200b"):
        with pytest.raises(ValidationError):
            validate_review(payload(text=blank))


def test_oversized_text_rejected():
    validate_review(payload(text="x" * MAX_TEXT_LENGTH))
    with pytest.raises(ValidationError):
        validate_review(payload(text="x" * (MAX_TEXT_LENGTH + 1)))


def test_control_characters_rejected():
    with pytest.raises(ValidationError):
        validate_review(payload(text="hello\x07world"))


def test_ordinary_whitespace_allowed_in_text():
    assert validate_review(payload(text="line one\nline two"))


def test_text_is_normalized():
    review = validate_review(payload(text="  spaced   out\u200b text  "))
    assert review.text == "spaced out text"


def test_blank_identifiers_rejected():
    with pytest.raises(ValidationError):
        validate_review(payload(review_id="   "))
    with pytest.raises(ValidationError):
        validate_review(payload(author=""))


def test_verified_purchase_must_be_boolean():
    with pytest.raises(ValidationError):
        validate_review(payload(verified_purchase="yes"))


def test_invalid_date_rejected():
    with pytest.raises(ValidationError):
        validate_review(payload(date="not-a-date"))
    with pytest.raises(ValidationError):
        validate_review(payload(date="2024-13-45"))


def test_unknown_fields_rejected():
    with pytest.raises(ValidationError) as exc:
        validate_review(payload(injected_field="surprise"))
    assert "injected_field" in str(exc.value)


def test_non_mapping_input_rejected():
    with pytest.raises(ValidationError):
        validate_review("just a string")


def test_batch_collects_errors_without_aborting():
    reviews, errors = validate_batch(
        [payload(review_id="a"), payload(review_id="b", rating=99), payload(review_id="c")]
    )
    assert [r.review_id for r in reviews] == ["a", "c"]
    assert len(errors) == 1
    assert errors[0].review_id == "b"


def test_batch_rejects_duplicate_ids():
    reviews, errors = validate_batch([payload(review_id="a"), payload(review_id="a")])
    assert len(reviews) == 1
    assert any("duplicate" in str(e) for e in errors)


def test_batch_honours_max_items():
    reviews, errors = validate_batch(
        [payload(review_id=f"r{i}") for i in range(10)], max_items=4
    )
    assert len(reviews) == 4
    assert any("limit" in str(e) for e in errors)


def test_batch_rejects_non_iterable():
    with pytest.raises(ValidationError):
        validate_batch(42)


def test_batch_rejects_a_bare_string():
    # A string is iterable, and iterating it would produce nonsense errors.
    with pytest.raises(ValidationError):
        validate_batch("r1")


def test_validation_error_reports_field_and_id():
    error = ValidationError("boom", field="rating", review_id="r9")
    assert error.field == "rating"
    assert error.review_id == "r9"
    assert "r9" in str(error) and "rating" in str(error)
