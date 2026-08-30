"""Input validation.

Untrusted review payloads arrive from the network. The demo detector accepted
``rating=99``, ``account_age_days=-5`` and a string rating without complaint,
and crashed with a bare ``AttributeError`` on ``text=None`` — a malformed item
could take down a whole batch.

Everything here fails with :class:`ValidationError`, which carries the offending
field and review id so a batch can skip one bad item and keep going.
"""

from __future__ import annotations

import unicodedata

from .errors import ValidationError
from .models import Review
from .normalize import normalize_text

__all__ = [
    "MAX_TEXT_LENGTH",
    "MAX_AUTHOR_LENGTH",
    "MAX_ID_LENGTH",
    "MAX_ACCOUNT_AGE_DAYS",
    "validate_review",
    "validate_batch",
]

MAX_TEXT_LENGTH = 20_000
MAX_AUTHOR_LENGTH = 200
MAX_ID_LENGTH = 200
# ~274 years. Anything beyond this is a corrupt record, not an old account.
MAX_ACCOUNT_AGE_DAYS = 100_000
MIN_RATING = 1
MAX_RATING = 5

_REVIEW_FIELDS = {
    "review_id",
    "author",
    "rating",
    "text",
    "verified_purchase",
    "account_age_days",
    "date",
}


def _require_str(value: object, field: str, review_id: str, max_length: int) -> str:
    if value is None:
        raise ValidationError(f"{field} is required", field=field, review_id=review_id)
    if not isinstance(value, str):
        raise ValidationError(
            f"{field} must be a string, got {type(value).__name__}",
            field=field,
            review_id=review_id,
        )
    if len(value) > max_length:
        raise ValidationError(
            f"{field} exceeds the {max_length} character limit ({len(value)})",
            field=field,
            review_id=review_id,
        )
    return value


def _validate_rating(value: object, review_id: str) -> int:
    # bool is a subclass of int; True would silently become rating 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"rating must be an integer, got {type(value).__name__}",
            field="rating",
            review_id=review_id,
        )
    if not MIN_RATING <= value <= MAX_RATING:
        raise ValidationError(
            f"rating must be between {MIN_RATING} and {MAX_RATING}, got {value}",
            field="rating",
            review_id=review_id,
        )
    return value


def _validate_account_age(value: object, review_id: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(
            f"account_age_days must be an integer or null, got {type(value).__name__}",
            field="account_age_days",
            review_id=review_id,
        )
    if value < 0:
        raise ValidationError(
            f"account_age_days cannot be negative, got {value}",
            field="account_age_days",
            review_id=review_id,
        )
    if value > MAX_ACCOUNT_AGE_DAYS:
        raise ValidationError(
            f"account_age_days exceeds {MAX_ACCOUNT_AGE_DAYS}, got {value}",
            field="account_age_days",
            review_id=review_id,
        )
    return value


def _validate_date(value: object, review_id: str) -> str | None:
    if value is None:
        return None
    text = _require_str(value, "date", review_id, 64)
    # Parsed only to reject garbage; the value is stored as given.
    from datetime import date as _date

    try:
        _date.fromisoformat(text[:10])
    except ValueError as exc:
        raise ValidationError(
            f"date must be an ISO-8601 date, got {text!r}",
            field="date",
            review_id=review_id,
        ) from exc
    return text


def _reject_control_characters(text: str, review_id: str) -> None:
    """Reject C0/C1 controls other than tab, newline and carriage return.

    Control characters in stored review text corrupt terminal output for human
    moderators and can be used to hide content from them.
    """

    for ch in text:
        if unicodedata.category(ch) == "Cc" and ch not in "\t\n\r":
            raise ValidationError(
                f"text contains the control character U+{ord(ch):04X}",
                field="text",
                review_id=review_id,
            )


def validate_review(raw: Review | dict) -> Review:
    """Return a validated, normalised :class:`Review`.

    Raises :class:`ValidationError` on the first problem found.
    """

    if isinstance(raw, Review):
        payload = {
            "review_id": raw.review_id,
            "author": raw.author,
            "rating": raw.rating,
            "text": raw.text,
            "verified_purchase": raw.verified_purchase,
            "account_age_days": raw.account_age_days,
            "date": raw.date,
        }
    elif isinstance(raw, dict):
        payload = raw
    else:
        raise ValidationError(
            f"review must be a Review or dict, got {type(raw).__name__}",
            field="review",
        )

    unknown = set(payload) - _REVIEW_FIELDS
    if unknown:
        raise ValidationError(
            f"unknown field(s): {', '.join(sorted(unknown))}",
            field=sorted(unknown)[0],
            review_id=str(payload.get("review_id", "")) or None,
        )

    raw_id = payload.get("review_id")
    review_id = _require_str(raw_id, "review_id", str(raw_id or ""), MAX_ID_LENGTH).strip()
    if not review_id:
        raise ValidationError("review_id cannot be blank", field="review_id")

    author = _require_str(
        payload.get("author"), "author", review_id, MAX_AUTHOR_LENGTH
    ).strip()
    if not author:
        raise ValidationError(
            "author cannot be blank", field="author", review_id=review_id
        )

    text = _require_str(payload.get("text"), "text", review_id, MAX_TEXT_LENGTH)
    _reject_control_characters(text, review_id)
    text = normalize_text(text)
    if not text:
        raise ValidationError(
            "text cannot be blank", field="text", review_id=review_id
        )

    verified = payload.get("verified_purchase", True)
    if not isinstance(verified, bool):
        raise ValidationError(
            f"verified_purchase must be a boolean, got {type(verified).__name__}",
            field="verified_purchase",
            review_id=review_id,
        )

    return Review(
        review_id=review_id,
        author=author,
        rating=_validate_rating(payload.get("rating"), review_id),
        text=text,
        verified_purchase=verified,
        account_age_days=_validate_account_age(
            payload.get("account_age_days"), review_id
        ),
        date=_validate_date(payload.get("date"), review_id),
    )


def validate_batch(
    items: object, *, max_items: int | None = None
) -> tuple[list[Review], list[ValidationError]]:
    """Validate many reviews, collecting rather than raising per-item errors.

    One malformed submission must not discard an entire batch, so failures are
    returned alongside the reviews that passed. Duplicate ids are rejected: two
    decisions under the same id make an audit trail ambiguous.
    """

    if isinstance(items, (str, bytes)) or not hasattr(items, "__iter__"):
        raise ValidationError(
            f"batch must be an iterable of reviews, got {type(items).__name__}",
            field="batch",
        )

    valid: list[Review] = []
    errors: list[ValidationError] = []
    seen: set[str] = set()

    for index, item in enumerate(items):
        if max_items is not None and index >= max_items:
            errors.append(
                ValidationError(
                    f"batch exceeds the {max_items} item limit", field="batch"
                )
            )
            break
        try:
            review = validate_review(item)
        except ValidationError as exc:
            errors.append(exc)
            continue
        if review.review_id in seen:
            errors.append(
                ValidationError(
                    f"duplicate review_id {review.review_id!r} in batch",
                    field="review_id",
                    review_id=review.review_id,
                )
            )
            continue
        seen.add(review.review_id)
        valid.append(review)

    return valid, errors
