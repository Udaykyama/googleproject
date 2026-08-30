"""Heuristic scoring engine for detecting likely fake/policy-violating reviews.

The signals implemented here mirror the kinds of patterns real Trust &
Safety / abuse-fighting teams look for (see ../RESEARCH.md):

* generic, templated praise/complaint phrases often used by paid reviewers
* extreme ratings (1 or 5 stars) paired with very short, low-effort text
* shouty text (excessive exclamation marks / ALL CAPS)
* reviews from unverified purchases
* reviews from very new accounts
* "review bursts" -- many reviews posted by the same author on the same day
* near-duplicate text shared across multiple reviews (a sign of a
  review farm or copy/paste campaign)

This is a simplified, educational demonstration, not a production
moderation system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Iterable

# Generic phrases frequently seen in low-effort / templated fake reviews.
_GENERIC_PHRASES = [
    "best product ever",
    "highly recommend",
    "changed my life",
    "five stars",
    "great product great service",
    "will buy again",
    "amazing product amazing service",
    "worth every penny",
    "exceeded my expectations",
    "don't waste your money",
]

# A review posted within this many days of account creation is
# considered "new account" for scoring purposes.
NEW_ACCOUNT_DAYS = 3

# Reviews with fewer than this many words paired with an extreme rating
# are considered "low effort".
SHORT_REVIEW_WORD_COUNT = 6

# Near-duplicate text similarity ratio (0-1) above which two reviews are
# flagged as likely copy/paste review-farm content.
DUPLICATE_SIMILARITY_THRESHOLD = 0.85

# Number of same-day reviews from one author that counts as a "burst".
BURST_REVIEW_COUNT = 3

RISK_HIGH = "high"
RISK_MEDIUM = "medium"
RISK_LOW = "low"


@dataclass
class Review:
    """A single review to be scored."""

    review_id: str
    author: str
    rating: int
    text: str
    verified_purchase: bool = True
    account_age_days: int | None = None
    date: str | None = None  # ISO date string, e.g. "2024-05-01"


@dataclass
class ReviewScore:
    """The result of scoring a single :class:`Review`."""

    review_id: str
    score: int
    risk_level: str
    reasons: list[str] = field(default_factory=list)


def _is_generic(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in _GENERIC_PHRASES)


def _is_shouty(text: str) -> bool:
    if not text:
        return False
    exclamations = text.count("!")
    letters = [c for c in text if c.isalpha()]
    caps_ratio = (
        sum(1 for c in letters if c.isupper()) / len(letters) if letters else 0
    )
    return exclamations >= 3 or caps_ratio > 0.6


def _risk_level(score: int) -> str:
    if score >= 60:
        return RISK_HIGH
    if score >= 30:
        return RISK_MEDIUM
    return RISK_LOW


def score_review(review: Review, reasons_only: bool = False) -> tuple[int, list[str]]:
    """Score a single review in isolation (no batch-level signals).

    Returns a ``(score, reasons)`` tuple. ``score`` is clamped to 0-100.
    """

    score = 0
    reasons: list[str] = []

    word_count = len(review.text.split())

    if _is_generic(review.text):
        score += 25
        reasons.append("generic/templated phrase detected")

    if review.rating in (1, 5) and word_count <= SHORT_REVIEW_WORD_COUNT:
        score += 20
        reasons.append("extreme rating with very short, low-effort text")

    if _is_shouty(review.text):
        score += 15
        reasons.append("excessive exclamation marks or ALL CAPS text")

    if not review.verified_purchase:
        score += 20
        reasons.append("unverified purchase")

    if review.account_age_days is not None and review.account_age_days <= NEW_ACCOUNT_DAYS:
        score += 20
        reasons.append(
            f"account created only {review.account_age_days} day(s) before review"
        )

    score = max(0, min(100, score))
    return score, reasons


def score_reviews(reviews: Iterable[Review]) -> list[ReviewScore]:
    """Score a batch of reviews, including batch-level signals.

    Batch-level signals detected here (in addition to the per-review
    signals from :func:`score_review`):

    * duplicate/near-duplicate review text across the batch
    * multiple reviews from the same author on the same day ("bursts")
    """

    reviews = list(reviews)
    base_results: dict[str, tuple[int, list[str]]] = {
        r.review_id: score_review(r) for r in reviews
    }

    # Detect near-duplicate text across the batch (O(n^2), fine for
    # the small demo/showcase batches this tool targets).
    duplicate_ids: set[str] = set()
    for i, a in enumerate(reviews):
        for b in reviews[i + 1 :]:
            if not a.text or not b.text:
                continue
            ratio = SequenceMatcher(None, a.text.lower(), b.text.lower()).ratio()
            if ratio >= DUPLICATE_SIMILARITY_THRESHOLD:
                duplicate_ids.add(a.review_id)
                duplicate_ids.add(b.review_id)

    # Detect same-author/same-day review bursts.
    author_day_counts: dict[tuple[str, str], int] = {}
    for r in reviews:
        if r.date:
            key = (r.author, r.date)
            author_day_counts[key] = author_day_counts.get(key, 0) + 1

    results: list[ReviewScore] = []
    for r in reviews:
        score, reasons = base_results[r.review_id]
        reasons = list(reasons)

        if r.review_id in duplicate_ids:
            score += 25
            reasons.append("near-duplicate text shared with another review")

        if r.date and author_day_counts.get((r.author, r.date), 0) >= BURST_REVIEW_COUNT:
            score += 20
            reasons.append(
                "review burst: author posted "
                f"{author_day_counts[(r.author, r.date)]} reviews on {r.date}"
            )

        score = max(0, min(100, score))
        results.append(
            ReviewScore(
                review_id=r.review_id,
                score=score,
                risk_level=_risk_level(score),
                reasons=reasons,
            )
        )

    results.sort(key=lambda rs: rs.score, reverse=True)
    return results
