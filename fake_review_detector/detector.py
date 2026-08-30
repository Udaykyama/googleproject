"""Compatibility surface for the original scoring API.

The heuristics that used to live here now sit in
:mod:`fake_review_detector.signals` (detection),
:mod:`fake_review_detector.dedupe` (near-duplicates) and
:mod:`fake_review_detector.engine` (scoring and enforcement), where they are
policy-driven, evasion-resistant and auditable.

The signals themselves are unchanged, and mirror what abuse-fighting teams look
for (see ``../RESEARCH.md``):

* generic, templated praise/complaint phrases often used by paid reviewers
* extreme ratings (1 or 5 stars) paired with very short, low-effort text
* shouty text (excessive exclamation marks / ALL CAPS)
* reviews from unverified purchases
* reviews from very new accounts
* "review bursts" -- many reviews posted by the same author on the same day
* near-duplicate text shared across multiple reviews

:func:`score_review` and :func:`score_reviews` are kept for existing callers.
They score, but they do not validate input or produce an enforcement decision.
New code should use :func:`fake_review_detector.engine.moderate_batch`, which
validates untrusted input, applies a versioned policy, and returns decisions
that can be written to an audit log and routed to human review.
"""

from __future__ import annotations

from typing import Iterable

from .engine import score_batch
from .models import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    Review,
    ReviewScore,
    RiskLevel,
)
from .policy import Policy
from .signals import GENERIC_PHRASES as _GENERIC_PHRASE_TUPLE
from .signals import evaluate_review, is_generic, is_shouty

__all__ = [
    "Review",
    "ReviewScore",
    "RISK_HIGH",
    "RISK_MEDIUM",
    "RISK_LOW",
    "score_review",
    "score_reviews",
    "NEW_ACCOUNT_DAYS",
    "SHORT_REVIEW_WORD_COUNT",
    "DUPLICATE_SIMILARITY_THRESHOLD",
    "BURST_REVIEW_COUNT",
]

_DEFAULT_POLICY = Policy()

# Retained for callers that imported these directly. The authoritative values
# now live on Policy, which is what the engine actually reads.
_GENERIC_PHRASES = list(_GENERIC_PHRASE_TUPLE)
NEW_ACCOUNT_DAYS = _DEFAULT_POLICY.new_account_days
SHORT_REVIEW_WORD_COUNT = _DEFAULT_POLICY.short_review_word_count
DUPLICATE_SIMILARITY_THRESHOLD = _DEFAULT_POLICY.duplicate_similarity_threshold
BURST_REVIEW_COUNT = _DEFAULT_POLICY.burst_review_count


def _is_generic(text: str) -> bool:
    return is_generic(text)


def _is_shouty(text: str) -> bool:
    hit, _ = is_shouty(text)
    return hit


def _risk_level(score: int) -> RiskLevel:
    return _DEFAULT_POLICY.risk_level(score)


def score_review(
    review: Review, reasons_only: bool = False, policy: Policy | None = None
) -> tuple[int, list[str]]:
    """Score a single review in isolation (no batch-level signals).

    Returns a ``(score, reasons)`` tuple. ``score`` is clamped to 0-100.

    Input is not validated; pass untrusted data through
    :func:`fake_review_detector.engine.moderate` instead.
    """

    policy = policy or _DEFAULT_POLICY
    hits = evaluate_review(review, policy)
    hits.sort(key=lambda h: (-h.weight, h.code))
    score = max(0, min(100, sum(h.weight for h in hits)))
    return score, [h.message for h in hits]


def score_reviews(
    reviews: Iterable[Review], policy: Policy | None = None
) -> list[ReviewScore]:
    """Score a batch of reviews, including batch-level signals.

    Batch-level signals detected here (in addition to the per-review
    signals from :func:`score_review`):

    * duplicate/near-duplicate review text across the batch
    * multiple reviews from the same author on the same day ("bursts")

    Results are ordered highest score first.
    """

    scores, _ = score_batch(list(reviews), policy or _DEFAULT_POLICY)
    scores.sort(key=lambda s: (-s.score, s.review_id))
    return scores
