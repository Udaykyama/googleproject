"""Detection signals.

Each signal returns a :class:`SignalHit` carrying a stable ``code``, the policy
weight, a human-readable message and structured ``evidence``. The evidence is
what makes a decision auditable: a moderator reviewing an appeal needs to see
*which* phrase matched or *which* other review the text duplicated, not just a
score.

Text is compared through :func:`fake_review_detector.normalize.matching_key`, and
the phrase table is folded through the same function at import time so both
sides of every comparison are normalised identically.
"""

from __future__ import annotations

from .models import Review, SignalHit
from .normalize import condensed_key, matching_key, mixed_script_words
from .policy import Policy

__all__ = [
    "GENERIC_PHRASES",
    "evaluate_review",
    "is_generic",
    "is_shouty",
]

#: Templated phrases common in paid and bulk-generated reviews.
GENERIC_PHRASES = (
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
)

#: Phrase → folded key. Built once, through the same folding the input gets.
_PHRASE_KEYS: dict[str, str] = {
    phrase: matching_key(phrase) for phrase in GENERIC_PHRASES
}

#: The same phrases with spaces removed, for text whose word boundaries were
#: destroyed by spacing every letter out.
_PHRASE_KEYS_CONDENSED: dict[str, str] = {
    phrase: key.replace(" ", "") for phrase, key in _PHRASE_KEYS.items()
}


def matched_phrases(text: str) -> list[str]:
    """Generic phrases present in ``text``, compared on folded keys."""

    key = matching_key(text)
    if not key:
        return []
    condensed = condensed_key(text)
    return [
        phrase
        for phrase, phrase_key in _PHRASE_KEYS.items()
        if phrase_key
        and (phrase_key in key or _PHRASE_KEYS_CONDENSED[phrase] in condensed)
    ]


def is_generic(text: str) -> bool:
    """True if the text contains a templated phrase, evasion attempts included."""

    return bool(matched_phrases(text))


def is_shouty(text: str) -> tuple[bool, dict]:
    """Detect excessive exclamation marks or ALL CAPS, with the counts used."""

    if not text:
        return False, {}
    exclamations = text.count("!")
    letters = [c for c in text if c.isalpha()]
    caps = sum(1 for c in letters if c.isupper())
    caps_ratio = caps / len(letters) if letters else 0.0
    hit = exclamations >= 3 or caps_ratio > 0.6
    return hit, {
        "exclamation_count": exclamations,
        "caps_ratio": round(caps_ratio, 3),
        "letter_count": len(letters),
    }


def _hit(policy: Policy, code: str, message: str, evidence: dict) -> SignalHit | None:
    """Build a hit, or ``None`` when the policy has zeroed the signal out."""

    weight = policy.weight(code)
    if weight <= 0:
        return None
    return SignalHit(code=code, weight=weight, message=message, evidence=evidence)


def evaluate_review(review: Review, policy: Policy) -> list[SignalHit]:
    """Signals detectable from a single review, without batch context."""

    hits: list[SignalHit] = []

    phrases = matched_phrases(review.text)
    if phrases:
        hits.append(
            _hit(
                policy,
                "GENERIC_PHRASE",
                "generic/templated phrase detected",
                {"phrases": sorted(phrases)},
            )
        )

    word_count = len(review.text.split())
    if review.rating in (1, 5) and word_count <= policy.short_review_word_count:
        hits.append(
            _hit(
                policy,
                "LOW_EFFORT_EXTREME_RATING",
                "extreme rating with very short, low-effort text",
                {"rating": review.rating, "word_count": word_count},
            )
        )

    shouty, shout_evidence = is_shouty(review.text)
    if shouty:
        hits.append(
            _hit(
                policy,
                "SHOUTY_TEXT",
                "excessive exclamation marks or ALL CAPS text",
                shout_evidence,
            )
        )

    if not review.verified_purchase:
        hits.append(
            _hit(policy, "UNVERIFIED_PURCHASE", "unverified purchase", {})
        )

    if (
        review.account_age_days is not None
        and review.account_age_days <= policy.new_account_days
    ):
        hits.append(
            _hit(
                policy,
                "NEW_ACCOUNT",
                f"account created only {review.account_age_days} day(s) before review",
                {"account_age_days": review.account_age_days},
            )
        )

    # Mixed scripts inside a single word are how phrase filters get evaded
    # (Cyrillic "е" for Latin "e"). Genuine multilingual text does not mix
    # scripts *within* a word, so this does not penalise non-English reviews.
    mixed = mixed_script_words(review.text)
    if mixed:
        hits.append(
            _hit(
                policy,
                "MIXED_SCRIPT_TEXT",
                "mixed-script characters within words (possible filter evasion)",
                {"words": mixed[:10], "count": len(mixed)},
            )
        )

    return [h for h in hits if h is not None]
