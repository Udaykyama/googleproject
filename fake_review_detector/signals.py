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
    "GENERIC_PHRASES_BY_LANGUAGE",
    "PHRASE_LANGUAGE",
    "evaluate_review",
    "is_generic",
    "is_shouty",
    "matched_phrases",
    "matched_phrase_languages",
]

#: Templated phrases common in paid and bulk-generated reviews, grouped by the
#: language they are written in.
#:
#: Review farms are not an English-language phenomenon, and an English-only
#: table makes non-English farms invisible to the strongest signal: before this
#: table was translated, the same templated text scored 40 in English but 15 in
#: Spanish. Each language below mirrors the English entries' *beats* --
#: recommendation intensity, star count, repeat-purchase promise.
#:
#: Entries are deliberately multi-word, and deliberately exclude bare praise
#: like "good product" or "excellent product". Those are ordinary in genuine
#: writing in every language -- note that the English table has no bare "great
#: product" either, only the fixed pair "great product great service". Adding
#: the bare form is the mistake that turns this signal into a false-positive
#: generator for whole languages: an early draft of the Russian entries included
#: "отличный товар", which flags the entirely ordinary review "Отличный товар,
#: доставка быстрая" ("Great product, fast delivery").
#:
#: Every phrase is folded through :func:`matching_key` at import, so accents,
#: case and punctuation are handled centrally rather than per entry.
GENERIC_PHRASES_BY_LANGUAGE: dict[str, tuple[str, ...]] = {
    "en": (
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
    ),
    "es": (
        "muy recomendado",
        "lo recomiendo mucho",
        "cinco estrellas",
        "lo compraré de nuevo",
    ),
    "pt": (
        "recomendo muito",
        "cinco estrelas",
        "vou comprar novamente",
        "comprarei novamente",
    ),
    "fr": (
        "je recommande vivement",
        "cinq étoiles",
        "j'achèterai encore",
    ),
    "de": (
        "sehr empfehlenswert",
        "kann ich nur empfehlen",
        "werde wieder kaufen",
        "fünf sterne",
    ),
    "it": (
        "lo consiglio vivamente",
        "cinque stelle",
        "comprerò ancora",
    ),
    "ru": (
        "очень рекомендую",
        "пять звёзд",
        "буду покупать ещё",
    ),
    "zh": (
        "强烈推荐",
        "五星好评",
        "会再次购买",
    ),
    "ja": (
        "とてもおすすめ",
        "また買います",
        "星五つ",
    ),
    "ko": (
        "강력 추천",
        "다시 구매",
    ),
    "tr": (
        "kesinlikle tavsiye ederim",
        "tekrar alacağım",
    ),
    "pl": (
        "gorąco polecam",
        "kupię ponownie",
    ),
    "id": (
        "sangat direkomendasikan",
        "akan beli lagi",
    ),
    "vi": (
        "rất đáng mua",
        "sẽ mua lại",
    ),
    "ar": (
        "أنصح به بشدة",
    ),
}

#: Every templated phrase, flattened. Kept as a flat tuple because it is part of
#: the public API; the per-language grouping above is the maintainable source.
GENERIC_PHRASES = tuple(
    phrase
    for phrases in GENERIC_PHRASES_BY_LANGUAGE.values()
    for phrase in phrases
)

#: Phrase → language, so evidence can say which language a template matched.
#: A Spanish match on a queue staffed by English readers is actionable routing
#: information, not just a score.
PHRASE_LANGUAGE: dict[str, str] = {
    phrase: language
    for language, phrases in GENERIC_PHRASES_BY_LANGUAGE.items()
    for phrase in phrases
}

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


def matched_phrase_languages(text: str) -> list[str]:
    """Languages whose templated phrases appear in ``text``, sorted."""

    return sorted({PHRASE_LANGUAGE[phrase] for phrase in matched_phrases(text)})


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
                {
                    "phrases": sorted(phrases),
                    "languages": sorted(
                        {PHRASE_LANGUAGE[phrase] for phrase in phrases}
                    ),
                },
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
