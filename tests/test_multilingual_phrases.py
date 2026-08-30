"""Tests for the multilingual templated-phrase table.

Before these phrases existed the table was English-only, so a review farm
operating in any other language was invisible to the strongest signal: the
identical templated text scored 40 in English and 15 in Spanish.

The risk in fixing that is precision. A phrase table is a blunt instrument, and
a too-ordinary entry does not just cause a few false positives, it causes them
for an entire language at once. Most of these tests guard that side.
"""

from __future__ import annotations

from fake_review_detector.engine import score_batch
from fake_review_detector.models import Review
from fake_review_detector.policy import Policy
from fake_review_detector.signals import (
    GENERIC_PHRASES,
    GENERIC_PHRASES_BY_LANGUAGE,
    PHRASE_LANGUAGE,
    is_generic,
    matched_phrase_languages,
    matched_phrases,
)

# One templated review per language, in the shape a farm actually posts.
TEMPLATED = {
    "en": "Best product ever! Amazing quality! Highly recommend! Will buy again!",
    "es": "¡Muy recomendado! ¡Lo compraré de nuevo! ¡Cinco estrellas!",
    "pt": "Recomendo muito! Vou comprar novamente! Cinco estrelas!",
    "fr": "Je recommande vivement! J'achèterai encore! Cinq étoiles!",
    "de": "Sehr empfehlenswert! Werde wieder kaufen! Fünf Sterne!",
    "it": "Lo consiglio vivamente! Comprerò ancora! Cinque stelle!",
    "ru": "Очень рекомендую! Буду покупать ещё! Пять звёзд!",
    "zh": "强烈推荐！会再次购买！五星好评！",
    "ja": "とてもおすすめ！また買います！星五つ！",
    "ko": "강력 추천! 다시 구매!",
    "tr": "Kesinlikle tavsiye ederim! Tekrar alacağım!",
    "pl": "Gorąco polecam! Kupię ponownie!",
    "id": "Sangat direkomendasikan! Akan beli lagi!",
    "vi": "Rất đáng mua! Sẽ mua lại!",
    "ar": "أنصح به بشدة",
}

# Ordinary reviews that happen to be positive. None may be flagged as templated:
# genuine enthusiasm is not spam, in any language.
ORDINARY = {
    "en": "Great product, delivery was fast. The manual could be clearer though.",
    "es": "Buen producto, la entrega fue rápida. El manual podría ser más claro.",
    "pt": "Bom produto, a entrega foi rápida. O manual poderia ser mais claro.",
    "fr": "Bon produit, livraison rapide. Le manuel pourrait être plus clair.",
    "de": "Gutes Produkt, schnelle Lieferung. Die Anleitung könnte klarer sein.",
    "it": "Buon prodotto, consegna rapida. Il manuale potrebbe essere più chiaro.",
    "ru": "Отличный товар, доставка быстрая",
    "zh": "这个产品很好，物流也快，说明书可以再清楚一点。",
    "ja": "この製品は良いです。配送も早かったですが、説明書は分かりにくいです。",
    "ko": "제품은 좋습니다. 배송도 빨랐어요. 설명서는 좀 아쉽네요.",
    "tr": "Ürün iyi, kargo hızlıydı. Kılavuz biraz daha açık olabilirdi.",
    "pl": "Dobry produkt, szybka dostawa. Instrukcja mogłaby być jaśniejsza.",
    "id": "Produk bagus, pengiriman cepat. Manualnya bisa lebih jelas.",
    "vi": "Sản phẩm tốt, giao hàng nhanh. Hướng dẫn có thể rõ ràng hơn.",
    "ar": "المنتج جيد والتوصيل كان سريعا.",
}


def _score(text: str) -> int:
    review = Review(
        review_id="r1",
        author="solo_author",
        rating=5,
        text=text,
        verified_purchase=True,
        account_age_days=900,
    )
    scores, _ = score_batch([review], Policy())
    return scores[0].score


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def test_every_language_in_the_table_has_a_templated_example_here():
    """Adding a language without a test would let it rot silently."""

    assert set(TEMPLATED) == set(GENERIC_PHRASES_BY_LANGUAGE)


def test_templated_reviews_are_detected_in_every_language():
    missed = {
        language: text
        for language, text in TEMPLATED.items()
        if not is_generic(text)
    }
    assert not missed, f"templated text not detected: {sorted(missed)}"


def test_a_lone_non_english_template_is_flagged_like_an_english_one():
    """The regression this table exists to prevent.

    A single templated review with no duplicate partner, from an established
    verified account, gets no help from the burst or dedupe signals. Before the
    table was translated, only the English one cleared the threshold.
    """

    threshold = Policy().medium_threshold
    for language, text in TEMPLATED.items():
        assert _score(text) >= threshold, f"{language} template not flagged"


# --------------------------------------------------------------------------
# Precision
# --------------------------------------------------------------------------


def test_ordinary_positive_reviews_are_never_templated():
    flagged = {
        language: matched_phrases(text)
        for language, text in ORDINARY.items()
        if is_generic(text)
    }
    assert not flagged, f"ordinary reviews matched a template phrase: {flagged}"


def test_no_entry_is_bare_praise_for_a_product():
    """The rule that keeps this table from flagging whole languages.

    'Отличный товар' means 'great product'. It is ordinary in genuine writing,
    and an early draft of this table flagged every Russian review containing it.
    The English table has never contained a bare 'great product' either, only
    the fixed pair 'great product great service'.
    """

    banned = {
        "excelente producto",
        "produto excelente",
        "excellent produit",
        "bestes produkt",
        "prodotto eccellente",
        "отличный товар",
        "лучший товар",
        "harika ürün",
        "produk bagus",
        "منتج ممتاز",
    }
    assert banned.isdisjoint(set(GENERIC_PHRASES))


def test_entries_are_multi_word_or_non_spaced_scripts():
    for phrase in GENERIC_PHRASES:
        if any("\u3040" <= ch <= "\u9fff" for ch in phrase):
            continue  # CJK does not delimit words with spaces
        assert " " in phrase, f"single-word entry is too blunt: {phrase!r}"


# --------------------------------------------------------------------------
# Table shape
# --------------------------------------------------------------------------


def test_flat_tuple_matches_the_grouped_table():
    grouped = [
        phrase
        for phrases in GENERIC_PHRASES_BY_LANGUAGE.values()
        for phrase in phrases
    ]
    assert list(GENERIC_PHRASES) == grouped


def test_no_duplicate_phrases():
    assert len(set(GENERIC_PHRASES)) == len(GENERIC_PHRASES)


def test_every_phrase_maps_to_its_language():
    assert set(PHRASE_LANGUAGE) == set(GENERIC_PHRASES)
    for language, phrases in GENERIC_PHRASES_BY_LANGUAGE.items():
        for phrase in phrases:
            assert PHRASE_LANGUAGE[phrase] == language


def test_the_english_table_is_unchanged():
    """Translating must not have altered the original entries."""

    assert GENERIC_PHRASES_BY_LANGUAGE["en"] == (
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


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


def test_evidence_reports_which_language_matched():
    """A moderator needs to know which language queue an appeal belongs in."""

    assert matched_phrase_languages(TEMPLATED["ja"]) == ["ja"]
    assert matched_phrase_languages(TEMPLATED["ru"]) == ["ru"]
    assert matched_phrase_languages("nothing templated here at all") == []


def test_signal_evidence_carries_phrases_and_languages():
    review = Review(
        review_id="r1",
        author="solo_author",
        rating=5,
        text=TEMPLATED["de"],
        verified_purchase=True,
        account_age_days=900,
    )
    scores, _ = score_batch([review], Policy())
    generic = [s for s in scores[0].signals if s.code == "GENERIC_PHRASE"]
    assert generic, "expected a GENERIC_PHRASE signal"
    evidence = generic[0].evidence
    assert evidence["languages"] == ["de"]
    assert evidence["phrases"]


# --------------------------------------------------------------------------
# Evasion, in non-Latin scripts
# --------------------------------------------------------------------------


def test_evasion_defences_apply_to_non_english_phrases_too():
    """Case, accents and padded punctuation must fold the same way everywhere."""

    assert is_generic("MUY RECOMENDADO")
    assert is_generic("muy    recomendado!!!")
    assert is_generic("Очень   рекомендую")
    assert is_generic("Sehr Empfehlenswert.")


def test_accent_stripping_does_not_break_accented_entries():
    assert is_generic("cinq étoiles")
    assert is_generic("cinq etoiles")
    assert is_generic("пять звёзд")
