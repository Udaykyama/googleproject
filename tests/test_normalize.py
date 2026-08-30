"""Tests for evasion-resistant normalization."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.normalize import (  # noqa: E402
    fold_homoglyphs,
    matching_key,
    mixed_script_words,
    normalize_text,
    strip_invisible,
    word_shingles,
)

# Every one of these bypassed the original substring match.
EVASIONS = [
    "Best product ever",
    "Bеst prоduct еver",  # Cyrillic е/о
    "Ｂｅｓｔ ｐｒｏｄｕｃｔ ｅｖｅｒ",  # fullwidth
    "Best pro\u200bduct ever",  # zero-width space
    "Best prodddduct everrr",  # character stretching
    "Best  product   ever",  # repeated spaces
    "B-e-s-t product... ever!!!",  # letter spacing
    "B E S T product ever",
    "BEST PRODUCT EVER",
    "Bést prodüct evér",  # accents
]


def test_all_known_evasions_share_one_key():
    keys = {matching_key(text) for text in EVASIONS}
    assert keys == {"best product ever"}, keys


def test_empty_and_whitespace_text():
    assert matching_key("") == ""
    assert matching_key("   \t\n ") == ""
    assert normalize_text("") == ""


def test_normalize_text_is_conservative():
    # Safe to show a human moderator: case, punctuation and words survive.
    assert normalize_text("  Great   product!  ") == "Great product!"
    assert normalize_text("Don't\u200b stop") == "Don't stop"


def test_normalize_text_preserves_case_and_punctuation():
    text = "Really GOOD value, would buy again."
    assert normalize_text(text) == text


def test_non_latin_scripts_survive_folding():
    # Folding to ASCII would empty these out and make every non-Latin review
    # collide with every other in duplicate detection.
    for text in ("Отличный товар", "この製品は良い", "منتج رائع", "καλό προϊόν"):
        assert matching_key(text) != ""


def test_distinct_non_latin_reviews_do_not_collide():
    assert matching_key("Отличный товар") != matching_key("Плохой продукт")
    assert matching_key("この製品は良い") != matching_key("これは悪い製品")


def test_homoglyph_folding_only_applies_to_mixed_script_words():
    # A genuine Russian word must not be transliterated into Latin, or it could
    # accidentally match an English phrase.
    russian = "рекомендую"
    assert fold_homoglyphs(russian) == russian
    # A Latin word wearing one Cyrillic character is folded.
    assert fold_homoglyphs("prоduct") == "product"


def test_mixed_script_words_flags_only_mixed_words():
    assert mixed_script_words("Bеst prоduct") == ["Bеst", "prоduct"]
    assert mixed_script_words("Отличный товар") == []
    assert mixed_script_words("Good product") == []
    # A sentence mixing whole words from two scripts is normal multilingual
    # text, not evasion.
    assert mixed_script_words("Great товар") == []


def test_strip_invisible_removes_zero_width_characters():
    assert strip_invisible("a\u200bb\u200cc\u200dd\ufeffe") == "abcde"
    assert strip_invisible("normal text") == "normal text"


def test_strip_invisible_keeps_ordinary_whitespace():
    assert strip_invisible("a b\tc\nd") == "a b\tc\nd"


def test_short_text_still_produces_a_shingle():
    assert word_shingles("great") == {"great"}
    assert word_shingles("") == set()


def test_word_shingles_are_order_sensitive():
    assert word_shingles("the quick brown fox") != word_shingles("fox brown quick the")


def test_matching_key_is_idempotent():
    for text in EVASIONS:
        once = matching_key(text)
        assert matching_key(once) == once


def test_legitimate_short_words_are_not_joined():
    # Only runs of three or more single characters are treated as spacing-out.
    assert matching_key("I am a fan of this") == "i am a fan of this"


def test_emoji_only_text_yields_empty_key():
    # Documented consequence: such text has no letters to compare. Dedupe
    # handles empty keys explicitly rather than letting them all collide.
    assert matching_key("🎉🎉🎉") == ""
