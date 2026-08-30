"""Evasion-resistant text normalization.

Naive moderation matches raw substrings, which is defeated by transformations
that leave text visually unchanged. All five of the following render as "best
product ever" to a human but evade a plain ``in`` check:

* ``Bеst product ever``      — Cyrillic U+0435 in place of Latin ``e``
* ``Ｂｅｓｔ ｐｒｏｄｕｃｔ ｅｖｅｒ``  — fullwidth forms
* ``Best pro\\u200bduct ever``  — zero-width space
* ``Best prodddduct ever``    — character stretching
* ``Best  product   ever``    — repeated whitespace

:func:`matching_key` folds all of them onto the same key.

Two distinct normalizations are provided, and the difference matters:

``normalize_text``
    Conservative. Repairs encoding-level noise (compatibility forms, invisible
    characters, whitespace) while preserving what the author actually wrote.
    Safe to store and show to a human reviewer.

``matching_key``
    Aggressive and lossy. Used only for phrase lookup and near-duplicate
    comparison, never displayed or persisted as content.

Homoglyph folding is applied only to words that *mix* scripts. A word written
entirely in Cyrillic is left alone, so a genuine Russian review is not mangled
into accidental matches; but ``Bеst``, which mixes Latin and Cyrillic, is
folded. Mixing scripts inside a single word is itself the attack signature, and
is exposed separately by :func:`mixed_script_words`.
"""

from __future__ import annotations

import re
import unicodedata

__all__ = [
    "normalize_text",
    "matching_key",
    "condensed_key",
    "fold_homoglyphs",
    "mixed_script_words",
    "strip_invisible",
    "word_shingles",
]

# Confusable code points mapped onto their Latin lookalikes. Deliberately
# limited to characters that are near-indistinguishable in common UI fonts;
# an over-broad table would fold unrelated text together.
_HOMOGLYPHS = {
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u04bb": "h", "\u0432": "b", "\u043a": "k", "\u043c": "m", "\u0442": "t",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M",
    "\u041d": "H", "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T",
    "\u0425": "X", "\u0423": "Y", "\u0406": "I", "\u0405": "S",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03c1": "p", "\u03c5": "u", "\u03bd": "v",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O",
    "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Other confusables
    "\u0131": "i", "\u01c0": "l", "\u2044": "/",
}

# Invisible / formatting characters used to break up matched substrings.
_EXPLICIT_INVISIBLES = {
    "\u00ad",  # soft hyphen
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
    "\u180e",  # mongolian vowel separator
}

_WHITESPACE_RE = re.compile(r"\s+")
_RUN_RE = re.compile(r"(.)\1+")
# Three or more consecutive single-character tokens, i.e. "b e s t" or "b-e-s-t"
# once punctuation has become whitespace. Requiring three avoids joining
# legitimate short words such as "a" and "I".
_SPACED_LETTERS_RE = re.compile(r"(?:(?<=\s)|^)(?:\w\s+){2,}\w(?=\s|$)")

_LATIN_RE = re.compile(r"[A-Za-z]")
_CYRILLIC_RE = re.compile(r"[\u0400-\u04FF]")
_GREEK_RE = re.compile(r"[\u0370-\u03FF]")


def strip_invisible(text: str) -> str:
    """Remove zero-width and formatting characters.

    Covers the explicit list above plus anything Unicode classifies as a format
    character (category ``Cf``), which catches bidi overrides and similar tricks
    without needing to enumerate them.
    """

    return "".join(
        ch
        for ch in text
        if ch not in _EXPLICIT_INVISIBLES and unicodedata.category(ch) != "Cf"
    )


def _scripts_in(word: str) -> set[str]:
    scripts = set()
    if _LATIN_RE.search(word):
        scripts.add("latin")
    if _CYRILLIC_RE.search(word):
        scripts.add("cyrillic")
    if _GREEK_RE.search(word):
        scripts.add("greek")
    return scripts


def mixed_script_words(text: str) -> list[str]:
    """Return words that mix alphabets, e.g. Latin ``B`` with Cyrillic ``е``.

    Legitimate text does not mix alphabets inside a single word, so this is a
    strong standalone spoofing indicator as well as the trigger for folding.
    """

    cleaned = strip_invisible(unicodedata.normalize("NFKC", text))
    return [word for word in _WHITESPACE_RE.split(cleaned) if word and len(_scripts_in(word)) > 1]


def fold_homoglyphs(text: str) -> str:
    """Map confusable characters onto Latin, but only in mixed-script words."""

    folded_words = []
    for word in _WHITESPACE_RE.split(text):
        if len(_scripts_in(word)) > 1:
            word = "".join(_HOMOGLYPHS.get(ch, ch) for ch in word)
        folded_words.append(word)
    return " ".join(folded_words)


def normalize_text(text: str) -> str:
    """Conservative normalization suitable for storage and display.

    Applies NFKC, removes invisible characters, and collapses whitespace. Case,
    punctuation, and word choice are preserved.
    """

    if not text:
        return ""
    normalized = unicodedata.normalize("NFKC", text)
    normalized = strip_invisible(normalized)
    return _WHITESPACE_RE.sub(" ", normalized).strip()


def _strip_punctuation(text: str) -> str:
    """Replace punctuation and symbols with spaces, preserving letters/digits.

    Uses Unicode general categories rather than an ASCII range, so scripts other
    than Latin survive. Stripping to ``[a-z0-9]`` would reduce an entire Russian
    or Japanese review to the empty string, which would then collide with every
    other non-Latin review in duplicate detection.
    """

    return "".join(
        ch if (unicodedata.category(ch)[0] in ("L", "N") or ch.isspace()) else " "
        for ch in text
    )


def matching_key(text: str) -> str:
    """Aggressively fold text to a comparison key.

    Lossy by design: the result is used for phrase lookup and duplicate
    comparison only. Runs of a repeated character collapse to one, so
    ``prodddduct`` and ``product`` share a key — this must be applied to both
    sides of any comparison, which :mod:`fake_review_detector.signals` does by
    keying its phrase table through this same function.
    """

    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text)
    folded = strip_invisible(folded)
    folded = fold_homoglyphs(folded)
    folded = folded.casefold()
    # Fold accented forms down to bare letters where possible.
    folded = unicodedata.normalize("NFKD", folded)
    folded = "".join(ch for ch in folded if not unicodedata.combining(ch))
    folded = _strip_punctuation(folded)
    folded = _RUN_RE.sub(r"\1", folded)
    folded = _WHITESPACE_RE.sub(" ", folded).strip()
    # Re-join letters that were spaced out to break up a matched phrase.
    folded = _SPACED_LETTERS_RE.sub(lambda m: m.group(0).replace(" ", ""), folded)
    # Rejoining can recreate runs the earlier pass could not see, because the
    # repeated characters were separated by the spacing ("r e c o m m e n d").
    folded = _RUN_RE.sub(r"\1", folded)
    return _WHITESPACE_RE.sub(" ", folded).strip()


def condensed_key(text: str) -> str:
    """:func:`matching_key` with all spaces removed.

    When every word of a phrase is spaced out ("B-e-s-t p-r-o-d-u-c-t e-v-e-r")
    the original word boundaries are genuinely unrecoverable, so no amount of
    re-joining restores "best product ever". Comparing the space-free forms of
    both sides sidesteps that. Only used as a secondary check, because it can
    match across word boundaries.
    """

    return matching_key(text).replace(" ", "")


def word_shingles(text: str, size: int = 3) -> set[str]:
    """Return the set of overlapping ``size``-word shingles of ``text``.

    Operates on :func:`matching_key` output, so shingling is already immune to
    the evasions above. Texts shorter than ``size`` words yield a single shingle
    covering the whole text, so short reviews still compare meaningfully.
    """

    if size < 1:
        raise ValueError("shingle size must be >= 1")
    words = matching_key(text).split()
    if not words:
        return set()
    if len(words) <= size:
        return {" ".join(words)}
    return {" ".join(words[i : i + size]) for i in range(len(words) - size + 1)}
