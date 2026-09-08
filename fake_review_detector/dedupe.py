"""Near-duplicate detection that scales.

The original implementation compared every pair of reviews with
:class:`difflib.SequenceMatcher`. Measured on this machine that is O(n²) with a
clean 4× cost per doubling — 100 reviews in 1.6s, 800 in 104s, extrapolating to
roughly 19 days for 100k reviews. Unusable for a real queue.

This module keeps the *same* acceptance test — ``SequenceMatcher.ratio() >=
threshold`` on the review text — but stops feeding it every pair. Above a
configurable batch size, MinHash + LSH banding proposes a small set of candidate
pairs and only those are verified. Blocking is a recall/latency trade-off, so
small batches still run the exact comparison and the mode used is reported.

Determinism matters here: a moderation decision must be reproducible on replay.
Python's built-in :func:`hash` is salted per process, so hashing goes through
:mod:`hashlib` with fixed, derived permutation constants instead.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from difflib import SequenceMatcher
from functools import cached_property
from itertools import chain
from typing import Iterable, Iterator, Sequence

from .models import Review
from .normalize import matching_key, word_shingles

__all__ = ["DuplicatePair", "DuplicateReport", "find_duplicates", "minhash_signature"]

# 2^61 - 1. Prime modulus for the permutation family.
_MERSENNE_PRIME = (1 << 61) - 1

NUM_PERM = 128
BANDS = 32
ROWS = NUM_PERM // BANDS


def _permutations(num_perm: int) -> list[tuple[int, int]]:
    """Deterministic (a, b) pairs for the ``(a*x + b) mod p`` hash family.

    Derived from a fixed digest rather than :mod:`random` so that signatures are
    identical across processes, platforms and Python versions.
    """

    perms: list[tuple[int, int]] = []
    for index in range(num_perm):
        seed = hashlib.blake2b(
            index.to_bytes(4, "big"), digest_size=16, person=b"minhash-perm"
        ).digest()
        a = int.from_bytes(seed[:8], "big") % (_MERSENNE_PRIME - 1)
        b = int.from_bytes(seed[8:], "big") % _MERSENNE_PRIME
        perms.append((a | 1, b))  # 'a' must be non-zero for a valid permutation
    return perms


_PERMS = _permutations(NUM_PERM)


def _shingle_hash(shingle: str) -> int:
    return int.from_bytes(
        hashlib.blake2b(shingle.encode("utf-8"), digest_size=8).digest(), "big"
    ) % _MERSENNE_PRIME


def minhash_signature(shingles: Iterable[str], num_perm: int = NUM_PERM) -> tuple[int, ...]:
    """MinHash signature for a shingle set. Empty input yields an empty tuple."""

    if isinstance(num_perm, bool) or not isinstance(num_perm, int) or num_perm < 1:
        raise ValueError("num_perm must be a positive integer")
    hashes = [_shingle_hash(s) for s in shingles]
    if not hashes:
        return ()
    perms = _PERMS if num_perm == NUM_PERM else _permutations(num_perm)
    return tuple(
        min(((a * h + b) % _MERSENNE_PRIME) for h in hashes) for a, b in perms[:num_perm]
    )


@dataclass(frozen=True)
class DuplicatePair:
    """Two reviews whose text passed the similarity threshold."""

    left_id: str
    right_id: str
    similarity: float

    def to_dict(self) -> dict:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "similarity": round(self.similarity, 4),
        }


@dataclass(frozen=True)
class DuplicateReport:
    """Duplicate pairs found in a batch, plus how they were found."""

    pairs: tuple[DuplicatePair, ...]
    mode: str  # "exact" or "lsh"
    candidate_pairs: int
    compared_pairs: int
    #: True when the per-review partner cap stopped some pairs being recorded.
    #: The reviews are still reported as duplicates; only the exhaustive list
    #: of who-matched-whom is incomplete.
    truncated: bool = False

    @cached_property
    def _partner_index(self) -> dict[str, tuple[tuple[str, float], ...]]:
        partners: dict[str, list[tuple[str, float]]] = {}
        for pair in self.pairs:
            partners.setdefault(pair.left_id, []).append((pair.right_id, pair.similarity))
            partners.setdefault(pair.right_id, []).append((pair.left_id, pair.similarity))
        return {
            review_id: tuple(sorted(matches, key=lambda item: (-item[1], item[0])))
            for review_id, matches in partners.items()
        }

    def ids(self) -> set[str]:
        return set(self._partner_index)

    def partners(self, review_id: str) -> list[tuple[str, float]]:
        """Reviews that ``review_id`` duplicated, with similarity, for evidence."""

        return list(self._partner_index.get(review_id, ()))


def _similar(left: str, right: str, threshold: float) -> float | None:
    """Similarity if it meets ``threshold``, else ``None``.

    ``real_quick_ratio`` and ``quick_ratio`` are cheap upper bounds on
    ``ratio``, so rejecting on them cannot discard a pair that would have
    passed. This keeps the result identical to the naive comparison while
    avoiding the expensive O(L²) match on obviously dissimilar text.
    """

    if left == right:
        return 1.0
    matcher = SequenceMatcher(None, left, right)
    if matcher.real_quick_ratio() < threshold:
        return None
    if matcher.quick_ratio() < threshold:
        return None
    ratio = matcher.ratio()
    return ratio if ratio >= threshold else None


def _exact_candidates(count: int) -> Iterator[tuple[int, int]]:
    for left in range(count):
        for right in range(left + 1, count):
            yield left, right


#: Largest set of documents compared pairwise inside one LSH bucket.
_BUCKET_WINDOW = 500


def _lsh_candidates(
    keys: Sequence[str], num_perm: int = NUM_PERM, bands: int = BANDS
) -> Iterator[tuple[int, int]]:
    """Candidate index pairs from MinHash banding.

    Documents whose folded key produces no shingles (emoji-only text, for
    instance) cannot be banded; they are grouped by exact key equality so they
    are not silently exempt from duplicate detection.
    """

    if bands < 1 or num_perm < 1 or num_perm % bands:
        raise ValueError("num_perm must be positive and divisible by bands")
    rows = num_perm // bands
    buckets: dict[bytes, list[int]] = {}
    degenerate: dict[str, list[int]] = {}

    for index, key in enumerate(keys):
        shingles = word_shingles(key) if key else set()
        signature = minhash_signature(shingles, num_perm=num_perm)
        if not signature:
            degenerate.setdefault(key, []).append(index)
            continue
        for band in range(bands):
            chunk = signature[band * rows : (band + 1) * rows]
            digest = hashlib.blake2b(
                band.to_bytes(2, "big")
                + b"".join(value.to_bytes(8, "big") for value in chunk),
                digest_size=12,
            ).digest()
            buckets.setdefault(digest, []).append(index)

    memberships: list[list[tuple[int, ...]]] = [[] for _ in keys]
    windows: set[tuple[int, ...]] = set()
    for group in chain(buckets.values(), degenerate.values()):
        if len(group) < 2:
            continue
        # A pathological bucket would reintroduce the quadratic blow-up, so
        # large buckets are compared in windows. Truncating the bucket instead
        # would silently drop its later members from detection entirely;
        # windowing avoids discarding the whole tail of a large cluster.
        for start in range(0, len(group), _BUCKET_WINDOW):
            window = tuple(group[start : start + _BUCKET_WINDOW])
            if len(window) < 2 or window in windows:
                continue
            windows.add(window)
            for index in window:
                memberships[index].append(window)
    buckets.clear()
    degenerate.clear()
    windows.clear()

    # Emit the same lexicographically ordered, unique pairs as before, but
    # retain only one review's candidate neighbors rather than the whole graph.
    for left, groups in enumerate(memberships):
        rights = {right for group in groups for right in group if right > left}
        for right in sorted(rights):
            yield left, right


def find_duplicates(
    reviews: Sequence[Review],
    *,
    threshold: float = 0.85,
    exact_max_batch: int = 200,
    max_partners: int = 25,
) -> DuplicateReport:
    """Find near-duplicate reviews in a batch.

    Uses exhaustive comparison for batches up to ``exact_max_batch`` and LSH
    blocking above it. ``threshold`` is applied by ``SequenceMatcher`` in both
    modes, so a pair reported in one mode would be reported in the other.

    ``max_partners`` bounds how many duplicate partners are recorded per
    review. A review bomb of n identical texts genuinely contains n*(n-1)/2
    duplicate pairs, so enumerating them all is quadratic no matter how the
    candidates are generated. Detection only needs a few partners per review,
    so pairs are skipped once a side is at the cap and
    :attr:`DuplicateReport.truncated` is set. The cap and LSH blocking can omit
    matches, so absence from this report is not proof of unique text. Both
    modes apply the cap over the same sorted candidate order, so results stay
    deterministic.
    """

    if isinstance(threshold, bool) or not math.isfinite(threshold) or not 0 < threshold <= 1:
        raise ValueError("threshold must be finite and within (0, 1]")
    if (
        isinstance(exact_max_batch, bool) or not isinstance(exact_max_batch, int)
        or exact_max_batch < 0
    ):
        raise ValueError("exact_max_batch must be a non-negative integer")
    if isinstance(max_partners, bool) or not isinstance(max_partners, int) or max_partners < 1:
        raise ValueError("max_partners must be a positive integer")
    reviews = list(reviews)
    count = len(reviews)
    if count < 2:
        return DuplicateReport(pairs=(), mode="exact", candidate_pairs=0, compared_pairs=0)

    texts = [r.text.lower() for r in reviews]

    if count <= exact_max_batch:
        mode = "exact"
        candidates = _exact_candidates(count)
    else:
        mode = "lsh"
        candidates = _lsh_candidates([matching_key(r.text) for r in reviews])

    pairs: list[DuplicatePair] = []
    compared = 0
    candidate_count = 0
    truncated = False
    partner_count: dict[int, int] = {}
    for left, right in candidates:
        candidate_count += 1
        if not texts[left] or not texts[right]:
            continue
        left_partners = partner_count.get(left, 0)
        right_partners = partner_count.get(right, 0)
        # Stop growing partner lists that are already at the cap. In a dense
        # cluster the under-cap review still has many other members of the
        # same cluster to match against, so it is still flagged.
        if left_partners >= max_partners or right_partners >= max_partners:
            truncated = True
            continue
        compared += 1
        similarity = _similar(texts[left], texts[right], threshold)
        if similarity is not None:
            partner_count[left] = partner_count.get(left, 0) + 1
            partner_count[right] = partner_count.get(right, 0) + 1
            pairs.append(
                DuplicatePair(
                    left_id=reviews[left].review_id,
                    right_id=reviews[right].review_id,
                    similarity=similarity,
                )
            )

    return DuplicateReport(
        pairs=tuple(pairs),
        mode=mode,
        candidate_pairs=candidate_count,
        compared_pairs=compared,
        truncated=truncated,
    )
