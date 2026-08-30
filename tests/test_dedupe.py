"""Tests for near-duplicate detection.

The key property is that LSH blocking is an optimisation, not a change in
meaning: it must agree with exhaustive comparison on the pairs it reports.
"""

import random
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.dedupe import (  # noqa: E402
    find_duplicates,
    minhash_signature,
)
from fake_review_detector.models import Review  # noqa: E402
from fake_review_detector.normalize import matching_key, word_shingles  # noqa: E402

WORDS = "battery life screen quality shipping price value camera sound build".split()


def make(review_id, text, author=None):
    return Review(
        review_id=review_id,
        author=author or f"a_{review_id}",
        rating=5,
        text=text,
        date="2024-05-01",
    )


def corpus(size, seed=1):
    rng = random.Random(seed)
    return [
        make(f"r{i}", " ".join(rng.choice(WORDS) for _ in range(30)))
        for i in range(size)
    ]


def pair_set(report):
    return {tuple(sorted((p.left_id, p.right_id))) for p in report.pairs}


def test_identical_text_is_a_duplicate():
    reviews = [make("a", "Exactly the same words here"), make("b", "Exactly the same words here")]
    assert pair_set(find_duplicates(reviews)) == {("a", "b")}


def test_distinct_text_is_not_a_duplicate():
    reviews = [
        make("a", "The battery lasted six hours during my commute"),
        make("b", "Assembly took twenty minutes and the instructions were clear"),
    ]
    assert find_duplicates(reviews).pairs == ()


def test_near_duplicate_above_threshold():
    reviews = [
        make("a", "This product works really well for my daily needs"),
        make("b", "This product works really well for my daily need"),
    ]
    assert pair_set(find_duplicates(reviews)) == {("a", "b")}


def test_threshold_is_honoured():
    reviews = [
        make("a", "This product works really well for my daily needs"),
        make("b", "A completely different sentence about something else entirely"),
    ]
    assert find_duplicates(reviews, threshold=0.99).pairs == ()
    assert find_duplicates(reviews, threshold=0.05).pairs != ()


def test_single_review_and_empty_batch():
    assert find_duplicates([]).pairs == ()
    assert find_duplicates([make("a", "only one")]).pairs == ()


def test_lsh_agrees_with_exhaustive_comparison():
    reviews = corpus(300)
    # Plant exact and near duplicates.
    reviews += [make(f"dup{i}", reviews[i].text) for i in range(15)]
    reviews += [make(f"near{i}", reviews[i].text + " really") for i in range(15, 30)]

    exact = find_duplicates(reviews, exact_max_batch=10**9)
    lsh = find_duplicates(reviews, exact_max_batch=1)

    assert exact.mode == "exact"
    assert lsh.mode == "lsh"
    assert pair_set(lsh) == pair_set(exact)
    # And it got there by examining far fewer pairs.
    assert lsh.candidate_pairs < exact.candidate_pairs / 100


def test_lsh_examines_far_fewer_pairs():
    reviews = corpus(400)
    lsh = find_duplicates(reviews, exact_max_batch=1)
    total_pairs = len(reviews) * (len(reviews) - 1) // 2
    assert lsh.candidate_pairs < total_pairs / 50


def test_mode_switches_on_batch_size():
    assert find_duplicates(corpus(10), exact_max_batch=200).mode == "exact"
    assert find_duplicates(corpus(250), exact_max_batch=200).mode == "lsh"


def test_report_exposes_partners_with_similarity():
    reviews = [make("a", "same text here"), make("b", "same text here")]
    report = find_duplicates(reviews)
    partners = report.partners("a")
    assert partners[0][0] == "b"
    assert partners[0][1] >= 0.85
    assert report.ids() == {"a", "b"}


def test_minhash_is_order_independent():
    assert minhash_signature({"a b c", "d e f"}) == minhash_signature({"d e f", "a b c"})


def test_minhash_of_empty_input_is_empty():
    assert minhash_signature([]) == ()


def test_similar_documents_have_similar_signatures():
    left = word_shingles(matching_key("the quick brown fox jumps over the lazy dog"))
    right = word_shingles(matching_key("the quick brown fox jumps over the lazy cat"))
    other = word_shingles(matching_key("completely unrelated words about shipping costs"))

    left_sig = minhash_signature(left)
    agreement = sum(a == b for a, b in zip(left_sig, minhash_signature(right)))
    disagreement = sum(a == b for a, b in zip(left_sig, minhash_signature(other)))
    assert agreement > disagreement


def test_minhash_is_deterministic_across_processes():
    # Python's built-in hash() is salted per process; using it here would make
    # duplicate detection unreproducible, which would break audit replay.
    code = (
        "import sys; sys.path.insert(0, %r);"
        "from fake_review_detector.dedupe import minhash_signature;"
        "print(sum(minhash_signature({'the quick brown', 'quick brown fox'})))"
        % str(Path(__file__).resolve().parents[1])
    )
    outputs = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": seed, "PATH": ""},
        ).stdout.strip()
        for seed in ("0", "1", "12345")
    }
    assert len(outputs) == 1


def test_empty_matching_keys_do_not_all_collide():
    # Emoji-only reviews fold to an empty key. They must be compared to each
    # other on their actual text, not treated as mutually identical.
    reviews = [make("a", "🎉🎉🎉"), make("b", "🚀🚀🚀"), make("c", "🎉🎉🎉")]
    reviews += corpus(250)
    pairs = pair_set(find_duplicates(reviews, exact_max_batch=1))
    assert ("a", "c") in pairs
    assert ("a", "b") not in pairs
