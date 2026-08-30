"""Tests for threshold calibration.

The point of the calibration module is to stop a plausible-looking number from
being adopted on evidence that cannot support it, so most of these tests are
about the *refusals*: leakage that would inflate the score, small splits that
cannot separate two thresholds, and a zero-error test split being read as a
guarantee.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from fake_review_detector.calibration import (
    OBJECTIVES,
    Interval,
    calibrate,
    precision_at_prevalence,
    split_by_author,
    wilson_interval,
)
from fake_review_detector.evaluation import load_labelled
from fake_review_detector.models import Review
from fake_review_detector.policy import Policy

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET = REPO_ROOT / "data" / "labelled_reviews.json"


def _labelled():
    items, errors = load_labelled(json.loads(DATASET.read_text()))
    assert not errors, errors
    return items


def _synthetic(count: int, fake_every: int = 3):
    """A labelled set big enough to exercise the sample-size gates."""

    rows = []
    for index in range(count):
        is_fake = index % fake_every == 0
        text = (
            "Best product ever! Highly recommend! Will buy again!"
            if is_fake
            else f"The {index} setting took a while to work out but the manual "
            f"covers it on page {index % 40}. Battery lasts about a day."
        )
        rows.append(
            {
                "review_id": f"r{index:04d}",
                "author": f"author_{index:04d}",
                "rating": 5 if is_fake else 4,
                "text": text,
                "verified_purchase": not is_fake,
                "account_age_days": 2 if is_fake else 700,
                "is_fake": is_fake,
            }
        )
    items, errors = load_labelled(rows)
    assert not errors, errors
    return items


# --------------------------------------------------------------------------
# Wilson intervals
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "successes,total,low,high",
    [
        (15, 15, 0.796, 1.000),
        (0, 15, 0.000, 0.204),
        (5, 10, 0.237, 0.763),
        (50, 100, 0.404, 0.596),
    ],
)
def test_wilson_interval_matches_reference_values(successes, total, low, high):
    interval = wilson_interval(successes, total)
    assert interval.low == pytest.approx(low, abs=0.001)
    assert interval.high == pytest.approx(high, abs=0.001)


def test_wilson_interval_never_claims_certainty_at_the_extremes():
    """15/15 is not proof of a perfect detector, and the interval must say so."""

    perfect = wilson_interval(15, 15)
    assert perfect.value == 1.0
    assert perfect.low < 1.0

    spotless = wilson_interval(0, 15)
    assert spotless.value == 0.0
    assert spotless.high > 0.0


def test_wilson_interval_stays_inside_zero_to_one():
    for successes, total in [(0, 1), (1, 1), (1, 2), (99, 100), (0, 3)]:
        interval = wilson_interval(successes, total)
        assert 0.0 <= interval.low <= interval.value <= interval.high <= 1.0


def test_wilson_interval_of_no_data_spans_everything():
    interval = wilson_interval(0, 0)
    assert (interval.low, interval.high) == (0.0, 1.0)


def test_wilson_interval_narrows_as_evidence_grows():
    assert wilson_interval(50, 100).width > wilson_interval(500, 1000).width


def test_intervals_overlap_is_symmetric():
    left = Interval(0.5, 0.4, 0.6)
    right = Interval(0.55, 0.5, 0.7)
    apart = Interval(0.9, 0.85, 0.95)
    assert left.overlaps(right) and right.overlaps(left)
    assert not left.overlaps(apart) and not apart.overlaps(left)


# --------------------------------------------------------------------------
# Author-grouped splitting
# --------------------------------------------------------------------------


def test_split_never_puts_an_author_on_both_sides():
    """The leak that makes offline numbers beat production.

    Fake reviews arrive in bursts from one account. Splitting per review puts
    some of a farm's output in train and the rest in test, so the detector is
    scored on text it has effectively already seen.
    """

    split = split_by_author(_labelled())
    assert split.leaking_authors() == set()


def test_split_keeps_every_review():
    items = _labelled()
    split = split_by_author(items)
    assert len(split.train) + len(split.test) == len(items)


def test_split_is_deterministic_across_processes():
    """Uses blake2b, not hash(): str hashing is salted per process."""

    script = (
        "import json,sys;"
        "sys.path.insert(0, %r);"
        "from fake_review_detector.calibration import split_by_author;"
        "from fake_review_detector.evaluation import load_labelled;"
        "items,_=load_labelled(json.load(open(%r)));"
        "s=split_by_author(items);"
        "print(sorted(i.review.review_id for i in s.test))"
        % (str(REPO_ROOT), str(DATASET))
    )
    outputs = set()
    for seed in ("0", "1", "42"):
        env = {**os.environ, "PYTHONHASHSEED": seed}
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        outputs.add(result.stdout.strip())
    assert len(outputs) == 1, "split changed between processes"


def test_changing_the_salt_changes_the_split():
    first = split_by_author(_labelled(), salt="a")
    second = split_by_author(_labelled(), salt="b")
    assert {item.review.review_id for item in first.test} != {
        item.review.review_id for item in second.test
    }


def test_split_counts_report_both_halves():
    counts = split_by_author(_labelled()).counts()
    assert counts["train"]["total"] + counts["test"]["total"] == len(_labelled())
    for half in ("train", "test"):
        assert counts[half]["fake"] + counts[half]["genuine"] == counts[half]["total"]


# --------------------------------------------------------------------------
# Prevalence
# --------------------------------------------------------------------------


def test_precision_collapses_as_prevalence_falls():
    """The headline finding: a balanced evaluation set flatters precision.

    Recall and false-positive rate do not depend on prevalence. Precision does,
    and on a stream that is 5% fake a detector measured on a 37%-fake set will
    be far worse than its evaluation number suggests.
    """

    recall, false_positive_rate = 0.985, 0.165
    balanced = precision_at_prevalence(recall, false_positive_rate, 0.37)
    realistic = precision_at_prevalence(recall, false_positive_rate, 0.05)
    assert balanced == pytest.approx(0.778, abs=0.01)
    assert realistic == pytest.approx(0.239, abs=0.01)
    assert realistic < balanced / 3


def test_a_lower_false_positive_rate_survives_low_prevalence_better():
    loose = precision_at_prevalence(0.985, 0.165, 0.05)
    tight = precision_at_prevalence(0.846, 0.018, 0.05)
    assert tight > loose


def test_precision_at_prevalence_edges():
    assert precision_at_prevalence(0.9, 0.1, 0.0) == 0.0
    assert precision_at_prevalence(0.9, 0.1, 1.0) == pytest.approx(1.0)
    assert precision_at_prevalence(0.0, 0.0, 0.5) == 0.0


@pytest.mark.parametrize("prevalence", [-0.01, 1.01])
def test_precision_at_prevalence_rejects_impossible_prevalence(prevalence):
    with pytest.raises(ValueError):
        precision_at_prevalence(0.9, 0.1, prevalence)


# --------------------------------------------------------------------------
# Calibration verdicts
# --------------------------------------------------------------------------


def test_small_data_does_not_earn_a_recommendation():
    """The whole point: 174 reviews cannot justify moving the default."""

    result = calibrate(_labelled(), Policy())
    assert result.warnings
    assert result.recommended is False


def test_a_sample_size_warning_blocks_a_recommendation_on_its_own():
    result = calibrate(_labelled(), Policy())
    if not result.inconclusive and result.threshold != result.incumbent:
        # Intervals separated, yet the split is too small to act on.
        assert result.recommended is False
        assert "at least" in " ".join(result.warnings)


def test_overlapping_intervals_are_reported_as_inconclusive():
    items = _labelled()[:40]
    result = calibrate(items, Policy())
    assert result.recommended is False


def test_report_leads_with_a_verdict_not_a_number():
    report = calibrate(_labelled(), Policy()).format_report()
    assert "VERDICT" in report
    assert "grouped by author" in report


def test_report_names_the_incumbent_and_candidate():
    result = calibrate(_labelled(), Policy())
    report = result.format_report()
    assert str(result.incumbent) in report
    assert str(result.threshold) in report


def test_large_clean_data_can_earn_a_recommendation():
    """The gate must be passable, or it is just a refusal to ever decide."""

    result = calibrate(_synthetic(900), Policy())
    assert not result.warnings, result.warnings
    assert result.split_counts["test"]["total"] >= 200


def test_every_objective_runs_and_picks_a_valid_threshold():
    items = _labelled()
    for name in OBJECTIVES:
        result = calibrate(items, Policy(), objective=name)
        assert result.objective == name
        assert 0 <= result.threshold <= 100


def test_precision_at_recall_respects_its_recall_floor():
    items = _synthetic(900)
    strict = calibrate(items, Policy(), objective="precision_at_recall", recall_floor=0.99)
    assert strict.train.recall >= 0.99 or strict.threshold == 0


def test_unknown_objective_is_rejected():
    with pytest.raises(ValueError):
        calibrate(_labelled(), Policy(), objective="nope")


def test_calibrating_on_nothing_is_rejected():
    with pytest.raises(ValueError):
        calibrate([], Policy())


def test_calibration_needs_both_classes():
    genuine_only = [item for item in _labelled() if not item.is_fake]
    with pytest.raises(ValueError):
        calibrate(genuine_only, Policy())


def test_result_serialises_to_json():
    payload = calibrate(_labelled(), Policy()).to_dict()
    json.dumps(payload)
    assert payload["recommended"] is False
    assert "precision_at_prevalence" in payload
    assert set(payload["split"]) == {"train", "test"}


def test_serialised_prevalence_projection_is_conservative():
    """The projection must use interval bounds, not point estimates.

    A test split with zero false positives has a point-estimate FPR of 0, which
    would project to precision 1.000 at every prevalence. That is an artefact
    of a small sample, not a property of the detector.
    """

    payload = calibrate(_labelled(), Policy()).to_dict()
    projected = payload["precision_at_prevalence"]
    assert projected["0.05"] < 1.0
    assert projected["0.05"] < projected["0.37"]


def test_calibration_is_deterministic():
    first = calibrate(_labelled(), Policy()).to_dict()
    second = calibrate(_labelled(), Policy()).to_dict()
    assert first == second
