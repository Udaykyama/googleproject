"""Choosing a threshold from measurements, not from taste.

A sweep over the whole labelled set shows which threshold scores best *on that
set*. Adopting it would be overfitting: the number reported would be the best
of many tried on the same data, which is optimistic by construction. So this
module does three things a sweep does not.

**It splits before it fits.** The threshold is chosen on the training half and
reported on a test half the calibration never saw.

**It splits by author, not by review.** Fake reviews arrive in bursts from one
account. Splitting per review would put a farm's output on both sides, so the
model would be tested on authors it was tuned on — the leak that makes offline
numbers look better than production. Grouping by author costs some balance in
the split and is worth it.

**It reports uncertainty.** On a few dozen reviews, precision 0.94 and 0.79 can
be the same number wearing different hats. Every rate comes with a Wilson
score interval, and :func:`calibrate` refuses to claim an improvement whose
interval overlaps the incumbent's. A confidence interval is not a formality
here: it is the difference between calibrating and fitting noise.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from math import sqrt
from typing import Callable, Iterable, Sequence

from .engine import score_batch
from .evaluation import LabelledReview, Metrics
from .policy import Policy

__all__ = [
    "Interval",
    "Split",
    "CalibrationResult",
    "wilson_interval",
    "split_by_author",
    "calibrate",
    "precision_at_prevalence",
    "OBJECTIVES",
    "TYPICAL_PREVALENCE",
]


@dataclass(frozen=True)
class Interval:
    """A proportion and its confidence interval."""

    value: float
    low: float
    high: float

    @property
    def width(self) -> float:
        return self.high - self.low

    def overlaps(self, other: "Interval") -> bool:
        return self.low <= other.high and other.low <= self.high

    def __str__(self) -> str:
        return f"{self.value:.3f} [{self.low:.3f}-{self.high:.3f}]"

    def to_dict(self) -> dict:
        return {
            "value": round(self.value, 4),
            "low": round(self.low, 4),
            "high": round(self.high, 4),
        }


def wilson_interval(successes: int, total: int, z: float = 1.96) -> Interval:
    """Wilson score interval for a proportion.

    Preferred over the textbook normal approximation because it stays inside
    [0, 1] and keeps its nerve at the extremes: 15/15 successes gives a lower
    bound near 0.8, not the 1.0 the normal approximation would claim. On sample
    sizes this small that difference is the whole point.
    """

    if total <= 0:
        return Interval(0.0, 0.0, 1.0)
    if successes < 0 or successes > total:
        raise ValueError("successes must be between 0 and total")

    proportion = successes / total
    denominator = 1 + z * z / total
    centre = proportion + z * z / (2 * total)
    spread = z * sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total))
    return Interval(
        value=proportion,
        low=max(0.0, (centre - spread) / denominator),
        high=min(1.0, (centre + spread) / denominator),
    )


def precision_at_prevalence(
    recall: float, false_positive_rate: float, prevalence: float
) -> float:
    """Precision this detector would show on a stream that is ``prevalence`` fake.

    Recall and false-positive rate are properties of the detector; precision is
    a property of the detector *and the population it runs on*. Reporting the
    precision measured on a balanced evaluation set as though it were the
    production number is the single easiest way to overstate a moderation
    system, so this makes the translation explicit.
    """

    if not 0.0 <= prevalence <= 1.0:
        raise ValueError(f"prevalence must be in [0, 1], got {prevalence}")
    true_positives = prevalence * recall
    false_positives = (1.0 - prevalence) * false_positive_rate
    flagged = true_positives + false_positives
    if flagged <= 0.0:
        return 0.0
    return true_positives / flagged


def _precision_interval(metrics: Metrics) -> Interval:
    flagged = metrics.true_positives + metrics.false_positives
    return wilson_interval(metrics.true_positives, flagged)


def _recall_interval(metrics: Metrics) -> Interval:
    actual = metrics.true_positives + metrics.false_negatives
    return wilson_interval(metrics.true_positives, actual)


def _false_positive_rate_interval(metrics: Metrics) -> Interval:
    genuine = metrics.false_positives + metrics.true_negatives
    return wilson_interval(metrics.false_positives, genuine)


@dataclass(frozen=True)
class Split:
    """A grouped train/test split of labelled data."""

    train: tuple[LabelledReview, ...]
    test: tuple[LabelledReview, ...]

    def counts(self) -> dict:
        def summarise(items: Sequence[LabelledReview]) -> dict:
            fake = sum(1 for item in items if item.is_fake)
            return {"total": len(items), "fake": fake, "genuine": len(items) - fake}

        return {"train": summarise(self.train), "test": summarise(self.test)}

    def leaking_authors(self) -> set[str]:
        """Authors present in both halves. Must always be empty."""

        return {item.review.author for item in self.train} & {
            item.review.author for item in self.test
        }


def _author_bucket(author: str, salt: str) -> float:
    """Stable position in [0, 1) for an author.

    Uses blake2b rather than ``hash()``: Python salts string hashing per
    process, so ``hash()`` would silently reshuffle the split between runs and
    make every reported number unreproducible.
    """

    digest = hashlib.blake2b(
        f"{salt}:{author}".encode("utf-8"), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big") / float(1 << 64)


def split_by_author(
    labelled: Iterable[LabelledReview],
    *,
    test_fraction: float = 0.4,
    salt: str = "fake-review-calibration-v1",
) -> Split:
    """Split so that no author appears in both halves.

    ``test_fraction`` is applied to authors, so the review counts will not land
    exactly on it — prolific authors move as a block. That is the intended
    trade-off.
    """

    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be between 0 and 1 exclusive")

    items = list(labelled)
    authors = sorted({item.review.author for item in items})
    test_authors = {
        author for author in authors if _author_bucket(author, salt) < test_fraction
    }

    train = tuple(item for item in items if item.review.author not in test_authors)
    test = tuple(item for item in items if item.review.author in test_authors)
    return Split(train=train, test=test)


def _metrics_at(
    score_by_id: dict[str, int],
    labelled: Sequence[LabelledReview],
    threshold: int,
) -> Metrics:
    tp = fp = tn = fn = 0
    for item in labelled:
        flagged = score_by_id.get(item.review.review_id, 0) >= threshold
        if flagged and item.is_fake:
            tp += 1
        elif flagged and not item.is_fake:
            fp += 1
        elif not flagged and item.is_fake:
            fn += 1
        else:
            tn += 1
    return Metrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        threshold=threshold,
    )


def _objective_f1(metrics: Metrics, recall_floor: float) -> float:
    return metrics.f1


def _objective_precision_at_recall(metrics: Metrics, recall_floor: float) -> float:
    """Maximise precision subject to a recall floor.

    The moderation-shaped objective. Missing fakes is bad, but every false
    positive is a real person's writing in a queue, so precision is what to
    push once recall is adequate. Below the floor the candidate is rejected
    outright rather than traded off.
    """

    if metrics.recall < recall_floor:
        return -1.0
    return metrics.precision


def _objective_youden(metrics: Metrics, recall_floor: float) -> float:
    return metrics.recall - metrics.false_positive_rate


#: Selectable objectives. Each maps (metrics, recall_floor) to a score to maximise.
OBJECTIVES: dict[str, Callable[[Metrics, float], float]] = {
    "f1": _objective_f1,
    "precision_at_recall": _objective_precision_at_recall,
    "youden": _objective_youden,
}


@dataclass(frozen=True)
class CalibrationResult:
    """A chosen threshold, and what it did on data it was not chosen on."""

    threshold: int
    objective: str
    incumbent: int
    train: Metrics
    test: Metrics
    incumbent_test: Metrics
    precision: Interval
    recall: Interval
    false_positive_rate: Interval
    incumbent_precision: Interval
    incumbent_recall: Interval
    incumbent_false_positive_rate: Interval
    split_counts: dict
    #: True when the test-set precision intervals of the candidate and the
    #: incumbent overlap — i.e. the data cannot tell them apart.
    inconclusive: bool
    warnings: tuple[str, ...] = ()

    @property
    def recommended(self) -> bool:
        """Whether the evidence supports changing the incumbent threshold.

        Separated confidence intervals are necessary but not sufficient. A
        small test split can separate two intervals by luck, so any sample-size
        warning also blocks the recommendation: the honest answer on thin data
        is "get more data", not "ship the winner".
        """

        return (
            not self.inconclusive
            and not self.warnings
            and self.threshold != self.incumbent
        )

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "objective": self.objective,
            "incumbent": self.incumbent,
            "recommended": self.recommended,
            "inconclusive": self.inconclusive,
            "split": self.split_counts,
            "train": self.train.to_dict(),
            "test": self.test.to_dict(),
            "incumbent_test": self.incumbent_test.to_dict(),
            "test_precision": self.precision.to_dict(),
            "test_recall": self.recall.to_dict(),
            "test_false_positive_rate": self.false_positive_rate.to_dict(),
            "incumbent_test_precision": self.incumbent_precision.to_dict(),
            "incumbent_test_recall": self.incumbent_recall.to_dict(),
            "incumbent_test_false_positive_rate": (
                self.incumbent_false_positive_rate.to_dict()
            ),
            "precision_at_prevalence": {
                f"{prevalence:.2f}": round(
                    precision_at_prevalence(
                        self.recall.low, self.false_positive_rate.high, prevalence
                    ),
                    4,
                )
                for prevalence in (0.37, 0.20, 0.10, 0.05)
            },
            "warnings": list(self.warnings),
        }

    def format_report(self) -> str:
        """A report that leads with the verdict, not the winning number."""

        counts = self.split_counts
        lines = [
            f"objective        {self.objective}",
            f"split            {counts['train']['total']} train "
            f"({counts['train']['fake']} fake) / {counts['test']['total']} test "
            f"({counts['test']['fake']} fake), grouped by author",
            f"candidate        threshold {self.threshold}",
            f"incumbent        threshold {self.incumbent}",
            "",
            "Held-out test set (the only numbers that mean anything):",
            f"  {'':<12} {'precision':>22}  {'recall':>22}",
            f"  {'candidate':<12} {str(self.precision):>22}"
            f"  {str(self.recall):>22}",
            f"  {'incumbent':<12} {str(self.incumbent_precision):>22}"
            f"  {str(self.incumbent_recall):>22}",
            "",
        ]
        if self.threshold == self.incumbent:
            lines.append("VERDICT: keep the current threshold; the sweep chose it too.")
        elif self.warnings and not self.inconclusive:
            lines.append(
                f"VERDICT: threshold {self.threshold} looks better than "
                f"{self.incumbent}, but the test split is too small to act on. "
                f"Treat this as a reason to collect more labelled data, not as "
                f"a licence to change the default."
            )
        elif self.inconclusive:
            lines.append(
                "VERDICT: not enough evidence to change the threshold. The "
                "candidate and incumbent confidence intervals overlap, so this "
                "data cannot tell them apart."
            )
        else:
            lines.append(
                f"VERDICT: the evidence supports moving the threshold to "
                f"{self.threshold}."
            )
        if self.warnings:
            lines.append("")
            lines.append("Warnings:")
            lines.extend(f"  - {warning}" for warning in self.warnings)
        return "\n".join(lines)


#: Plausible range for the true share of fake reviews on a live platform.
#: Published research corpora are built at or near 50/50 because a balanced set
#: is easier to learn from, but real prevalence is far lower. This matters more
#: than it looks: recall and false-positive rate do not depend on prevalence,
#: but *precision* does, and it collapses as prevalence falls. A detector
#: measured at 0.78 precision on a 37%-fake set is at 0.24 on a 5%-fake stream
#: -- three of every four flags wrong -- without a single line of code changing.
TYPICAL_PREVALENCE = (0.05, 0.20)


#: Below this many test reviews, any difference between thresholds is noise.
MIN_TEST_REVIEWS = 200
#: Below this many fakes in the test half, recall is barely measurable.
MIN_TEST_FAKES = 30


def calibrate(
    labelled: Sequence[LabelledReview],
    policy: Policy | None = None,
    *,
    objective: str = "precision_at_recall",
    recall_floor: float = 0.90,
    start: int = 0,
    stop: int = 100,
    step: int = 5,
    test_fraction: float = 0.4,
    salt: str = "fake-review-calibration-v1",
) -> CalibrationResult:
    """Pick a threshold on a training split and report it on a held-out one.

    The returned :attr:`CalibrationResult.recommended` is deliberately hard to
    set: it requires the candidate to beat the incumbent on test data by more
    than the confidence intervals can explain. On a small set it will almost
    always be ``False``, which is the correct answer rather than a failure.
    """

    if objective not in OBJECTIVES:
        raise ValueError(
            f"unknown objective {objective!r}; choose from {sorted(OBJECTIVES)}"
        )
    if step <= 0:
        raise ValueError("step must be positive")
    if not 0.0 <= recall_floor <= 1.0:
        raise ValueError("recall_floor must be between 0 and 1")

    policy = policy or Policy()
    items = list(labelled)
    if not items:
        raise ValueError("no labelled reviews to calibrate on")

    fakes = sum(1 for item in items if item.is_fake)
    if fakes == 0 or fakes == len(items):
        # With one class present, recall or false-positive rate is undefined and
        # every threshold scores identically, so the sweep would return an
        # arbitrary winner that looks like a real result.
        present = "fake" if fakes else "genuine"
        raise ValueError(
            f"calibration needs both classes; all {len(items)} review(s) are {present}"
        )

    split = split_by_author(items, test_fraction=test_fraction, salt=salt)
    if not split.train or not split.test:
        raise ValueError(
            "the author split produced an empty half; the labelled set needs "
            "reviews from more distinct authors"
        )

    # Score once, then re-threshold. Scoring is the expensive part and the
    # scores do not depend on the threshold.
    scores, _ = score_batch([item.review for item in items], policy)
    score_by_id = {s.review_id: s.score for s in scores}

    score_objective = OBJECTIVES[objective]
    best_threshold = policy.medium_threshold
    best_value = float("-inf")
    for threshold in range(start, stop + 1, step):
        value = score_objective(_metrics_at(score_by_id, split.train, threshold), recall_floor)
        # Strict > keeps the lowest threshold among ties, which is the
        # conservative choice: it flags more, and flagging enqueues for review.
        if value > best_value:
            best_value, best_threshold = value, threshold

    test = _metrics_at(score_by_id, split.test, best_threshold)
    incumbent_test = _metrics_at(score_by_id, split.test, policy.medium_threshold)
    precision = _precision_interval(test)
    incumbent_precision = _precision_interval(incumbent_test)

    warnings: list[str] = []
    test_fakes = test.true_positives + test.false_negatives
    if len(split.test) < MIN_TEST_REVIEWS:
        warnings.append(
            f"test split has {len(split.test)} review(s); at least "
            f"{MIN_TEST_REVIEWS} are needed before a threshold change is "
            "defensible"
        )
    if test_fakes < MIN_TEST_FAKES:
        warnings.append(
            f"test split has {test_fakes} fake review(s); recall is not "
            f"meaningfully measurable below about {MIN_TEST_FAKES}"
        )
    leaks = split.leaking_authors()
    if leaks:  # pragma: no cover - split_by_author makes this unreachable
        warnings.append(f"author leakage between splits: {sorted(leaks)}")

    return CalibrationResult(
        threshold=best_threshold,
        objective=objective,
        incumbent=policy.medium_threshold,
        train=_metrics_at(score_by_id, split.train, best_threshold),
        test=test,
        incumbent_test=incumbent_test,
        precision=precision,
        recall=_recall_interval(test),
        incumbent_precision=incumbent_precision,
        incumbent_recall=_recall_interval(incumbent_test),
        false_positive_rate=_false_positive_rate_interval(test),
        incumbent_false_positive_rate=_false_positive_rate_interval(incumbent_test),
        split_counts=split.counts(),
        inconclusive=precision.overlaps(incumbent_precision),
        warnings=tuple(warnings),
    )
