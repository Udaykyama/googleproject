"""Measuring whether the system actually works.

The demo reported scores with no way to know if they were right. For moderation
that is the central question, because the two error types have very different
costs: a false negative leaves one fake review up, a false positive deletes a
real person's writing. Precision and false-positive rate therefore matter more
than raw accuracy — and on the naturally imbalanced data moderation sees,
accuracy is actively misleading, so it is reported last and never alone.

:func:`threshold_sweep` exists so a threshold is chosen from measurements rather
than picked because it looks round.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .engine import score_batch
from .errors import ValidationError
from .models import Review
from .policy import Policy
from .validation import validate_batch

__all__ = ["Metrics", "LabelledReview", "evaluate", "threshold_sweep", "load_labelled"]


@dataclass(frozen=True)
class LabelledReview:
    """A review with ground truth attached. ``is_fake`` is the label."""

    review: Review
    is_fake: bool


@dataclass(frozen=True)
class Metrics:
    """Confusion matrix and the rates derived from it."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    threshold: int

    @property
    def precision(self) -> float:
        """Of everything flagged, how much was actually fake."""

        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else 0.0

    @property
    def recall(self) -> float:
        """Of everything actually fake, how much was caught."""

        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else 0.0

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        if denominator == 0:
            return 0.0
        return 2 * self.precision * self.recall / denominator

    @property
    def false_positive_rate(self) -> float:
        """Share of genuine reviews wrongly flagged. The cost of over-blocking."""

        genuine = self.false_positives + self.true_negatives
        return self.false_positives / genuine if genuine else 0.0

    @property
    def accuracy(self) -> float:
        total = (
            self.true_positives
            + self.false_positives
            + self.true_negatives
            + self.false_negatives
        )
        correct = self.true_positives + self.true_negatives
        return correct / total if total else 0.0

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
        }

    def format_table(self) -> str:
        return (
            f"threshold {self.threshold}\n"
            f"  precision           {self.precision:.3f}\n"
            f"  recall              {self.recall:.3f}\n"
            f"  f1                  {self.f1:.3f}\n"
            f"  false positive rate {self.false_positive_rate:.3f}\n"
            f"  accuracy            {self.accuracy:.3f}\n"
            f"  TP {self.true_positives}  FP {self.false_positives}  "
            f"TN {self.true_negatives}  FN {self.false_negatives}"
        )


def load_labelled(
    items: Iterable[dict],
) -> tuple[list[LabelledReview], list[ValidationError]]:
    """Load reviews carrying an ``is_fake`` boolean label."""

    payloads: list[dict] = []
    labels: list[bool] = []
    errors: list[ValidationError] = []

    for item in items:
        if not isinstance(item, dict):
            errors.append(
                ValidationError(
                    f"labelled review must be an object, got {type(item).__name__}",
                    field="review",
                )
            )
            continue
        payload = dict(item)
        label = payload.pop("is_fake", None)
        if not isinstance(label, bool):
            errors.append(
                ValidationError(
                    "is_fake label is required and must be a boolean",
                    field="is_fake",
                    review_id=str(payload.get("review_id", "")) or None,
                )
            )
            continue
        payloads.append(payload)
        labels.append(label)

    reviews, validation_errors = validate_batch(payloads)
    errors.extend(validation_errors)

    # validate_batch drops invalid rows, so re-pair by id rather than position.
    label_by_id: dict[str, bool] = {}
    for payload, label in zip(payloads, labels):
        review_id = str(payload.get("review_id", "")).strip()
        if review_id:
            label_by_id[review_id] = label

    return (
        [
            LabelledReview(review=review, is_fake=label_by_id[review.review_id])
            for review in reviews
            if review.review_id in label_by_id
        ],
        errors,
    )


def evaluate(
    labelled: Sequence[LabelledReview],
    policy: Policy | None = None,
    threshold: int | None = None,
) -> Metrics:
    """Score the labelled set and compare against ground truth.

    A review counts as flagged when its score reaches ``threshold``, which
    defaults to the policy's medium threshold — the point at which the system
    stops leaving content alone.
    """

    policy = policy or Policy()
    if threshold is None:
        threshold = policy.medium_threshold

    labelled = list(labelled)
    scores, _ = score_batch([item.review for item in labelled], policy)
    score_by_id = {s.review_id: s.score for s in scores}

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


def threshold_sweep(
    labelled: Sequence[LabelledReview],
    policy: Policy | None = None,
    *,
    start: int = 0,
    stop: int = 100,
    step: int = 5,
) -> list[Metrics]:
    """Metrics across a range of thresholds.

    Reviews are scored once and re-thresholded, so the sweep costs the same as a
    single evaluation.
    """

    if step <= 0:
        raise ValueError("step must be positive")

    policy = policy or Policy()
    labelled = list(labelled)
    scores, _ = score_batch([item.review for item in labelled], policy)
    score_by_id = {s.review_id: s.score for s in scores}

    results: list[Metrics] = []
    for threshold in range(start, stop + 1, step):
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
        results.append(
            Metrics(
                true_positives=tp,
                false_positives=fp,
                true_negatives=tn,
                false_negatives=fn,
                threshold=threshold,
            )
        )
    return results
