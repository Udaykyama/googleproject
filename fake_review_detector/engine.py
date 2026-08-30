"""The moderation engine: signals in, enforcement decisions out.

Separated from :mod:`fake_review_detector.signals` because scoring and
*enforcement* are different concerns with different failure modes. A wrong score
is a tuning problem; a wrong enforcement action deletes someone's speech. The
policy decides what a score means, and this module never removes content on its
own initiative — see :meth:`Policy.action_for`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .dedupe import DuplicateReport, find_duplicates
from .errors import ValidationError
from .models import (
    Action,
    ModerationDecision,
    Review,
    ReviewScore,
    RiskLevel,
    SignalHit,
)
from .policy import Policy
from .signals import evaluate_review
from .validation import validate_batch, validate_review

__all__ = ["BatchResult", "moderate", "moderate_batch", "score_batch"]


@dataclass
class BatchResult:
    """Everything produced by one batch run, including what went wrong."""

    decisions: list[ModerationDecision] = field(default_factory=list)
    scores: list[ReviewScore] = field(default_factory=list)
    errors: list[ValidationError] = field(default_factory=list)
    duplicate_report: DuplicateReport | None = None
    policy_version: str = ""
    policy_digest: str = ""

    @property
    def accepted(self) -> int:
        return len(self.decisions)

    @property
    def rejected(self) -> int:
        return len(self.errors)

    def by_action(self) -> dict[str, int]:
        counts = {action.value: 0 for action in Action}
        for decision in self.decisions:
            counts[decision.action.value] += 1
        return counts

    def needing_review(self) -> list[ModerationDecision]:
        return [d for d in self.decisions if d.requires_human_review]

    def to_dict(self) -> dict:
        report = self.duplicate_report
        return {
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "actions": self.by_action(),
            "duplicates": {
                "mode": report.mode if report else "exact",
                "pairs": len(report.pairs) if report else 0,
                "candidate_pairs": report.candidate_pairs if report else 0,
            },
            "decisions": [d.to_dict() for d in self.decisions],
            "errors": [
                {"review_id": e.review_id, "field": e.field, "message": str(e.args[0])}
                for e in self.errors
            ],
        }


def _batch_signals(
    reviews: Sequence[Review], policy: Policy, report: DuplicateReport
) -> dict[str, list[SignalHit]]:
    """Signals that only exist across a batch: duplicates and bursts."""

    by_id = {r.review_id: r for r in reviews}
    hits: dict[str, list[SignalHit]] = {r.review_id: [] for r in reviews}

    duplicate_weight = policy.weight("NEAR_DUPLICATE_TEXT")
    template_weight = policy.weight("REPEATED_AUTHOR_TEMPLATE")
    for review_id in report.ids():
        partners = report.partners(review_id)
        if duplicate_weight > 0:
            hits[review_id].append(
                SignalHit(
                    code="NEAR_DUPLICATE_TEXT",
                    weight=duplicate_weight,
                    message="near-duplicate text shared with another review",
                    evidence={
                        "matches": [
                            {"review_id": pid, "similarity": round(sim, 4)}
                            for pid, sim in partners[:5]
                        ],
                        "match_count": len(partners),
                    },
                )
            )
        # Duplicate text from the *same* author is a stronger signal than
        # duplicate text across accounts: it is one person copy-pasting.
        if template_weight > 0:
            author = by_id[review_id].author
            same_author = [
                pid for pid, _ in partners if by_id[pid].author == author
            ]
            if same_author:
                hits[review_id].append(
                    SignalHit(
                        code="REPEATED_AUTHOR_TEMPLATE",
                        weight=template_weight,
                        message="author reused near-identical text across reviews",
                        evidence={
                            "review_ids": sorted(same_author)[:5],
                            "match_count": len(same_author),
                        },
                    )
                )

    burst_weight = policy.weight("AUTHOR_BURST")
    if burst_weight > 0:
        counts: dict[tuple[str, str], int] = {}
        for review in reviews:
            if review.date:
                key = (review.author, review.date)
                counts[key] = counts.get(key, 0) + 1
        for review in reviews:
            if not review.date:
                continue
            observed = counts.get((review.author, review.date), 0)
            if observed >= policy.burst_review_count:
                hits[review.review_id].append(
                    SignalHit(
                        code="AUTHOR_BURST",
                        weight=burst_weight,
                        message=(
                            "review burst: author posted "
                            f"{observed} reviews on {review.date}"
                        ),
                        evidence={
                            "author": review.author,
                            "date": review.date,
                            "count": observed,
                        },
                    )
                )

    return hits


def score_batch(
    reviews: Sequence[Review], policy: Policy | None = None
) -> tuple[list[ReviewScore], DuplicateReport]:
    """Score already-validated reviews, including cross-review signals."""

    policy = policy or Policy()
    reviews = list(reviews)
    report = find_duplicates(
        reviews,
        threshold=policy.duplicate_similarity_threshold,
        exact_max_batch=policy.exact_dedupe_max_batch,
    )
    batch_hits = _batch_signals(reviews, policy, report)

    scores: list[ReviewScore] = []
    for review in reviews:
        hits = evaluate_review(review, policy) + batch_hits.get(review.review_id, [])
        hits.sort(key=lambda h: (-h.weight, h.code))
        total = max(0, min(100, sum(h.weight for h in hits)))
        scores.append(
            ReviewScore(
                review_id=review.review_id,
                score=total,
                risk_level=policy.risk_level(total),
                reasons=[h.message for h in hits],
                signals=hits,
            )
        )
    return scores, report


def _decide(review: Review, score: ReviewScore, policy: Policy) -> ModerationDecision:
    action = policy.action_for(score.risk_level, score.score)
    return ModerationDecision(
        review_id=review.review_id,
        action=action,
        risk_level=score.risk_level,
        score=score.score,
        signals=list(score.signals),
        policy_version=policy.version,
        policy_digest=policy.digest(),
        content_digest=review.content_digest(),
    )


def moderate(
    review: Review | dict, policy: Policy | None = None
) -> ModerationDecision:
    """Validate, score and decide on a single review.

    Cross-review signals cannot fire on a batch of one, so a review moderated
    alone may score lower than the same review inside its batch.
    """

    policy = policy or Policy()
    validated = validate_review(review)
    scores, _ = score_batch([validated], policy)
    return _decide(validated, scores[0], policy)


def moderate_batch(
    items: Iterable[Review | dict],
    policy: Policy | None = None,
    *,
    max_items: int | None = None,
) -> BatchResult:
    """Validate, score and decide on a batch.

    Invalid items are collected in ``errors`` rather than aborting the run: one
    malformed submission must not stall a moderation queue.
    """

    policy = policy or Policy()
    reviews, errors = validate_batch(items, max_items=max_items)
    scores, report = score_batch(reviews, policy)
    by_id = {r.review_id: r for r in reviews}

    scores.sort(key=lambda s: (-s.score, s.review_id))
    decisions = [_decide(by_id[s.review_id], s, policy) for s in scores]

    return BatchResult(
        decisions=decisions,
        scores=scores,
        errors=errors,
        duplicate_report=report,
        policy_version=policy.version,
        policy_digest=policy.digest(),
    )
