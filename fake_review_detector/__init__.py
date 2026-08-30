"""Fake Review Detector.

A dependency-free review moderation system: it validates untrusted review
submissions, scores them against a versioned policy, decides an enforcement
action, routes anything uncertain to human review, and records every decision in
a tamper-evident audit log. See ``RESEARCH.md`` for background on the problem.

Typical use::

    from fake_review_detector import moderate_batch
    result = moderate_batch(reviews)
    for decision in result.needing_review():
        ...

:func:`score_review` and :func:`score_reviews` remain available for callers of
the original scoring-only API.
"""

from .audit import AuditLog, replay
from .detector import score_review, score_reviews
from .engine import BatchResult, moderate, moderate_batch, score_batch
from .errors import AuditLogError, ModerationError, PolicyError, ValidationError
from .evaluation import Metrics, evaluate, threshold_sweep
from .models import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    Action,
    ModerationDecision,
    Review,
    ReviewScore,
    RiskLevel,
    SignalHit,
)
from .policy import Policy
from .queue import Outcome, QueueItem, QueueState, ReviewQueue
from .validation import validate_batch, validate_review

__all__ = [
    # Core types
    "Review",
    "ReviewScore",
    "SignalHit",
    "ModerationDecision",
    "Action",
    "RiskLevel",
    "RISK_HIGH",
    "RISK_MEDIUM",
    "RISK_LOW",
    # Pipeline
    "moderate",
    "moderate_batch",
    "score_batch",
    "BatchResult",
    "Policy",
    "validate_review",
    "validate_batch",
    # Operations
    "ReviewQueue",
    "QueueItem",
    "QueueState",
    "Outcome",
    "AuditLog",
    "replay",
    # Measurement
    "evaluate",
    "threshold_sweep",
    "Metrics",
    # Errors
    "ModerationError",
    "ValidationError",
    "PolicyError",
    "AuditLogError",
    # Original API
    "score_review",
    "score_reviews",
]
