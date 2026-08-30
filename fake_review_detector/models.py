"""Core data types for the moderation pipeline.

The flow is ``Review`` → ``SignalHit`` list → ``ReviewScore`` → ``ModerationDecision``.

Enumerations subclass :class:`str` so that ``RiskLevel.HIGH == "high"`` holds.
That keeps the pre-existing string-comparison API working and makes every type
here JSON-serialisable without a custom encoder.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

__all__ = [
    "Review",
    "SignalHit",
    "ReviewScore",
    "ModerationDecision",
    "Action",
    "RiskLevel",
    "RISK_HIGH",
    "RISK_MEDIUM",
    "RISK_LOW",
    "utc_now_iso",
]


def utc_now_iso() -> str:
    """Timezone-aware UTC timestamp, second precision, for decision records."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class RiskLevel(str, Enum):
    """How likely a review is to be inauthentic."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Action(str, Enum):
    """The enforcement outcome of a moderation decision.

    Ordered by severity. ``ENQUEUE`` is the safety valve: it defers to a human
    rather than acting automatically, and is where anything uncertain lands.
    """

    ALLOW = "allow"
    MONITOR = "monitor"
    ENQUEUE = "enqueue"
    REMOVE = "remove"


# Retained as module-level names because the original public API exposed them.
RISK_HIGH = RiskLevel.HIGH
RISK_MEDIUM = RiskLevel.MEDIUM
RISK_LOW = RiskLevel.LOW


@dataclass(frozen=True)
class Review:
    """A single review submitted for moderation.

    Frozen so that a decision record always corresponds to exactly the content
    that was scored; use :func:`dataclasses.replace` to derive a cleaned copy.
    """

    review_id: str
    author: str
    rating: int
    text: str
    verified_purchase: bool = True
    account_age_days: int | None = None
    date: str | None = None  # ISO date, e.g. "2024-05-01"

    def content_digest(self) -> str:
        """Stable digest of the fields that moderation actually reads.

        Lets an audit record prove *which* content produced a decision, and lets
        a re-run detect that a review was edited after being decided on.
        """

        payload = json.dumps(
            {
                "review_id": self.review_id,
                "author": self.author,
                "rating": self.rating,
                "text": self.text,
                "verified_purchase": self.verified_purchase,
                "account_age_days": self.account_age_days,
                "date": self.date,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.blake2b(payload.encode("utf-8"), digest_size=16).hexdigest()


@dataclass(frozen=True)
class SignalHit:
    """One detection signal that fired on a review.

    ``code`` is a stable machine-readable identifier. Prose messages get
    reworded over time; codes are what dashboards aggregate on and what appeal
    workflows key off, so they must not change once published.

    ``evidence`` records *why* the signal fired (the phrase matched, the peer
    review id, the observed count). Without it a moderator cannot audit a
    decision and a user cannot meaningfully appeal it.
    """

    code: str
    weight: int
    message: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "weight": self.weight,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass
class ReviewScore:
    """Aggregate score for one review.

    ``reasons`` is kept as a list of human-readable strings for the original
    API; ``signals`` carries the structured form used by the decision layer.
    """

    review_id: str
    score: int
    risk_level: RiskLevel
    reasons: list[str] = field(default_factory=list)
    signals: list[SignalHit] = field(default_factory=list)

    @property
    def codes(self) -> list[str]:
        """Stable signal codes that fired, in weight order."""

        return [s.code for s in self.signals]

    def to_dict(self) -> dict:
        return {
            "review_id": self.review_id,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "reasons": list(self.reasons),
            "signals": [s.to_dict() for s in self.signals],
        }


@dataclass(frozen=True)
class ModerationDecision:
    """An enforcement decision, and everything needed to justify it later.

    Carries the policy version and digest so a decision made months ago can be
    reproduced against the exact configuration that produced it, and the content
    digest so an edited review is not mistaken for the one that was judged.
    """

    review_id: str
    action: Action
    risk_level: RiskLevel
    score: int
    signals: list[SignalHit]
    policy_version: str
    policy_digest: str
    content_digest: str
    decided_at: str = field(default_factory=utc_now_iso)
    appealable: bool = True

    @property
    def requires_human_review(self) -> bool:
        return self.action is Action.ENQUEUE

    @property
    def reasons(self) -> list[str]:
        return [s.message for s in self.signals]

    @property
    def codes(self) -> list[str]:
        return [s.code for s in self.signals]

    def to_dict(self) -> dict:
        return {
            "review_id": self.review_id,
            "action": self.action.value,
            "risk_level": self.risk_level.value,
            "score": self.score,
            "signals": [s.to_dict() for s in self.signals],
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "content_digest": self.content_digest,
            "decided_at": self.decided_at,
            "appealable": self.appealable,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "ModerationDecision":
        return cls(
            review_id=payload["review_id"],
            action=Action(payload["action"]),
            risk_level=RiskLevel(payload["risk_level"]),
            score=payload["score"],
            signals=[
                SignalHit(
                    code=s["code"],
                    weight=s["weight"],
                    message=s["message"],
                    evidence=s.get("evidence", {}),
                )
                for s in payload.get("signals", [])
            ],
            policy_version=payload["policy_version"],
            policy_digest=payload["policy_digest"],
            content_digest=payload["content_digest"],
            decided_at=payload["decided_at"],
            appealable=payload.get("appealable", True),
        )
