"""Versioned moderation policy.

Weights and thresholds are configuration, not code. A moderation system has to
answer "why was this removed?" months later, which means the exact settings in
force at decision time must be recoverable. Every :class:`Policy` therefore has
a ``version`` and a content ``digest``, both recorded on each decision.

Loaded policies are validated up front and raise :class:`PolicyError` on any
problem: a typo in a weight must fail at startup, not silently mis-moderate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .errors import PolicyError
from .models import Action, RiskLevel

__all__ = ["Policy", "SIGNAL_CODES", "DEFAULT_POLICY_VERSION"]

DEFAULT_POLICY_VERSION = "2024.11.0"

#: Every signal the engine can emit. A policy that weights an unknown code is
#: rejected, which catches renames and typos before they reach production.
SIGNAL_CODES = (
    "GENERIC_PHRASE",
    "LOW_EFFORT_EXTREME_RATING",
    "SHOUTY_TEXT",
    "UNVERIFIED_PURCHASE",
    "NEW_ACCOUNT",
    "NEAR_DUPLICATE_TEXT",
    "AUTHOR_BURST",
    "MIXED_SCRIPT_TEXT",
    "REPEATED_AUTHOR_TEMPLATE",
)

_DEFAULT_WEIGHTS: Mapping[str, int] = {
    "GENERIC_PHRASE": 25,
    "LOW_EFFORT_EXTREME_RATING": 20,
    "SHOUTY_TEXT": 15,
    "UNVERIFIED_PURCHASE": 20,
    "NEW_ACCOUNT": 20,
    "NEAR_DUPLICATE_TEXT": 25,
    "AUTHOR_BURST": 20,
    "MIXED_SCRIPT_TEXT": 15,
    "REPEATED_AUTHOR_TEMPLATE": 20,
}

_DEFAULT_ACTIONS: Mapping[str, str] = {
    "low": Action.ALLOW.value,
    "medium": Action.ENQUEUE.value,
    "high": Action.ENQUEUE.value,
}


@dataclass(frozen=True)
class Policy:
    """Weights, thresholds and enforcement mapping for one policy version."""

    version: str = DEFAULT_POLICY_VERSION
    weights: Mapping[str, int] = field(default_factory=lambda: dict(_DEFAULT_WEIGHTS))
    medium_threshold: int = 30
    high_threshold: int = 60
    actions: Mapping[str, str] = field(default_factory=lambda: dict(_DEFAULT_ACTIONS))
    # Heuristics alone must not delete user content. Automatic removal stays off
    # unless an operator turns it on deliberately and has measured precision.
    allow_auto_removal: bool = False
    auto_removal_threshold: int = 90
    new_account_days: int = 3
    short_review_word_count: int = 6
    duplicate_similarity_threshold: float = 0.85
    burst_review_count: int = 3
    # Above this batch size, candidate pairs come from LSH blocking instead of
    # comparing every pair. See :mod:`fake_review_detector.dedupe`.
    exact_dedupe_max_batch: int = 200

    def __post_init__(self) -> None:
        # Merge over the defaults so a caller can override a single weight
        # without restating the whole table; unknown codes are still rejected.
        merged = {**_DEFAULT_WEIGHTS, **dict(self.weights)}
        object.__setattr__(self, "weights", merged)
        self._validate()
        object.__setattr__(self, "weights", MappingProxyType(merged))
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))

    def _validate(self) -> None:
        if not self.version or not isinstance(self.version, str):
            raise PolicyError("policy version must be a non-empty string")

        unknown = set(self.weights) - set(SIGNAL_CODES)
        if unknown:
            raise PolicyError(
                f"unknown signal code(s) in weights: {', '.join(sorted(unknown))}"
            )
        missing = set(SIGNAL_CODES) - set(self.weights)
        if missing:
            raise PolicyError(
                f"missing weight(s) for signal code(s): {', '.join(sorted(missing))}"
            )
        for code, weight in self.weights.items():
            if isinstance(weight, bool) or not isinstance(weight, int):
                raise PolicyError(f"weight for {code} must be an integer")
            if not 0 <= weight <= 100:
                raise PolicyError(f"weight for {code} must be within 0-100, got {weight}")

        for name in ("medium_threshold", "high_threshold", "auto_removal_threshold"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise PolicyError(f"{name} must be an integer")
            if not 0 <= value <= 100:
                raise PolicyError(f"{name} must be within 0-100, got {value}")
        if self.medium_threshold > self.high_threshold:
            raise PolicyError(
                "medium_threshold cannot exceed high_threshold "
                f"({self.medium_threshold} > {self.high_threshold})"
            )

        expected_levels = {level.value for level in RiskLevel}
        if set(self.actions) != expected_levels:
            raise PolicyError(
                f"actions must map exactly {sorted(expected_levels)}, "
                f"got {sorted(self.actions)}"
            )
        for level, action in self.actions.items():
            try:
                resolved = Action(action)
            except ValueError as exc:
                raise PolicyError(
                    f"unknown action {action!r} for risk level {level!r}"
                ) from exc
            if resolved is Action.REMOVE and not self.allow_auto_removal:
                raise PolicyError(
                    f"action 'remove' for risk level {level!r} requires "
                    "allow_auto_removal=true"
                )

        if not 0.0 < self.duplicate_similarity_threshold <= 1.0:
            raise PolicyError(
                "duplicate_similarity_threshold must be within (0, 1], got "
                f"{self.duplicate_similarity_threshold}"
            )
        for name in (
            "new_account_days",
            "short_review_word_count",
            "burst_review_count",
            "exact_dedupe_max_batch",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolicyError(f"{name} must be a non-negative integer")
        if self.burst_review_count < 2:
            raise PolicyError("burst_review_count must be at least 2")

    def weight(self, code: str) -> int:
        """Weight for ``code``, or 0 if the policy disables that signal."""

        return int(self.weights.get(code, 0))

    def risk_level(self, score: int) -> RiskLevel:
        if score >= self.high_threshold:
            return RiskLevel.HIGH
        if score >= self.medium_threshold:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def action_for(self, level: RiskLevel, score: int) -> Action:
        """Enforcement action for a risk level, honouring the removal guard."""

        action = Action(self.actions[level.value])
        if action is Action.REMOVE:
            if not self.allow_auto_removal or score < self.auto_removal_threshold:
                return Action.ENQUEUE
        return action

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "weights": dict(sorted(self.weights.items())),
            "medium_threshold": self.medium_threshold,
            "high_threshold": self.high_threshold,
            "actions": dict(sorted(self.actions.items())),
            "allow_auto_removal": self.allow_auto_removal,
            "auto_removal_threshold": self.auto_removal_threshold,
            "new_account_days": self.new_account_days,
            "short_review_word_count": self.short_review_word_count,
            "duplicate_similarity_threshold": self.duplicate_similarity_threshold,
            "burst_review_count": self.burst_review_count,
            "exact_dedupe_max_batch": self.exact_dedupe_max_batch,
        }

    def digest(self) -> str:
        """Content hash of the policy, recorded on every decision it produces.

        Two policies sharing a version string but differing in any setting have
        different digests, so a silently edited config cannot masquerade as the
        one that made an earlier decision.
        """

        payload = json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False)
        return hashlib.blake2b(payload.encode("utf-8"), digest_size=16).hexdigest()

    @classmethod
    def from_dict(cls, payload: object) -> "Policy":
        if not isinstance(payload, dict):
            raise PolicyError(
                f"policy must be a JSON object, got {type(payload).__name__}"
            )
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(payload) - known
        if unknown:
            raise PolicyError(
                f"unknown policy field(s): {', '.join(sorted(unknown))}"
            )
        return cls(**{**cls().to_dict(), **payload})

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        try:
            raw = Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file {path} is not valid JSON: {exc}") from exc
        return cls.from_dict(payload)
