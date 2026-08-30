"""Exception hierarchy for the moderation system.

Every error raised by this package derives from :class:`ModerationError`, so
callers embedding the engine in a service can catch a single base class.

The distinction that matters operationally is between errors caused by *the
content being moderated* (:class:`ValidationError` — expected, per-item, should
be counted and skipped) and errors caused by *the system's own configuration*
(:class:`PolicyError`, :class:`AuditLogError` — unexpected, should fail loudly
at startup rather than silently degrade moderation quality).
"""

from __future__ import annotations

__all__ = [
    "ModerationError",
    "ValidationError",
    "PolicyError",
    "AuditLogError",
]


class ModerationError(Exception):
    """Base class for every error raised by this package."""


class ValidationError(ModerationError):
    """A review could not be accepted for moderation.

    Carries the offending field and the review id (when known) so a service can
    log which item failed without re-parsing the payload.
    """

    def __init__(self, message: str, *, field: str | None = None, review_id: str | None = None):
        super().__init__(message)
        self.field = field
        self.review_id = review_id

    def __str__(self) -> str:
        location = ""
        if self.review_id is not None:
            location += f" review_id={self.review_id!r}"
        if self.field is not None:
            location += f" field={self.field!r}"
        return super().__str__() + location


class PolicyError(ModerationError):
    """A policy document is malformed, inconsistent, or unsafe to run."""


class AuditLogError(ModerationError):
    """The audit log could not be written or replayed."""
