"""Core data types shared by every InboxReady check.

The vocabulary here maps directly onto how Gmail treats a sending domain:

``BLOCKER``
    Gmail will reject or spam-folder the mail outright (5.7.x / policy
    rejection). This is the "your mail does not arrive" tier.
``CRITICAL``
    Not an immediate rejection today, but it violates a published requirement
    that is actively enforced, so delivery is on borrowed time.
``WARNING``
    Legal but weak. Usually means "you are authenticated but not protected",
    e.g. ``p=none`` DMARC.
``INFO``
    Observations and best-practice nudges.
``PASS``
    The requirement is satisfied.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Ordered severity levels. Higher ``rank`` is worse."""

    PASS = ("pass", 0)
    INFO = ("info", 1)
    WARNING = ("warning", 2)
    CRITICAL = ("critical", 3)
    BLOCKER = ("blocker", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    @classmethod
    def from_label(cls, label: str) -> "Severity":
        for member in cls:
            if member.label == label.strip().lower():
                return member
        valid = ", ".join(m.label for m in cls)
        raise ValueError(f"unknown severity {label!r} (expected one of: {valid})")


#: Points deducted from the 100-point compliance score for each finding.
_SEVERITY_PENALTY = {
    Severity.PASS: 0,
    Severity.INFO: 0,
    Severity.WARNING: 4,
    Severity.CRITICAL: 12,
    Severity.BLOCKER: 30,
}


@dataclass(frozen=True)
class Finding:
    """A single observation about a sender's configuration.

    ``code`` is a stable machine-readable identifier (e.g. ``SPF_MULTIPLE``) so
    that reports can be diffed across runs and suppressed selectively.
    """

    code: str
    title: str
    severity: Severity
    detail: str = ""
    remediation: str = ""
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "remediation": self.remediation,
            "reference": self.reference,
        }


@dataclass
class CheckResult:
    """The output of one check module (SPF, DKIM, message hygiene, ...)."""

    name: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    skipped_reason: str | None = None

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    @property
    def skipped(self) -> bool:
        return self.skipped_reason is not None

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.PASS)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "name": self.name,
            "worst_severity": self.worst.label,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }
        if self.skipped_reason:
            payload["skipped_reason"] = self.skipped_reason
        return payload


@dataclass
class AuditReport:
    """Aggregated result of an audit run."""

    target: str
    results: list[CheckResult] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)

    def add(self, result: CheckResult) -> CheckResult:
        self.results.append(result)
        return result

    @property
    def findings(self) -> list[Finding]:
        return [f for result in self.results for f in result.findings]

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), default=Severity.PASS)

    def counts(self) -> dict[str, int]:
        counts = {severity.label: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    @property
    def score(self) -> int:
        """A 0-100 compliance score.

        Deliberately simple and monotonic: every finding subtracts a fixed
        penalty for its severity, floored at zero. It is a communication aid,
        not a substitute for reading the findings.
        """

        score = 100
        for finding in self.findings:
            score -= _SEVERITY_PENALTY[finding.severity]
        return max(0, score)

    @property
    def gmail_ready(self) -> bool:
        """True when nothing found would get mail rejected by Gmail today."""

        return self.worst.rank < Severity.CRITICAL.rank

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "score": self.score,
            "gmail_ready": self.gmail_ready,
            "worst_severity": self.worst.label,
            "counts": self.counts(),
            "context": self.context,
            "checks": [result.to_dict() for result in self.results],
        }
