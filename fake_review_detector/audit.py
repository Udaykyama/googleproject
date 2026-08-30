"""Append-only, tamper-evident audit log.

A moderation system has to be able to answer, months later: what was decided,
on what content, under which policy, and has that record been altered since?

Records are JSON Lines, one decision per line, each carrying the hash of the
previous record. Editing or deleting any earlier line breaks the chain from that
point on, which :meth:`AuditLog.verify` reports with the exact line number.
This detects tampering; it does not prevent it. Preventing it is a filesystem
and access-control problem, not something a library can claim to solve.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .errors import AuditLogError
from .models import ModerationDecision, Review, utc_now_iso
from .policy import Policy

__all__ = ["AuditLog", "AuditRecord", "ChainStatus", "replay"]

GENESIS_HASH = "0" * 32


def _record_hash(previous_hash: str, payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.blake2b(
        (previous_hash + body).encode("utf-8"), digest_size=16
    ).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """One line of the log: a decision plus its chain metadata."""

    sequence: int
    decision: ModerationDecision
    previous_hash: str
    record_hash: str
    recorded_at: str

    def to_dict(self) -> dict:
        return {
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
            "decision": self.decision.to_dict(),
        }


@dataclass(frozen=True)
class ChainStatus:
    """Result of verifying the log."""

    valid: bool
    records: int
    broken_at: int | None = None
    reason: str = ""

    def __str__(self) -> str:
        if self.valid:
            return f"chain intact across {self.records} record(s)"
        return f"chain broken at line {self.broken_at}: {self.reason}"


class AuditLog:
    """A JSON Lines audit log with hash chaining."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    # -- writing ---------------------------------------------------------

    def _last_hash(self) -> tuple[str, int]:
        last_hash, sequence = GENESIS_HASH, 0
        for record in self.read():
            last_hash, sequence = record.record_hash, record.sequence
        return last_hash, sequence

    def append(self, decisions: ModerationDecision | Iterable[ModerationDecision]) -> int:
        """Append one or more decisions. Returns how many were written."""

        if isinstance(decisions, ModerationDecision):
            decisions = [decisions]
        decisions = list(decisions)
        if not decisions:
            return 0

        previous_hash, sequence = self._last_hash()
        lines: list[str] = []
        for decision in decisions:
            sequence += 1
            payload = {
                "sequence": sequence,
                "recorded_at": utc_now_iso(),
                "previous_hash": previous_hash,
                "decision": decision.to_dict(),
            }
            payload["record_hash"] = _record_hash(previous_hash, payload)
            previous_hash = payload["record_hash"]
            lines.append(json.dumps(payload, sort_keys=True, ensure_ascii=False))

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            # Append-and-flush so a crash cannot leave a partial record that
            # would look like tampering on the next verify.
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write("\n".join(lines) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            raise AuditLogError(f"cannot write audit log {self.path}: {exc}") from exc
        return len(lines)

    # -- reading ---------------------------------------------------------

    def read(self) -> Iterator[AuditRecord]:
        """Yield records in order. Missing log means no records."""

        if not self.path.exists():
            return
        try:
            handle = open(self.path, "r", encoding="utf-8")
        except OSError as exc:
            raise AuditLogError(f"cannot read audit log {self.path}: {exc}") from exc
        with handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                    yield AuditRecord(
                        sequence=payload["sequence"],
                        decision=ModerationDecision.from_dict(payload["decision"]),
                        previous_hash=payload["previous_hash"],
                        record_hash=payload["record_hash"],
                        recorded_at=payload["recorded_at"],
                    )
                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    raise AuditLogError(
                        f"{self.path} line {line_number} is not a valid audit record: {exc}"
                    ) from exc

    def verify(self) -> ChainStatus:
        """Recompute the chain and report the first inconsistency."""

        previous_hash = GENESIS_HASH
        expected_sequence = 0
        count = 0

        try:
            records = list(self.read())
        except AuditLogError as exc:
            return ChainStatus(valid=False, records=0, broken_at=None, reason=str(exc))

        for record in records:
            count += 1
            expected_sequence += 1
            if record.sequence != expected_sequence:
                return ChainStatus(
                    valid=False,
                    records=count,
                    broken_at=count,
                    reason=f"expected sequence {expected_sequence}, found {record.sequence}",
                )
            if record.previous_hash != previous_hash:
                return ChainStatus(
                    valid=False,
                    records=count,
                    broken_at=count,
                    reason="previous_hash does not match the preceding record",
                )
            payload = {
                "sequence": record.sequence,
                "recorded_at": record.recorded_at,
                "previous_hash": record.previous_hash,
                "decision": record.decision.to_dict(),
            }
            if _record_hash(previous_hash, payload) != record.record_hash:
                return ChainStatus(
                    valid=False,
                    records=count,
                    broken_at=count,
                    reason="record contents do not match record_hash",
                )
            previous_hash = record.record_hash

        return ChainStatus(valid=True, records=count)

    def decisions(self) -> list[ModerationDecision]:
        return [record.decision for record in self.read()]


def replay(
    log: AuditLog, reviews: Iterable[Review | dict], policy: Policy | None = None
) -> list[dict]:
    """Re-derive decisions and report where they differ from the log.

    Used to answer "would today's policy have decided this differently?" and to
    detect content edited after a decision was made. ``decided_at`` is excluded
    from the comparison because it is a wall-clock value, not an input.
    """

    from .engine import moderate_batch

    result = moderate_batch(reviews, policy)
    fresh = {d.review_id: d for d in result.decisions}
    differences: list[dict] = []

    for record in log.read():
        original = record.decision
        current = fresh.get(original.review_id)
        if current is None:
            differences.append(
                {
                    "review_id": original.review_id,
                    "difference": "missing",
                    "detail": "review not present in the replayed batch",
                }
            )
            continue
        if current.content_digest != original.content_digest:
            differences.append(
                {
                    "review_id": original.review_id,
                    "difference": "content_changed",
                    "detail": "review text or metadata was edited after the decision",
                }
            )
        if current.action is not original.action:
            differences.append(
                {
                    "review_id": original.review_id,
                    "difference": "action_changed",
                    "detail": f"{original.action.value} -> {current.action.value}",
                }
            )
        elif current.score != original.score:
            differences.append(
                {
                    "review_id": original.review_id,
                    "difference": "score_changed",
                    "detail": f"{original.score} -> {current.score}",
                }
            )

    return differences
