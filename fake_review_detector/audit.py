"""Append-only, tamper-evident audit log.

A moderation system has to be able to answer, months later: what was decided,
on what content, under which policy, and has that record been altered since?

Records are JSON Lines, one decision per line, each carrying the hash of the
previous record. Editing or deleting any earlier line breaks the chain from that
point on, which :meth:`AuditLog.verify` reports with the exact line number.
This detects tampering; it does not prevent it. Preventing it is a filesystem
and access-control problem, not something a library can claim to solve.

A hash chain alone cannot detect *truncation*. Dropping records from the end
leaves a shorter chain that is still internally consistent, and deleting one's
most recent inconvenient decisions is the obvious insider attack. So the log is
paired with an **anchor**: a small sidecar recording how many records exist and
the hash of the last one. :meth:`AuditLog.verify` compares the log against it
and reports a shortfall.

The anchor is only as good as where it is kept. Stored beside the log, it
raises the bar from one edit to two coordinated ones; that is an improvement,
not a guarantee. Point ``anchor_path`` at append-only or separately
administered storage to make it meaningful. When no anchor exists,
:attr:`ChainStatus.anchor_checked` is ``False`` and the truncation check is
reported as *not performed* rather than as a pass.
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

__all__ = ["Anchor", "AuditLog", "AuditRecord", "ChainStatus", "replay"]

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
class Anchor:
    """How many records the log should have, and the hash of the last one."""

    records: int
    head_hash: str
    updated_at: str

    def to_dict(self) -> dict:
        return {
            "records": self.records,
            "head_hash": self.head_hash,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "Anchor":
        try:
            records = payload["records"]
            head_hash = payload["head_hash"]
        except KeyError as exc:
            raise AuditLogError(f"anchor is missing {exc} field") from exc
        if not isinstance(records, int) or isinstance(records, bool) or records < 0:
            raise AuditLogError("anchor 'records' must be a non-negative integer")
        if not isinstance(head_hash, str) or not head_hash:
            raise AuditLogError("anchor 'head_hash' must be a non-empty string")
        return cls(
            records=records,
            head_hash=head_hash,
            updated_at=str(payload.get("updated_at", "")),
        )


@dataclass(frozen=True)
class ChainStatus:
    """Result of verifying the log."""

    valid: bool
    records: int
    broken_at: int | None = None
    reason: str = ""
    #: False when no anchor was found, meaning truncation could not be checked.
    anchor_checked: bool = False

    def __str__(self) -> str:
        if not self.valid:
            if self.broken_at is None:
                return f"chain invalid: {self.reason}"
            return f"chain broken at line {self.broken_at}: {self.reason}"
        if self.anchor_checked:
            return f"chain intact across {self.records} record(s), anchor matches"
        return (
            f"chain intact across {self.records} record(s); "
            "no anchor found, so truncation was not checked"
        )


class AuditLog:
    """A JSON Lines audit log with hash chaining."""

    def __init__(self, path: str | Path, anchor_path: str | Path | None = None):
        self.path = Path(path)
        #: Sidecar recording the expected length and head hash. Defaults to
        #: beside the log; pass ``anchor_path`` to put it on storage the log
        #: writer cannot reach, which is what makes the check meaningful.
        self.anchor_path = (
            Path(anchor_path)
            if anchor_path is not None
            else self.path.with_name(self.path.name + ".anchor")
        )

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

        # Refuse to extend a log that no longer matches its anchor. Without
        # this, truncating and then appending would launder the deletion: the
        # anchor would be rewritten to describe the shortened log and every
        # later verify would pass. Re-anchor deliberately via write_anchor()
        # if the current state is known good.
        anchor = self.read_anchor()
        if anchor is not None and (
            sequence != anchor.records or previous_hash != anchor.head_hash
        ):
            raise AuditLogError(
                f"refusing to append to {self.path}: it does not match its anchor "
                f"(anchor expects {anchor.records} record(s), found {sequence}). "
                "Verify the log, then re-anchor if the current state is correct."
            )

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

        self.write_anchor(Anchor(sequence, previous_hash, utc_now_iso()))
        return len(lines)

    # -- anchor ----------------------------------------------------------

    def write_anchor(self, anchor: Anchor | None = None) -> Anchor:
        """Record the current length and head hash. Written atomically so a
        crash mid-write cannot leave an anchor that fails every later verify."""

        if anchor is None:
            head_hash, records = self._last_hash()
            anchor = Anchor(records, head_hash, utc_now_iso())

        temporary = self.anchor_path.with_name(self.anchor_path.name + ".tmp")
        try:
            self.anchor_path.parent.mkdir(parents=True, exist_ok=True)
            with open(temporary, "w", encoding="utf-8") as handle:
                json.dump(anchor.to_dict(), handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.anchor_path)
        except OSError as exc:
            raise AuditLogError(
                f"cannot write audit anchor {self.anchor_path}: {exc}"
            ) from exc
        return anchor

    def read_anchor(self) -> Anchor | None:
        """The stored anchor, or ``None`` when the log has never been anchored."""

        if not self.anchor_path.exists():
            return None
        try:
            with open(self.anchor_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except OSError as exc:
            raise AuditLogError(
                f"cannot read audit anchor {self.anchor_path}: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise AuditLogError(f"{self.anchor_path} is not valid JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise AuditLogError(f"{self.anchor_path} must contain a JSON object")
        return Anchor.from_dict(payload)

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

    def verify(self, *, check_anchor: bool = True) -> ChainStatus:
        """Recompute the chain and report the first inconsistency.

        When ``check_anchor`` is set and an anchor exists, the log is also
        compared against it, which is what catches truncation.
        """

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

        if not check_anchor:
            return ChainStatus(valid=True, records=count, anchor_checked=False)

        try:
            anchor = self.read_anchor()
        except AuditLogError as exc:
            return ChainStatus(valid=False, records=count, reason=str(exc))

        if anchor is None:
            return ChainStatus(valid=True, records=count, anchor_checked=False)

        if count < anchor.records:
            return ChainStatus(
                valid=False,
                records=count,
                broken_at=count + 1,
                reason=(
                    f"log truncated: anchor expects {anchor.records} record(s), "
                    f"found {count}"
                ),
                anchor_checked=True,
            )
        if count > anchor.records:
            # More records than the anchor knows about. Benign if the anchor is
            # simply stale, so it is reported rather than silently accepted.
            return ChainStatus(
                valid=False,
                records=count,
                reason=(
                    f"anchor is stale: expects {anchor.records} record(s), "
                    f"found {count}. Re-anchor if this growth is expected."
                ),
                anchor_checked=True,
            )
        if previous_hash != anchor.head_hash:
            return ChainStatus(
                valid=False,
                records=count,
                broken_at=count,
                reason="head hash does not match the anchor",
                anchor_checked=True,
            )

        return ChainStatus(valid=True, records=count, anchor_checked=True)

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
