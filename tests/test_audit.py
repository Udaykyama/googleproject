"""Tests for the audit log, its tamper detection, and replay."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.audit import AuditLog, replay  # noqa: E402
from fake_review_detector.engine import moderate_batch  # noqa: E402
from fake_review_detector.errors import AuditLogError  # noqa: E402
from fake_review_detector.policy import Policy  # noqa: E402


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=4,
        text="A perfectly ordinary review of a perfectly ordinary product.",
        verified_purchase=True,
        account_age_days=500,
        date="2024-05-01",
    )
    base.update(overrides)
    return base


def batch():
    return [
        payload(review_id="clean"),
        payload(review_id="fake", rating=5, text="Best product ever!!!",
                verified_purchase=False, account_age_days=1),
    ]


def test_missing_log_reads_as_empty(tmp_path):
    log = AuditLog(tmp_path / "absent.jsonl")
    assert log.decisions() == []
    assert log.verify().valid


def test_append_and_read_back(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    result = moderate_batch(batch())
    assert log.append(result.decisions) == 2
    assert [d.review_id for d in log.decisions()] == [d.review_id for d in result.decisions]


def test_append_single_decision(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.append(moderate_batch(batch()).decisions[0]) == 1
    assert log.verify().records == 1


def test_appending_nothing_is_a_no_op(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.append([]) == 0
    assert not (tmp_path / "audit.jsonl").exists()


def test_chain_survives_multiple_appends(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for _ in range(3):
        log.append(moderate_batch(batch()).decisions)
    status = log.verify()
    assert status.valid
    assert status.records == 6


def test_sequence_numbers_are_contiguous(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(moderate_batch(batch()).decisions)
    log.append(moderate_batch(batch()).decisions)
    assert [r.sequence for r in log.read()] == [1, 2, 3, 4]


def test_edited_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(moderate_batch(batch()).decisions)

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["decision"]["action"] = "allow"
    lines[0] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    status = log.verify()
    assert not status.valid
    assert status.broken_at == 1
    assert "record_hash" in status.reason


def test_deleted_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(moderate_batch(batch()).decisions)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")
    assert not log.verify().valid


def test_reordered_records_are_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(moderate_batch(batch()).decisions)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    assert not log.verify().valid


def test_corrupt_line_reports_the_line_number(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(moderate_batch(batch()).decisions)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("{not json\n")
    with pytest.raises(AuditLogError) as exc:
        list(log.read())
    assert "line 3" in str(exc.value)


def test_verify_reports_corruption_without_raising(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    status = AuditLog(path).verify()
    assert not status.valid


def test_blank_lines_are_ignored(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(moderate_batch(batch()).decisions)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("\n\n")
    assert log.verify().valid


def test_replay_of_unchanged_data_reports_no_differences(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    items = batch()
    log.append(moderate_batch(items).decisions)
    assert replay(log, items) == []


def test_replay_detects_edited_content(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    items = batch()
    log.append(moderate_batch(items).decisions)

    edited = [dict(item) for item in items]
    edited[0]["text"] = "Completely rewritten after the decision was made."
    differences = {d["difference"] for d in replay(log, edited)}
    assert "content_changed" in differences


def test_replay_detects_a_policy_change(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    items = batch()
    log.append(moderate_batch(items).decisions)

    # An operator decides low-risk content should be monitored, not ignored.
    watchful = Policy(actions={"low": "monitor", "medium": "enqueue", "high": "enqueue"})
    differences = replay(log, items, watchful)
    assert any(d["difference"] == "action_changed" for d in differences)
    assert any("allow -> monitor" in d["detail"] for d in differences)


def test_replay_detects_a_score_change(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    items = batch()
    log.append(moderate_batch(items).decisions)

    # Reweighting a signal changes scores without changing the action taken.
    reweighted = Policy(weights={"UNVERIFIED_PURCHASE": 1, "NEW_ACCOUNT": 1})
    differences = replay(log, items, reweighted)
    assert any(d["difference"] == "score_changed" for d in differences)


def test_replay_reports_missing_reviews(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    items = batch()
    log.append(moderate_batch(items).decisions)
    differences = replay(log, items[:1])
    assert any(d["difference"] == "missing" for d in differences)


def test_records_are_json_serialisable(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append(moderate_batch(batch()).decisions)
    for record in log.read():
        json.dumps(record.to_dict())


def test_log_directory_is_created(tmp_path):
    log = AuditLog(tmp_path / "nested" / "deeper" / "audit.jsonl")
    log.append(moderate_batch(batch()).decisions)
    assert log.verify().valid
