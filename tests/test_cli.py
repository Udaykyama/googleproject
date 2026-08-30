"""Tests for the command-line interface."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fake_review_detector.cli import main  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "sample_reviews.json"
LABELLED = ROOT / "data" / "labelled_reviews.json"


def write(path, items):
    path.write_text(json.dumps(items), encoding="utf-8")
    return path


def payload(**overrides):
    base = dict(
        review_id="r1",
        author="someone",
        rating=5,
        text="Best product ever!!!",
        verified_purchase=False,
        account_age_days=1,
        date="2024-05-01",
    )
    base.update(overrides)
    return base


def test_legacy_bare_path_invocation_still_works(capsys):
    # The original CLI took a single file path with no subcommand.
    assert main([str(SAMPLE)]) == 0
    assert "score=" in capsys.readouterr().out


def test_score_subcommand(capsys):
    assert main(["score", str(SAMPLE)]) == 0
    out = capsys.readouterr().out
    assert "sent for human review" in out
    assert "policy" in out


def test_score_json_output(capsys):
    assert main(["score", str(SAMPLE), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["policy_version"]
    assert report["decisions"]
    assert set(report["actions"]) == {"allow", "monitor", "enqueue", "remove"}


def test_score_verbose_includes_evidence(capsys):
    assert main(["score", str(SAMPLE), "--verbose"]) == 0
    assert "evidence:" in capsys.readouterr().out


def test_score_reports_invalid_items(tmp_path, capsys):
    path = write(tmp_path / "r.json", [payload(), payload(review_id="bad", rating=99)])
    assert main(["score", str(path)]) == 0
    captured = capsys.readouterr()
    assert "rejected as invalid" in captured.err
    assert "bad" in captured.err


def test_missing_file_is_a_clean_error(tmp_path, capsys):
    assert main(["score", str(tmp_path / "absent.json")]) == 1
    assert "Error:" in capsys.readouterr().err


def test_malformed_json_is_a_clean_error(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["score", str(path)]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_non_array_json_is_a_clean_error(tmp_path, capsys):
    path = tmp_path / "obj.json"
    path.write_text('{"review_id": "r1"}', encoding="utf-8")
    assert main(["score", str(path)]) == 1
    assert "JSON array" in capsys.readouterr().err


def test_policy_file_is_applied(tmp_path, capsys):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"version": "custom.1"}), encoding="utf-8")
    assert main(["score", str(SAMPLE), "--policy", str(policy_path)]) == 0
    assert "custom.1" in capsys.readouterr().out


def test_invalid_policy_file_is_a_clean_error(tmp_path, capsys):
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"medium_threshold": 900}), encoding="utf-8")
    assert main(["score", str(SAMPLE), "--policy", str(policy_path)]) == 1
    assert "Error:" in capsys.readouterr().err


def test_evaluate_subcommand(capsys):
    assert main(["evaluate", str(LABELLED)]) == 0
    out = capsys.readouterr().out
    assert "precision" in out and "false positive rate" in out


def test_evaluate_json_and_sweep(capsys):
    assert main(["evaluate", str(LABELLED), "--json"]) == 0
    assert "precision" in json.loads(capsys.readouterr().out)

    assert main(["evaluate", str(LABELLED), "--sweep", "--step", "25", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["threshold"] for r in rows] == [0, 25, 50, 75, 100]


def test_audit_log_and_verification(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    assert main(["score", str(SAMPLE), "--audit-log", str(log)]) == 0
    capsys.readouterr()

    assert main(["verify", "--audit-log", str(log)]) == 0
    assert "intact" in capsys.readouterr().out

    lines = log.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["decision"]["score"] = 0
    lines[0] = json.dumps(record, sort_keys=True)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["verify", "--audit-log", str(log)]) == 1
    assert "broken" in capsys.readouterr().out


def test_replay_reports_a_match_then_a_difference(tmp_path, capsys):
    log = tmp_path / "audit.jsonl"
    reviews = write(tmp_path / "r.json", json.loads(SAMPLE.read_text(encoding="utf-8")))
    assert main(["score", str(reviews), "--audit-log", str(log)]) == 0
    capsys.readouterr()

    assert main(["replay", str(reviews), "--audit-log", str(log)]) == 0
    assert "matches" in capsys.readouterr().out

    items = json.loads(reviews.read_text(encoding="utf-8"))
    items[0]["text"] = "Entirely rewritten after the fact."
    write(reviews, items)
    assert main(["replay", str(reviews), "--audit-log", str(log)]) == 1
    assert "content_changed" in capsys.readouterr().out


def test_queue_workflow(tmp_path, capsys):
    queue_path = tmp_path / "queue.json"
    assert main(["score", str(SAMPLE), "--queue", str(queue_path)]) == 0
    assert "added to" in capsys.readouterr().out

    assert main(["queue", "--queue", str(queue_path), "--list"]) == 0
    assert "pending" in capsys.readouterr().out

    assert main(["queue", "--queue", str(queue_path), "--claim", "alice", "--limit", "1"]) == 0
    claimed = capsys.readouterr().out
    assert "score=" in claimed
    review_id = claimed.split()[0]

    assert main([
        "queue", "--queue", str(queue_path), "--resolve", review_id,
        "--moderator", "alice", "--outcome", "overturned", "--note", "genuine",
    ]) == 0
    assert "resolved as overturned" in capsys.readouterr().out

    assert main(["queue", "--queue", str(queue_path), "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["outcomes"]["overturned"] == 1
    assert stats["overturn_rate"] == 1.0


def test_queue_resolve_requires_moderator_and_outcome(tmp_path, capsys):
    queue_path = tmp_path / "queue.json"
    main(["score", str(SAMPLE), "--queue", str(queue_path)])
    capsys.readouterr()
    assert main(["queue", "--queue", str(queue_path), "--resolve", "r2"]) == 1
    assert "requires" in capsys.readouterr().err


def test_empty_queue_reports_cleanly(tmp_path, capsys):
    assert main(["queue", "--queue", str(tmp_path / "absent.json")]) == 0
    assert "0 item(s)" in capsys.readouterr().out


def test_no_arguments_prints_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()
