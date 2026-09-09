"""Live SQLite backup, verification, retention, and restore behavior."""

import json
import shutil
import sqlite3
import stat
from datetime import datetime, timezone

import pytest

from fake_review_detector import BackupError, SQLiteStore, backup_database, moderate
from fake_review_detector.cli import main


def _seed(path, review_id="r1"):
    store = SQLiteStore(path)
    decision = moderate({
        "review_id": review_id,
        "author": "sample",
        "rating": 5,
        "text": "Best product ever!!!",
        "verified_purchase": False,
    })
    store.enqueue([decision])
    return store


def test_live_backup_is_verified_private_and_restorable(tmp_path):
    source = tmp_path / "data" / "moderation.sqlite3"
    store = _seed(source)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    with sqlite3.connect(source) as live:
        live.execute(
            "INSERT INTO rate_limits (client, tokens, last_seen) VALUES (?, ?, ?)",
            ("client", 1.0, 1.0),
        )
        live.commit()
        result = backup_database(
            source,
            backup_dir,
            now=datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc),
        )

    assert result.path.name == "moderation-20260908T120000.000000Z.sqlite3"
    assert result.records == 1
    assert result.removed == ()
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o600
    assert SQLiteStore(result.path, create=False).verify().valid

    store.enqueue([moderate({
        "review_id": "r2",
        "author": "sample",
        "rating": 1,
        "text": "Do not buy this product!!!",
        "verified_purchase": False,
    })])
    assert SQLiteStore(result.path, create=False).verify().records == 1

    restored = tmp_path / "restored" / "moderation.sqlite3"
    restored.parent.mkdir()
    shutil.copy2(result.path, restored)
    status = SQLiteStore(restored, create=False).verify()
    assert status.valid and status.anchor_checked and status.records == 1


def test_tampered_audit_chain_never_becomes_a_backup(tmp_path):
    source = tmp_path / "data" / "moderation.sqlite3"
    _seed(source)
    with sqlite3.connect(source) as connection:
        raw = connection.execute(
            "SELECT record FROM audit_records WHERE sequence = 1"
        ).fetchone()[0]
        record = json.loads(raw)
        record["decision"]["score"] = 0
        connection.execute(
            "UPDATE audit_records SET record = ? WHERE sequence = 1",
            (json.dumps(record),),
        )

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    with pytest.raises(BackupError, match="audit verification failed"):
        backup_database(source, backup_dir)
    assert list(backup_dir.iterdir()) == []


def test_missing_audit_anchor_never_leaves_a_partial_backup(tmp_path):
    source = tmp_path / "data" / "moderation.sqlite3"
    _seed(source)
    with sqlite3.connect(source) as connection:
        connection.execute("DELETE FROM audit_head")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    with pytest.raises(BackupError, match="anchor is missing"):
        backup_database(source, backup_dir)
    assert list(backup_dir.iterdir()) == []


def test_retention_only_removes_timestamped_regular_backups(tmp_path):
    source = tmp_path / "data" / "moderation.sqlite3"
    _seed(source)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    oldest = backup_dir / "moderation-20240101T000000.000000Z.sqlite3"
    newer = backup_dir / "moderation-20250101T000000.000000Z.sqlite3"
    unrelated = backup_dir / "operator-notes.txt"
    oldest.write_bytes(b"old")
    newer.write_bytes(b"newer")
    unrelated.write_text("keep", encoding="utf-8")

    result = backup_database(
        source,
        backup_dir,
        keep=2,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.removed == (oldest,)
    assert not oldest.exists()
    assert newer.exists() and result.path.exists() and unrelated.exists()


def test_retention_always_keeps_the_new_backup_after_clock_rollback(tmp_path):
    source = tmp_path / "data" / "moderation.sqlite3"
    _seed(source)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    future = backup_dir / "moderation-20990101T000000.000000Z.sqlite3"
    future.write_bytes(b"future")

    result = backup_database(
        source,
        backup_dir,
        keep=1,
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    assert result.path.is_file()
    assert result.removed == (future,)
    assert not future.exists()


def test_missing_paths_fail_without_creating_output(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    with pytest.raises(BackupError, match="does not exist"):
        backup_database(tmp_path / "missing.sqlite3", backup_dir)
    assert list(backup_dir.iterdir()) == []

    source = tmp_path / "moderation.sqlite3"
    _seed(source)
    with pytest.raises(BackupError, match="backup directory does not exist"):
        backup_database(source, tmp_path / "missing-backups")


def test_backup_cli_reports_success_and_failure(tmp_path, capsys):
    source = tmp_path / "moderation.sqlite3"
    _seed(source)
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    assert main([
        "backup",
        "--database", str(source),
        "--output-dir", str(backup_dir),
        "--keep", "3",
    ]) == 0
    assert "verified backup:" in capsys.readouterr().out

    assert main([
        "backup",
        "--database", str(tmp_path / "missing.sqlite3"),
        "--output-dir", str(backup_dir),
    ]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Error:" in captured.err


def test_verify_can_require_sqlite_and_audit_integrity(tmp_path, capsys):
    source = tmp_path / "moderation.sqlite3"
    _seed(source)
    assert main([
        "verify",
        "--database", str(source),
        "--integrity",
        "--require-anchor",
    ]) == 0
    output = capsys.readouterr().out
    assert "SQLite integrity check passed" in output
    assert "anchor matches" in output

    assert main([
        "verify",
        "--audit-log", str(tmp_path / "audit.jsonl"),
        "--integrity",
    ]) == 1
    assert "--integrity requires --database" in capsys.readouterr().err
