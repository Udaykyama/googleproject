"""Operational-check success, timeout, threshold, and backup failure cases."""

import http.client
import json
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import pytest

from fake_review_detector import SQLiteStore, backup_database, moderate
from fake_review_detector.cli import main
from fake_review_detector.operations import run_operational_checks

UTC = timezone.utc
BACKUP_TIME = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
DiskUsage = namedtuple("DiskUsage", "total used free")


class _Response:
    status = 200

    def __init__(self, body=b'{"status":"ready"}', *, status=200):
        self.body = body
        self.status = status

    def read1(self, limit):
        chunk, self.body = self.body[:limit], self.body[limit:]
        return chunk


class _Socket:
    def settimeout(self, timeout):
        self.timeout = timeout


def _connection(monkeypatch, *, response=None, error=None):
    response = response or _Response()

    class Connection:
        def __init__(self, host, *, port, timeout):
            self.sock = _Socket()

        def connect(self):
            pass

        def request(self, method, path, *, headers):
            assert method == "GET" and path == "/readyz"

        def getresponse(self):
            if error is not None:
                raise error
            return response

        def close(self):
            pass

    monkeypatch.setattr(
        "fake_review_detector.operations._HTTPConnection",
        Connection,
    )


def _ready(monkeypatch):
    _connection(monkeypatch)


def _seed(tmp_path, *, now=BACKUP_TIME):
    data_dir = tmp_path / "data"
    database = data_dir / "moderation.sqlite3"
    store = SQLiteStore(database)
    store.enqueue([
        moderate({
            "review_id": "ops-1",
            "author": "sample",
            "rating": 5,
            "text": "Best product ever!!!",
            "verified_purchase": False,
        })
    ])
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup = backup_database(database, backup_dir, now=now)
    return data_dir, backup_dir, backup.path


def _run(data_dir, backup_dir, **overrides):
    settings = {
        "readiness_url": "http://127.0.0.1:8000/readyz",
        "data_dir": data_dir,
        "backup_dir": backup_dir,
        "minimum_free_bytes": 0,
        "minimum_free_percent": 0,
        "maximum_backup_age": 36 * 60 * 60,
        "now": BACKUP_TIME + timedelta(hours=1),
    }
    settings.update(overrides)
    return run_operational_checks(**settings)


def test_operational_check_success_is_machine_readable_and_path_free(
    tmp_path, monkeypatch
):
    _ready(monkeypatch)
    data_dir, backup_dir, _ = _seed(tmp_path)

    report = _run(data_dir, backup_dir)

    assert report.ok
    payload = report.to_dict()
    assert [check["code"] for check in payload["checks"]] == [
        "ready",
        "disk_space_available",
        "backup_recent",
        "backup_verified",
    ]
    encoded = json.dumps(payload)
    assert str(tmp_path) not in encoded
    assert payload["checks"][-1]["audit_records"] == 1


def test_readiness_timeout_has_a_distinct_nonzero_result(tmp_path, monkeypatch):
    data_dir, backup_dir, _ = _seed(tmp_path)
    _connection(monkeypatch, error=TimeoutError())
    report = _run(data_dir, backup_dir, readiness_timeout=0.25)

    assert not report.ok
    assert report.checks[0].code == "readiness_timeout"


def test_readiness_rejects_nonlocal_or_query_bearing_urls(tmp_path, monkeypatch):
    data_dir, backup_dir, _ = _seed(tmp_path)

    def unexpected(host, *, port, timeout):
        pytest.fail("an invalid readiness URL must not be requested")

    monkeypatch.setattr(
        "fake_review_detector.operations._HTTPConnection", unexpected
    )
    report = _run(
        data_dir,
        backup_dir,
        readiness_url="https://example.test/readyz?token=secret",
    )

    assert not report.ok
    assert report.checks[0].code == "readiness_url_invalid"


def test_readiness_does_not_follow_redirects(tmp_path, monkeypatch):
    data_dir, backup_dir, _ = _seed(tmp_path)
    _connection(monkeypatch, response=_Response(b"", status=302))

    report = _run(data_dir, backup_dir)

    assert not report.ok
    assert report.checks[0].code == "readiness_http_error"
    assert report.checks[0].details["http_status"] == 302


def test_malformed_readiness_response_is_sanitized(tmp_path, monkeypatch):
    data_dir, backup_dir, _ = _seed(tmp_path)
    _connection(
        monkeypatch,
        error=http.client.BadStatusLine("private-response-marker"),
    )

    report = _run(data_dir, backup_dir)

    assert report.checks[0].code == "readiness_invalid_response"
    assert "private-response-marker" not in json.dumps(report.to_dict())


def test_readiness_timeout_is_a_total_deadline(tmp_path, monkeypatch):
    data_dir, backup_dir, _ = _seed(tmp_path)

    class Clock:
        value = 100.0

        def __call__(self):
            return self.value

    clock = Clock()

    class SlowResponse(_Response):
        def read1(self, limit):
            clock.value += 0.06
            return b"x"

    _connection(monkeypatch, response=SlowResponse())
    monkeypatch.setattr(
        "fake_review_detector.operations.time.monotonic", clock
    )

    report = _run(data_dir, backup_dir, readiness_timeout=0.1)

    assert report.checks[0].code == "readiness_timeout"


def test_disk_threshold_reports_both_absolute_and_percentage_headroom(
    tmp_path, monkeypatch
):
    _ready(monkeypatch)
    data_dir, backup_dir, _ = _seed(tmp_path)
    monkeypatch.setattr(
        "fake_review_detector.operations.shutil.disk_usage",
        lambda path: DiskUsage(total=1000, used=951, free=49),
    )

    report = _run(
        data_dir,
        backup_dir,
        minimum_free_bytes=50,
        minimum_free_percent=5,
    )

    disk = report.checks[1]
    assert not disk.ok and disk.code == "disk_space_low"
    assert disk.details["free_bytes"] == 49
    assert disk.details["free_percent"] == 4.9


def test_stale_backup_is_still_integrity_checked(tmp_path, monkeypatch):
    _ready(monkeypatch)
    data_dir, backup_dir, _ = _seed(tmp_path)

    report = _run(
        data_dir,
        backup_dir,
        now=BACKUP_TIME + timedelta(days=3),
    )

    assert report.checks[2].code == "backup_stale"
    assert report.checks[3].code == "backup_verified"
    assert not report.ok


def test_invalid_latest_backup_fails_without_deleting_it(tmp_path, monkeypatch):
    _ready(monkeypatch)
    data_dir, backup_dir, backup = _seed(tmp_path)
    backup.write_bytes(b"not a SQLite database")
    unrelated = backup_dir / "operator-note.txt"
    unrelated.write_text("keep", encoding="utf-8")

    report = _run(data_dir, backup_dir)

    assert report.checks[2].code == "backup_recent"
    assert report.checks[3].code == "backup_integrity_failed"
    assert backup.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert str(backup) not in json.dumps(report.to_dict())


def test_missing_backup_is_an_actionable_cli_failure(
    tmp_path, monkeypatch, capsys
):
    _ready(monkeypatch)
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    data_dir.mkdir()
    backup_dir.mkdir()

    result = main([
        "operational-check",
        "--data-dir", str(data_dir),
        "--backup-dir", str(backup_dir),
        "--min-free-bytes", "0",
        "--min-free-percent", "0",
    ])

    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert [check["code"] for check in payload["checks"]][-2:] == [
        "backup_missing",
        "backup_unavailable",
    ]


def test_cli_success_and_backup_timeout_are_wired(
    tmp_path, monkeypatch, capsys
):
    _ready(monkeypatch)
    data_dir, backup_dir, _ = _seed(tmp_path, now=datetime.now(UTC))
    observed = {}

    def verified(path, *, timeout):
        observed["timeout"] = timeout
        return 1

    monkeypatch.setattr(
        "fake_review_detector.operations.verify_backup", verified
    )
    result = main([
        "operational-check",
        "--data-dir", str(data_dir),
        "--backup-dir", str(backup_dir),
        "--min-free-bytes", "0",
        "--min-free-percent", "0",
        "--backup-timeout", "0.75",
    ])

    assert result == 0
    assert json.loads(capsys.readouterr().out)["status"] == "ok"
    assert observed["timeout"] == 0.75


@pytest.mark.parametrize(
    "args",
    [
        ["--min-free-percent", "101"],
        ["--min-free-percent", "nan"],
        ["--max-backup-age", "0"],
        ["--readiness-timeout", "inf"],
    ],
)
def test_invalid_operational_thresholds_are_rejected(args):
    with pytest.raises(SystemExit) as caught:
        main([
            "operational-check",
            "--data-dir", "/tmp/data",
            "--backup-dir", "/tmp/backups",
            *args,
        ])
    assert caught.value.code == 2
