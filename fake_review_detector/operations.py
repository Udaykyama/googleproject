"""Dependency-free, read-only checks for the supported single-host deployment."""

from __future__ import annotations

import http.client
import json
import math
import shutil
import socket
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .backup import BackupSnapshot, latest_backup, verify_backup
from .errors import BackupError

__all__ = ["CheckResult", "OperationalReport", "run_operational_checks"]

_MAX_READINESS_BODY = 4096
_LOCAL_READINESS_HOSTS = frozenset({"127.0.0.1", "::1", "localhost", "app"})
_HTTPConnection = http.client.HTTPConnection


@dataclass(frozen=True)
class CheckResult:
    """One actionable result with a stable machine-readable cause code."""

    name: str
    ok: bool
    code: str
    details: dict[str, int | float | str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": "ok" if self.ok else "failed",
            "code": self.code,
            **self.details,
        }


@dataclass(frozen=True)
class OperationalReport:
    """All checks from one invocation."""

    checked_at: datetime
    checks: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "ok" if self.ok else "failed",
            "checked_at": self.checked_at.isoformat().replace("+00:00", "Z"),
            "checks": [check.to_dict() for check in self.checks],
        }


def _readiness(url: str, timeout: float) -> CheckResult:
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        return CheckResult("readiness", False, "readiness_url_invalid", {})
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _LOCAL_READINESS_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/readyz"
        or parsed.query
        or parsed.fragment
        or port is not None and not 1 <= port <= 65535
    ):
        return CheckResult("readiness", False, "readiness_url_invalid", {})

    started = time.monotonic()
    deadline = started + timeout
    connection = _HTTPConnection(
        parsed.hostname,
        port=port or 80,
        timeout=timeout,
    )
    try:
        connection.connect()
        _set_connection_timeout(connection, deadline)
        connection.request(
            "GET",
            "/readyz",
            headers={
                "Accept": "application/json",
                "User-Agent": "inboxready-ops/1",
            },
        )
        _set_connection_timeout(connection, deadline)
        response = connection.getresponse()
        status = response.status
        body = _read_response_body(response, connection, deadline)
    except (TimeoutError, socket.timeout):
        return CheckResult("readiness", False, "readiness_timeout", {})
    except http.client.HTTPException:
        return CheckResult(
            "readiness", False, "readiness_invalid_response", {}
        )
    except (OSError, ValueError):
        return CheckResult("readiness", False, "readiness_unreachable", {})
    finally:
        connection.close()

    duration_ms = round(max(0.0, time.monotonic() - started) * 1000, 3)
    if len(body) > _MAX_READINESS_BODY:
        return CheckResult(
            "readiness",
            False,
            "readiness_invalid_response",
            {"http_status": status, "duration_ms": duration_ms},
        )
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if status != 200:
        return CheckResult(
            "readiness",
            False,
            "readiness_http_error",
            {"http_status": status, "duration_ms": duration_ms},
        )
    if payload != {"status": "ready"}:
        return CheckResult(
            "readiness",
            False,
            "readiness_not_ready",
            {"http_status": status, "duration_ms": duration_ms},
        )
    return CheckResult(
        "readiness",
        True,
        "ready",
        {"http_status": status, "duration_ms": duration_ms},
    )


def _set_connection_timeout(
    connection: http.client.HTTPConnection, deadline: float
) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    if connection.sock is not None:
        connection.sock.settimeout(remaining)


def _read_response_body(
    response: http.client.HTTPResponse,
    connection: http.client.HTTPConnection,
    deadline: float,
) -> bytes:
    body = bytearray()
    while len(body) <= _MAX_READINESS_BODY:
        _set_connection_timeout(connection, deadline)
        chunk = response.read1(
            min(512, _MAX_READINESS_BODY + 1 - len(body))
        )
        if not chunk:
            break
        body.extend(chunk)
    return bytes(body)


def _disk_space(
    data_dir: Path, minimum_bytes: int, minimum_percent: float
) -> CheckResult:
    try:
        if not data_dir.is_dir():
            return CheckResult(
                "data_filesystem", False, "data_directory_unavailable", {}
            )
        usage = shutil.disk_usage(data_dir)
    except OSError:
        return CheckResult("data_filesystem", False, "disk_usage_failed", {})
    free_percent = (usage.free / usage.total * 100) if usage.total else 0.0
    details: dict[str, int | float | str] = {
        "free_bytes": usage.free,
        "free_percent": round(free_percent, 3),
        "minimum_free_bytes": minimum_bytes,
        "minimum_free_percent": minimum_percent,
    }
    if usage.free < minimum_bytes or free_percent < minimum_percent:
        return CheckResult(
            "data_filesystem", False, "disk_space_low", details
        )
    return CheckResult("data_filesystem", True, "disk_space_available", details)


def _backups(
    backup_dir: Path,
    *,
    now: datetime,
    maximum_age: float,
    verification_timeout: float,
) -> tuple[CheckResult, CheckResult]:
    try:
        backup = latest_backup(backup_dir)
    except BackupError:
        unavailable = CheckResult(
            "backup_recency", False, "backup_directory_unavailable", {}
        )
        not_verified = CheckResult(
            "backup_integrity", False, "backup_unavailable", {}
        )
        return unavailable, not_verified
    if backup is None:
        missing = CheckResult("backup_recency", False, "backup_missing", {})
        not_verified = CheckResult(
            "backup_integrity", False, "backup_unavailable", {}
        )
        return missing, not_verified

    recency = _backup_recency(backup, now=now, maximum_age=maximum_age)
    try:
        records = verify_backup(backup.path, timeout=verification_timeout)
    except BackupError:
        integrity = CheckResult(
            "backup_integrity", False, "backup_integrity_failed", {}
        )
    else:
        integrity = CheckResult(
            "backup_integrity",
            True,
            "backup_verified",
            {"audit_records": records},
        )
    return recency, integrity


def _backup_recency(
    backup: BackupSnapshot, *, now: datetime, maximum_age: float
) -> CheckResult:
    age = (now - backup.created_at).total_seconds()
    details: dict[str, int | float | str] = {
        "age_seconds": round(age, 3),
        "maximum_age_seconds": maximum_age,
        "backup_created_at": backup.created_at.isoformat().replace("+00:00", "Z"),
    }
    if age < -300:
        return CheckResult(
            "backup_recency", False, "backup_timestamp_in_future", details
        )
    if age > maximum_age:
        return CheckResult("backup_recency", False, "backup_stale", details)
    return CheckResult("backup_recency", True, "backup_recent", details)


def run_operational_checks(
    *,
    readiness_url: str,
    data_dir: str | Path,
    backup_dir: str | Path,
    minimum_free_bytes: int = 1_073_741_824,
    minimum_free_percent: float = 10.0,
    maximum_backup_age: float = 129_600.0,
    readiness_timeout: float = 5.0,
    backup_timeout: float = 30.0,
    now: datetime | None = None,
) -> OperationalReport:
    """Check readiness, durable-disk headroom, and latest verified backup."""

    for name, value in (
        ("readiness_timeout", readiness_timeout),
        ("backup_timeout", backup_timeout),
        ("maximum_backup_age", maximum_backup_age),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
        ):
            raise ValueError(f"{name} must be finite and greater than zero")
    if (
        isinstance(minimum_free_bytes, bool)
        or not isinstance(minimum_free_bytes, int)
        or minimum_free_bytes < 0
    ):
        raise ValueError("minimum_free_bytes must be a non-negative integer")
    if (
        isinstance(minimum_free_percent, bool)
        or not isinstance(minimum_free_percent, (int, float))
        or not math.isfinite(minimum_free_percent)
        or not 0 <= minimum_free_percent <= 100
    ):
        raise ValueError("minimum_free_percent must be between zero and 100")

    instant = now or datetime.now(timezone.utc)
    if not isinstance(instant, datetime) or instant.tzinfo is None:
        raise ValueError("now must be a timezone-aware datetime")
    instant = instant.astimezone(timezone.utc)
    data_path = Path(data_dir).expanduser()
    backup_path = Path(backup_dir).expanduser()

    readiness = _readiness(readiness_url, float(readiness_timeout))
    disk = _disk_space(
        data_path, minimum_free_bytes, float(minimum_free_percent)
    )
    recency, integrity = _backups(
        backup_path,
        now=instant,
        maximum_age=float(maximum_backup_age),
        verification_timeout=float(backup_timeout),
    )
    return OperationalReport(instant, (readiness, disk, recency, integrity))
