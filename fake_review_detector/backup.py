"""Verified, atomic backups for the live SQLite moderation database."""

from __future__ import annotations

import os
import re
import sqlite3
import tempfile
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .errors import AuditLogError, BackupError, StorageError
from .sqlite_store import SQLiteStore

__all__ = ["BackupResult", "backup_database"]

_BACKUP_NAME = re.compile(
    r"^moderation-\d{8}T\d{6}\.\d{6}Z\.sqlite3$"
)


@dataclass(frozen=True)
class BackupResult:
    """A published backup and the retention work completed with it."""

    path: Path
    records: int
    removed: tuple[Path, ...]


def _filename(now: datetime | None = None) -> str:
    instant = now or datetime.now(timezone.utc)
    if not isinstance(instant, datetime):
        raise BackupError("backup timestamp must be a datetime")
    if instant.tzinfo is None:
        raise BackupError("backup timestamp must include a timezone")
    timestamp = instant.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"moderation-{timestamp}.sqlite3"


def _copy_database(source: Path, destination: Path, timeout: float) -> None:
    try:
        with closing(
            sqlite3.connect(
                source.as_uri() + "?mode=ro",
                uri=True,
                timeout=timeout,
            )
        ) as live, closing(
            sqlite3.connect(destination, timeout=timeout)
        ) as backup:
            live.execute("PRAGMA query_only = ON")
            live.backup(backup, pages=256, sleep=0.05)
    except sqlite3.Error as exc:
        raise BackupError(f"SQLite backup failed: {exc}") from exc


def _verify_audit_chain(path: Path, timeout: float) -> int:
    try:
        store = SQLiteStore(path, timeout=timeout, create=False)
        store.check_integrity()
        status = store.verify()
    except (AuditLogError, StorageError) as exc:
        raise BackupError(f"backup could not be opened for verification: {exc}") from exc
    if not status.valid or not status.anchor_checked:
        raise BackupError(f"backup audit verification failed: {status}")
    return status.records


def _remove_partial(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        raise BackupError(f"partial backup could not be removed: {exc}") from exc


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(directory, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prune(directory: Path, keep: int, current: Path) -> tuple[Path, ...]:
    try:
        candidates = sorted(
            (
                path
                for path in directory.iterdir()
                if _BACKUP_NAME.fullmatch(path.name)
                and path.is_file()
                and not path.is_symlink()
            ),
            key=lambda path: path.name,
            reverse=True,
        )
    except OSError as exc:
        raise BackupError(f"cannot list backup directory {directory}: {exc}") from exc

    if current not in candidates:
        raise BackupError(f"newly published backup is missing: {current}")
    previous = [path for path in candidates if path != current]
    expired = previous[max(keep - 1, 0):]
    removed = []
    for path in expired:
        try:
            path.unlink()
        except OSError as exc:
            raise BackupError(f"cannot remove expired backup {path}: {exc}") from exc
        removed.append(path)
    return tuple(removed)


def backup_database(
    database: str | Path,
    output_dir: str | Path,
    *,
    keep: int = 14,
    timeout: float = 30.0,
    now: datetime | None = None,
) -> BackupResult:
    """Back up a live database, verify it, publish it, then enforce retention.

    The final timestamped path appears only after SQLite's backup API finishes,
    ``PRAGMA integrity_check`` succeeds, and the hash-chained audit history
    matches its transactional anchor. Files not created by this mechanism are
    never considered for retention.
    """

    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
        raise BackupError("backup retention must be a positive integer")
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not 0 < timeout < float("inf")
    ):
        raise BackupError("backup timeout must be finite and greater than zero")

    try:
        source = Path(database).expanduser().resolve()
        directory = Path(output_dir).expanduser().resolve()
        source_exists = source.is_file()
        directory_exists = directory.is_dir()
    except (OSError, RuntimeError) as exc:
        raise BackupError(f"cannot resolve backup paths: {exc}") from exc
    if not source_exists:
        raise BackupError(f"moderation database does not exist: {source}")
    if not directory_exists:
        raise BackupError(f"backup directory does not exist: {directory}")

    final_path = directory / _filename(now)
    if final_path.exists():
        raise BackupError(f"refusing to overwrite existing backup {final_path}")

    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".moderation-", suffix=".partial", dir=directory
        )
        os.close(descriptor)
    except OSError as exc:
        raise BackupError(f"cannot create a partial backup in {directory}: {exc}") from exc

    temporary_path = Path(temporary_name)
    published = False
    try:
        _copy_database(source, temporary_path, float(timeout))
        records = _verify_audit_chain(temporary_path, float(timeout))
        os.chmod(temporary_path, 0o600)
        with temporary_path.open("rb") as backup_file:
            os.fsync(backup_file.fileno())
        os.replace(temporary_path, final_path)
        published = True
        _fsync_directory(directory)
    except OSError as exc:
        state = f" at {final_path}" if published else ""
        raise BackupError(f"cannot durably publish verified backup{state}: {exc}") from exc
    finally:
        if not published:
            _remove_partial(temporary_path)

    try:
        removed = _prune(directory, keep, final_path)
        if removed:
            _fsync_directory(directory)
    except (BackupError, OSError) as exc:
        raise BackupError(
            f"verified backup was published at {final_path}, "
            f"but retention did not complete: {exc}"
        ) from exc
    if not final_path.is_file():
        raise BackupError(f"published backup disappeared before completion: {final_path}")
    return BackupResult(path=final_path, records=records, removed=removed)
