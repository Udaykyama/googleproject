"""Privacy-safe request correlation and structured application logging."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import sys
from datetime import datetime, timezone
from types import TracebackType
from typing import Any

from flask import Request

from .config import AppConfig

__all__ = [
    "EventFormatter",
    "configure_event_logger",
    "event",
    "request_id",
    "safe_client_address",
    "safe_exception_fields",
]

_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}", re.ASCII)
_FIELDS = (
    "request_id",
    "method",
    "route",
    "endpoint",
    "status",
    "duration_ms",
    "client",
    "error_type",
    "stack",
)


class EventFormatter(logging.Formatter):
    def __init__(self, output_format: str) -> None:
        super().__init__()
        self.output_format = output_format

    def format(self, record: logging.LogRecord) -> str:
        default_event = (
            "gunicorn.lifecycle"
            if record.name.startswith("gunicorn.")
            else "application"
        )
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "severity": record.levelname,
            "event": getattr(record, "event", default_event),
            "message": record.getMessage(),
            "process_id": record.process,
        }
        for name in _FIELDS:
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        if self.output_format == "json":
            return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
        return " ".join(
            f"{key}={json.dumps(value, ensure_ascii=True, separators=(',', ':'))}"
            for key, value in payload.items()
        )


def configure_event_logger(app_name: str, config: AppConfig) -> logging.Logger:
    """Create an isolated logger so framework access logs cannot add raw URLs."""

    logger = logging.Logger(f"inboxready.web.{app_name}", level=config.log_level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(EventFormatter(config.log_format))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def event(
    logger: logging.Logger,
    level: int,
    name: str,
    message: str,
    **fields: Any,
) -> None:
    """Emit one allowlisted event; callers pass only already-sanitized fields."""

    extra = {"event": name}
    extra.update({key: value for key, value in fields.items() if key in _FIELDS})
    logger.log(level, message, extra=extra)


def request_id(candidate: str | None) -> str | None:
    """Return a bounded safe caller ID, or ``None`` when it must be replaced."""

    if candidate is None or not _REQUEST_ID.fullmatch(candidate):
        return None
    return candidate


def safe_client_address(request: Request) -> str | None:
    """Normalize one selected peer address; never preserve forwarding chains."""

    candidate = request.remote_addr
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        return None


def safe_exception_fields(exc: BaseException) -> dict[str, Any]:
    """Describe an exception without its message, locals, or filesystem paths."""

    error_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
    stack: list[str] = []
    traceback: TracebackType | None = exc.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        module = str(frame.f_globals.get("__name__", "unknown"))
        stack.append(f"{module}.{frame.f_code.co_name}:{traceback.tb_lineno}")
        traceback = traceback.tb_next
    return {"error_type": error_type, "stack": stack[-8:]}
