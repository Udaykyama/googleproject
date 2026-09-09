"""Gunicorn logging that cannot echo request targets, headers, or tracebacks."""

from __future__ import annotations

import os
import sys
from typing import Any

from gunicorn.glogging import Logger

from .observability import EventFormatter, safe_exception_fields

__all__ = ["SafeGunicornLogger"]


class SafeGunicornLogger(Logger):
    """Keep server lifecycle logs while sanitizing every request error path."""

    def setup(self, cfg) -> None:
        super().setup(cfg)
        output_format = (os.environ.get("LOG_FORMAT") or "text").strip().lower()
        if output_format not in {"json", "text"}:
            raise RuntimeError("LOG_FORMAT must be 'json' or 'text'")
        formatter = EventFormatter(output_format)
        for handler in self.error_log.handlers:
            handler.setFormatter(formatter)

    def access(self, resp, req, environ, request_time) -> None:
        """App-level route logs replace Gunicorn's raw-target access log."""

    def warning(self, msg, *args, **kwargs) -> None:
        if str(msg).startswith("Invalid request from ip="):
            self.error_log.warning(
                "invalid HTTP request rejected",
                extra={"event": "gunicorn.invalid_request"},
            )
            return
        if "graceful timeout" in str(msg).lower():
            self.error_log.warning(
                "worker graceful timeout",
                extra={"event": "gunicorn.worker_timeout"},
            )
            return
        self.error_log.warning(
            "Gunicorn reported a warning",
            extra={"event": "gunicorn.warning"},
        )

    def debug(self, msg, *args, **kwargs) -> None:
        # Debug call sites include request paths and exception values.
        return

    def error(self, msg, *args, **kwargs) -> None:
        lowered = str(msg).lower()
        if "worker timeout" in lowered:
            name, message = "gunicorn.worker_timeout", "worker timed out"
        elif "failed to boot" in lowered:
            name, message = "gunicorn.worker_boot_failed", "worker failed to boot"
        elif "exited with code" in lowered or "was sent sigkill" in lowered:
            name, message = "gunicorn.worker_exited", "worker exited unexpectedly"
        else:
            name, message = "gunicorn.error", "Gunicorn reported an error"
        self.error_log.error(message, extra={"event": name})

    def critical(self, msg, *args, **kwargs) -> None:
        self.error_log.critical(
            "Gunicorn reported a critical error",
            extra={"event": "gunicorn.critical"},
        )

    def exception(self, msg, *args, **kwargs) -> None:
        exc = sys.exc_info()[1]
        fields: dict[str, Any] = {"event": "gunicorn.error"}
        if exc is not None:
            fields.update(safe_exception_fields(exc))
        self.error_log.error("Gunicorn operation failed", extra=fields)
