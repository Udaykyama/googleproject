"""Configuration for the web UI, and the deployment decisions it encodes.

Everything here exists because a browser-facing deployment has failure modes a
CLI does not. Two settings in particular are not cosmetic:

``live_dns``
    InboxReady resolves whatever domain a visitor types. Exposed publicly and
    unthrottled, that is a free DNS-scanning service. It is therefore **off by
    default**: the app ships in demo mode, serving the bundled fixtures only,
    which has no outbound network surface at all. Turning it on also turns on
    per-IP rate limiting, a per-audit query budget, and a request deadline.

``storage``
    The review queue and the audit log are single-writer files. On a host that
    runs several instances, or whose disk is discarded on restart, two workers
    corrupt each other's queue and the hash-chained log silently loses the very
    history it exists to protect. Rather than let that happen quietly, the mode
    is explicit:

    ``memory``
        Default. The queue lives in the process and is lost on restart, and no
        audit log is written at all. Safe to run anywhere, including serverless
        hosts, precisely because it promises nothing.
    ``file``
        A real :class:`~fake_review_detector.queue.ReviewQueue` and a real
        :class:`~fake_review_detector.audit.AuditLog` with its anchor. Requires
        ``DATA_DIR``, a persistent disk, and **exactly one instance**.

The UI states which mode is active on every page, so nobody reads a durable
guarantee into an ephemeral deployment.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

__all__ = ["AppConfig", "ConfigError", "MEMORY", "FILE"]

MEMORY = "memory"
FILE = "file"

#: Where the repository's demo assets live when running from a checkout.
_REPO_ROOT = Path(__file__).resolve().parent.parent


def _default_demo_dir() -> Path | None:
    """The bundled ``examples/`` directory, when running from a checkout."""

    candidate = _REPO_ROOT / "examples"
    return candidate if candidate.is_dir() else None


class ConfigError(ValueError):
    """Raised when the environment asks for something unsafe or impossible."""


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    value = raw.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ConfigError(f"{name} must be a boolean, got {raw!r}")


def _bounded_int(
    env: Mapping[str, str], name: str, default: int, minimum: int = 1
) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value}")
    return value


def _positive_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if value <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {value}")
    return value


@dataclass(frozen=True)
class AppConfig:
    """Resolved settings for one running instance."""

    secret_key: str
    live_dns: bool = False
    storage: str = MEMORY
    data_dir: Path | None = None
    demo_dir: Path | None = field(default_factory=_default_demo_dir)

    #: Hard ceiling on an uploaded ``.eml`` or review batch. Uploads are read
    #: into memory and never written to disk, so this is also a memory bound.
    max_upload_bytes: int = 256 * 1024
    #: Reviews accepted per batch. Duplicate detection is superlinear in dense
    #: clusters, so an unbounded batch is a CPU exhaustion vector.
    max_reviews: int = 200
    #: DNS queries one audit may issue before it is abandoned. A full audit of
    #: a healthy domain uses roughly 30; a pathological SPF chain uses more.
    dns_query_budget: int = 120
    #: Per-query DNS timeout. Lower than the CLI's 5s: a browser is waiting.
    dns_timeout: float = 3.0
    #: Wall-clock ceiling for one audit. The work happens on a worker thread so
    #: a slow domain returns an error instead of occupying the request forever.
    audit_deadline: float = 25.0
    #: Live-DNS audits allowed per client per minute, and the largest burst.
    rate_limit_per_minute: int = 6
    rate_limit_burst: int = 3
    #: Number of trusted reverse proxies in front of the app. Zero means
    #: ``X-Forwarded-For`` is ignored, because trusting a spoofable header
    #: would let a client evade the rate limit by varying it.
    trusted_proxy_hops: int = 0

    @property
    def persistent(self) -> bool:
        return self.storage == FILE

    @property
    def storage_summary(self) -> str:
        """One line for the UI banner. Deliberately blunt."""

        if self.persistent:
            return (
                "Queue and audit log are written to disk. This requires a "
                "persistent volume and exactly one instance."
            )
        return (
            "Queue is held in memory and is lost when the process restarts. "
            "No audit log is written — use the CLI for a durable, "
            "tamper-evident record."
        )

    @property
    def fixtures_dir(self) -> Path | None:
        return self.demo_dir / "fixtures" if self.demo_dir else None

    @property
    def messages_dir(self) -> Path | None:
        return self.demo_dir / "messages" if self.demo_dir else None

    @property
    def sample_reviews(self) -> Path | None:
        if self.demo_dir is None:
            return None
        candidate = self.demo_dir.parent / "data" / "sample_reviews.json"
        return candidate if candidate.is_file() else None

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "AppConfig":
        env = os.environ if env is None else env

        storage = (env.get("STORAGE") or MEMORY).strip().lower()
        if storage not in {MEMORY, FILE}:
            raise ConfigError(
                f"STORAGE must be {MEMORY!r} or {FILE!r}, got {storage!r}"
            )

        raw_data_dir = (env.get("DATA_DIR") or "").strip()
        data_dir = Path(raw_data_dir).expanduser().resolve() if raw_data_dir else None
        if storage == FILE and data_dir is None:
            raise ConfigError(
                "STORAGE=file needs DATA_DIR to point at a persistent directory. "
                "Without one the audit log would be discarded on restart, which "
                "is exactly the tampering the log exists to detect."
            )

        raw_demo = (env.get("DEMO_DIR") or "").strip()
        if raw_demo:
            demo_dir: Path | None = Path(raw_demo).expanduser().resolve()
            if not demo_dir.is_dir():
                raise ConfigError(f"DEMO_DIR {raw_demo!r} is not a directory")
        else:
            demo_dir = _default_demo_dir()

        secret_key = env.get("SECRET_KEY") or ""
        if not secret_key:
            # Ephemeral: sessions, and therefore CSRF tokens, do not survive a
            # restart. Fine for a demo, wrong for anything multi-instance.
            secret_key = secrets.token_urlsafe(32)

        return cls(
            secret_key=secret_key,
            live_dns=_flag(env, "LIVE_DNS", False),
            storage=storage,
            data_dir=data_dir,
            demo_dir=demo_dir,
            max_upload_bytes=_bounded_int(
                env, "MAX_UPLOAD_BYTES", cls.max_upload_bytes
            ),
            max_reviews=_bounded_int(env, "MAX_REVIEWS", cls.max_reviews),
            dns_query_budget=_bounded_int(
                env, "DNS_QUERY_BUDGET", cls.dns_query_budget
            ),
            dns_timeout=_positive_float(env, "DNS_TIMEOUT", cls.dns_timeout),
            audit_deadline=_positive_float(env, "AUDIT_DEADLINE", cls.audit_deadline),
            rate_limit_per_minute=_bounded_int(
                env, "RATE_LIMIT_PER_MINUTE", cls.rate_limit_per_minute
            ),
            rate_limit_burst=_bounded_int(
                env, "RATE_LIMIT_BURST", cls.rate_limit_burst
            ),
            trusted_proxy_hops=_bounded_int(
                env, "TRUSTED_PROXY_HOPS", cls.trusted_proxy_hops, minimum=0
            ),
        )
