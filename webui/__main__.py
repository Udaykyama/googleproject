"""``python -m webui`` — a development server.

Werkzeug's server is for development only, and says so loudly when it starts.
The README documents Gunicorn for deployment, with SQLite storage when using
multiple workers. ``STORAGE=file`` still requires a single worker.
"""

from __future__ import annotations

import os
import sys

from fake_review_detector.errors import ModerationError

from .config import AppConfig, ConfigError


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in {"-h", "--help"}:
        print(__doc__)
        print(
            "Environment: LIVE_DNS, STORAGE, DATA_DIR, SECRET_KEY, HOST, PORT.\n"
            "See the 'Web UI' section of README.md."
        )
        return 0
    if argv:
        print("webui: options are configured through environment variables; use --help", file=sys.stderr)
        return 2

    try:
        config = AppConfig.from_env()
        host = os.environ.get("HOST", "127.0.0.1").strip()
        if not host:
            raise ConfigError("HOST cannot be blank")
        try:
            port = int(os.environ.get("PORT", "8000"))
        except ValueError:
            raise ConfigError("PORT must be an integer between 1 and 65535") from None
        if not 1 <= port <= 65535:
            raise ConfigError("PORT must be between 1 and 65535")
    except ConfigError as exc:
        print(f"webui: {exc}", file=sys.stderr)
        return 2

    try:
        from .app import create_app
    except ModuleNotFoundError as exc:
        if exc.name not in {"flask", "werkzeug"}:
            raise
        print("webui: install the web extra with: pip install '.[web]'", file=sys.stderr)
        return 2

    try:
        app = create_app(config)
    except (ModerationError, OSError) as exc:
        print(f"webui: cannot initialize storage: {exc}", file=sys.stderr)
        return 2

    print(f"webui: DNS mode      {'live' if config.live_dns else 'demo fixtures only'}")
    print(f"webui: storage       {config.storage} — {config.storage_summary}")
    print(f"webui: listening on  http://{host}:{port}")

    # Never debug=True: the Werkzeug debugger is a remote code execution
    # console for anyone who can reach it.
    try:
        app.run(host=host, port=port, debug=False)
    finally:
        app.extensions["ui_audit_service"].close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
