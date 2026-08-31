"""``python -m webui`` — a development server.

Werkzeug's server is for development only, and says so loudly when it starts.
The README documents Gunicorn with a single worker for anything else, which is
also what ``STORAGE=file`` requires.
"""

from __future__ import annotations

import os
import sys

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

    try:
        config = AppConfig.from_env()
    except ConfigError as exc:
        print(f"webui: {exc}", file=sys.stderr)
        return 2

    from .app import create_app

    app = create_app(config)
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))

    print(f"webui: DNS mode      {'live' if config.live_dns else 'demo fixtures only'}")
    print(f"webui: storage       {config.storage} — {config.storage_summary}")
    print(f"webui: listening on  http://{host}:{port}")

    # Never debug=True: the Werkzeug debugger is a remote code execution
    # console for anyone who can reach it.
    app.run(host=host, port=port, debug=False)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
