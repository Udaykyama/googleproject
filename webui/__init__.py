"""An optional web front end for the two tools in this repository.

Importing this package requires Flask, which is why it is an extra
(``pip install '.[web]'``) and never a dependency of ``inboxready`` or
``fake_review_detector``. The arrow points one way: the web layer imports the
libraries, the libraries know nothing about it, and both keep running with no
third-party packages installed at all.

    from webui import create_app
    app = create_app()

Or, for a local look:

    python -m webui
"""

from __future__ import annotations

__version__ = "1.0.0"

from .config import AppConfig, ConfigError

__all__ = ["__version__", "create_app", "AppConfig", "ConfigError"]


def create_app(config: AppConfig | None = None):
    """Build the Flask application.

    Imported lazily so that ``AppConfig`` and ``ConfigError`` remain available
    to a caller that wants to validate configuration before deciding whether
    the web extra is even installed.
    """

    from .app import create_app as _create_app

    return _create_app(config)
