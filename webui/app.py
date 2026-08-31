"""The Flask application: routing, CSRF, rate limiting, response headers.

Kept thin on purpose. Validation lives in :mod:`webui.audits` and
:mod:`webui.moderation` so it can be tested without a request context, and so
the detection and audit logic below it stays entirely unaware that a web layer
exists.

Two security notes worth stating explicitly:

* There is **no authentication**. Anyone who can reach the app can work the
  queue. That is acceptable for a local demo and is called out in the README;
  a real deployment puts an identity proxy in front of it.
* Uploads are read into memory, size-capped by Werkzeug before the body is
  consumed, and never written to disk or logged. An uploaded ``.eml`` may
  contain someone's real mail.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets

from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from .audits import MODE_LIVE, AuditProblem, AuditService
from .config import AppConfig
from .moderation import BatchProblem, ModerationService
from .ratelimit import RateLimiter

__all__ = ["create_app"]

_CSRF_FIELD = "csrf_token"
_CSRF_SESSION_KEY = "_csrf"

#: No inline script or style anywhere, so the policy can stay strict. The UI
#: uses <details> for expandable findings rather than JavaScript.
_CSP = (
    "default-src 'none'; "
    "style-src 'self'; "
    "img-src 'self'; "
    "form-action 'self'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'"
)

bp = Blueprint("ui", __name__)


# -- CSRF ----------------------------------------------------------------
# Hand-rolled rather than pulled in as a dependency: it is a session-stored
# random token and a constant-time comparison, and the app already has a
# signed session.


def csrf_token() -> str:
    token = session.get(_CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_urlsafe(32)
        session[_CSRF_SESSION_KEY] = token
    return token


def _check_csrf() -> None:
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return
    submitted = request.form.get(_CSRF_FIELD, "")
    expected = session.get(_CSRF_SESSION_KEY, "")
    if not expected or not hmac.compare_digest(submitted, expected):
        abort(400, "This form expired or came from another site. Try again.")


# -- rate limiting -------------------------------------------------------


def _client_id() -> str:
    # ProxyFix has already rewritten remote_addr when the deployment declared
    # how many proxies to trust; when it declared none, this is the socket
    # peer and X-Forwarded-For is ignored.
    return request.remote_addr or "unknown"


def _enforce_rate_limit() -> None:
    limiter: RateLimiter = current_app.extensions["ui_rate_limiter"]
    verdict = limiter.check(_client_id())
    if not verdict.allowed:
        abort(429, retry_after=verdict.retry_after)


# -- routes --------------------------------------------------------------


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


@bp.route("/inbox", methods=["GET", "POST"])
def inbox():
    service: AuditService = current_app.extensions["ui_audit_service"]
    modes = service.available_modes()
    context = {
        "modes": modes,
        "fixtures": sorted(service.assets.fixtures),
        "messages": sorted(service.assets.messages),
        "form": request.form,
        "report": None,
    }

    if request.method == "GET":
        return render_template("inbox.html", **context)

    try:
        message, message_name = _message_from_request(service)
        audit_request = service.build_request(
            request.form, message=message, message_name=message_name
        )
        if audit_request.mode == MODE_LIVE:
            _enforce_rate_limit()
        report = service.run(audit_request)
    except AuditProblem as exc:
        context["error"] = str(exc)
        return render_template("inbox.html", **context), 400

    context["report"] = report
    context["request_summary"] = audit_request
    return render_template("inbox.html", **context)


def _message_from_request(service: AuditService):
    """Read the .eml from an upload or the demo set. Never touches disk."""

    demo = (request.form.get("demo_message") or "").strip()
    upload = request.files.get("message")

    if upload is not None and upload.filename:
        raw = upload.read()
        if not raw:
            raise AuditProblem("That file is empty.")
        # Werkzeug enforces MAX_CONTENT_LENGTH on the whole body before we get
        # here; this guards the single-part case explicitly.
        limit = current_app.config["MAX_CONTENT_LENGTH"]
        if limit is not None and len(raw) > limit:
            raise RequestEntityTooLarge()
        return raw, upload.filename
    if demo:
        return service.demo_message(demo)
    return None, ""


@bp.route("/reviews", methods=["GET", "POST"])
def reviews():
    service: ModerationService = current_app.extensions["ui_moderation_service"]
    context = {
        "form": request.form,
        "result": None,
        "sample_available": bool(service.config.sample_reviews),
        "pasted": request.form.get("reviews", ""),
    }

    if request.method == "GET":
        if request.args.get("sample") and service.config.sample_reviews:
            context["pasted"] = service.sample()
        return render_template("reviews.html", **context)

    try:
        raw = _reviews_from_request()
        parsed = service.parse(raw)
        result = service.moderate(parsed)
    except BatchProblem as exc:
        context["error"] = str(exc)
        return render_template("reviews.html", **context), 400

    queued = service.enqueue(result) if request.form.get("enqueue") else 0
    context["result"] = result
    context["queued"] = queued
    return render_template("reviews.html", **context)


def _reviews_from_request():
    upload = request.files.get("batch")
    if upload is not None and upload.filename:
        raw = upload.read()
        if not raw:
            raise BatchProblem("That file is empty.")
        limit = current_app.config["MAX_CONTENT_LENGTH"]
        if limit is not None and len(raw) > limit:
            raise RequestEntityTooLarge()
        return raw
    return request.form.get("reviews", "")


@bp.route("/queue")
def review_queue():
    service: ModerationService = current_app.extensions["ui_moderation_service"]
    snapshot = service.snapshot()
    return render_template(
        "queue.html",
        items=snapshot.items,
        stats=snapshot.stats,
        integrity=service.integrity(),
    )


@bp.route("/queue/claim", methods=["POST"])
def queue_claim():
    service: ModerationService = current_app.extensions["ui_moderation_service"]
    try:
        claimed = service.claim(
            request.form.get("moderator", ""), request.form.get("limit", 1)
        )
    except BatchProblem as exc:
        flash(str(exc), "error")
    else:
        flash(
            f"Claimed {claimed} item(s)." if claimed else "Nothing left to claim.",
            "notice" if claimed else "warning",
        )
    return redirect(url_for("ui.review_queue"))


@bp.route("/queue/resolve", methods=["POST"])
def queue_resolve():
    service: ModerationService = current_app.extensions["ui_moderation_service"]
    review_id = request.form.get("review_id", "")
    try:
        service.resolve(
            review_id,
            request.form.get("moderator", ""),
            request.form.get("outcome", ""),
            request.form.get("note", ""),
        )
    except BatchProblem as exc:
        flash(str(exc), "error")
    else:
        flash(f"Recorded a verdict on {review_id}.", "notice")
    return redirect(url_for("ui.review_queue"))


# -- application factory -------------------------------------------------


def create_app(config: AppConfig | None = None) -> Flask:
    """Build the application. Raises :class:`ConfigError` on a bad environment."""

    config = config or AppConfig.from_env()

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key,
        MAX_CONTENT_LENGTH=config.max_upload_bytes,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set unconditionally: the app is only ever meant to be reached over
        # HTTPS or over loopback, and loopback tolerates a Secure cookie in
        # every current browser.
        SESSION_COOKIE_SECURE=True,
        JSON_SORT_KEYS=False,
    )
    app.config["UI_CONFIG"] = config

    if config.trusted_proxy_hops:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=config.trusted_proxy_hops,
            x_proto=config.trusted_proxy_hops,
            x_host=0,
            x_prefix=0,
        )

    app.extensions["ui_audit_service"] = AuditService(config)
    app.extensions["ui_moderation_service"] = ModerationService(config)
    app.extensions["ui_rate_limiter"] = RateLimiter(
        per_minute=config.rate_limit_per_minute, burst=config.rate_limit_burst
    )

    app.before_request(_check_csrf)
    app.register_blueprint(bp)

    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["app_config"] = config
    app.jinja_env.filters["pretty_json"] = _pretty_json

    @app.after_request
    def _harden(response):
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        # An audit reflects whatever the visitor submitted, including an
        # uploaded message. Nothing here should sit in a shared cache.
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        response = render_template(
            "error.html",
            code=exc.code,
            name=exc.name,
            description=exc.description,
        )
        headers = {}
        retry_after = getattr(exc, "retry_after", None)
        if retry_after:
            headers["Retry-After"] = str(retry_after)
        return response, exc.code or 500, headers

    @app.errorhandler(Exception)
    def _unexpected(exc: Exception):
        # Log the traceback, show the visitor nothing: an audit's internals can
        # include the domain and message they submitted.
        app.logger.exception("unhandled error serving %s", request.path)
        return (
            render_template(
                "error.html",
                code=500,
                name="Internal Server Error",
                description="Something went wrong handling that request.",
            ),
            500,
        )

    if not app.debug:  # pragma: no cover - logging setup
        logging.getLogger("werkzeug").setLevel(logging.WARNING)

    return app


def _pretty_json(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
