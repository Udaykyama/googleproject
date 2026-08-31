"""Tests for the optional web layer.

The web layer is additive: it calls ``inboxready.audit()`` and
``fake_review_detector.moderate_batch()`` and renders what they return. So
these tests deliberately do *not* re-test detection logic. They cover the
things a web front end adds that a CLI does not have:

* input arriving from a hostile source, rather than from a developer's shell
* uploads, which may be enormous, binary, or someone's real mail
* limits — batch size, upload size, DNS query budget, request rate
* the storage decision, which is the one place a bad deployment can quietly
  turn the audit log's integrity guarantee into a fiction

Flask is an optional extra, so the whole module skips when it is absent. That
keeps ``pytest tests/`` working in a stdlib-only checkout, which is the same
promise the packages themselves make.
"""

import json
import re
import sys
from pathlib import Path

import pytest

flask = pytest.importorskip("flask", reason="web UI extra not installed")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from webui.app import create_app  # noqa: E402
from webui.audits import (  # noqa: E402
    AuditProblem,
    AuditService,
    QueryBudgetExceeded,
    _BudgetedResolver,
)
from webui.config import AppConfig, ConfigError  # noqa: E402
from webui.moderation import BatchProblem, ModerationService  # noqa: E402
from webui.ratelimit import RateLimiter  # noqa: E402

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def config(**overrides) -> AppConfig:
    settings = {"secret_key": "test-key-not-a-secret"}
    settings.update(overrides)
    return AppConfig(**settings)


@pytest.fixture
def client():
    return create_app(config()).test_client()


def token(client, path="/inbox") -> str:
    """Fetch a page and pull its CSRF token out, as a browser would."""

    match = CSRF_RE.search(client.get(path).get_data(as_text=True))
    assert match, f"no CSRF token rendered on {path}"
    return match.group(1)


def audit_form(client, **overrides) -> dict:
    form = {
        "csrf_token": token(client),
        "mode": "fixture",
        "fixture": "compliant-sender",
        "domain": "mail.example-good.test",
        "selectors": "google",
        "ips": "",
        "daily_volume": "0",
        "spam_rate": "",
    }
    form.update(overrides)
    return form


def sample_batch() -> str:
    return (ROOT / "data" / "sample_reviews.json").read_text(encoding="utf-8")


# -- the pages exist and say what they should ----------------------------


@pytest.mark.parametrize("path", ["/", "/inbox", "/reviews", "/queue", "/healthz"])
def test_every_page_loads(client, path):
    assert client.get(path).status_code == 200


def test_health_check_is_json(client):
    assert client.get("/healthz").get_json() == {"status": "ok"}


def test_pages_carry_hardening_headers(client):
    headers = client.get("/").headers
    assert "'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    # An audit page reflects a submitted domain and possibly a submitted
    # message. It must not land in a shared cache.
    assert headers["Cache-Control"] == "no-store"


def test_no_inline_script_or_style_anywhere():
    """The CSP forbids both, so a template using either would break silently."""

    for template in (ROOT / "webui" / "templates").glob("*.html"):
        body = template.read_text(encoding="utf-8")
        assert "<script" not in body.lower(), template.name
        assert "<style" not in body.lower(), template.name
        assert "style=" not in body.lower(), template.name


def test_storage_mode_is_stated_on_the_page(client):
    body = client.get("/queue").get_data(as_text=True)
    assert "lost when the process restarts" in body


def test_persistent_mode_says_so_instead(tmp_path):
    app = create_app(config(storage="file", data_dir=tmp_path))
    body = app.test_client().get("/queue").get_data(as_text=True)
    assert "persistent volume and exactly one instance" in body


# -- CSRF ----------------------------------------------------------------


def test_post_without_a_token_is_rejected(client):
    response = client.post("/inbox", data={"domain": "example.test"})
    assert response.status_code == 400


def test_post_with_someone_elses_token_is_rejected(client):
    stolen = token(client)
    other = create_app(config()).test_client()
    response = other.post("/inbox", data=audit_form(other, csrf_token=stolen))
    assert response.status_code == 400


def test_queue_actions_are_csrf_protected(client):
    assert client.post("/queue/claim", data={"moderator": "alice"}).status_code == 400
    assert client.post("/queue/resolve", data={"review_id": "r1"}).status_code == 400


# -- InboxReady form validation ------------------------------------------


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"domain": ""}, "Enter a domain"),
        ({"domain": "not a domain"}, "is not a valid domain name"),
        ({"domain": "a" * 300}, "too long"),
        ({"domain": "example.test/../etc"}, "is not a valid domain name"),
        ({"selectors": "not/a/selector"}, "not a valid DKIM selector"),
        ({"ips": "999.1.1.1"}, "not an IP address"),
        ({"daily_volume": "many"}, "whole number"),
        ({"daily_volume": "-1"}, "cannot be negative"),
        ({"spam_rate": "high"}, "must be a percentage"),
        ({"spam_rate": "500"}, "between 0 and 100"),
    ],
)
def test_bad_input_is_explained_not_crashed(client, overrides, expected):
    response = client.post("/inbox", data=audit_form(client, **overrides))
    assert response.status_code == 400
    assert expected in response.get_data(as_text=True)


def test_too_many_selectors_is_capped(client):
    selectors = " ".join(f"s{n}" for n in range(50))
    response = client.post("/inbox", data=audit_form(client, selectors=selectors))
    assert response.status_code == 400
    assert "At most" in response.get_data(as_text=True)


def test_a_fixture_audit_matches_the_command_line(client):
    """The web layer must not reshape the verdict it was given."""

    response = client.post(
        "/inbox",
        data=audit_form(
            client,
            fixture="failing-sender",
            domain="deals.example-shop.test",
            selectors="google legacy",
            ips="203.0.113.25",
            daily_volume="1200000",
            spam_rate="0.42",
        ),
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "Score 0/100" in body
    assert "NOT READY" in " ".join(body.split())
    assert "SPF_TOO_MANY_LOOKUPS" in body


def test_a_healthy_fixture_passes(client):
    response = client.post(
        "/inbox",
        data=audit_form(
            client,
            fixture="compliant-sender",
            domain="mail.example-good.test",
            selectors="google",
            ips="198.51.100.25",
            daily_volume="8000",
            spam_rate="0.05",
        ),
    )
    body = " ".join(response.get_data(as_text=True).split())
    assert "Score 96/100" in body
    assert "status: READY" in body


def test_an_unknown_fixture_is_refused_by_name(client):
    """Fixtures are chosen from a fixed list, never by path."""

    for attempt in ("../../etc/passwd", "/etc/passwd", "nope"):
        response = client.post("/inbox", data=audit_form(client, fixture=attempt))
        assert response.status_code == 400
        assert "bundled demo fixtures" in response.get_data(as_text=True)


# -- live DNS ------------------------------------------------------------


def test_live_dns_is_off_by_default(client):
    response = client.post("/inbox", data=audit_form(client, mode="live"))
    assert response.status_code == 400
    assert "disabled on this deployment" in response.get_data(as_text=True)


def test_live_dns_appears_once_enabled():
    service = AuditService(config(live_dns=True))
    assert "live" in service.available_modes()
    assert "live" not in AuditService(config()).available_modes()


def test_the_query_budget_aborts_an_audit_rather_than_degrading_it():
    """A budget breach must not look like an ordinary DNS failure.

    Every check catches ``DnsError`` and carries on with a partial answer. If
    the budget raised one, a truncated audit would be reported as a real
    verdict. It must escape instead.
    """

    from inboxready.dnsresolver import DnsError, SystemResolver

    assert not issubclass(QueryBudgetExceeded, DnsError)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(SystemResolver, "_lookup", lambda self, name, rrtype: [])
    try:
        resolver = _BudgetedResolver(budget=2, timeout=1.0)
        with pytest.raises(QueryBudgetExceeded):
            for n in range(5):
                resolver.query(f"host{n}.test", "TXT")
        assert resolver.query_count == 3
    finally:
        monkeypatch.undo()


def test_cached_answers_do_not_burn_budget():
    """Only real network queries count, or a wide audit would abort needlessly."""

    resolver = _BudgetedResolver(budget=1, timeout=1.0)
    resolver._cache[("a.test", "TXT")] = []
    for _ in range(20):
        resolver.query("a.test", "TXT")
    assert resolver.query_count == 0


# -- uploads -------------------------------------------------------------


def test_an_oversized_upload_is_rejected_before_it_is_read(client):
    payload = b"x" * (config().max_upload_bytes + 4096)
    response = client.post(
        "/inbox",
        data=audit_form(client, message=(_BytesFile(payload), "big.eml")),
        content_type="multipart/form-data",
    )
    assert response.status_code == 413


def test_an_empty_upload_is_explained(client):
    response = client.post(
        "/inbox",
        data=audit_form(client, message=(_BytesFile(b""), "empty.eml")),
        content_type="multipart/form-data",
    )
    assert response.status_code == 400


def test_a_binary_review_batch_is_explained_not_traced(client):
    response = client.post(
        "/reviews",
        data={
            "csrf_token": token(client, "/reviews"),
            "batch": (_BytesFile(b"\xff\xfe\x00binary"), "reviews.json"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "not UTF-8" in response.get_data(as_text=True)


def test_uploaded_message_content_is_never_logged(client, caplog):
    secret = b"Subject: quarterly numbers\r\n\r\naccount 4111111111111111\r\n"
    with caplog.at_level("DEBUG"):
        client.post(
            "/inbox",
            data=audit_form(client, message=(_BytesFile(secret), "private.eml")),
            content_type="multipart/form-data",
        )
    assert "4111111111111111" not in caplog.text


class _BytesFile:
    """Minimal file-like object for the test client's multipart encoder."""

    def __init__(self, data: bytes):
        from io import BytesIO

        self._buffer = BytesIO(data)

    def read(self, *args):
        return self._buffer.read(*args)

    def seek(self, *args):
        return self._buffer.seek(*args)

    def tell(self):
        return self._buffer.tell()


# -- review batches ------------------------------------------------------


def test_the_sample_batch_scores(client):
    response = client.post(
        "/reviews",
        data={"csrf_token": token(client, "/reviews"), "reviews": sample_batch()},
    )
    body = response.get_data(as_text=True)
    assert response.status_code == 200
    assert "6 review(s) scored" in body
    assert "for human review" in body


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", "Paste a JSON array"),
        ("   ", "Paste a JSON array"),
        ("{oops", "not valid JSON"),
        ("[]", "batch is empty"),
        ('{"count": 2}', "Expected a JSON array"),
        ("[1, 2, 3]", "must be a review object"),
    ],
)
def test_a_bad_batch_is_explained(client, raw, expected):
    response = client.post(
        "/reviews", data={"csrf_token": token(client, "/reviews"), "reviews": raw}
    )
    assert response.status_code == 400
    assert expected in response.get_data(as_text=True)


def test_the_batch_size_cap_is_enforced_and_names_the_way_out():
    """Duplicate detection is superlinear, so an unbounded batch is a DoS."""

    service = ModerationService(config(max_reviews=5))
    oversized = [{"review_id": str(n), "text": "x"} for n in range(6)]
    with pytest.raises(BatchProblem) as caught:
        service.parse(json.dumps(oversized))
    assert "command-line tool has no such limit" in str(caught.value)


def test_an_object_wrapper_is_accepted():
    service = ModerationService(config())
    assert service.parse('{"reviews": [{"review_id": "r1", "text": "hi"}]}')


# -- the queue -----------------------------------------------------------


def test_the_moderation_round_trip(client):
    client.post(
        "/reviews",
        data={
            "csrf_token": token(client, "/reviews"),
            "reviews": sample_batch(),
            "enqueue": "1",
        },
    )
    assert "r2" in client.get("/queue").get_data(as_text=True)

    claimed = client.post(
        "/queue/claim",
        data={"csrf_token": token(client, "/queue"), "moderator": "alice", "limit": "2"},
        follow_redirects=True,
    )
    assert "Claimed 2 item(s)." in claimed.get_data(as_text=True)

    resolved = client.post(
        "/queue/resolve",
        data={
            "csrf_token": token(client, "/queue"),
            "review_id": "r2",
            "moderator": "alice",
            "outcome": "overturned",
            "note": "genuine buyer",
        },
        follow_redirects=True,
    )
    body = resolved.get_data(as_text=True)
    assert "Recorded a verdict on r2." in body
    # An overturn rate is the honest measure of whether the scores are any
    # good, so the console has to show it.
    assert "overturn rate 100.0%" in body


def test_an_unattributed_decision_is_refused(client):
    response = client.post(
        "/queue/claim",
        data={"csrf_token": token(client, "/queue"), "moderator": "  "},
        follow_redirects=True,
    )
    assert "cannot be audited" in response.get_data(as_text=True)


def test_a_bad_outcome_is_refused(client):
    response = client.post(
        "/queue/resolve",
        data={
            "csrf_token": token(client, "/queue"),
            "review_id": "r1",
            "moderator": "alice",
            "outcome": "whatever",
        },
        follow_redirects=True,
    )
    assert "upheld, overturned, or unclear" in response.get_data(as_text=True)


def test_memory_storage_writes_nothing(tmp_path):
    app = create_app(config(data_dir=tmp_path))
    client = app.test_client()
    client.post(
        "/reviews",
        data={
            "csrf_token": token(client, "/reviews"),
            "reviews": sample_batch(),
            "enqueue": "1",
        },
    )
    assert list(tmp_path.iterdir()) == []


def test_file_storage_writes_a_verifiable_audit_log(tmp_path):
    from fake_review_detector.audit import AuditLog

    app = create_app(config(storage="file", data_dir=tmp_path))
    client = app.test_client()
    client.post(
        "/reviews",
        data={
            "csrf_token": token(client, "/reviews"),
            "reviews": sample_batch(),
            "enqueue": "1",
        },
    )
    client.post(
        "/queue/claim",
        data={"csrf_token": token(client, "/queue"), "moderator": "alice"},
    )
    client.post(
        "/queue/resolve",
        data={
            "csrf_token": token(client, "/queue"),
            "review_id": "r2",
            "moderator": "alice",
            "outcome": "upheld",
        },
    )

    log = AuditLog(tmp_path / "decisions.jsonl")
    assert "intact" in str(log.verify())
    assert (tmp_path / "queue.json").is_file()
    assert (tmp_path / "decisions.jsonl.anchor").is_file()


def test_the_queue_survives_a_restart_in_file_mode(tmp_path):
    settings = config(storage="file", data_dir=tmp_path)
    first = create_app(settings).test_client()
    first.post(
        "/reviews",
        data={
            "csrf_token": token(first, "/reviews"),
            "reviews": sample_batch(),
            "enqueue": "1",
        },
    )
    second = create_app(settings).test_client()
    assert "r2" in second.get("/queue").get_data(as_text=True)


def test_the_queue_does_not_survive_a_restart_in_memory_mode():
    settings = config()
    first = create_app(settings).test_client()
    first.post(
        "/reviews",
        data={
            "csrf_token": token(first, "/reviews"),
            "reviews": sample_batch(),
            "enqueue": "1",
        },
    )
    second = create_app(settings).test_client()
    assert "r2" not in second.get("/queue").get_data(as_text=True)


# -- configuration -------------------------------------------------------


def test_file_storage_without_a_data_dir_is_refused():
    """Silently defaulting to a temp dir would make the log's guarantee false."""

    with pytest.raises(ConfigError) as caught:
        AppConfig.from_env({"STORAGE": "file"})
    assert "DATA_DIR" in str(caught.value)


@pytest.mark.parametrize(
    "env",
    [
        {"STORAGE": "database"},
        {"LIVE_DNS": "maybe"},
        {"MAX_REVIEWS": "lots"},
        {"MAX_REVIEWS": "0"},
        {"DNS_TIMEOUT": "-1"},
        {"DEMO_DIR": "/nonexistent-directory-for-tests"},
    ],
)
def test_a_bad_environment_fails_at_startup(env):
    with pytest.raises(ConfigError):
        AppConfig.from_env(env)


def test_defaults_are_the_safe_ones():
    settings = AppConfig.from_env({})
    assert settings.live_dns is False
    assert settings.persistent is False


def test_a_missing_secret_key_gets_an_ephemeral_one():
    first = AppConfig.from_env({})
    second = AppConfig.from_env({})
    assert first.secret_key and first.secret_key != second.secret_key


def test_forwarded_headers_are_ignored_unless_declared():
    """Trusting X-Forwarded-For by default would make the rate limit useless."""

    assert AppConfig.from_env({}).trusted_proxy_hops == 0


# -- rate limiting -------------------------------------------------------


def test_the_limiter_refills_over_time():
    clock = _Clock()
    limiter = RateLimiter(per_minute=60, burst=2, clock=clock)
    assert limiter.check("1.2.3.4").allowed
    assert limiter.check("1.2.3.4").allowed
    denied = limiter.check("1.2.3.4")
    assert not denied.allowed
    assert denied.retry_after >= 1

    clock.advance(2)
    assert limiter.check("1.2.3.4").allowed


def test_clients_are_limited_separately():
    limiter = RateLimiter(per_minute=60, burst=1, clock=_Clock())
    assert limiter.check("1.1.1.1").allowed
    assert limiter.check("2.2.2.2").allowed
    assert not limiter.check("1.1.1.1").allowed


def test_the_limiter_does_not_grow_without_bound():
    """Otherwise the limiter itself is the memory-exhaustion vector."""

    clock = _Clock()
    limiter = RateLimiter(per_minute=60, burst=1, clock=clock, max_clients=50)
    for n in range(500):
        limiter.check(f"10.0.0.{n}")
        clock.advance(0.1)
    assert len(limiter) <= 50


def test_live_audits_are_rate_limited(monkeypatch):
    app = create_app(config(live_dns=True, rate_limit_per_minute=60, rate_limit_burst=1))
    client = app.test_client()
    # The limit is checked before the audit runs, so stub the audit out: this
    # test is about the throttle, and it must not depend on the network.
    monkeypatch.setattr(AuditService, "run", lambda self, request: None)

    first = client.post(
        "/inbox", data=audit_form(client, mode="live", domain="example.test")
    )
    assert first.status_code == 200

    response = client.post(
        "/inbox", data=audit_form(client, mode="live", domain="example.test")
    )
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_fixture_audits_are_not_rate_limited(client):
    """They do no network work, so limiting them only breaks the demo."""

    for _ in range(10):
        response = client.post("/inbox", data=audit_form(client))
        assert response.status_code == 200


class _Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


# -- error handling ------------------------------------------------------


def test_an_unexpected_failure_does_not_leak_internals(monkeypatch, client):
    def explode(self, request):
        raise RuntimeError("secret-domain.internal timed out at 10.0.0.1")

    monkeypatch.setattr(AuditService, "run", explode)
    response = client.post("/inbox", data=audit_form(client))
    assert response.status_code == 500
    assert "secret-domain.internal" not in response.get_data(as_text=True)


def test_an_unknown_page_renders_the_error_template(client):
    response = client.get("/no-such-page")
    assert response.status_code == 404
    assert "404" in response.get_data(as_text=True)


def test_the_audit_service_reports_a_missing_demo_directory():
    service = AuditService(config(demo_dir=None))
    assert service.available_modes() == ["offline"]
    with pytest.raises(AuditProblem):
        service.build_request({"mode": "fixture", "domain": "example.test"})


def test_an_install_without_the_examples_still_serves_every_page():
    """A wheel does not ship examples/, so this is the installed-app path."""

    client = create_app(config(demo_dir=None)).test_client()
    for path in ("/", "/inbox", "/reviews", "/queue", "/healthz"):
        assert client.get(path).status_code == 200
    assert "No demo fixtures are installed" in client.get("/inbox").get_data(
        as_text=True
    )
