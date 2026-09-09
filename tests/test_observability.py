"""Privacy and correlation guarantees for production request logging."""

import json
import re

import pytest

pytest.importorskip("flask")

from fake_review_detector.errors import StorageError
from webui.app import create_app
from webui.config import AppConfig, ConfigError


def _config(**overrides) -> AppConfig:
    settings = {
        "secret_key": "test-key-not-a-secret-32-characters",
        "log_format": "json",
        "log_level": "INFO",
    }
    settings.update(overrides)
    return AppConfig(**settings)


def _events(capsys) -> list[dict]:
    return [
        json.loads(line)
        for line in capsys.readouterr().out.splitlines()
        if line.strip()
    ]


def test_valid_request_id_is_returned_and_structured(capsys):
    client = create_app(_config()).test_client()
    response = client.get(
        "/readyz?token=query-secret",
        headers={"X-Request-ID": "deploy-check_2026.09"},
    )

    assert response.headers["X-Request-ID"] == "deploy-check_2026.09"
    events = _events(capsys)
    request_event = events[-1]
    assert request_event["event"] == "http.request"
    assert request_event["request_id"] == "deploy-check_2026.09"
    assert request_event["method"] == "GET"
    assert request_event["route"] == "/readyz"
    assert request_event["endpoint"] == "ui.readyz"
    assert request_event["status"] == 200
    assert request_event["duration_ms"] >= 0
    assert request_event["process_id"] > 0
    assert request_event["severity"] == "INFO"
    assert "query-secret" not in json.dumps(events)


def test_untrusted_request_id_is_replaced_and_not_logged(capsys):
    client = create_app(_config()).test_client()
    response = client.get(
        "/missing/private-object",
        headers={"X-Request-ID": "invalid request id with spaces"},
    )

    generated = response.headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", generated)
    output = json.dumps(_events(capsys))
    assert "invalid request id with spaces" not in output
    assert "private-object" not in output
    assert '"route": "unmatched"' in output


def test_error_logs_exclude_exception_messages_and_submitted_content(
    tmp_path, capsys, monkeypatch
):
    app = create_app(
        _config(storage="sqlite", data_dir=tmp_path)
    )
    service = app.extensions["ui_moderation_service"]

    def unavailable():
        raise StorageError("/private/storage/moderation.sqlite3 contains customer-data")

    monkeypatch.setattr(service, "healthcheck", unavailable)
    response = app.test_client().get(
        "/readyz?secret=raw-query-value",
        headers={"X-Request-ID": "storage-check"},
    )

    assert response.status_code == 503
    output = json.dumps(_events(capsys))
    assert "/private/storage" not in output
    assert "customer-data" not in output
    assert "raw-query-value" not in output
    assert "fake_review_detector.errors.StorageError" in output
    assert "storage.unavailable" in output


def test_unexpected_exception_message_is_not_logged(capsys, monkeypatch):
    app = create_app(_config())
    service = app.extensions["ui_moderation_service"]

    def explode(*, page, state):
        raise RuntimeError("private-domain.internal /srv/private/customer.sqlite3")

    monkeypatch.setattr(service, "snapshot", explode)
    response = app.test_client().get("/queue?page=customer-secret")

    assert response.status_code == 500
    output = json.dumps(_events(capsys))
    assert "private-domain.internal" not in output
    assert "/srv/private" not in output
    assert "customer-secret" not in output
    assert "builtins.RuntimeError" in output
    assert "http.unhandled_error" in output


def test_request_body_and_forwarding_chain_are_not_logged(capsys):
    app = create_app(
        _config(log_client_address=True, trusted_proxy_hops=1)
    )
    client = app.test_client()
    response = client.post(
        "/reviews",
        data={
            "reviews": "private review body 4111111111111111",
            "csrf_token": "private-csrf-value",
        },
        headers={
            "X-Forwarded-For": "forwarding-chain-marker, 203.0.113.7",
            "Cookie": "session=private-session-value",
        },
    )

    assert response.status_code == 400
    output = json.dumps(_events(capsys))
    for secret in (
        "private review body",
        "4111111111111111",
        "private-csrf-value",
        "private-session-value",
        "forwarding-chain-marker",
    ):
        assert secret not in output
    assert "203.0.113.7" in output


def test_development_logging_remains_readable(capsys):
    client = create_app(
        _config(log_format="text")
    ).test_client()
    client.get("/healthz")
    line = capsys.readouterr().out.strip()
    assert not line.startswith("{")
    assert 'event="http.request"' in line
    assert 'route="/healthz"' in line


@pytest.mark.parametrize(
    "env",
    [
        {"LOG_FORMAT": "xml"},
        {"LOG_LEVEL": "verbose"},
        {"LOG_CLIENT_ADDRESS": "sometimes"},
    ],
)
def test_invalid_logging_configuration_fails_at_startup(env):
    with pytest.raises(ConfigError):
        AppConfig.from_env(env)


@pytest.mark.parametrize(
    "settings",
    [
        {"log_format": "JSON"},
        {"log_level": "info"},
        {"log_client_address": 1},
    ],
)
def test_direct_logging_configuration_is_validated(settings):
    with pytest.raises(ConfigError):
        _config(**settings)
