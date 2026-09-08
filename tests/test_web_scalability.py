"""Concurrent workers, bounded work, and large-queue web behavior."""

import multiprocessing
import threading
from collections import OrderedDict
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import replace

import pytest

pytest.importorskip("flask")

from fake_review_detector import SQLiteStore, moderate
from fake_review_detector.errors import StorageBusyError
from test_webui import audit_form, config, sample_batch, token
from inboxready.dnsresolver import DnsError, SystemResolver
from webui.app import create_app
from webui.audits import (
    AuditBusy, AuditDeadlineExceeded, AuditProblem, AuditRequest, AuditService,
    AuditTimedOut, _BudgetedResolver,
)
from webui.config import AppConfig, ConfigError
from webui.ratelimit import RateLimiter, SQLiteRateLimiter


def seeded_app(tmp_path, *, count=7, **settings):
    app = create_app(config(storage="sqlite", data_dir=tmp_path, **settings))
    store = app.extensions["ui_moderation_service"].store.database
    seed = moderate({
        "review_id": "seed", "author": "sample", "rating": 5,
        "text": "Best product ever!!!", "verified_purchase": False,
    })
    store.enqueue(replace(seed, review_id=f"r{i:03}") for i in range(count))
    return app, store


def _consume_shared_token(path):
    limiter = SQLiteRateLimiter(
        SQLiteStore(path), per_minute=60, burst=3, clock=lambda: 1000.0
    )
    return limiter.check("shared-client").allowed


def test_sqlite_requires_both_a_directory_and_stable_secret(tmp_path):
    with pytest.raises(ConfigError, match="DATA_DIR"):
        AppConfig.from_env({"STORAGE": "sqlite"})
    with pytest.raises(ConfigError, match="SECRET_KEY"):
        AppConfig.from_env({"STORAGE": "sqlite", "DATA_DIR": str(tmp_path)})
    settings = AppConfig.from_env({
        "STORAGE": "sqlite", "DATA_DIR": str(tmp_path),
        "SECRET_KEY": "stable-test-key",
    })
    assert settings.persistent and settings.storage == "sqlite"


@pytest.mark.parametrize("name", ["DNS_TIMEOUT", "AUDIT_DEADLINE", "SQLITE_TIMEOUT"])
@pytest.mark.parametrize("value", ["nan", "inf", "-inf", "0"])
def test_nonfinite_limits_are_rejected(name, value):
    with pytest.raises(ConfigError):
        AppConfig.from_env({name: value})


@pytest.mark.parametrize("settings", [
    {"audit_workers": 0}, {"queue_page_size": 201},
    {"dns_timeout": float("nan")}, {"trusted_proxy_hops": -1},
])
def test_direct_config_construction_cannot_bypass_limits(settings):
    with pytest.raises(ConfigError):
        config(**settings)


def test_session_and_queue_are_shared_across_app_workers(tmp_path):
    settings = config(storage="sqlite", data_dir=tmp_path)
    first = create_app(settings).test_client()
    csrf = token(first, "/reviews")
    second = create_app(settings).test_client()
    second.set_cookie("session", first.get_cookie("session").value)
    response = second.post("/reviews", data={
        "csrf_token": csrf, "reviews": sample_batch(), "enqueue": "1",
    })
    assert response.status_code == 200
    assert "r2" in first.get("/queue").get_data(as_text=True)
    assert "transactional SQLite" in response.get_data(as_text=True)


def test_sqlite_rate_allowance_is_shared_by_actual_processes(tmp_path):
    path = tmp_path / "moderation.sqlite3"
    SQLiteStore(path)
    with ProcessPoolExecutor(
        max_workers=4, mp_context=multiprocessing.get_context("spawn")
    ) as pool:
        allowed = list(pool.map(_consume_shared_token, [path] * 12))
    assert sum(allowed) == 3


def test_http_rate_limit_does_not_reset_between_workers(tmp_path, monkeypatch):
    settings = config(
        storage="sqlite", data_dir=tmp_path, live_dns=True, rate_limit_burst=1
    )
    monkeypatch.setattr(AuditService, "run", lambda self, request: None)
    first = create_app(settings).test_client()
    assert first.post("/inbox", data=audit_form(first, mode="live")).status_code == 200
    second = create_app(settings).test_client()
    response = second.post("/inbox", data=audit_form(second, mode="live"))
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_queue_is_paginated_with_distinct_empty_states(tmp_path):
    app, store = seeded_app(tmp_path, queue_page_size=2)
    client = app.test_client()
    first = client.get("/queue?state=pending").get_data(as_text=True)
    second = client.get("/queue?state=pending&page=2").get_data(as_text=True)
    assert first.count('class="check queue-item"') == 2
    assert second.count('class="check queue-item"') == 2
    assert "Showing 1 to 2" in first and "Showing 3 to 4" in second
    assert "r000" in first and "r000" not in second
    assert "7 total" in first
    filtered = client.get("/queue?state=resolved").get_data(as_text=True)
    assert "No resolved items right now" in filtered
    assert "The queue is empty" not in filtered
    beyond = client.get("/queue?page=100").get_data(as_text=True)
    assert "Return to the first page" in beyond


@pytest.mark.parametrize("query", ["page=0", "page=nope", "page=1.5", "state=invalid"])
def test_invalid_queue_filters_are_explained(tmp_path, query):
    app, _ = seeded_app(tmp_path)
    assert app.test_client().get(f"/queue?{query}").status_code == 400


def test_page_load_does_not_rescan_the_audit_history(tmp_path, monkeypatch):
    app, store = seeded_app(tmp_path)

    def unexpected_scan():
        pytest.fail("a queue page must not scan the decision history")

    monkeypatch.setattr(store, "verify", unexpected_scan)
    response = app.test_client().get("/queue")
    assert response.status_code == 200
    assert "Full history not checked" in response.get_data(as_text=True)


def test_explicit_integrity_check_and_release_are_wired(tmp_path):
    app, store = seeded_app(tmp_path)
    store.claim("alice")
    client = app.test_client()
    response = client.post("/queue/release", data={
        "csrf_token": token(client, "/queue"), "review_id": "r000",
        "state": "pending", "page": "2",
    })
    assert response.status_code == 302
    assert "page=2" in response.location and "state=pending" in response.location
    assert store.get("r000").state.value == "pending"
    checked = client.post("/queue/verify", data={
        "csrf_token": token(client, "/queue"),
    }, follow_redirects=True)
    assert "anchor matches" in checked.get_data(as_text=True)
    assert client.post("/queue/verify").status_code == 400
    assert client.post("/queue/release").status_code == 400


def test_readiness_detects_missing_storage_but_liveness_still_responds(tmp_path):
    app, store = seeded_app(tmp_path)
    client = app.test_client()
    assert client.get("/readyz").get_json() == {"status": "ready"}
    store.path.unlink()
    response = client.get("/readyz")
    assert response.status_code == 503
    assert response.get_json() == {"status": "unavailable"}
    assert client.get("/healthz").status_code == 200


def test_storage_contention_is_retryable_without_exposing_paths(tmp_path, monkeypatch):
    app, store = seeded_app(tmp_path)
    client = app.test_client()

    def busy(decisions):
        raise StorageBusyError("private-database-location")

    monkeypatch.setattr(store, "enqueue", busy)
    response = client.post("/reviews", data={
        "csrf_token": token(client, "/reviews"), "reviews": sample_batch(),
        "enqueue": "1",
    })
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "1"
    assert "private-database-location" not in response.get_data(as_text=True)


def test_non_ascii_csrf_token_is_rejected_without_a_server_error():
    client = create_app(config()).test_client()
    response = client.post(
        "/inbox", data=audit_form(client, csrf_token="\u2603")
    )
    assert response.status_code == 400


def test_busy_pool_refuses_work_instead_of_growing_a_submission_queue(monkeypatch):
    service = AuditService(config(audit_workers=1, audit_deadline=5))
    started, release = threading.Event(), threading.Event()

    def blocked(**kwargs):
        started.set()
        assert release.wait(5)

    monkeypatch.setattr("webui.audits.run_inboxready_audit", blocked)
    request = AuditRequest(mode="offline", message=b"Subject: sample\n\nbody")
    try:
        with ThreadPoolExecutor(max_workers=1) as requests:
            future = requests.submit(service.run, request)
            try:
                assert started.wait(2)
                for _ in range(20):
                    with pytest.raises(AuditBusy):
                        service.run(request)
            finally:
                release.set()
            assert future.result(timeout=2) is None
    finally:
        release.set()
        service.close()


def test_timeout_stops_further_dns_queries_and_holds_the_slot_until_exit(monkeypatch):
    monkeypatch.setattr(SystemResolver, "_import_dnspython", staticmethod(lambda: None))
    monkeypatch.setattr("inboxready.dnsresolver.shutil.which", lambda name: "/usr/bin/dig")
    resolver = _BudgetedResolver(budget=120, timeout=1)
    service = AuditService(config(audit_workers=1, audit_deadline=0.1))
    release = threading.Event()
    calls = []

    def slow_lookup(self, name, rrtype):
        calls.append(name)
        assert release.wait(5)
        return []

    def many_queries(**kwargs):
        for index in range(20):
            resolver.query(f"host{index}.test", "TXT")

    monkeypatch.setattr(SystemResolver, "_lookup", slow_lookup)
    monkeypatch.setattr(service, "_resolver", lambda request: resolver)
    monkeypatch.setattr("webui.audits.run_inboxready_audit", many_queries)
    request = AuditRequest(mode="live", domain="example.test")
    try:
        with pytest.raises(AuditTimedOut):
            service.run(request)
        with pytest.raises(AuditBusy):
            service.run(request)
    finally:
        release.set()
        service.close()
    assert calls == ["host0.test"]
    assert resolver.query_count == 1
    resolver._cache[("cached.test", "TXT")] = []
    with pytest.raises(AuditDeadlineExceeded):
        resolver.query("cached.test", "TXT")


def test_resolver_setup_failure_does_not_leak_admission_slots(monkeypatch):
    service = AuditService(config(audit_workers=1))

    def unavailable(request):
        raise DnsError("no resolver")

    monkeypatch.setattr(service, "_resolver", unavailable)
    try:
        for _ in range(3):
            with pytest.raises(AuditProblem, match="cannot resolve DNS"):
                service.run(AuditRequest(mode="live", domain="example.test"))
    finally:
        service.close()


@pytest.mark.parametrize("problem, status", [(AuditBusy("busy"), 503), (AuditTimedOut("late"), 504)])
def test_audit_resource_failures_use_the_correct_http_status(monkeypatch, problem, status):
    def fail(self, request):
        raise problem

    monkeypatch.setattr(AuditService, "run", fail)
    client = create_app(config()).test_client()
    assert client.post("/inbox", data=audit_form(client)).status_code == status


def test_memory_rate_limit_does_not_scan_all_clients():
    class NoScan(OrderedDict):
        def items(self):
            for index, item in enumerate(super().items()):
                assert index == 0, "eviction scanned every active client"
                yield item

    limiter = RateLimiter(60, 1, clock=lambda: 1000.0)
    limiter._buckets = NoScan((f"client-{i}", (0.0, 1000.0)) for i in range(1000))
    assert not limiter.check("client-500").allowed


@pytest.mark.parametrize("persistent", [False, True])
def test_rate_buckets_remain_bounded_and_refill(tmp_path, persistent):
    now = [1000.0]
    kwargs = dict(per_minute=60, burst=1, max_clients=5, clock=lambda: now[0])
    limiter = (
        SQLiteRateLimiter(SQLiteStore(tmp_path / "db"), **kwargs)
        if persistent else RateLimiter(**kwargs)
    )
    for i in range(100):
        assert limiter.check(f"client-{i}").allowed
    assert len(limiter) == 5
    assert not limiter.check("client-99").allowed
    now[0] += 1
    assert limiter.check("client-99").allowed
    assert len(limiter) == 1


@pytest.mark.parametrize("cost", [0, -1, float("nan"), float("inf"), 2])
def test_invalid_rate_cost_is_not_silently_accepted(cost):
    with pytest.raises(ValueError):
        RateLimiter(60, 1).check("client", cost)


@pytest.mark.parametrize("port", ["not-a-number", "0", "-1", "65536"])
def test_invalid_server_port_is_a_clean_startup_error(monkeypatch, capsys, port):
    from webui.__main__ import main

    monkeypatch.setenv("PORT", port)
    assert main([]) == 2
    assert "PORT" in capsys.readouterr().err
