"""Tests for the DNS resolver abstraction and hostname validation."""

from __future__ import annotations

import json
import importlib.util
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from support import SRC  # noqa: F401  (adds src/ to sys.path)

from inboxready.dnsresolver import (
    NXDOMAIN,
    DnsError,
    StaticResolver,
    SystemResolver,
    is_valid_hostname,
    normalize_name,
    reverse_pointer,
)


class HostnameValidationTests(unittest.TestCase):
    def test_accepts_ordinary_names(self):
        for name in ("example.com", "mail.example.co.uk", "a.b.c.d.e", "xn--bcher-kva.example"):
            self.assertTrue(is_valid_hostname(name), name)

    def test_accepts_underscore_labels_used_by_email_policy(self):
        for name in ("_dmarc.example.com", "google._domainkey.example.com", "_smtp._tls.x.com"):
            self.assertTrue(is_valid_hostname(name), name)

    def test_rejects_shell_metacharacters(self):
        for name in (
            "example.com; rm -rf /",
            "example.com`id`",
            "$(whoami).example.com",
            "example.com|cat /etc/passwd",
            "-@nameserver",
            "exam ple.com",
            "exa\nmple.com",
        ):
            self.assertFalse(is_valid_hostname(name), name)

    def test_rejects_empty_and_overlong_names(self):
        self.assertFalse(is_valid_hostname(""))
        self.assertFalse(is_valid_hostname("a" * 64 + ".com"))
        self.assertFalse(is_valid_hostname(".".join(["abcd"] * 60)))
        self.assertFalse(is_valid_hostname("example.com\n"))

    def test_normalize_name_lowercases_and_strips_root_dot(self):
        self.assertEqual(normalize_name("Example.COM."), "example.com")

    def test_normalize_name_rejects_injection(self):
        with self.assertRaises(ValueError):
            normalize_name("example.com; id")

    def test_normalize_name_handles_underscore_labels(self):
        self.assertEqual(normalize_name("_DMARC.Example.com"), "_dmarc.example.com")

    def test_reverse_pointer(self):
        self.assertEqual(reverse_pointer("203.0.113.25"), "25.113.0.203.in-addr.arpa")
        self.assertTrue(reverse_pointer("2001:db8::1").endswith("ip6.arpa"))


class StaticResolverTests(unittest.TestCase):
    def setUp(self):
        self.resolver = StaticResolver(
            {
                "example.com": {"TXT": ["v=spf1 -all"], "A": ["192.0.2.1"]},
                "empty.example": {"A": []},
            }
        )

    def test_returns_records(self):
        self.assertEqual(self.resolver.txt("example.com"), ["v=spf1 -all"])

    def test_is_case_insensitive(self):
        self.assertEqual(self.resolver.txt("EXAMPLE.com."), ["v=spf1 -all"])

    def test_nodata_returns_empty_list(self):
        self.assertEqual(self.resolver.txt("empty.example"), [])

    def test_missing_name_raises_nxdomain(self):
        with self.assertRaises(NXDOMAIN):
            self.resolver.txt("absent.example")

    def test_results_are_cached_and_counted(self):
        self.resolver.txt("example.com")
        self.resolver.txt("example.com")
        self.assertEqual(self.resolver.query_count, 1)

    def test_negative_results_are_cached_too(self):
        for _ in range(3):
            with self.assertRaises(NXDOMAIN):
                self.resolver.txt("absent.example")
        self.assertEqual(self.resolver.query_count, 1)

    def test_callers_cannot_mutate_the_cache(self):
        first = self.resolver.txt("example.com")
        first.append("injected")
        self.assertEqual(self.resolver.txt("example.com"), ["v=spf1 -all"])

    def test_rejects_unsupported_rrtype(self):
        with self.assertRaises(ValueError):
            self.resolver.query("example.com", "SRV")

    def test_from_file(self):
        payload = {"dns": {"a.example": {"TXT": ["hello"]}}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            resolver = StaticResolver.from_file(path)
        self.assertEqual(resolver.txt("a.example"), ["hello"])

    def test_malformed_fixture_shapes_are_clean_errors(self):
        for records in (
            [], {"a.example": []}, {"a.example": {"TXT": "not an array"}},
            {"a.example": {"TXT": [42]}},
        ):
            with self.subTest(records=records), self.assertRaises(ValueError):
                StaticResolver(records)

    def test_top_level_array_fixture_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "fixture.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                StaticResolver.from_file(path)


class SystemResolverTests(unittest.TestCase):
    def setUp(self):
        backend = patch.object(SystemResolver, "_import_dnspython", return_value=None)
        executable = patch("inboxready.dnsresolver.shutil.which", return_value="/usr/bin/dig")
        backend.start()
        executable.start()
        self.addCleanup(backend.stop)
        self.addCleanup(executable.stop)

    def response(self, status="NOERROR", answer=""):
        return CompletedProcess(
            [], 0, stdout=f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 1\n{answer}",
            stderr="",
        )

    def test_nxdomain_is_distinguished_and_cached(self):
        resolver = SystemResolver()
        with patch("inboxready.dnsresolver.subprocess.run", return_value=self.response("NXDOMAIN")) as run:
            for _ in range(3):
                with self.assertRaises(NXDOMAIN):
                    resolver.txt("absent.example")
        self.assertEqual(run.call_count, 1)

    def test_transient_dns_failures_are_not_cached_as_missing_records(self):
        resolver = SystemResolver()
        with patch("inboxready.dnsresolver.subprocess.run", return_value=self.response("SERVFAIL")) as run:
            for _ in range(2):
                with self.assertRaises(DnsError) as caught:
                    resolver.txt("example.com")
                self.assertNotIsInstance(caught.exception, NXDOMAIN)
        self.assertEqual(run.call_count, 2)

    def test_nodata_is_successful_and_cached(self):
        resolver = SystemResolver()
        with patch("inboxready.dnsresolver.subprocess.run", return_value=self.response()) as run:
            self.assertEqual(resolver.txt("example.com"), [])
            self.assertEqual(resolver.txt("example.com"), [])
        self.assertEqual(run.call_count, 1)

    def test_null_mx_is_not_destroyed_by_root_dot_normalization(self):
        resolver = SystemResolver()
        answer = "example.com. 300 IN MX 0 .\n"
        with patch("inboxready.dnsresolver.subprocess.run", return_value=self.response(answer=answer)):
            self.assertEqual(resolver.mx("example.com"), ["0 ."])
        self.assertEqual(SystemResolver._render_rdata("0 .", "MX"), "0 .")

    def test_subprocess_respects_the_actual_timeout(self):
        resolver = SystemResolver(timeout=0.25)
        with patch("inboxready.dnsresolver.subprocess.run", return_value=self.response()) as run:
            resolver.txt("example.com")
        self.assertEqual(run.call_args.kwargs["timeout"], 0.25)
        self.assertIn("+comments", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_invalid_timeouts_and_nameservers_fail_before_queries(self):
        for timeout in (0, -1, float("nan"), float("inf")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                SystemResolver(timeout=timeout)
        with self.assertRaises(ValueError):
            SystemResolver(nameserver="not-an-address")

    def test_missing_status_is_an_error_not_an_empty_answer(self):
        resolver = SystemResolver()
        with patch(
            "inboxready.dnsresolver.subprocess.run",
            return_value=CompletedProcess([], 0, stdout="", stderr=""),
        ), self.assertRaises(DnsError):
            resolver.txt("example.com")


@unittest.skipUnless(importlib.util.find_spec("dns"), "optional dnspython backend absent")
class NativeResolverTests(unittest.TestCase):
    def test_native_resolver_is_reused_and_timeouts_follow_the_remaining_budget(self):
        with patch("dns.resolver.Resolver") as factory:
            factory.return_value.resolve.return_value = ["0 ."]
            resolver = SystemResolver(timeout=2, nameserver="127.0.0.1")
            self.assertEqual(resolver.mx("first.example"), ["0 ."])
            resolver.timeout = 0.25
            self.assertEqual(resolver.mx("second.example"), ["0 ."])
            self.assertEqual(factory.call_count, 1)
            native = factory.return_value
            self.assertEqual(native.nameservers, ["127.0.0.1"])
            self.assertEqual(native.timeout, 0.25)
            self.assertEqual(native.lifetime, 0.25)
            native.resolve.assert_called_with("second.example", "MX", search=False)

    def test_native_txt_chunks_are_joined(self):
        from types import SimpleNamespace

        with patch("dns.resolver.Resolver") as factory:
            factory.return_value.resolve.return_value = [
                SimpleNamespace(strings=(b"v=spf1 ", b"-all"))
            ]
            self.assertEqual(SystemResolver().txt("example.com"), ["v=spf1 -all"])

    def test_expected_backend_errors_are_reported_but_programming_errors_escape(self):
        import dns.resolver

        with patch("dns.resolver.Resolver") as factory:
            factory.return_value.resolve.side_effect = dns.resolver.NoNameservers()
            with self.assertRaises(DnsError):
                SystemResolver().txt("example.com")
            factory.return_value.resolve.side_effect = RuntimeError("unexpected backend bug")
            with self.assertRaises(RuntimeError):
                SystemResolver().txt("example.com")


if __name__ == "__main__":
    unittest.main()
