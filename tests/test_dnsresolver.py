"""Tests for the DNS resolver abstraction and hostname validation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from support import SRC  # noqa: F401  (adds src/ to sys.path)

from inboxready.dnsresolver import (
    NXDOMAIN,
    StaticResolver,
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


if __name__ == "__main__":
    unittest.main()
