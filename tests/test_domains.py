"""Tests for organizational-domain resolution and DMARC alignment."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from support import SRC  # noqa: F401

from inboxready.domains import PublicSuffixList, check_alignment


class OrganizationalDomainTests(unittest.TestCase):
    def setUp(self):
        self.psl = PublicSuffixList()

    def test_single_label_tld(self):
        self.assertEqual(self.psl.organizational_domain("mail.example.com"), "example.com")
        self.assertEqual(self.psl.organizational_domain("example.com"), "example.com")

    def test_deeply_nested_subdomain(self):
        self.assertEqual(
            self.psl.organizational_domain("a.b.c.d.example.io"), "example.io"
        )

    def test_multi_label_suffix(self):
        self.assertEqual(self.psl.organizational_domain("shop.example.co.uk"), "example.co.uk")
        self.assertEqual(self.psl.organizational_domain("example.com.au"), "example.com.au")

    def test_bare_public_suffix_returns_itself(self):
        self.assertEqual(self.psl.organizational_domain("co.uk"), "co.uk")

    def test_trailing_dot_and_case_are_normalized(self):
        self.assertEqual(self.psl.organizational_domain("Mail.Example.COM."), "example.com")

    def test_empty_input(self):
        self.assertEqual(self.psl.organizational_domain(""), "")

    def test_built_in_list_is_not_authoritative(self):
        self.assertFalse(PublicSuffixList().authoritative)

    def test_loading_a_real_list_marks_it_authoritative(self):
        content = "// comment\n\ncom\nco.uk\n*.compute.amazonaws.com\n!city.example\n"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "psl.dat"
            path.write_text(content, encoding="utf-8")
            psl = PublicSuffixList.from_file(path)
        self.assertTrue(psl.authoritative)
        self.assertEqual(psl.organizational_domain("a.b.compute.amazonaws.com"), "b.compute.amazonaws.com")

    def test_is_subdomain_of(self):
        self.assertTrue(self.psl.is_subdomain_of("mail.example.com", "example.com"))
        self.assertTrue(self.psl.is_subdomain_of("example.com", "example.com"))
        self.assertFalse(self.psl.is_subdomain_of("notexample.com", "example.com"))
        self.assertFalse(self.psl.is_subdomain_of("example.com", "mail.example.com"))


class AlignmentTests(unittest.TestCase):
    def test_exact_match_aligns_in_both_modes(self):
        for mode in ("r", "s"):
            self.assertTrue(check_alignment("example.com", "example.com", mode).aligned)

    def test_relaxed_alignment_allows_subdomains(self):
        self.assertTrue(check_alignment("example.com", "mail.example.com", "r").aligned)
        self.assertTrue(check_alignment("mail.example.com", "example.com", "r").aligned)

    def test_strict_alignment_rejects_subdomains(self):
        self.assertFalse(check_alignment("example.com", "mail.example.com", "s").aligned)

    def test_different_organizations_never_align(self):
        for mode in ("r", "s"):
            self.assertFalse(check_alignment("example.com", "esp-shared.net", mode).aligned)

    def test_cousin_domains_do_not_align(self):
        self.assertFalse(check_alignment("example.com", "example.com.evil.test", "r").aligned)

    def test_shared_public_suffix_is_not_shared_organization(self):
        self.assertFalse(check_alignment("a.co.uk", "b.co.uk", "r").aligned)

    def test_case_and_trailing_dots_are_ignored(self):
        self.assertTrue(check_alignment("Example.COM.", "example.com", "s").aligned)

    def test_missing_domain_does_not_align(self):
        self.assertFalse(check_alignment("example.com", "", "r").aligned)

    def test_invalid_mode_raises(self):
        with self.assertRaises(ValueError):
            check_alignment("example.com", "example.com", "x")

    def test_result_serialises(self):
        payload = check_alignment("example.com", "mail.example.com", "r").to_dict()
        self.assertTrue(payload["aligned"])
        self.assertEqual(payload["mode"], "r")


if __name__ == "__main__":
    unittest.main()
