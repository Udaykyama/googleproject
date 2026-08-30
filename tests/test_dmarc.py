"""Tests for DMARC parsing, policy grading, and organizational-domain fallback."""

from __future__ import annotations

import unittest

from support import SRC, finding_codes  # noqa: F401

from inboxready.checks.dmarc import check_dmarc, parse_dmarc_record
from inboxready.dnsresolver import StaticResolver
from inboxready.domains import PublicSuffixList
from inboxready.models import Severity


class DmarcParsingTests(unittest.TestCase):
    def test_parses_a_full_record(self):
        record = parse_dmarc_record(
            "v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=r; "
            "rua=mailto:a@example.com,mailto:b@example.com; fo=1",
            "example.com",
        )
        self.assertEqual(record.policy, "reject")
        self.assertEqual(record.subdomain_policy, "quarantine")
        self.assertEqual(record.dkim_alignment, "s")
        self.assertEqual(len(record.rua), 2)
        self.assertEqual(record.errors, [])

    def test_subdomain_policy_defaults_to_policy(self):
        self.assertEqual(
            parse_dmarc_record("v=DMARC1; p=reject", "example.com").subdomain_policy, "reject"
        )

    def test_requires_p_tag(self):
        record = parse_dmarc_record("v=DMARC1; rua=mailto:a@example.com", "example.com")
        self.assertTrue(any("'p' is missing" in e for e in record.errors))

    def test_version_must_come_first(self):
        record = parse_dmarc_record("p=reject; v=DMARC1", "example.com")
        self.assertTrue(any("must come first" in e for e in record.errors))

    def test_rejects_invalid_policy(self):
        record = parse_dmarc_record("v=DMARC1; p=block", "example.com")
        self.assertTrue(any("is invalid" in e for e in record.errors))

    def test_rejects_out_of_range_pct(self):
        self.assertTrue(parse_dmarc_record("v=DMARC1; p=none; pct=150", "e.com").errors)

    def test_rejects_non_numeric_pct(self):
        self.assertTrue(parse_dmarc_record("v=DMARC1; p=none; pct=half", "e.com").errors)

    def test_rejects_bad_alignment_mode(self):
        self.assertTrue(parse_dmarc_record("v=DMARC1; p=none; adkim=x", "e.com").errors)

    def test_rejects_non_mailto_rua(self):
        record = parse_dmarc_record("v=DMARC1; p=none; rua=https://example.com/r", "e.com")
        self.assertTrue(any("mailto" in e for e in record.errors))

    def test_accepts_rua_with_size_limit(self):
        record = parse_dmarc_record("v=DMARC1; p=none; rua=mailto:a@e.com!10m", "e.com")
        self.assertEqual(record.errors, [])

    def test_flags_unknown_tag(self):
        record = parse_dmarc_record("v=DMARC1; p=none; mystery=1", "e.com")
        self.assertTrue(any("unknown tag" in e for e in record.errors))

    def test_detects_duplicate_tag(self):
        record = parse_dmarc_record("v=DMARC1; p=none; p=reject", "e.com")
        self.assertTrue(any("duplicate" in e for e in record.errors))


class DmarcCheckTests(unittest.TestCase):
    def test_missing_record_is_a_blocker(self):
        result = check_dmarc(StaticResolver({"example.com": {"TXT": []}}), "example.com")
        self.assertIn("DMARC_MISSING", finding_codes(result))
        self.assertEqual(result.worst, Severity.BLOCKER)

    def test_reject_policy_is_clean(self):
        resolver = StaticResolver(
            {
                "_dmarc.example.com": {
                    "TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
                }
            }
        )
        self.assertEqual(check_dmarc(resolver, "example.com").findings, [])

    def test_none_policy_is_a_warning(self):
        resolver = StaticResolver(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=none; rua=mailto:d@example.com"]}}
        )
        result = check_dmarc(resolver, "example.com")
        self.assertIn("DMARC_POLICY_NONE", finding_codes(result))
        self.assertEqual(result.worst, Severity.WARNING)

    def test_quarantine_policy_is_a_warning(self):
        resolver = StaticResolver(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=quarantine; rua=mailto:d@example.com"]}}
        )
        self.assertIn("DMARC_POLICY_QUARANTINE", finding_codes(check_dmarc(resolver, "example.com")))

    def test_multiple_records_are_a_blocker(self):
        resolver = StaticResolver(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject", "v=DMARC1; p=none"]}}
        )
        self.assertIn("DMARC_MULTIPLE", finding_codes(check_dmarc(resolver, "example.com")))

    def test_partial_pct_is_a_warning(self):
        resolver = StaticResolver(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; pct=20; rua=mailto:d@example.com"]}}
        )
        self.assertIn("DMARC_PARTIAL_PCT", finding_codes(check_dmarc(resolver, "example.com")))

    def test_missing_rua_is_a_warning(self):
        resolver = StaticResolver({"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject"]}})
        self.assertIn("DMARC_NO_RUA", finding_codes(check_dmarc(resolver, "example.com")))

    def test_falls_back_to_the_organizational_domain(self):
        resolver = StaticResolver(
            {
                "_dmarc.example.com": {
                    "TXT": ["v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"]
                }
            }
        )
        result = check_dmarc(resolver, "mail.example.com")
        self.assertIn("DMARC_INHERITED", finding_codes(result))
        # The `sp=` tag is what actually governs the subdomain.
        self.assertEqual(result.data["effective_policy"], "none")
        self.assertIn("DMARC_POLICY_NONE", finding_codes(result))

    def test_subdomain_record_takes_precedence_over_inheritance(self):
        resolver = StaticResolver(
            {
                "_dmarc.mail.example.com": {
                    "TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.com"]
                },
                "_dmarc.example.com": {"TXT": ["v=DMARC1; p=none"]},
            }
        )
        result = check_dmarc(resolver, "mail.example.com")
        self.assertEqual(result.data["effective_policy"], "reject")
        self.assertNotIn("DMARC_INHERITED", finding_codes(result))

    def test_unauthorised_external_report_destination_is_flagged(self):
        resolver = StaticResolver(
            {"_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:r@vendor.example"]}}
        )
        result = check_dmarc(resolver, "example.com")
        self.assertIn("DMARC_EXTERNAL_REPORT_UNAUTHORISED", finding_codes(result))

    def test_authorised_external_report_destination_is_accepted(self):
        resolver = StaticResolver(
            {
                "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:r@vendor.example"]},
                "example.com._report._dmarc.vendor.example": {"TXT": ["v=DMARC1"]},
            }
        )
        result = check_dmarc(resolver, "example.com")
        self.assertNotIn("DMARC_EXTERNAL_REPORT_UNAUTHORISED", finding_codes(result))

    def test_same_org_report_destination_needs_no_authorisation(self):
        resolver = StaticResolver(
            {
                "_dmarc.example.com": {
                    "TXT": ["v=DMARC1; p=reject; rua=mailto:r@reports.example.com"]
                }
            }
        )
        result = check_dmarc(resolver, "example.com")
        self.assertNotIn("DMARC_EXTERNAL_REPORT_UNAUTHORISED", finding_codes(result))

    def test_strict_alignment_is_reported(self):
        resolver = StaticResolver(
            {
                "_dmarc.example.com": {
                    "TXT": ["v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com"]
                }
            }
        )
        self.assertIn("DMARC_STRICT_ALIGNMENT", finding_codes(check_dmarc(resolver, "example.com")))

    def test_multi_label_suffix_is_handled(self):
        resolver = StaticResolver(
            {"_dmarc.example.co.uk": {"TXT": ["v=DMARC1; p=reject; rua=mailto:d@example.co.uk"]}}
        )
        result = check_dmarc(resolver, "mail.example.co.uk", psl=PublicSuffixList())
        self.assertEqual(result.data["organizational_domain"], "example.co.uk")
        self.assertIn("DMARC_INHERITED", finding_codes(result))


if __name__ == "__main__":
    unittest.main()
