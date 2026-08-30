"""Tests for SPF parsing and policy evaluation (RFC 7208)."""

from __future__ import annotations

import unittest

from support import SRC, finding_codes  # noqa: F401

from inboxready.checks.spf import check_spf, parse_spf_record
from inboxready.dnsresolver import StaticResolver
from inboxready.models import Severity


class SpfParsingTests(unittest.TestCase):
    def test_parses_mechanisms_and_qualifiers(self):
        record = parse_spf_record("v=spf1 ip4:192.0.2.0/24 include:_spf.example.com ~all")
        self.assertEqual([t.name for t in record.terms], ["ip4", "include", "all"])
        self.assertEqual(record.all_term.qualifier, "~")
        self.assertEqual(record.errors, [])

    def test_requires_version_token(self):
        record = parse_spf_record("include:_spf.example.com -all")
        self.assertTrue(record.errors)

    def test_detects_unknown_mechanism(self):
        record = parse_spf_record("v=spf1 includ:_spf.example.com -all")
        bad = [t for t in record.terms if t.kind == "unknown"]
        self.assertEqual(len(bad), 1)

    def test_detects_terms_after_all(self):
        record = parse_spf_record("v=spf1 -all include:_spf.example.com")
        trailing = record.terms[-1]
        self.assertTrue(any("never be evaluated" in e for e in trailing.errors))

    def test_detects_duplicate_all(self):
        record = parse_spf_record("v=spf1 ~all -all")
        self.assertTrue(any("duplicate" in e for t in record.terms for e in t.errors))

    def test_rejects_malformed_ip4(self):
        record = parse_spf_record("v=spf1 ip4:999.1.1.1 -all")
        self.assertTrue(record.terms[0].errors)

    def test_rejects_ipv6_in_ip4_mechanism(self):
        record = parse_spf_record("v=spf1 ip4:2001:db8::1 -all")
        self.assertTrue(record.terms[0].errors)

    def test_flags_overly_broad_ip4_range(self):
        record = parse_spf_record("v=spf1 ip4:0.0.0.0/0 -all")
        self.assertTrue(any("authorises" in e for e in record.terms[0].errors))

    def test_ptr_mechanism_is_flagged_as_deprecated(self):
        record = parse_spf_record("v=spf1 ptr -all")
        self.assertTrue(any("deprecated" in e for e in record.terms[0].errors))

    def test_unknown_modifier_is_a_warning_not_a_mechanism(self):
        record = parse_spf_record("v=spf1 mystery=value -all")
        term = record.terms[0]
        self.assertEqual(term.kind, "modifier")
        self.assertTrue(term.errors)

    def test_redirect_is_recognised(self):
        record = parse_spf_record("v=spf1 redirect=_spf.example.com")
        self.assertEqual(record.redirect, "_spf.example.com")
        self.assertIsNone(record.all_term)


class SpfCheckTests(unittest.TestCase):
    def test_missing_record_is_a_blocker(self):
        resolver = StaticResolver({"example.com": {"TXT": []}})
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_MISSING", finding_codes(result))
        self.assertEqual(result.worst, Severity.BLOCKER)

    def test_nonexistent_domain_is_reported(self):
        resolver = StaticResolver({})
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_LOOKUP_FAILED", finding_codes(result))

    def test_multiple_records_are_a_blocker(self):
        resolver = StaticResolver(
            {"example.com": {"TXT": ["v=spf1 -all", "v=spf1 include:a.example -all"]}}
        )
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_MULTIPLE", finding_codes(result))

    def test_plus_all_is_a_blocker(self):
        resolver = StaticResolver({"example.com": {"TXT": ["v=spf1 ip4:192.0.2.1 +all"]}})
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_ALL_PASS", finding_codes(result))

    def test_neutral_all_is_critical(self):
        resolver = StaticResolver({"example.com": {"TXT": ["v=spf1 ip4:192.0.2.1 ?all"]}})
        self.assertIn("SPF_ALL_NEUTRAL", finding_codes(check_spf(resolver, "example.com")))

    def test_softfail_all_is_only_informational(self):
        resolver = StaticResolver({"example.com": {"TXT": ["v=spf1 ip4:192.0.2.1 ~all"]}})
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_ALL_SOFTFAIL", finding_codes(result))
        self.assertEqual(result.worst, Severity.INFO)

    def test_missing_all_is_critical(self):
        resolver = StaticResolver({"example.com": {"TXT": ["v=spf1 ip4:192.0.2.1"]}})
        self.assertIn("SPF_NO_ALL", finding_codes(check_spf(resolver, "example.com")))

    def test_clean_record_produces_no_findings(self):
        resolver = StaticResolver(
            {
                "example.com": {"TXT": ["v=spf1 include:_spf.example.com -all"]},
                "_spf.example.com": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
            }
        )
        result = check_spf(resolver, "example.com")
        self.assertEqual(result.findings, [])

    def test_counts_lookups_across_include_chain(self):
        resolver = StaticResolver(
            {
                "example.com": {"TXT": ["v=spf1 include:a.example include:b.example -all"]},
                "a.example": {"TXT": ["v=spf1 a mx -all"]},
                "b.example": {"TXT": ["v=spf1 include:c.example -all"]},
                "c.example": {"TXT": ["v=spf1 ip4:192.0.2.0/24 -all"]},
            }
        )
        result = check_spf(resolver, "example.com")
        # 2 includes + (a, mx) + 1 nested include = 5
        self.assertEqual(result.data["dns_lookups"], 5)

    def test_exceeding_ten_lookups_is_a_blocker(self):
        zone = {
            "example.com": {
                "TXT": [
                    "v=spf1 a mx ptr include:i1.example include:i2.example "
                    "include:i3.example include:i4.example -all"
                ]
            }
        }
        for index in range(1, 5):
            zone[f"i{index}.example"] = {"TXT": ["v=spf1 a mx -all"]}
        result = check_spf(StaticResolver(zone), "example.com")
        self.assertIn("SPF_TOO_MANY_LOOKUPS", finding_codes(result))
        self.assertEqual(result.data["dns_lookups"], 15)

    def test_warns_when_near_the_lookup_limit(self):
        zone = {
            "example.com": {
                "TXT": ["v=spf1 a mx include:i1.example include:i2.example -all"]
            },
            "i1.example": {"TXT": ["v=spf1 a mx include:i3.example -all"]},
            "i2.example": {"TXT": ["v=spf1 a -all"]},
            "i3.example": {"TXT": ["v=spf1 a mx -all"]},
        }
        result = check_spf(StaticResolver(zone), "example.com")
        self.assertEqual(result.data["dns_lookups"], 10)
        self.assertIn("SPF_LOOKUPS_NEAR_LIMIT", finding_codes(result))
        self.assertNotIn("SPF_TOO_MANY_LOOKUPS", finding_codes(result))

    def test_include_loop_is_detected_and_terminates(self):
        resolver = StaticResolver(
            {
                "example.com": {"TXT": ["v=spf1 include:loop.example -all"]},
                "loop.example": {"TXT": ["v=spf1 include:example.com -all"]},
            }
        )
        result = check_spf(resolver, "example.com")
        self.assertIn("SPF_INCLUDE_LOOP", finding_codes(result))

    def test_void_lookups_are_counted(self):
        resolver = StaticResolver(
            {
                "example.com": {
                    "TXT": [
                        "v=spf1 include:v1.example include:v2.example include:v3.example -all"
                    ]
                }
            }
        )
        result = check_spf(resolver, "example.com")
        self.assertEqual(result.data["void_lookups"], 3)
        self.assertIn("SPF_VOID_LOOKUPS", finding_codes(result))

    def test_expansion_can_be_disabled(self):
        resolver = StaticResolver(
            {"example.com": {"TXT": ["v=spf1 include:a.example -all"]}}
        )
        result = check_spf(resolver, "example.com", expand=False)
        self.assertNotIn("dns_lookups", result.data)


if __name__ == "__main__":
    unittest.main()
