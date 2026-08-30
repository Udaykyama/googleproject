"""Tests for MX, reverse DNS, transport security, and BIMI checks."""

from __future__ import annotations

import unittest

from support import SRC, finding_codes  # noqa: F401

from inboxready.checks.network import (
    check_bimi,
    check_mx,
    check_sending_ips,
    check_transport_security,
)
from inboxready.dnsresolver import StaticResolver
from inboxready.models import Severity


class MxTests(unittest.TestCase):
    def test_present_mx_is_clean(self):
        resolver = StaticResolver({"example.com": {"MX": ["10 mx1.example.com"]}})
        self.assertEqual(check_mx(resolver, "example.com").findings, [])

    def test_missing_mx_is_a_warning(self):
        resolver = StaticResolver({"example.com": {"MX": []}})
        self.assertIn("MX_MISSING", finding_codes(check_mx(resolver, "example.com")))

    def test_nxdomain_is_a_blocker(self):
        result = check_mx(StaticResolver({}), "example.com")
        self.assertIn("DOMAIN_NXDOMAIN", finding_codes(result))
        self.assertEqual(result.worst, Severity.BLOCKER)

    def test_null_mx_is_a_warning(self):
        resolver = StaticResolver({"example.com": {"MX": ["0 ."]}})
        self.assertIn("MX_NULL", finding_codes(check_mx(resolver, "example.com")))


class SendingIpTests(unittest.TestCase):
    def test_no_ips_is_skipped(self):
        self.assertTrue(check_sending_ips(StaticResolver({}), []).skipped)

    def test_forward_confirmed_ip_is_clean(self):
        resolver = StaticResolver(
            {
                "25.100.51.198.in-addr.arpa": {"PTR": ["mta1.example.com"]},
                "mta1.example.com": {"A": ["198.51.100.25"]},
            }
        )
        codes = finding_codes(check_sending_ips(resolver, ["198.51.100.25"]))
        self.assertNotIn("FCRDNS_FAILED", codes)
        self.assertNotIn("PTR_MISSING", codes)

    def test_missing_ptr_is_a_blocker(self):
        resolver = StaticResolver({"25.100.51.198.in-addr.arpa": {"PTR": []}})
        self.assertIn("PTR_MISSING", finding_codes(check_sending_ips(resolver, ["198.51.100.25"])))

    def test_nonexistent_ptr_is_a_blocker(self):
        self.assertIn(
            "PTR_MISSING", finding_codes(check_sending_ips(StaticResolver({}), ["198.51.100.25"]))
        )

    def test_ptr_without_matching_forward_record_fails(self):
        resolver = StaticResolver(
            {
                "25.100.51.198.in-addr.arpa": {"PTR": ["mta1.example.com"]},
                "mta1.example.com": {"A": ["203.0.113.9"]},
            }
        )
        self.assertIn("FCRDNS_FAILED", finding_codes(check_sending_ips(resolver, ["198.51.100.25"])))

    def test_ipv6_uses_aaaa_for_confirmation(self):
        address = "2001:db8::1"
        resolver = StaticResolver(
            {
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": {
                    "PTR": ["mta6.example.com"]
                },
                "mta6.example.com": {"AAAA": [address]},
            }
        )
        self.assertNotIn("FCRDNS_FAILED", finding_codes(check_sending_ips(resolver, [address])))

    def test_invalid_ip_is_reported(self):
        self.assertIn("IP_INVALID", finding_codes(check_sending_ips(StaticResolver({}), ["nope"])))

    def test_private_ip_is_flagged_but_still_checked(self):
        result = check_sending_ips(StaticResolver({}), ["10.0.0.1"])
        codes = finding_codes(result)
        self.assertIn("IP_NOT_PUBLIC", codes)
        self.assertIn("PTR_MISSING", codes)

    def test_loopback_skips_resolution(self):
        result = check_sending_ips(StaticResolver({}), ["127.0.0.1"])
        self.assertIn("IP_NOT_PUBLIC", finding_codes(result))
        self.assertNotIn("PTR_MISSING", finding_codes(result))


class TransportSecurityTests(unittest.TestCase):
    def test_full_configuration_is_clean(self):
        resolver = StaticResolver(
            {
                "_mta-sts.example.com": {"TXT": ["v=STSv1; id=20260115T120000"]},
                "_smtp._tls.example.com": {"TXT": ["v=TLSRPTv1; rua=mailto:tls@example.com"]},
            }
        )
        self.assertEqual(check_transport_security(resolver, "example.com").findings, [])

    def test_missing_policies_are_informational(self):
        result = check_transport_security(StaticResolver({}), "example.com")
        self.assertEqual(finding_codes(result), {"MTA_STS_MISSING", "TLSRPT_MISSING"})
        self.assertEqual(result.worst, Severity.INFO)

    def test_mta_sts_without_id_is_a_warning(self):
        resolver = StaticResolver({"_mta-sts.example.com": {"TXT": ["v=STSv1"]}})
        self.assertIn("MTA_STS_NO_ID", finding_codes(check_transport_security(resolver, "example.com")))

    def test_duplicate_mta_sts_records_are_a_warning(self):
        resolver = StaticResolver(
            {"_mta-sts.example.com": {"TXT": ["v=STSv1; id=1", "v=STSv1; id=2"]}}
        )
        self.assertIn(
            "MTA_STS_MULTIPLE", finding_codes(check_transport_security(resolver, "example.com"))
        )


class BimiTests(unittest.TestCase):
    def test_absent_record_is_skipped(self):
        self.assertTrue(check_bimi(StaticResolver({}), "example.com").skipped)

    def test_bimi_without_enforcement_is_a_warning(self):
        resolver = StaticResolver(
            {
                "default._bimi.example.com": {
                    "TXT": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]
                }
            }
        )
        result = check_bimi(resolver, "example.com", dmarc_policy="none")
        self.assertIn("BIMI_WITHOUT_ENFORCEMENT", finding_codes(result))

    def test_bimi_with_reject_policy_is_clean(self):
        resolver = StaticResolver(
            {
                "default._bimi.example.com": {
                    "TXT": ["v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem"]
                }
            }
        )
        self.assertEqual(check_bimi(resolver, "example.com", dmarc_policy="reject").findings, [])

    def test_missing_logo_and_vmc_are_reported(self):
        resolver = StaticResolver({"default._bimi.example.com": {"TXT": ["v=BIMI1;"]}})
        codes = finding_codes(check_bimi(resolver, "example.com", dmarc_policy="reject"))
        self.assertIn("BIMI_NO_LOGO", codes)
        self.assertIn("BIMI_NO_VMC", codes)


if __name__ == "__main__":
    unittest.main()
