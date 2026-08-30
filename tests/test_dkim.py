"""Tests for DKIM key parsing and grading (RFC 6376, RFC 8301)."""

from __future__ import annotations

import unittest

from support import RSA_512_B64, RSA_2048_B64, SRC, finding_codes  # noqa: F401

from inboxready.checks.dkim import check_dkim, parse_dkim_record, rsa_key_bits
from inboxready.dnsresolver import StaticResolver
from inboxready.models import Severity


class RsaKeyBitsTests(unittest.TestCase):
    def test_reads_2048_bit_subject_public_key_info(self):
        self.assertEqual(rsa_key_bits(RSA_2048_B64), 2048)

    def test_reads_512_bit_key(self):
        self.assertEqual(rsa_key_bits(RSA_512_B64), 512)

    def test_tolerates_embedded_whitespace(self):
        spaced = "\n ".join(RSA_2048_B64[i : i + 40] for i in range(0, len(RSA_2048_B64), 40))
        self.assertEqual(rsa_key_bits(spaced), 2048)

    def test_returns_none_for_garbage(self):
        for value in ("", "not base64!!", "YWJjZA=="):
            self.assertIsNone(rsa_key_bits(value), value)

    def test_returns_none_for_truncated_der(self):
        self.assertIsNone(rsa_key_bits(RSA_2048_B64[:40]))


class DkimRecordParsingTests(unittest.TestCase):
    def test_parses_tags(self):
        key = parse_dkim_record("s", "example.com", f"v=DKIM1; k=rsa; p={RSA_2048_B64}")
        self.assertEqual(key.key_type, "rsa")
        self.assertFalse(key.revoked)
        self.assertEqual(key.errors, [])

    def test_detects_revoked_key(self):
        self.assertTrue(parse_dkim_record("s", "example.com", "v=DKIM1; k=rsa; p=").revoked)

    def test_detects_testing_flag(self):
        self.assertTrue(parse_dkim_record("s", "e.com", "v=DKIM1; t=y; p=x").testing)
        self.assertTrue(parse_dkim_record("s", "e.com", "v=DKIM1; t=s:y; p=x").testing)
        self.assertFalse(parse_dkim_record("s", "e.com", "v=DKIM1; t=s; p=x").testing)

    def test_strips_whitespace_inside_the_key(self):
        key = parse_dkim_record("s", "e.com", "v=DKIM1; p=abc\n  def")
        self.assertEqual(key.public_key, "abcdef")

    def test_reports_missing_p_tag(self):
        self.assertTrue(parse_dkim_record("s", "e.com", "v=DKIM1; k=rsa").errors)

    def test_long_key_material_is_elided_from_reports(self):
        payload = parse_dkim_record("s", "e.com", f"v=DKIM1; p={RSA_2048_B64}").to_dict()
        self.assertNotIn(RSA_2048_B64, str(payload))
        self.assertIn("392 base64 chars", str(payload))
        # The parsed key itself stays intact for the bit-length check.
        self.assertEqual(
            parse_dkim_record("s", "e.com", f"v=DKIM1; p={RSA_2048_B64}").public_key,
            RSA_2048_B64,
        )


class DkimCheckTests(unittest.TestCase):
    def _zone(self, record: str, selector: str = "google") -> StaticResolver:
        return StaticResolver({f"{selector}._domainkey.example.com": {"TXT": [record]}})

    def test_healthy_key_produces_no_findings(self):
        resolver = self._zone(f"v=DKIM1; k=rsa; h=sha256; p={RSA_2048_B64}")
        result = check_dkim(resolver, "example.com", selectors=["google"])
        self.assertEqual(result.findings, [])

    def test_explicit_missing_selector_is_critical(self):
        resolver = StaticResolver({"example.com": {"TXT": []}})
        result = check_dkim(resolver, "example.com", selectors=["google"])
        self.assertIn("DKIM_SELECTOR_MISSING", finding_codes(result))

    def test_probed_absence_is_only_a_warning(self):
        resolver = StaticResolver({"example.com": {"TXT": []}})
        result = check_dkim(resolver, "example.com")
        self.assertIn("DKIM_MISSING", finding_codes(result))
        self.assertEqual(result.worst, Severity.WARNING)
        self.assertEqual(result.data["discovery_mode"], "probed")

    def test_revoked_key_is_a_blocker(self):
        result = check_dkim(self._zone("v=DKIM1; k=rsa; p="), "example.com", selectors=["google"])
        self.assertIn("DKIM_KEY_REVOKED", finding_codes(result))

    def test_short_key_is_a_blocker(self):
        result = check_dkim(
            self._zone(f"v=DKIM1; k=rsa; p={RSA_512_B64}"), "example.com", selectors=["google"]
        )
        self.assertIn("DKIM_KEY_TOO_SHORT", finding_codes(result))
        self.assertEqual(result.data["key_bits"]["google"], 512)

    def test_testing_mode_is_a_warning(self):
        result = check_dkim(
            self._zone(f"v=DKIM1; k=rsa; t=y; p={RSA_2048_B64}"),
            "example.com",
            selectors=["google"],
        )
        self.assertIn("DKIM_TESTING_MODE", finding_codes(result))

    def test_sha1_only_is_critical(self):
        result = check_dkim(
            self._zone(f"v=DKIM1; k=rsa; h=sha1; p={RSA_2048_B64}"),
            "example.com",
            selectors=["google"],
        )
        self.assertIn("DKIM_SHA1_ONLY", finding_codes(result))

    def test_undecodable_key_is_reported(self):
        result = check_dkim(
            self._zone("v=DKIM1; k=rsa; p=@@@notbase64@@@"), "example.com", selectors=["google"]
        )
        self.assertIn("DKIM_KEY_UNREADABLE", finding_codes(result))

    def test_ed25519_is_informational(self):
        result = check_dkim(
            self._zone("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="),
            "example.com",
            selectors=["google"],
        )
        self.assertIn("DKIM_ED25519", finding_codes(result))
        self.assertEqual(result.worst, Severity.INFO)

    def test_unknown_key_type_is_critical(self):
        result = check_dkim(
            self._zone("v=DKIM1; k=magic; p=abcd"), "example.com", selectors=["google"]
        )
        self.assertIn("DKIM_KEY_TYPE_UNKNOWN", finding_codes(result))

    def test_probing_can_be_disabled(self):
        result = check_dkim(StaticResolver({}), "example.com", probe_common=False)
        self.assertTrue(result.skipped)


if __name__ == "__main__":
    unittest.main()
