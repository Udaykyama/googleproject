"""Tests for message-level checks: RFC 5322, RFC 8058, alignment, ARC."""

from __future__ import annotations

import unittest

from support import SRC, finding_codes  # noqa: F401

from inboxready.checks.message import (
    check_message,
    parse_authentication_results,
    parse_dkim_signature,
    parse_message,
)
from inboxready.models import Severity

COMPLIANT = b"""\
From: Example <news@mail.example.com>
To: customer@gmail.com
Subject: Monthly update
Date: Tue, 13 Jan 2026 09:15:00 +0000
Message-ID: <20260113091500.abc@mail.example.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="bnd"
List-Unsubscribe: <https://mail.example.com/u/tok>, <mailto:u@mail.example.com>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=mail.example.com; s=google;
 h=from:to:subject:date:message-id; bh=x; b=y

--bnd
Content-Type: text/plain; charset=utf-8

Hello.

--bnd
Content-Type: text/html; charset=utf-8

<html><body><p>Hello.</p></body></html>

--bnd--
"""


def build(headers: str, body: str = "Hello.\n") -> bytes:
    return (headers.strip("\n") + "\n\n" + body).encode("utf-8")


class ParsingHelperTests(unittest.TestCase):
    def test_parse_dkim_signature(self):
        tags = parse_dkim_signature("v=1; a=rsa-sha256; d=example.com; s=sel; h=from:to; b=AA BB")
        self.assertEqual(tags["d"], "example.com")
        self.assertEqual(tags["h"], "from:to")
        self.assertEqual(tags["b"], "AABB")

    def test_parse_authentication_results(self):
        header = (
            "mx.google.com; spf=pass smtp.mailfrom=a@b.com; dkim=fail header.i=@b.com; "
            "dmarc=fail (p=NONE)"
        )
        parsed = parse_authentication_results(header)
        self.assertEqual(parsed, {"spf": "pass", "dkim": "fail", "dmarc": "fail"})

    def test_parse_message_extracts_from_domain(self):
        parsed = parse_message(COMPLIANT)
        self.assertEqual(parsed.from_domain, "mail.example.com")

    def test_decodes_rfc2047_display_names(self):
        raw = build("From: =?utf-8?q?Caf=C3=A9?= <a@example.com>\nDate: Tue, 13 Jan 2026 09:15:00 +0000")
        self.assertEqual(parse_message(raw).from_addresses[0][0], "Café")


class CompliantMessageTests(unittest.TestCase):
    def test_no_findings(self):
        result = check_message(COMPLIANT, bulk=True)
        self.assertEqual(result.findings, [])

    def test_from_domain_recorded(self):
        self.assertEqual(check_message(COMPLIANT).data["from_domain"], "mail.example.com")


class RequiredHeaderTests(unittest.TestCase):
    def test_missing_from_is_a_blocker(self):
        raw = build("To: a@gmail.com\nDate: Tue, 13 Jan 2026 09:15:00 +0000")
        self.assertIn("MSG_NO_FROM", finding_codes(check_message(raw)))

    def test_missing_date_is_a_blocker(self):
        raw = build("From: a@example.com\nTo: b@gmail.com")
        self.assertIn("MSG_NO_DATE", finding_codes(check_message(raw)))

    def test_duplicate_from_is_a_blocker(self):
        raw = build(
            "From: a@example.com\nFrom: b@evil.test\nTo: c@gmail.com\n"
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertIn("MSG_DUPLICATE_FROM", finding_codes(check_message(raw)))

    def test_invalid_date_is_reported(self):
        raw = build("From: a@example.com\nTo: b@gmail.com\nDate: yesterday")
        self.assertIn("MSG_DATE_INVALID", finding_codes(check_message(raw)))

    def test_missing_message_id_is_critical(self):
        raw = build("From: a@example.com\nTo: b@gmail.com\nDate: Tue, 13 Jan 2026 09:15:00 +0000")
        self.assertIn("MSG_NO_MESSAGE_ID", finding_codes(check_message(raw)))

    def test_malformed_message_id_is_a_warning(self):
        raw = build(
            "From: a@example.com\nTo: b@gmail.com\nDate: Tue, 13 Jan 2026 09:15:00 +0000\n"
            "Message-ID: not-an-id"
        )
        self.assertIn("MSG_MESSAGE_ID_MALFORMED", finding_codes(check_message(raw)))

    def test_missing_recipient_headers_flagged(self):
        raw = build("From: a@example.com\nDate: Tue, 13 Jan 2026 09:15:00 +0000")
        self.assertIn("MSG_NO_RECIPIENT_HEADER", finding_codes(check_message(raw)))

    def test_missing_subject_flagged(self):
        raw = build("From: a@example.com\nTo: b@gmail.com\nDate: Tue, 13 Jan 2026 09:15:00 +0000")
        self.assertIn("MSG_NO_SUBJECT", finding_codes(check_message(raw)))

    def test_multiple_from_without_sender(self):
        raw = build(
            "From: a@example.com, b@example.com\nTo: c@gmail.com\n"
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertIn("MSG_MULTIPLE_FROM_NO_SENDER", finding_codes(check_message(raw)))

    def test_multiple_from_with_sender_is_accepted(self):
        raw = build(
            "From: a@example.com, b@example.com\nSender: a@example.com\nTo: c@gmail.com\n"
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertNotIn("MSG_MULTIPLE_FROM_NO_SENDER", finding_codes(check_message(raw)))


class FromHeaderTests(unittest.TestCase):
    def test_gmail_from_is_a_blocker(self):
        raw = build(
            "From: Someone <someone@gmail.com>\nTo: b@gmail.com\n"
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertIn("MSG_IMPERSONATES_GMAIL", finding_codes(check_message(raw)))

    def test_deceptive_display_name_is_critical(self):
        raw = build(
            'From: "Billing <billing@bank.example>" <deals@shop.test>\nTo: b@gmail.com\n'
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertIn("MSG_DECEPTIVE_DISPLAY_NAME", finding_codes(check_message(raw)))

    def test_display_name_matching_the_real_address_is_fine(self):
        raw = build(
            'From: "deals@shop.test" <deals@shop.test>\nTo: b@gmail.com\n'
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertNotIn("MSG_DECEPTIVE_DISPLAY_NAME", finding_codes(check_message(raw)))

    def test_off_domain_reply_to_is_informational(self):
        raw = build(
            "From: a@example.com\nReply-To: help@other.test\nTo: b@gmail.com\n"
            "Date: Tue, 13 Jan 2026 09:15:00 +0000"
        )
        self.assertIn("MSG_REPLYTO_OFF_DOMAIN", finding_codes(check_message(raw)))

    def test_expected_domain_mismatch_is_reported(self):
        result = check_message(COMPLIANT, expected_domain="other.test")
        self.assertIn("MSG_FROM_UNEXPECTED_DOMAIN", finding_codes(result))

    def test_expected_domain_relaxed_match_is_accepted(self):
        result = check_message(COMPLIANT, expected_domain="example.com")
        self.assertNotIn("MSG_FROM_UNEXPECTED_DOMAIN", finding_codes(result))


class UnsubscribeTests(unittest.TestCase):
    BASE = (
        "From: a@example.com\nTo: b@gmail.com\nSubject: s\n"
        "Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n"
    )

    def test_missing_header_is_a_blocker_for_bulk(self):
        result = check_message(build(self.BASE), bulk=True)
        self.assertIn("MSG_NO_LIST_UNSUBSCRIBE", finding_codes(result))

    def test_not_required_for_transactional(self):
        result = check_message(build(self.BASE), bulk=False)
        self.assertNotIn("MSG_NO_LIST_UNSUBSCRIBE", finding_codes(result))

    def test_mailto_only_is_a_blocker(self):
        raw = build(
            self.BASE
            + "List-Unsubscribe: <mailto:u@example.com>\n"
            + "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
        )
        self.assertIn("MSG_UNSUBSCRIBE_MAILTO_ONLY", finding_codes(check_message(raw)))

    def test_plain_http_is_critical(self):
        raw = build(
            self.BASE
            + "List-Unsubscribe: <http://example.com/u>\n"
            + "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
        )
        codes = finding_codes(check_message(raw))
        self.assertIn("MSG_UNSUBSCRIBE_NOT_HTTPS", codes)

    def test_missing_one_click_post_is_a_blocker(self):
        raw = build(self.BASE + "List-Unsubscribe: <https://example.com/u>")
        result = check_message(raw)
        self.assertIn("MSG_NO_ONE_CLICK_POST", finding_codes(result))
        self.assertEqual(
            next(f for f in result.findings if f.code == "MSG_NO_ONE_CLICK_POST").severity,
            Severity.BLOCKER,
        )

    def test_wrong_one_click_post_value_is_critical(self):
        raw = build(
            self.BASE
            + "List-Unsubscribe: <https://example.com/u>\n"
            + "List-Unsubscribe-Post: List-Unsubscribe=Yes"
        )
        result = check_message(raw)
        self.assertEqual(
            next(f for f in result.findings if f.code == "MSG_NO_ONE_CLICK_POST").severity,
            Severity.CRITICAL,
        )

    def test_unbracketed_uri_is_a_blocker(self):
        raw = build(
            self.BASE
            + "List-Unsubscribe: https://example.com/u\n"
            + "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
        )
        self.assertIn("MSG_UNSUBSCRIBE_MALFORMED", finding_codes(check_message(raw)))

    def test_https_without_mailto_is_informational(self):
        raw = build(
            self.BASE
            + "List-Unsubscribe: <https://example.com/u>\n"
            + "List-Unsubscribe-Post: List-Unsubscribe=One-Click"
        )
        self.assertIn("MSG_UNSUBSCRIBE_NO_MAILTO", finding_codes(check_message(raw)))


class DkimSignatureTests(unittest.TestCase):
    BASE = (
        "From: a@example.com\nTo: b@gmail.com\nSubject: s\n"
        "Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n"
        "List-Unsubscribe: <https://example.com/u>, <mailto:u@example.com>\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\n"
    )

    def test_unsigned_message_is_a_blocker(self):
        self.assertIn("MSG_NOT_DKIM_SIGNED", finding_codes(check_message(build(self.BASE))))

    def test_unaligned_signature_is_a_blocker(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha256; d=esp-shared.test; s=m; "
            "h=from:to:subject:date:message-id; bh=x; b=y"
        )
        self.assertIn("MSG_DKIM_NOT_ALIGNED", finding_codes(check_message(raw)))

    def test_subdomain_signature_is_aligned(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha256; d=mail.example.com; s=m; "
            "h=from:to:subject:date:message-id; bh=x; b=y"
        )
        self.assertNotIn("MSG_DKIM_NOT_ALIGNED", finding_codes(check_message(raw)))

    def test_sha1_signature_is_critical(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=m; "
            "h=from:to:subject:date:message-id; bh=x; b=y"
        )
        self.assertIn("MSG_DKIM_SHA1", finding_codes(check_message(raw)))

    def test_body_length_tag_is_critical(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; l=100; "
            "h=from:to:subject:date:message-id; bh=x; b=y"
        )
        self.assertIn("MSG_DKIM_LENGTH_TAG", finding_codes(check_message(raw)))

    def test_unsigned_from_is_a_blocker(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; h=to:subject; bh=x; b=y"
        )
        self.assertIn("MSG_DKIM_FROM_UNSIGNED", finding_codes(check_message(raw)))

    def test_partially_signed_headers_are_a_warning(self):
        raw = build(
            self.BASE + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; h=from; bh=x; b=y"
        )
        self.assertIn("MSG_DKIM_HEADERS_UNSIGNED", finding_codes(check_message(raw)))

    def test_signature_bytes_are_not_echoed_in_report_data(self):
        raw = build(
            self.BASE
            + "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; "
            "h=from:to:subject:date:message-id; bh=SECRETBH; b=SECRETSIG"
        )
        data = check_message(raw).data
        self.assertNotIn("SECRETSIG", str(data))
        self.assertNotIn("SECRETBH", str(data))


class AuthenticationResultsTests(unittest.TestCase):
    BASE = (
        "From: a@example.com\nTo: b@gmail.com\nSubject: s\n"
        "Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n"
        "List-Unsubscribe: <https://example.com/u>, <mailto:u@example.com>\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; "
        "h=from:to:subject:date:message-id; bh=x; b=y\n"
    )

    def test_dmarc_fail_is_a_blocker(self):
        raw = build(self.BASE + "Authentication-Results: mx.google.com; dmarc=fail (p=NONE)")
        self.assertIn("MSG_AUTH_DMARC_FAIL", finding_codes(check_message(raw)))

    def test_spf_softfail_is_critical(self):
        raw = build(self.BASE + "Authentication-Results: mx.google.com; spf=softfail")
        self.assertIn("MSG_AUTH_SPF_SOFTFAIL", finding_codes(check_message(raw)))

    def test_all_pass_produces_nothing(self):
        raw = build(
            self.BASE + "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass"
        )
        self.assertEqual(check_message(raw).findings, [])


class ArcTests(unittest.TestCase):
    BASE = (
        "From: a@example.com\nTo: b@gmail.com\nSubject: s\n"
        "Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n"
        "List-Unsubscribe: <https://example.com/u>, <mailto:u@example.com>\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; "
        "h=from:to:subject:date:message-id; bh=x; b=y\n"
    )

    def test_complete_chain_is_informational(self):
        raw = build(
            self.BASE
            + "ARC-Seal: i=1; a=rsa-sha256; d=relay.test; s=arc; b=x\n"
            + "ARC-Message-Signature: i=1; a=rsa-sha256; d=relay.test; s=arc; b=y\n"
            + "ARC-Authentication-Results: i=1; relay.test; spf=pass"
        )
        result = check_message(raw)
        self.assertIn("MSG_ARC_PRESENT", finding_codes(result))
        self.assertEqual(result.worst, Severity.INFO)

    def test_incomplete_chain_is_a_warning(self):
        raw = build(self.BASE + "ARC-Seal: i=1; a=rsa-sha256; d=relay.test; s=arc; b=x")
        self.assertIn("MSG_ARC_INCOMPLETE", finding_codes(check_message(raw)))

    def test_absent_chain_produces_nothing(self):
        self.assertFalse(check_message(build(self.BASE)).data["arc_present"])


class BodyTests(unittest.TestCase):
    BASE = (
        "From: a@example.com\nTo: b@gmail.com\nSubject: s\n"
        "Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n"
        "List-Unsubscribe: <https://example.com/u>, <mailto:u@example.com>\n"
        "List-Unsubscribe-Post: List-Unsubscribe=One-Click\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=m; "
        "h=from:to:subject:date:message-id; bh=x; b=y\n"
    )

    def test_html_only_single_part_is_a_warning(self):
        raw = build(self.BASE + "Content-Type: text/html", "<html></html>\n")
        self.assertIn("MSG_HTML_ONLY", finding_codes(check_message(raw)))

    def test_plain_text_only_is_fine(self):
        raw = build(self.BASE + "Content-Type: text/plain")
        self.assertNotIn("MSG_HTML_ONLY", finding_codes(check_message(raw)))

    def test_multipart_html_without_plain_is_a_warning(self):
        raw = build(
            self.BASE + 'MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary="b"',
            '--b\nContent-Type: text/html\n\n<html></html>\n\n--b--\n',
        )
        self.assertIn("MSG_HTML_ONLY", finding_codes(check_message(raw)))


if __name__ == "__main__":
    unittest.main()
