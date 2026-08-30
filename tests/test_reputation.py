"""Tests for bulk-sender classification and spam-rate thresholds."""

from __future__ import annotations

import unittest

from support import SRC, finding_codes  # noqa: F401

from inboxready.checks.reputation import (
    BULK_SENDER_THRESHOLD,
    SPAM_RATE_LIMIT,
    SPAM_RATE_TARGET,
    check_reputation,
)
from inboxready.models import Severity


class ReputationTests(unittest.TestCase):
    def test_no_inputs_is_skipped(self):
        self.assertTrue(check_reputation().skipped)

    def test_volume_at_threshold_is_bulk(self):
        result = check_reputation(daily_volume=BULK_SENDER_THRESHOLD)
        self.assertTrue(result.data["bulk_sender"])
        self.assertIn("REP_BULK_SENDER", finding_codes(result))

    def test_volume_below_threshold_is_not_bulk(self):
        result = check_reputation(daily_volume=100)
        self.assertFalse(result.data["bulk_sender"])
        self.assertNotIn("REP_BULK_SENDER", finding_codes(result))

    def test_near_threshold_is_warned(self):
        result = check_reputation(daily_volume=BULK_SENDER_THRESHOLD - 500)
        self.assertIn("REP_NEAR_BULK_THRESHOLD", finding_codes(result))

    def test_explicit_bulk_flag_overrides_volume(self):
        result = check_reputation(daily_volume=10, bulk=True)
        self.assertTrue(result.data["bulk_sender"])
        self.assertIn("REP_BULK_SENDER", finding_codes(result))

    def test_spam_rate_at_limit_is_a_blocker(self):
        result = check_reputation(spam_rate=SPAM_RATE_LIMIT)
        self.assertIn("REP_SPAM_RATE_CRITICAL", finding_codes(result))
        self.assertEqual(result.worst, Severity.BLOCKER)

    def test_spam_rate_above_target_is_critical(self):
        result = check_reputation(spam_rate=0.2)
        self.assertIn("REP_SPAM_RATE_ELEVATED", finding_codes(result))
        self.assertEqual(result.worst, Severity.CRITICAL)

    def test_spam_rate_at_target_is_a_pass(self):
        result = check_reputation(spam_rate=SPAM_RATE_TARGET)
        self.assertIn("REP_SPAM_RATE_OK", finding_codes(result))
        self.assertEqual(result.worst, Severity.PASS)

    def test_healthy_spam_rate_is_a_pass(self):
        result = check_reputation(spam_rate=0.02)
        self.assertIn("REP_SPAM_RATE_OK", finding_codes(result))

    def test_absent_spam_rate_is_noted(self):
        self.assertIn("REP_NO_SPAM_RATE", finding_codes(check_reputation(daily_volume=10)))

    def test_negative_values_are_rejected(self):
        self.assertIn("REP_VOLUME_INVALID", finding_codes(check_reputation(daily_volume=-1)))
        self.assertIn(
            "REP_SPAM_RATE_INVALID", finding_codes(check_reputation(spam_rate=-0.5, bulk=False))
        )


if __name__ == "__main__":
    unittest.main()
