"""End-to-end tests: orchestration, reporting, and the command line."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from support import EXAMPLES, SRC, finding_codes  # noqa: F401

from inboxready.audit import audit, audit_domain, audit_message
from inboxready.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main
from inboxready.dnsresolver import StaticResolver
from inboxready.models import AuditReport, CheckResult, Finding, Severity
from inboxready.report import render

FAILING_FIXTURE = EXAMPLES / "fixtures" / "failing-sender.json"
COMPLIANT_FIXTURE = EXAMPLES / "fixtures" / "compliant-sender.json"
FAILING_MESSAGE = EXAMPLES / "messages" / "failing-campaign.eml"
COMPLIANT_MESSAGE = EXAMPLES / "messages" / "compliant-campaign.eml"


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:  # argparse errors
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class SeverityTests(unittest.TestCase):
    def test_ordering(self):
        self.assertLess(Severity.INFO, Severity.WARNING)
        self.assertLess(Severity.WARNING, Severity.CRITICAL)
        self.assertLess(Severity.CRITICAL, Severity.BLOCKER)

    def test_from_label(self):
        self.assertIs(Severity.from_label("Blocker"), Severity.BLOCKER)
        with self.assertRaises(ValueError):
            Severity.from_label("catastrophic")


class ReportModelTests(unittest.TestCase):
    def _report(self, *severities: Severity) -> AuditReport:
        report = AuditReport(target="example.com")
        result = CheckResult(name="spf")
        for index, severity in enumerate(severities):
            result.add(Finding(code=f"C{index}", title="t", severity=severity))
        report.add(result)
        return report

    def test_empty_report_is_perfect(self):
        report = self._report()
        self.assertEqual(report.score, 100)
        self.assertTrue(report.gmail_ready)
        self.assertIs(report.worst, Severity.PASS)

    def test_info_and_pass_do_not_reduce_the_score(self):
        self.assertEqual(self._report(Severity.INFO, Severity.PASS).score, 100)

    def test_score_is_floored_at_zero(self):
        self.assertEqual(self._report(*([Severity.BLOCKER] * 10)).score, 0)

    def test_warnings_do_not_block_readiness(self):
        report = self._report(Severity.WARNING)
        self.assertTrue(report.gmail_ready)
        self.assertEqual(report.score, 96)

    def test_critical_blocks_readiness(self):
        self.assertFalse(self._report(Severity.CRITICAL).gmail_ready)

    def test_counts(self):
        counts = self._report(Severity.WARNING, Severity.WARNING, Severity.BLOCKER).counts()
        self.assertEqual(counts["warning"], 2)
        self.assertEqual(counts["blocker"], 1)


class AuditOrchestrationTests(unittest.TestCase):
    def test_domain_audit_runs_every_dns_check(self):
        resolver = StaticResolver.from_file(COMPLIANT_FIXTURE)
        report = audit_domain(resolver, "mail.example-good.test", selectors=["google"])
        self.assertEqual(
            [r.name for r in report.results],
            ["mx", "spf", "dkim", "dmarc", "sending_ips", "transport_security", "bimi"],
        )
        self.assertTrue(report.gmail_ready)

    def test_compliant_fixture_has_no_blocking_findings(self):
        resolver = StaticResolver.from_file(COMPLIANT_FIXTURE)
        report = audit_domain(
            resolver, "mail.example-good.test", selectors=["google"], ips=["198.51.100.25"]
        )
        blocking = [f for f in report.findings if f.severity.rank >= Severity.CRITICAL.rank]
        self.assertEqual(blocking, [])

    def test_failing_fixture_surfaces_the_expected_blockers(self):
        resolver = StaticResolver.from_file(FAILING_FIXTURE)
        report = audit_domain(
            resolver,
            "deals.example-shop.test",
            selectors=["google", "legacy"],
            ips=["203.0.113.25", "203.0.113.26"],
        )
        codes = finding_codes(report)
        for expected in (
            "SPF_ALL_PASS",
            "SPF_TOO_MANY_LOOKUPS",
            "DKIM_KEY_REVOKED",
            "DKIM_KEY_TOO_SHORT",
            "DMARC_POLICY_NONE",
            "FCRDNS_FAILED",
            "PTR_MISSING",
        ):
            self.assertIn(expected, codes)
        self.assertFalse(report.gmail_ready)

    def test_message_only_audit_needs_no_resolver(self):
        report = audit_message(COMPLIANT_MESSAGE.read_bytes())
        self.assertEqual(report.findings, [])
        self.assertEqual(report.target, "mail.example-good.test")

    def test_combined_audit_includes_reputation(self):
        resolver = StaticResolver.from_file(COMPLIANT_FIXTURE)
        report = audit(
            resolver=resolver,
            domain="mail.example-good.test",
            raw_message=COMPLIANT_MESSAGE.read_bytes(),
            selectors=["google"],
            daily_volume=120_000,
            spam_rate=0.04,
        )
        self.assertIn("reputation", [r.name for r in report.results])
        self.assertTrue(report.gmail_ready)

    def test_audit_without_any_input_raises(self):
        with self.assertRaises(ValueError):
            audit()

    def test_audit_without_resolver_skips_dns(self):
        report = audit(domain="example.com", raw_message=COMPLIANT_MESSAGE.read_bytes())
        self.assertEqual(report.context["dns_skipped"], "no resolver supplied")

    def test_transactional_flag_disables_unsubscribe_requirement(self):
        raw = b"From: a@example.com\nTo: b@gmail.com\nSubject: Receipt\n" \
              b"Date: Tue, 13 Jan 2026 09:15:00 +0000\nMessage-ID: <x@example.com>\n\nHi\n"
        codes = finding_codes(audit(raw_message=raw, bulk=False))
        self.assertNotIn("MSG_NO_LIST_UNSUBSCRIBE", codes)


class RenderTests(unittest.TestCase):
    def setUp(self):
        resolver = StaticResolver.from_file(FAILING_FIXTURE)
        self.report = audit_domain(
            resolver, "deals.example-shop.test", selectors=["google", "legacy"]
        )

    def test_text_render_is_plain_without_color(self):
        text = render(self.report, "text", color=False)
        self.assertNotIn("\033[", text)
        self.assertIn("deals.example-shop.test", text)
        self.assertIn("SPF_ALL_PASS", text)

    def test_text_render_can_be_coloured(self):
        self.assertIn("\033[", render(self.report, "text", color=True))

    def test_json_render_round_trips(self):
        payload = json.loads(render(self.report, "json"))
        self.assertEqual(payload["target"], "deals.example-shop.test")
        self.assertFalse(payload["gmail_ready"])
        self.assertIn("checks", payload)
        codes = {
            finding["code"] for check in payload["checks"] for finding in check["findings"]
        }
        self.assertIn("SPF_TOO_MANY_LOOKUPS", codes)

    def test_markdown_render_has_headings(self):
        markdown = render(self.report, "markdown")
        self.assertTrue(markdown.startswith("# InboxReady audit"))
        self.assertIn("## SPF (RFC 7208)", markdown)

    def test_unknown_format_raises(self):
        with self.assertRaises(ValueError):
            render(self.report, "yaml")


class CliTests(unittest.TestCase):
    def test_compliant_fixture_exits_zero(self):
        code, out, _ = run_cli(
            [
                "mail.example-good.test",
                "--fixture", str(COMPLIANT_FIXTURE),
                "--selector", "google",
                "--message", str(COMPLIANT_MESSAGE),
                "--spam-rate", "0.04",
                "--daily-volume", "120000",
                "--no-color",
            ]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertIn("READY", out)

    def test_failing_fixture_exits_one(self):
        code, out, _ = run_cli(
            [
                "deals.example-shop.test",
                "--fixture", str(FAILING_FIXTURE),
                "--selector", "google",
                "--message", str(FAILING_MESSAGE),
                "--no-color",
            ]
        )
        self.assertEqual(code, EXIT_FINDINGS)
        self.assertIn("NOT READY", out)

    def test_fail_on_threshold_is_respected(self):
        # A daily volume just under the bulk threshold yields a warning and an
        # info finding, but nothing critical.
        argv = [
            "mail.example-good.test",
            "--fixture", str(COMPLIANT_FIXTURE),
            "--selector", "google",
            "--daily-volume", "4500",
            "--no-color",
        ]
        self.assertEqual(run_cli(argv + ["--fail-on", "critical"])[0], EXIT_OK)
        self.assertEqual(run_cli(argv + ["--fail-on", "warning"])[0], EXIT_FINDINGS)
        self.assertEqual(run_cli(argv + ["--fail-on", "info"])[0], EXIT_FINDINGS)

    def test_clean_report_passes_the_strictest_threshold(self):
        code, _, _ = run_cli(
            [
                "mail.example-good.test",
                "--fixture", str(COMPLIANT_FIXTURE),
                "--selector", "google",
                "--fail-on", "info",
                "--no-color",
            ]
        )
        self.assertEqual(code, EXIT_OK)

    def test_json_output(self):
        code, out, _ = run_cli(
            [
                "mail.example-good.test",
                "--fixture", str(COMPLIANT_FIXTURE),
                "--selector", "google",
                "--format", "json",
            ]
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["target"], "mail.example-good.test")

    def test_offline_message_audit(self):
        code, out, _ = run_cli(["--message", str(COMPLIANT_MESSAGE), "--offline", "--no-color"])
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Message hygiene", out)

    def test_output_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "report.md"
            code, _, _ = run_cli(
                [
                    "mail.example-good.test",
                    "--fixture", str(COMPLIANT_FIXTURE),
                    "--selector", "google",
                    "--format", "markdown",
                    "--output", str(target),
                ]
            )
            self.assertEqual(code, EXIT_OK)
            self.assertIn("# InboxReady audit", target.read_text(encoding="utf-8"))

    def test_no_arguments_is_a_usage_error(self):
        self.assertEqual(run_cli([])[0], EXIT_USAGE)

    def test_invalid_domain_is_rejected(self):
        self.assertEqual(run_cli(["example.com; rm -rf /"])[0], EXIT_USAGE)

    def test_offline_and_fixture_are_mutually_exclusive(self):
        self.assertEqual(
            run_cli(["example.com", "--offline", "--fixture", str(COMPLIANT_FIXTURE)])[0],
            EXIT_USAGE,
        )

    def test_offline_without_message_is_a_usage_error(self):
        self.assertEqual(run_cli(["example.com", "--offline"])[0], EXIT_USAGE)

    def test_unreadable_message_is_a_usage_error(self):
        code, _, err = run_cli(["--message", "/nonexistent/nope.eml", "--offline"])
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("cannot read message", err)


if __name__ == "__main__":
    unittest.main()
