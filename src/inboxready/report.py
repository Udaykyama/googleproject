"""Rendering an :class:`~inboxready.models.AuditReport` for humans and machines."""

from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap

from .models import AuditReport, CheckResult, Finding, Severity

__all__ = ["render", "render_text", "render_json", "render_markdown", "FORMATS"]

FORMATS = ("text", "json", "markdown")

_ANSI = {
    Severity.PASS: "\033[32m",
    Severity.INFO: "\033[36m",
    Severity.WARNING: "\033[33m",
    Severity.CRITICAL: "\033[31m",
    Severity.BLOCKER: "\033[1;37;41m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

_ICON = {
    Severity.PASS: "PASS",
    Severity.INFO: "INFO",
    Severity.WARNING: "WARN",
    Severity.CRITICAL: "CRIT",
    Severity.BLOCKER: "BLOCK",
}

_CHECK_TITLES = {
    "mx": "Mail exchangers",
    "spf": "SPF (RFC 7208)",
    "dkim": "DKIM (RFC 6376)",
    "dmarc": "DMARC (RFC 7489)",
    "sending_ips": "Sending IPs / reverse DNS",
    "transport_security": "Transport security (MTA-STS, TLS-RPT)",
    "bimi": "BIMI",
    "message": "Message hygiene (RFC 5322 / 8058)",
    "reputation": "Volume & spam rate",
}


def render(report: AuditReport, fmt: str = "text", color: bool | None = None) -> str:
    """Render ``report`` in the requested format."""

    if fmt == "json":
        return render_json(report)
    if fmt == "markdown":
        return render_markdown(report)
    if fmt == "text":
        return render_text(report, color=color)
    raise ValueError(f"unknown format {fmt!r} (expected one of: {', '.join(FORMATS)})")


def render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False)


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _width(default: int = 88) -> int:
    try:
        return max(60, min(default, shutil.get_terminal_size((default, 24)).columns))
    except OSError:  # pragma: no cover - non-tty environments
        return default


def render_text(report: AuditReport, color: bool | None = None) -> str:
    use_color = _supports_color() if color is None else color
    width = _width()

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if use_color else text

    lines: list[str] = []
    lines.append("=" * width)
    lines.append(paint(f"InboxReady audit: {report.target}", _BOLD) if use_color else f"InboxReady audit: {report.target}")
    lines.append("=" * width)

    verdict = "READY" if report.gmail_ready else "NOT READY"
    verdict_colour = _ANSI[Severity.PASS] if report.gmail_ready else _ANSI[Severity.BLOCKER]
    lines.append(
        f"Score {report.score}/100   Gmail bulk-sender status: "
        f"{paint(verdict, verdict_colour)}"
    )

    counts = report.counts()
    summary = "   ".join(
        f"{_ICON[severity]} {counts[severity.label]}"
        for severity in reversed(list(Severity))
        if counts[severity.label]
    )
    lines.append(f"Findings: {summary or 'none'}")
    if report.context:
        for key, value in report.context.items():
            lines.append(f"{key.replace('_', ' ').capitalize()}: {value}")
    lines.append("")

    for result in report.results:
        lines.extend(_render_check_text(result, width, paint))

    lines.append("-" * width)
    if report.gmail_ready:
        lines.append("No blocking issues found against Google's published sender requirements.")
    else:
        blocking = [
            f for f in report.findings if f.severity.rank >= Severity.CRITICAL.rank
        ]
        lines.append(f"Fix these {len(blocking)} issue(s) before sending bulk mail to Gmail:")
        for finding in blocking:
            lines.append(f"  - [{finding.code}] {finding.title}")
    lines.append("")
    return "\n".join(lines)


def _render_check_text(result: CheckResult, width: int, paint) -> list[str]:
    title = _CHECK_TITLES.get(result.name, result.name)
    lines = [paint(f"## {title}", _BOLD)]

    if result.skipped:
        lines.append(f"   skipped: {result.skipped_reason}")
        lines.append("")
        return lines

    if not result.findings:
        lines.append(f"   {paint('PASS', _ANSI[Severity.PASS])}  no issues found")
        lines.append("")
        return lines

    for finding in sorted(result.findings, key=lambda f: -f.severity.rank):
        badge = paint(f"{_ICON[finding.severity]:<5}", _ANSI[finding.severity])
        lines.append(f"   {badge} {finding.title}  [{finding.code}]")
        for label, body in (("", finding.detail), ("fix: ", finding.remediation)):
            if not body:
                continue
            wrapped = textwrap.wrap(
                f"{label}{body}", width=width - 10, initial_indent="", subsequent_indent="  "
            )
            lines.extend(f"         {line}" for line in wrapped)
        if finding.reference:
            lines.append(f"         ref: {finding.reference}")
        lines.append("")
    return lines


def render_markdown(report: AuditReport) -> str:
    counts = report.counts()
    lines = [
        f"# InboxReady audit: `{report.target}`",
        "",
        f"**Score:** {report.score}/100 &nbsp;&nbsp; "
        f"**Gmail bulk-sender status:** {'READY' if report.gmail_ready else 'NOT READY'}",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in reversed(list(Severity)):
        lines.append(f"| {severity.label} | {counts[severity.label]} |")
    lines.append("")

    for result in report.results:
        lines.append(f"## {_CHECK_TITLES.get(result.name, result.name)}")
        lines.append("")
        if result.skipped:
            lines.append(f"_Skipped: {result.skipped_reason}_")
            lines.append("")
            continue
        if not result.findings:
            lines.append("No issues found.")
            lines.append("")
            continue
        for finding in sorted(result.findings, key=lambda f: -f.severity.rank):
            lines.extend(_render_finding_markdown(finding))
        lines.append("")
    return "\n".join(lines)


def _render_finding_markdown(finding: Finding) -> list[str]:
    lines = [f"### `{finding.severity.label.upper()}` {finding.title}", ""]
    lines.append(f"- **Code:** `{finding.code}`")
    if finding.detail:
        lines.append(f"- **Detail:** {finding.detail}")
    if finding.remediation:
        lines.append(f"- **Fix:** {finding.remediation}")
    if finding.reference:
        lines.append(f"- **Reference:** {finding.reference}")
    lines.append("")
    return lines
