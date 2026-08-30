"""Audit orchestration: runs the checks and assembles a report."""

from __future__ import annotations

from .checks.dkim import check_dkim
from .checks.dmarc import check_dmarc
from .checks.message import check_message
from .checks.network import check_bimi, check_mx, check_sending_ips, check_transport_security
from .checks.reputation import check_reputation
from .checks.spf import check_spf
from .dnsresolver import Resolver
from .domains import PublicSuffixList
from .models import AuditReport

__all__ = ["audit_domain", "audit_message", "audit"]


def audit_domain(
    resolver: Resolver,
    domain: str,
    selectors: list[str] | None = None,
    ips: list[str] | None = None,
    psl: PublicSuffixList | None = None,
    probe_selectors: bool = True,
    expand_spf: bool = True,
) -> AuditReport:
    """Run every DNS-side check against ``domain``."""

    psl = psl or PublicSuffixList()
    report = AuditReport(target=domain)
    report.context["organizational_domain"] = psl.organizational_domain(domain)

    report.add(check_mx(resolver, domain))
    report.add(check_spf(resolver, domain, expand=expand_spf))
    report.add(check_dkim(resolver, domain, selectors=selectors, probe_common=probe_selectors))
    dmarc = report.add(check_dmarc(resolver, domain, psl=psl))
    report.add(check_sending_ips(resolver, ips or []))
    report.add(check_transport_security(resolver, domain))
    report.add(
        check_bimi(resolver, domain, dmarc_policy=dmarc.data.get("effective_policy"))
    )

    report.context["dns_queries"] = resolver.query_count
    return report


def audit_message(
    raw: bytes,
    bulk: bool = True,
    psl: PublicSuffixList | None = None,
    expected_domain: str | None = None,
) -> AuditReport:
    """Run the message-level checks against a raw ``.eml``."""

    psl = psl or PublicSuffixList()
    result = check_message(raw, bulk=bulk, psl=psl, expected_domain=expected_domain)
    report = AuditReport(target=expected_domain or result.data.get("from_domain") or "message")
    report.add(result)
    return report


def audit(
    resolver: Resolver | None = None,
    domain: str | None = None,
    raw_message: bytes | None = None,
    selectors: list[str] | None = None,
    ips: list[str] | None = None,
    daily_volume: int | None = None,
    spam_rate: float | None = None,
    bulk: bool | None = None,
    psl: PublicSuffixList | None = None,
    probe_selectors: bool = True,
    expand_spf: bool = True,
) -> AuditReport:
    """Run a combined audit over DNS, a sample message, and sending stats.

    Every input is optional so the tool degrades gracefully: a domain with no
    sample message still gets a full DNS audit, and a message can be checked
    offline with no resolver at all.
    """

    if domain is None and raw_message is None:
        raise ValueError("audit() needs a domain, a raw message, or both")

    psl = psl or PublicSuffixList()

    if domain and resolver is not None:
        report = audit_domain(
            resolver,
            domain,
            selectors=selectors,
            ips=ips,
            psl=psl,
            probe_selectors=probe_selectors,
            expand_spf=expand_spf,
        )
    else:
        report = AuditReport(target=domain or "message")
        if domain:
            report.context["organizational_domain"] = psl.organizational_domain(domain)
            report.context["dns_skipped"] = "no resolver supplied"

    if raw_message is not None:
        message_result = check_message(
            raw_message,
            bulk=True if bulk is None else bulk,
            psl=psl,
            expected_domain=domain,
        )
        report.add(message_result)
        if report.target in {"", "message"}:
            report.target = message_result.data.get("from_domain") or "message"

    report.add(check_reputation(daily_volume=daily_volume, spam_rate=spam_rate, bulk=bulk))
    return report
