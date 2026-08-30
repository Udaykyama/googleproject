"""InboxReady — audit a sender against Google's Gmail bulk sender requirements.

Google began rejecting non-compliant bulk mail at the SMTP layer in November
2025. InboxReady checks a sending domain and a sample message against the
published requirements — SPF, DKIM, DMARC, forward-confirmed reverse DNS,
transport security, RFC 5322 formatting, RFC 8058 one-click unsubscribe, and
Postmaster Tools spam-rate thresholds — and explains how to fix what it finds.
"""

from __future__ import annotations

__version__ = "1.0.0"

from .audit import audit, audit_domain, audit_message
from .dnsresolver import DnsError, Resolver, StaticResolver, SystemResolver
from .domains import PublicSuffixList, check_alignment
from .models import AuditReport, CheckResult, Finding, Severity
from .report import render

__all__ = [
    "__version__",
    "audit",
    "audit_domain",
    "audit_message",
    "render",
    "AuditReport",
    "CheckResult",
    "Finding",
    "Severity",
    "Resolver",
    "StaticResolver",
    "SystemResolver",
    "DnsError",
    "PublicSuffixList",
    "check_alignment",
]
