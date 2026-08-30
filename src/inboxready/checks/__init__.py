"""Individual compliance checks, one module per requirement area."""

from __future__ import annotations

from .dkim import check_dkim
from .dmarc import check_dmarc
from .message import check_message
from .network import check_bimi, check_mx, check_sending_ips, check_transport_security
from .reputation import check_reputation
from .spf import check_spf

__all__ = [
    "check_bimi",
    "check_dkim",
    "check_dmarc",
    "check_message",
    "check_mx",
    "check_reputation",
    "check_sending_ips",
    "check_spf",
    "check_transport_security",
]
