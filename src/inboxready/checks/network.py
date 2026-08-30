"""Transport and infrastructure checks: MX, FCrDNS, MTA-STS, TLS-RPT, BIMI.

Google requires a valid forward-and-reverse DNS record for every sending IP and
a TLS-secured connection. These are the requirements that are invisible in an
email client but decide whether the SMTP conversation is allowed to happen.

Everything here is DNS-only by design — InboxReady never fetches a URL supplied
by the domain under audit, which keeps it free of server-side request forgery
risk when run against untrusted input.
"""

from __future__ import annotations

import ipaddress

from ..dnsresolver import NXDOMAIN, DnsError, Resolver
from ..models import CheckResult, Finding, Severity

__all__ = ["check_mx", "check_sending_ips", "check_transport_security", "check_bimi"]

#: Ranges reserved for documentation (RFC 5737, RFC 3849). Addresses here are
#: never routable, but they are what appears in examples and test fixtures.
_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)


def _safe_txt(resolver: Resolver, name: str) -> tuple[list[str], str | None]:
    try:
        return resolver.txt(name), None
    except NXDOMAIN:
        return [], None
    except (DnsError, ValueError) as exc:
        return [], str(exc)


def check_mx(resolver: Resolver, domain: str) -> CheckResult:
    """Check that the domain can receive mail.

    A sending domain that cannot receive mail cannot process bounces, abuse
    reports, or the unsubscribe confirmations Google's rules require.
    """

    result = CheckResult(name="mx")
    try:
        records = resolver.mx(domain)
    except NXDOMAIN:
        result.add(
            Finding(
                code="DOMAIN_NXDOMAIN",
                title="Domain does not exist",
                severity=Severity.BLOCKER,
                detail=f"{domain} returned NXDOMAIN.",
                remediation="Check the spelling and that the zone is delegated.",
                reference="RFC 1035",
            )
        )
        return result
    except (DnsError, ValueError) as exc:
        result.skipped_reason = str(exc)
        return result

    result.data["mx"] = records
    if not records:
        result.add(
            Finding(
                code="MX_MISSING",
                title="No MX record published",
                severity=Severity.WARNING,
                detail=(
                    f"{domain} publishes no MX record, so it cannot receive bounces, abuse "
                    "complaints, or replies. Receivers treat reply-less domains with suspicion."
                ),
                remediation=(
                    "Publish an MX record, or send from a subdomain that has one. Use "
                    "'0 .' (RFC 7505) only if the domain must never receive mail."
                ),
                reference="RFC 5321 §5.1",
            )
        )
        return result

    if any(host.split(maxsplit=1)[-1].strip() in {".", ""} for host in records):
        result.add(
            Finding(
                code="MX_NULL",
                title="Domain publishes a null MX",
                severity=Severity.WARNING,
                detail=(
                    "A null MX ('0 .') declares that the domain accepts no mail, so bounces "
                    "and unsubscribe replies are discarded."
                ),
                remediation="Send from a domain that can receive mail.",
                reference="RFC 7505",
            )
        )
    return result


def check_sending_ips(resolver: Resolver, ips: list[str]) -> CheckResult:
    """Verify forward-confirmed reverse DNS for each sending IP.

    Google requires that a sending IP has a PTR record *and* that the name it
    points to resolves back to the same IP. Publishing a PTR alone is not
    enough, and a missing or unconfirmed PTR is a common cause of rejection.
    """

    result = CheckResult(name="sending_ips")
    if not ips:
        result.skipped_reason = "no sending IPs supplied (pass --ip to check FCrDNS)"
        return result

    checked: list[dict[str, object]] = []
    for raw_ip in ips:
        try:
            address = ipaddress.ip_address(raw_ip.strip())
        except ValueError:
            result.add(
                Finding(
                    code="IP_INVALID",
                    title=f"'{raw_ip}' is not an IP address",
                    severity=Severity.WARNING,
                    detail="Sending hosts must be given as literal IPv4 or IPv6 addresses.",
                    remediation="Supply the public IP your MTA connects from.",
                    reference="",
                )
            )
            continue

        entry: dict[str, object] = {"ip": str(address)}
        checked.append(entry)

        entry["global"] = address.is_global
        if not address.is_global:
            result.add(
                Finding(
                    code="IP_NOT_PUBLIC",
                    title=f"{address} is not globally routable",
                    severity=Severity.WARNING,
                    detail=(
                        f"{address} is in a reserved range ({_reserved_range_name(address)}). "
                        "Receivers only ever see the public address your mail egresses from, so "
                        "this is unlikely to be the IP Gmail evaluates."
                    ),
                    remediation="Audit the public NAT or egress address instead.",
                    reference="RFC 5735 / RFC 4193 / RFC 5737",
                )
            )
        if address.is_loopback or address.is_link_local:
            # Nothing meaningful to resolve; reverse DNS for these is local-only.
            continue

        try:
            names = resolver.ptr(str(address))
        except NXDOMAIN:
            names = []
        except (DnsError, ValueError) as exc:
            entry["error"] = str(exc)
            continue

        entry["ptr"] = names
        if not names:
            result.add(
                Finding(
                    code="PTR_MISSING",
                    title=f"{address} has no PTR record",
                    severity=Severity.BLOCKER,
                    detail=(
                        "Google requires a valid reverse DNS record for every sending IP. "
                        "Mail from IPs without one is rejected."
                    ),
                    remediation="Ask the network or cloud provider that owns the IP to set a PTR.",
                    reference="Google sender guidelines; RFC 1912 §2.1",
                )
            )
            continue

        confirmed = []
        for name in names:
            try:
                forward = resolver.a(name) if address.version == 4 else resolver.aaaa(name)
            except (NXDOMAIN, DnsError, ValueError):
                forward = []
            if any(_same_ip(candidate, address) for candidate in forward):
                confirmed.append(name)

        entry["forward_confirmed"] = confirmed
        if not confirmed:
            result.add(
                Finding(
                    code="FCRDNS_FAILED",
                    title=f"{address} fails forward-confirmed reverse DNS",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"PTR points to {', '.join(names)}, but none of those names resolve back "
                        f"to {address}. Receivers treat this as an unverified host."
                    ),
                    remediation="Publish a matching forward record for the PTR hostname.",
                    reference="Google sender guidelines; RFC 1912 §2.1",
                )
            )

    result.data["ips"] = checked
    return result


def _same_ip(candidate: str, address) -> bool:
    try:
        return ipaddress.ip_address(candidate.strip()) == address
    except ValueError:
        return False


def _reserved_range_name(address) -> str:
    """Describe why an address is not globally routable."""

    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link-local"
    if address.is_multicast:
        return "multicast"
    if address.is_unspecified:
        return "unspecified"
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return "documentation, RFC 5737 / RFC 3849"
    if address.is_private:
        return "private"
    return "reserved"


def check_transport_security(resolver: Resolver, domain: str) -> CheckResult:
    """Check MTA-STS (RFC 8461) and TLS-RPT (RFC 8460) policy records.

    Only the DNS side is inspected. Confirming the HTTPS policy file requires
    fetching ``https://mta-sts.<domain>/.well-known/mta-sts.txt``, which is
    deliberately out of scope.
    """

    result = CheckResult(name="transport_security")

    sts_records, sts_error = _safe_txt(resolver, f"_mta-sts.{domain}")
    sts_records = [txt for txt in sts_records if txt.strip().lower().startswith("v=stsv1")]
    result.data["mta_sts"] = sts_records
    if sts_error:
        result.data["mta_sts_error"] = sts_error

    if not sts_records:
        result.add(
            Finding(
                code="MTA_STS_MISSING",
                title="No MTA-STS policy published",
                severity=Severity.INFO,
                detail=(
                    "Without MTA-STS, an attacker who can intercept the connection can strip "
                    "STARTTLS and read mail in transit. Google publishes and honours MTA-STS."
                ),
                remediation=(
                    "Publish '_mta-sts.<domain> TXT \"v=STSv1; id=<timestamp>\"' and serve a "
                    "policy at https://mta-sts.<domain>/.well-known/mta-sts.txt."
                ),
                reference="RFC 8461",
            )
        )
    else:
        if len(sts_records) > 1:
            result.add(
                Finding(
                    code="MTA_STS_MULTIPLE",
                    title="More than one MTA-STS record published",
                    severity=Severity.WARNING,
                    detail="Receivers cannot decide which policy version applies.",
                    remediation="Keep exactly one _mta-sts TXT record.",
                    reference="RFC 8461 §3.1",
                )
            )
        tags = _tag_map(sts_records[0])
        if not tags.get("id"):
            result.add(
                Finding(
                    code="MTA_STS_NO_ID",
                    title="MTA-STS record has no 'id' tag",
                    severity=Severity.WARNING,
                    detail="The 'id' tag is what tells receivers to refresh a cached policy.",
                    remediation="Add 'id=' with a value you bump on every policy change.",
                    reference="RFC 8461 §3.1",
                )
            )
        result.data["mta_sts_tags"] = tags

    tlsrpt_records, tlsrpt_error = _safe_txt(resolver, f"_smtp._tls.{domain}")
    tlsrpt_records = [txt for txt in tlsrpt_records if txt.strip().lower().startswith("v=tlsrptv1")]
    result.data["tls_rpt"] = tlsrpt_records
    if tlsrpt_error:
        result.data["tls_rpt_error"] = tlsrpt_error
    if not tlsrpt_records:
        result.add(
            Finding(
                code="TLSRPT_MISSING",
                title="No TLS-RPT record published",
                severity=Severity.INFO,
                detail=(
                    "TLS-RPT is how receivers tell you that TLS negotiation to your domain is "
                    "failing. Without it, downgrade attacks and expired certificates are silent."
                ),
                remediation=(
                    "Publish '_smtp._tls.<domain> TXT \"v=TLSRPTv1; rua=mailto:tls@<domain>\"'."
                ),
                reference="RFC 8460 §3",
            )
        )
    return result


def check_bimi(resolver: Resolver, domain: str, dmarc_policy: str | None = None) -> CheckResult:
    """Check the BIMI record, which requires DMARC enforcement to be honoured."""

    result = CheckResult(name="bimi")
    records, error = _safe_txt(resolver, f"default._bimi.{domain}")
    records = [txt for txt in records if txt.strip().lower().startswith("v=bimi1")]
    result.data["bimi"] = records
    if error:
        result.data["error"] = error

    if not records:
        result.skipped_reason = "no BIMI record published (optional)"
        return result

    tags = _tag_map(records[0])
    result.data["tags"] = tags

    if not tags.get("l"):
        result.add(
            Finding(
                code="BIMI_NO_LOGO",
                title="BIMI record has no logo URL",
                severity=Severity.WARNING,
                detail="The 'l=' tag must point to an SVG Tiny PS logo.",
                remediation="Add 'l=https://<domain>/bimi/logo.svg'.",
                reference="BIMI draft §4.2",
            )
        )
    if dmarc_policy not in {"quarantine", "reject"}:
        result.add(
            Finding(
                code="BIMI_WITHOUT_ENFORCEMENT",
                title="BIMI published without DMARC enforcement",
                severity=Severity.WARNING,
                detail=(
                    f"BIMI requires a DMARC policy of quarantine or reject; the effective "
                    f"policy is '{dmarc_policy or 'unknown'}', so Gmail will not display the "
                    "logo."
                ),
                remediation="Advance DMARC to at least 'p=quarantine'.",
                reference="BIMI draft §7.1",
            )
        )
    if not tags.get("a"):
        result.add(
            Finding(
                code="BIMI_NO_VMC",
                title="BIMI record has no Verified Mark Certificate",
                severity=Severity.INFO,
                detail="Gmail requires a VMC ('a=' tag) before it displays a BIMI logo.",
                remediation="Obtain a VMC and reference it with 'a=https://.../vmc.pem'.",
                reference="BIMI draft §4.3",
            )
        )
    return result


def _tag_map(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for chunk in record.split(";"):
        name, sep, value = chunk.strip().partition("=")
        if sep and name.strip():
            tags[name.strip().lower()] = value.strip()
    return tags
