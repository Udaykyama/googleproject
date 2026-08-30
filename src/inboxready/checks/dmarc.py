"""DMARC policy audit (RFC 7489).

DMARC is the requirement Google added in 2024 and began enforcing with SMTP
rejections in November 2025. It is also the one senders most often satisfy in
name only: ``p=none`` technically meets the bar while providing no protection
against anyone spoofing the domain.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..dnsresolver import NXDOMAIN, DnsError, Resolver
from ..domains import PublicSuffixList
from ..models import CheckResult, Finding, Severity

__all__ = ["check_dmarc", "parse_dmarc_record", "DmarcRecord"]

_VALID_POLICIES = {"none", "quarantine", "reject"}
_VALID_ALIGNMENT = {"r", "s"}
_VALID_FO = {"0", "1", "d", "s"}
_VALID_RF = {"afrf"}
_KNOWN_TAGS = {"v", "p", "sp", "np", "rua", "ruf", "adkim", "aspf", "pct", "fo", "rf", "ri"}
_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


@dataclass
class DmarcRecord:
    """A parsed ``v=DMARC1`` record."""

    raw: str
    domain: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    inherited_from: str | None = None

    @property
    def policy(self) -> str:
        return self.tags.get("p", "").lower()

    @property
    def subdomain_policy(self) -> str:
        return self.tags.get("sp", self.policy).lower()

    @property
    def percentage(self) -> int:
        try:
            return int(self.tags.get("pct", "100"))
        except ValueError:
            return 100

    @property
    def rua(self) -> list[str]:
        return _split_uris(self.tags.get("rua", ""))

    @property
    def ruf(self) -> list[str]:
        return _split_uris(self.tags.get("ruf", ""))

    @property
    def dkim_alignment(self) -> str:
        return self.tags.get("adkim", "r").lower()

    @property
    def spf_alignment(self) -> str:
        return self.tags.get("aspf", "r").lower()

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "domain": self.domain,
            "inherited_from": self.inherited_from,
            "tags": dict(self.tags),
            "policy": self.policy,
            "subdomain_policy": self.subdomain_policy,
            "percentage": self.percentage,
            "errors": list(self.errors),
        }


def _split_uris(value: str) -> list[str]:
    return [uri.strip() for uri in value.split(",") if uri.strip()]


def parse_dmarc_record(raw: str, domain: str) -> DmarcRecord:
    """Parse a DMARC tag-value list, collecting syntax errors."""

    record = DmarcRecord(raw=raw, domain=domain)
    chunks = [chunk.strip() for chunk in raw.split(";")]
    chunks = [chunk for chunk in chunks if chunk]

    for index, chunk in enumerate(chunks):
        name, sep, value = chunk.partition("=")
        name = name.strip()
        value = value.strip()
        if not sep or not _TAG_RE.match(name):
            record.errors.append(f"malformed tag {chunk!r} (expected name=value)")
            continue
        lowered = name.lower()
        if lowered in record.tags:
            record.errors.append(f"duplicate tag '{lowered}'")
        record.tags[lowered] = value
        if index == 0 and lowered != "v":
            record.errors.append("the 'v=DMARC1' tag must come first")

    version = record.tags.get("v", "")
    if version.upper() != "DMARC1":
        record.errors.append(f"version must be 'DMARC1', got {version or '(missing)'!r}")

    for name in record.tags:
        if name not in _KNOWN_TAGS:
            record.errors.append(f"unknown tag '{name}' — receivers ignore it; check for a typo")

    _validate_values(record)
    return record


def _validate_values(record: DmarcRecord) -> None:
    if "p" not in record.tags:
        record.errors.append("required tag 'p' is missing")
    elif record.policy not in _VALID_POLICIES:
        record.errors.append(
            f"policy 'p={record.tags['p']}' is invalid (expected none, quarantine or reject)"
        )

    if "sp" in record.tags and record.tags["sp"].lower() not in _VALID_POLICIES:
        record.errors.append(f"subdomain policy 'sp={record.tags['sp']}' is invalid")
    if "np" in record.tags and record.tags["np"].lower() not in _VALID_POLICIES:
        record.errors.append(f"non-existent-subdomain policy 'np={record.tags['np']}' is invalid")

    for tag in ("adkim", "aspf"):
        if tag in record.tags and record.tags[tag].lower() not in _VALID_ALIGNMENT:
            record.errors.append(f"'{tag}={record.tags[tag]}' is invalid (expected 'r' or 's')")

    if "pct" in record.tags:
        try:
            pct = int(record.tags["pct"])
        except ValueError:
            record.errors.append(f"'pct={record.tags['pct']}' is not an integer")
        else:
            if not 0 <= pct <= 100:
                record.errors.append(f"'pct={pct}' must be between 0 and 100")

    if "ri" in record.tags:
        try:
            int(record.tags["ri"])
        except ValueError:
            record.errors.append(f"'ri={record.tags['ri']}' is not an integer")

    if "fo" in record.tags:
        options = {opt.strip().lower() for opt in record.tags["fo"].split(":") if opt.strip()}
        invalid = options - _VALID_FO
        if invalid:
            record.errors.append(f"'fo' contains invalid options: {', '.join(sorted(invalid))}")

    if "rf" in record.tags and record.tags["rf"].lower() not in _VALID_RF:
        record.errors.append(f"'rf={record.tags['rf']}' is invalid (expected 'afrf')")

    for tag in ("rua", "ruf"):
        for uri in _split_uris(record.tags.get(tag, "")):
            # Strip the optional "!size" suffix before validating the URI.
            parsed = urlparse(uri.split("!", 1)[0])
            if parsed.scheme != "mailto" or not parsed.path:
                record.errors.append(
                    f"'{tag}' entry {uri!r} is not a valid mailto: URI"
                )


def _fetch_dmarc(resolver: Resolver, domain: str) -> tuple[list[str], str | None]:
    try:
        txts = resolver.txt(f"_dmarc.{domain}")
    except NXDOMAIN:
        return [], None
    except (DnsError, ValueError) as exc:
        return [], str(exc)
    return [txt for txt in txts if txt.strip().lower().startswith("v=dmarc1")], None


def check_dmarc(
    resolver: Resolver,
    domain: str,
    psl: PublicSuffixList | None = None,
) -> CheckResult:
    """Audit the DMARC policy that applies to ``domain``."""

    result = CheckResult(name="dmarc")
    psl = psl or PublicSuffixList()
    org_domain = psl.organizational_domain(domain)

    records, error = _fetch_dmarc(resolver, domain)
    inherited_from: str | None = None

    if not records and not error and org_domain and org_domain != domain:
        # RFC 7489 §6.6.3: fall back to the organizational domain's policy,
        # where the `sp=` tag (if present) is what actually governs us.
        records, error = _fetch_dmarc(resolver, org_domain)
        if records:
            inherited_from = org_domain

    if error:
        result.add(
            Finding(
                code="DMARC_LOOKUP_FAILED",
                title="Could not read DMARC record",
                severity=Severity.CRITICAL,
                detail=error,
                remediation="Confirm _dmarc TXT records are served for the domain.",
                reference="RFC 7489 §6.6.3",
            )
        )
        return result

    if not records:
        result.add(
            Finding(
                code="DMARC_MISSING",
                title="No DMARC record published",
                severity=Severity.BLOCKER,
                detail=(
                    f"Neither _dmarc.{domain} nor the organizational domain "
                    f"(_dmarc.{org_domain}) publishes a DMARC record. Google requires bulk "
                    "senders to publish a DMARC policy and rejects mail from domains without "
                    "one."
                ),
                remediation=(
                    "Publish 'v=DMARC1; p=none; rua=mailto:dmarc-reports@your-domain.example' "
                    "to start collecting reports, then tighten to quarantine and reject."
                ),
                reference="Google sender guidelines; RFC 7489 §6.3",
            )
        )
        return result

    if len(records) > 1:
        result.add(
            Finding(
                code="DMARC_MULTIPLE",
                title="More than one DMARC record published",
                severity=Severity.BLOCKER,
                detail=(
                    f"{len(records)} DMARC records found. RFC 7489 requires receivers to ignore "
                    "the domain's policy entirely when this happens."
                ),
                remediation="Keep exactly one _dmarc TXT record.",
                reference="RFC 7489 §6.6.3",
            )
        )

    record = parse_dmarc_record(records[0], inherited_from or domain)
    record.inherited_from = inherited_from
    result.data["record"] = record.to_dict()
    result.data["organizational_domain"] = org_domain
    if not psl.authoritative:
        result.data["psl_note"] = (
            "organizational domain derived from the built-in suffix table; pass "
            "--public-suffix-list for authoritative results"
        )

    for message in record.errors:
        severity = Severity.WARNING if "unknown tag" in message else Severity.CRITICAL
        result.add(
            Finding(
                code="DMARC_RECORD_ERROR",
                title="DMARC record problem",
                severity=severity,
                detail=message,
                remediation="Correct the record syntax; invalid records are ignored wholesale.",
                reference="RFC 7489 §6.3",
            )
        )

    effective_policy = record.subdomain_policy if inherited_from else record.policy
    result.data["effective_policy"] = effective_policy

    if inherited_from:
        result.add(
            Finding(
                code="DMARC_INHERITED",
                title=f"DMARC policy inherited from {inherited_from}",
                severity=Severity.INFO,
                detail=(
                    f"{domain} has no record of its own, so the organizational domain's "
                    f"policy applies. The effective policy is '{effective_policy or 'unset'}' "
                    f"(from {'sp=' if 'sp' in record.tags else 'p='})."
                ),
                remediation=(
                    "Publish a dedicated _dmarc record on the sending subdomain when it needs "
                    "its own policy or reporting stream."
                ),
                reference="RFC 7489 §6.6.3",
            )
        )

    _grade_policy(effective_policy, record, result)

    if record.percentage < 100:
        result.add(
            Finding(
                code="DMARC_PARTIAL_PCT",
                title=f"DMARC applies to only {record.percentage}% of mail",
                severity=Severity.WARNING,
                detail=(
                    f"'pct={record.percentage}' means receivers apply the policy to a sample. "
                    "Spoofed mail passes through the remainder untouched."
                ),
                remediation="Raise to 'pct=100' once reports look clean.",
                reference="RFC 7489 §6.3",
            )
        )

    if not record.rua:
        result.add(
            Finding(
                code="DMARC_NO_RUA",
                title="DMARC record requests no aggregate reports",
                severity=Severity.WARNING,
                detail=(
                    "Without a 'rua' address you get no visibility into which sources are "
                    "failing authentication, which makes moving to p=reject guesswork."
                ),
                remediation="Add 'rua=mailto:dmarc-reports@your-domain.example'.",
                reference="RFC 7489 §7.1",
            )
        )

    _check_external_report_authorisation(resolver, record, result, psl)

    if record.dkim_alignment == "s" or record.spf_alignment == "s":
        strict = [
            name
            for name, mode in (("adkim", record.dkim_alignment), ("aspf", record.spf_alignment))
            if mode == "s"
        ]
        result.add(
            Finding(
                code="DMARC_STRICT_ALIGNMENT",
                title=f"Strict alignment enabled ({', '.join(strict)})",
                severity=Severity.INFO,
                detail=(
                    "Strict mode requires an exact domain match, so mail sent from subdomains "
                    "or via an ESP's own domain will fail DMARC."
                ),
                remediation="Verify every sending source signs with the exact From: domain.",
                reference="RFC 7489 §3.1",
            )
        )

    return result


def _grade_policy(policy: str, record: DmarcRecord, result: CheckResult) -> None:
    if policy == "reject":
        return
    if policy == "quarantine":
        result.add(
            Finding(
                code="DMARC_POLICY_QUARANTINE",
                title="DMARC policy is 'quarantine'",
                severity=Severity.WARNING,
                detail=(
                    "Quarantine is a good staging step, but spoofed mail still reaches the "
                    "spam folder rather than being rejected."
                ),
                remediation="Move to 'p=reject' once aggregate reports show all sources aligned.",
                reference="RFC 7489 §6.3",
            )
        )
        return
    if policy == "none":
        result.add(
            Finding(
                code="DMARC_POLICY_NONE",
                title="DMARC policy is 'p=none' (monitoring only)",
                severity=Severity.WARNING,
                detail=(
                    "'p=none' satisfies Google's minimum bar but instructs receivers to take no "
                    "action, so anyone can still spoof this domain. It is a starting point, "
                    "not a destination."
                ),
                remediation=(
                    "Use aggregate reports to enumerate your senders, then advance to "
                    "quarantine and finally reject."
                ),
                reference="Google sender guidelines; RFC 7489 §6.3",
            )
        )
        return

    result.add(
        Finding(
            code="DMARC_POLICY_INVALID",
            title="DMARC record has no usable policy",
            severity=Severity.BLOCKER,
            detail=(
                f"The effective policy resolved to {policy or '(none)'!r}, so the record cannot "
                "be applied and the domain counts as having no DMARC."
            ),
            remediation="Set a valid 'p=' tag.",
            reference="RFC 7489 §6.3",
        )
    )
    # Referenced for context in the report payload.
    result.data.setdefault("invalid_policy_raw", record.tags.get("p", ""))


def _check_external_report_authorisation(
    resolver: Resolver,
    record: DmarcRecord,
    result: CheckResult,
    psl: PublicSuffixList,
) -> None:
    """Verify external report destinations opt in (RFC 7489 §7.1)."""

    policy_domain = record.domain
    policy_org = psl.organizational_domain(policy_domain)
    for tag, uris in (("rua", record.rua), ("ruf", record.ruf)):
        for uri in uris:
            address = uri.split("!", 1)[0]
            _, _, mailbox_domain = address.partition("@")
            mailbox_domain = mailbox_domain.strip().rstrip(".").lower()
            if not mailbox_domain or psl.organizational_domain(mailbox_domain) == policy_org:
                continue
            authorisation = f"{policy_domain}._report._dmarc.{mailbox_domain}"
            try:
                txts = resolver.txt(authorisation)
            except (NXDOMAIN, DnsError, ValueError):
                txts = []
            if not any(txt.strip().lower().startswith("v=dmarc1") for txt in txts):
                result.add(
                    Finding(
                        code="DMARC_EXTERNAL_REPORT_UNAUTHORISED",
                        title=f"External {tag} destination is not authorised",
                        severity=Severity.WARNING,
                        detail=(
                            f"Reports are addressed to {address}, which is outside "
                            f"{policy_org}. Receivers will not send them unless "
                            f"{authorisation} publishes a 'v=DMARC1' record."
                        ),
                        remediation=(
                            f"Ask the report provider to publish the {authorisation} record."
                        ),
                        reference="RFC 7489 §7.1",
                    )
                )
