"""SPF policy audit (RFC 7208).

SPF is the check senders most often get *technically* right and *practically*
wrong: the record parses, but it blows the 10 DNS-lookup budget because of
nested ``include:`` chains, so every receiver evaluates it to ``permerror`` and
treats the mail as unauthenticated.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ..dnsresolver import NXDOMAIN, DnsError, Resolver
from ..models import CheckResult, Finding, Severity

__all__ = ["check_spf", "parse_spf_record", "SpfRecord", "SpfTerm", "MAX_DNS_LOOKUPS"]

#: RFC 7208 section 4.6.4 — the total number of DNS-querying terms allowed.
MAX_DNS_LOOKUPS = 10
#: RFC 7208 section 4.6.4 — lookups returning no records, capped at two.
MAX_VOID_LOOKUPS = 2
#: Guard against `include:` loops; RFC 7208 has no explicit depth cap.
MAX_RECURSION_DEPTH = 12

_SPF_PREFIX = re.compile(r"^v=spf1(\s|$)", re.IGNORECASE)
_QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
#: Mechanisms (plus the `redirect` modifier) that cost a DNS lookup.
_LOOKUP_MECHANISMS = {"include", "a", "mx", "ptr", "exists"}
_KNOWN_MODIFIERS = {"redirect", "exp"}
_TERM_RE = re.compile(r"^([+\-~?]?)([A-Za-z][A-Za-z0-9_.\-]*)(?:([:=/])(.*))?$", re.DOTALL)


@dataclass
class SpfTerm:
    """A single parsed SPF term."""

    raw: str
    kind: str  # "mechanism" | "modifier" | "unknown"
    name: str
    qualifier: str = "+"
    value: str = ""
    separator: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def costs_lookup(self) -> bool:
        if self.kind == "mechanism":
            return self.name in _LOOKUP_MECHANISMS
        return self.kind == "modifier" and self.name == "redirect"

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "name": self.name,
            "qualifier": self.qualifier,
            "value": self.value,
            "errors": list(self.errors),
        }


@dataclass
class SpfRecord:
    """A parsed ``v=spf1`` record."""

    raw: str
    terms: list[SpfTerm] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def all_term(self) -> SpfTerm | None:
        for term in self.terms:
            if term.kind == "mechanism" and term.name == "all":
                return term
        return None

    @property
    def redirect(self) -> str | None:
        for term in self.terms:
            if term.kind == "modifier" and term.name == "redirect":
                return term.value
        return None

    def to_dict(self) -> dict[str, object]:
        return {
            "raw": self.raw,
            "terms": [t.to_dict() for t in self.terms],
            "errors": list(self.errors),
        }


def parse_spf_record(raw: str) -> SpfRecord:
    """Parse an SPF record into terms, collecting syntax errors as it goes."""

    record = SpfRecord(raw=raw)
    tokens = raw.split()
    if not tokens or tokens[0].lower() != "v=spf1":
        record.errors.append("record must begin with the version token 'v=spf1'")
        return record

    seen_all = False
    seen_modifiers: set[str] = set()
    for token in tokens[1:]:
        term = _parse_term(token)
        if term.kind == "mechanism" and term.name == "all":
            if seen_all:
                term.errors.append("duplicate 'all' mechanism")
            seen_all = True
        elif seen_all:
            term.errors.append("term appears after 'all' and can never be evaluated")
        if term.kind == "modifier":
            if term.name in seen_modifiers:
                term.errors.append(f"modifier '{term.name}' may appear at most once")
            seen_modifiers.add(term.name)
        record.terms.append(term)

    if record.redirect and seen_all:
        record.errors.append(
            "'redirect=' is ignored when an 'all' mechanism is present (RFC 7208 6.1)"
        )
    return record


def _parse_term(token: str) -> SpfTerm:
    match = _TERM_RE.match(token)
    if not match:
        return SpfTerm(
            raw=token, kind="unknown", name=token, errors=[f"unparseable term {token!r}"]
        )

    qualifier, name, separator, value = match.groups()
    value = value or ""
    lowered = name.lower()

    if separator == "=" and not qualifier:
        term = SpfTerm(
            raw=token, kind="modifier", name=lowered, value=value, separator="="
        )
        if lowered not in _KNOWN_MODIFIERS:
            # Unknown modifiers must be ignored by evaluators, not treated as
            # errors (RFC 7208 6). Flag them so typos are still visible.
            term.errors.append(
                f"unknown modifier '{lowered}' — receivers ignore it; check for a typo"
            )
        elif not value:
            term.errors.append(f"modifier '{lowered}' requires a value")
        return term

    term = SpfTerm(
        raw=token,
        kind="mechanism",
        name=lowered,
        qualifier=qualifier or "+",
        value=value,
        separator=separator or "",
    )
    if lowered not in _MECHANISMS:
        term.kind = "unknown"
        term.errors.append(
            f"unknown mechanism '{name}' — this makes the whole record a permerror"
        )
        return term

    _validate_mechanism(term)
    return term


def _validate_mechanism(term: SpfTerm) -> None:
    name, value = term.name, term.value

    if name == "all" and value:
        term.errors.append("'all' does not take a value")
    elif name in {"ip4", "ip6"}:
        if not value:
            term.errors.append(f"'{name}' requires an address or CIDR block")
        else:
            _validate_ip(term, value, version=4 if name == "ip4" else 6)
    elif name == "include":
        if not value:
            term.errors.append("'include' requires a domain")
        elif term.separator != ":":
            term.errors.append("'include' must use ':' as its separator")
    elif name == "exists":
        if not value:
            term.errors.append("'exists' requires a domain")
    elif name == "ptr":
        term.errors.append(
            "'ptr' is deprecated: it is slow, unreliable, and receivers may ignore it"
        )


def _validate_ip(term: SpfTerm, value: str, version: int) -> None:
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
        else:
            network = ipaddress.ip_network(f"{value}/{32 if version == 4 else 128}", strict=False)
    except ValueError as exc:
        term.errors.append(f"invalid IPv{version} value {value!r}: {exc}")
        return
    if network.version != version:
        term.errors.append(
            f"'{term.name}' expects an IPv{version} address but got IPv{network.version}"
        )
        return
    # A /0 or near-/0 block authorises effectively the whole internet.
    too_broad = network.prefixlen <= (8 if version == 4 else 32)
    if too_broad and term.qualifier == "+":
        term.errors.append(
            f"{network} authorises {network.num_addresses:,} addresses to send as this domain"
        )


def _fetch_spf(resolver: Resolver, domain: str) -> tuple[list[str], str | None]:
    """Return ``(spf_records, error)`` for ``domain``."""

    try:
        txts = resolver.txt(domain)
    except NXDOMAIN:
        return [], f"domain {domain} does not exist in DNS"
    except (DnsError, ValueError) as exc:
        return [], str(exc)
    return [txt for txt in txts if _SPF_PREFIX.match(txt.strip())], None


def _count_lookups(
    resolver: Resolver,
    domain: str,
    result: CheckResult,
    depth: int = 0,
    visited: set[str] | None = None,
) -> tuple[int, int]:
    """Recursively total the DNS-querying terms reachable from ``domain``.

    Returns ``(lookups, void_lookups)``. Cycles and excessive depth stop the
    walk and are recorded as findings.
    """

    visited = visited if visited is not None else set()
    key = domain.strip().lower().rstrip(".")
    if key in visited:
        result.add(
            Finding(
                code="SPF_INCLUDE_LOOP",
                title="SPF include chain contains a loop",
                severity=Severity.CRITICAL,
                detail=f"'{key}' is reached more than once while expanding the record.",
                remediation="Break the cycle so evaluation terminates.",
                reference="RFC 7208 §11.2",
            )
        )
        return 0, 0
    if depth > MAX_RECURSION_DEPTH:
        return 0, 0
    visited.add(key)

    records, error = _fetch_spf(resolver, key)
    if error or len(records) != 1:
        # Nested failures are surfaced as void lookups rather than duplicate
        # findings; the top-level record already reports its own problems.
        return 0, 1 if depth > 0 else 0

    parsed = parse_spf_record(records[0])
    lookups = 0
    voids = 0
    for term in parsed.terms:
        if not term.costs_lookup:
            continue
        lookups += 1
        target = term.value.split("/", 1)[0] if term.name in {"a", "mx"} else term.value
        if term.name in {"include", "redirect"} and target and "%" not in target:
            child_lookups, child_voids = _count_lookups(
                resolver, target, result, depth + 1, visited
            )
            lookups += child_lookups
            voids += child_voids
    return lookups, voids


def check_spf(resolver: Resolver, domain: str, expand: bool = True) -> CheckResult:
    """Audit the SPF policy published for ``domain``."""

    result = CheckResult(name="spf")
    records, error = _fetch_spf(resolver, domain)

    if error:
        result.add(
            Finding(
                code="SPF_LOOKUP_FAILED",
                title="Could not read SPF record",
                severity=Severity.CRITICAL,
                detail=error,
                remediation="Confirm the domain resolves and its TXT records are served.",
                reference="RFC 7208 §3",
            )
        )
        result.data["error"] = error
        return result

    if not records:
        result.add(
            Finding(
                code="SPF_MISSING",
                title="No SPF record published",
                severity=Severity.BLOCKER,
                detail=(
                    f"{domain} publishes no 'v=spf1' TXT record, so no sending host can be "
                    "authorised by SPF. Google requires SPF or DKIM for all senders, and "
                    "both for bulk senders."
                ),
                remediation=(
                    "Publish a TXT record on the domain, e.g. "
                    "'v=spf1 include:_spf.your-esp.example -all'."
                ),
                reference="Google sender guidelines; RFC 7208 §3",
            )
        )
        result.data["records"] = []
        return result

    if len(records) > 1:
        result.add(
            Finding(
                code="SPF_MULTIPLE",
                title="More than one SPF record published",
                severity=Severity.BLOCKER,
                detail=(
                    f"{len(records)} 'v=spf1' records found. RFC 7208 requires evaluators to "
                    "return permerror, which means SPF fails for every message."
                ),
                remediation="Merge them into a single record with one 'all' mechanism.",
                reference="RFC 7208 §4.5",
            )
        )

    raw = records[0]
    parsed = parse_spf_record(raw)
    result.data["records"] = records
    result.data["parsed"] = parsed.to_dict()

    for message in parsed.errors:
        result.add(
            Finding(
                code="SPF_RECORD_ERROR",
                title="SPF record problem",
                severity=Severity.WARNING,
                detail=message,
                remediation="Correct the record syntax.",
                reference="RFC 7208 §6",
            )
        )

    for term in parsed.terms:
        for message in term.errors:
            severity = Severity.WARNING
            if term.kind == "unknown":
                severity = Severity.BLOCKER
            elif "authorises" in message:
                severity = Severity.CRITICAL
            result.add(
                Finding(
                    code="SPF_TERM_INVALID" if term.kind == "unknown" else "SPF_TERM_WARNING",
                    title=f"SPF term '{term.raw}'",
                    severity=severity,
                    detail=message,
                    remediation="Fix or remove the term.",
                    reference="RFC 7208 §5",
                )
            )

    _check_all_mechanism(parsed, result)

    if len(raw) > 450:
        result.add(
            Finding(
                code="SPF_RECORD_LONG",
                title="SPF record is very long",
                severity=Severity.INFO,
                detail=(
                    f"The record is {len(raw)} characters. Records over 255 characters must be "
                    "split into multiple character-strings, and some publishing UIs get this "
                    "wrong."
                ),
                remediation="Verify the published record is served as concatenated strings.",
                reference="RFC 7208 §3.3",
            )
        )

    if expand:
        lookups, voids = _count_lookups(resolver, domain, result)
        result.data["dns_lookups"] = lookups
        result.data["void_lookups"] = voids
        if lookups > MAX_DNS_LOOKUPS:
            result.add(
                Finding(
                    code="SPF_TOO_MANY_LOOKUPS",
                    title="SPF exceeds the 10 DNS-lookup limit",
                    severity=Severity.BLOCKER,
                    detail=(
                        f"Evaluating this record requires {lookups} DNS lookups; the limit is "
                        f"{MAX_DNS_LOOKUPS}. Receivers return permerror, so SPF fails even for "
                        "hosts you legitimately authorised."
                    ),
                    remediation=(
                        "Flatten or prune 'include:' chains, or move rarely used senders to a "
                        "dedicated subdomain."
                    ),
                    reference="RFC 7208 §4.6.4",
                )
            )
        elif lookups >= MAX_DNS_LOOKUPS - 1:
            result.add(
                Finding(
                    code="SPF_LOOKUPS_NEAR_LIMIT",
                    title="SPF is close to the DNS-lookup limit",
                    severity=Severity.WARNING,
                    detail=(
                        f"{lookups} of {MAX_DNS_LOOKUPS} lookups are used. Any provider that "
                        "adds an include to their own record will push you over."
                    ),
                    remediation="Reduce the chain now to leave headroom.",
                    reference="RFC 7208 §4.6.4",
                )
            )
        if voids > MAX_VOID_LOOKUPS:
            result.add(
                Finding(
                    code="SPF_VOID_LOOKUPS",
                    title="Too many SPF lookups return nothing",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"{voids} referenced names have no usable SPF record; more than "
                        f"{MAX_VOID_LOOKUPS} void lookups is a permerror."
                    ),
                    remediation="Remove includes that point at domains with no SPF record.",
                    reference="RFC 7208 §4.6.4",
                )
            )

    return result


def _check_all_mechanism(parsed: SpfRecord, result: CheckResult) -> None:
    all_term = parsed.all_term
    if all_term is None:
        if parsed.redirect:
            result.add(
                Finding(
                    code="SPF_REDIRECT_ONLY",
                    title="SPF policy is delegated via redirect=",
                    severity=Severity.INFO,
                    detail=f"Policy comes from '{parsed.redirect}'.",
                    remediation="Confirm the target record ends in '-all' or '~all'.",
                    reference="RFC 7208 §6.1",
                )
            )
            return
        result.add(
            Finding(
                code="SPF_NO_ALL",
                title="SPF record has no 'all' mechanism",
                severity=Severity.CRITICAL,
                detail=(
                    "Without a terminal 'all', evaluation returns neutral for every host that "
                    "is not explicitly listed — the same as having no policy."
                ),
                remediation="Append '-all' (or '~all' while you are still verifying senders).",
                reference="RFC 7208 §5.1",
            )
        )
        return

    qualifier = all_term.qualifier
    if qualifier == "+":
        result.add(
            Finding(
                code="SPF_ALL_PASS",
                title="SPF record ends in '+all'",
                severity=Severity.BLOCKER,
                detail=(
                    "'+all' authorises every host on the internet to send as this domain. It "
                    "is worse than publishing nothing, and receivers treat it as abuse."
                ),
                remediation="Replace '+all' with '-all' immediately.",
                reference="RFC 7208 §5.1",
            )
        )
    elif qualifier == "?":
        result.add(
            Finding(
                code="SPF_ALL_NEUTRAL",
                title="SPF record ends in '?all'",
                severity=Severity.CRITICAL,
                detail="'?all' is explicitly neutral and provides no protection.",
                remediation="Use '-all' once your legitimate senders are listed.",
                reference="RFC 7208 §5.1",
            )
        )
    elif qualifier == "~":
        result.add(
            Finding(
                code="SPF_ALL_SOFTFAIL",
                title="SPF record ends in '~all'",
                severity=Severity.INFO,
                detail=(
                    "'~all' (softfail) is a valid staging posture and satisfies Google's "
                    "requirement, but it asks receivers to accept unauthorised mail."
                ),
                remediation="Move to '-all' once DMARC reports show all sources aligned.",
                reference="RFC 7208 §5.1",
            )
        )
