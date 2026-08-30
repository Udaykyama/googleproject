"""Per-message audit: RFC 5322 hygiene, RFC 8058 unsubscribe, and alignment.

A domain can have flawless DNS and still be rejected, because Gmail's rules
also constrain the messages themselves: the ``From:`` header must be aligned
with the authenticated identity, bulk mail must carry a working one-click
unsubscribe, and the message must be RFC 5322 compliant.

This module works on a raw ``.eml`` file and needs no network access at all.
"""

from __future__ import annotations

import email
import email.policy
import re
from dataclasses import dataclass, field
from email.header import decode_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime

from ..domains import PublicSuffixList, check_alignment
from ..models import CheckResult, Finding, Severity

__all__ = [
    "parse_message",
    "check_message",
    "parse_dkim_signature",
    "parse_authentication_results",
    "ParsedMessage",
]

_MESSAGE_ID_RE = re.compile(r"^<[^<>@\s]+@[^<>@\s]+>$")
_ADDR_IN_DISPLAY_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
#: Headers RFC 6376 §5.4 and common practice expect a DKIM signature to cover.
_RECOMMENDED_SIGNED_HEADERS = ("from", "subject", "date", "to", "message-id")


@dataclass
class ParsedMessage:
    """A raw message plus the derived identities InboxReady reasons about."""

    message: Message
    raw_size: int
    from_addresses: list[tuple[str, str]] = field(default_factory=list)
    dkim_signatures: list[dict[str, str]] = field(default_factory=list)
    auth_results: list[dict[str, str]] = field(default_factory=list)

    @property
    def from_domain(self) -> str:
        for _, address in self.from_addresses:
            _, _, domain = address.partition("@")
            if domain:
                return domain.strip().rstrip(".").lower()
        return ""

    def header(self, name: str) -> str | None:
        value = self.message.get(name)
        return None if value is None else _decode_header_value(value)

    def headers(self, name: str) -> list[str]:
        return [_decode_header_value(v) for v in self.message.get_all(name, [])]


def _decode_header_value(value: object) -> str:
    """Decode RFC 2047 encoded-words and collapse folding whitespace."""

    text = str(value)
    try:
        parts = decode_header(text)
    except Exception:  # pragma: no cover - decode_header is very permissive
        return " ".join(text.split())
    decoded = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            decoded.append(chunk.decode(charset or "utf-8", "replace"))
        else:
            decoded.append(chunk)
    return " ".join("".join(decoded).split())


def parse_message(raw: bytes) -> ParsedMessage:
    """Parse a raw RFC 5322 message.

    ``compat32`` is used deliberately: the modern policy raises on defective
    headers, and defective headers are exactly what this tool needs to report
    on rather than crash over.
    """

    message = email.message_from_bytes(raw, policy=email.policy.compat32)
    parsed = ParsedMessage(message=message, raw_size=len(raw))
    parsed.from_addresses = [
        (_decode_header_value(name), address.strip().lower())
        for name, address in getaddresses(
            [_decode_header_value(v) for v in message.get_all("From", [])]
        )
    ]
    parsed.dkim_signatures = [
        parse_dkim_signature(value) for value in message.get_all("DKIM-Signature", [])
    ]
    parsed.auth_results = [
        parse_authentication_results(value)
        for value in message.get_all("Authentication-Results", [])
    ]
    return parsed


def parse_dkim_signature(header_value: str) -> dict[str, str]:
    """Parse a ``DKIM-Signature`` header into its tag-value pairs."""

    tags: dict[str, str] = {}
    for chunk in str(header_value).split(";"):
        name, sep, value = chunk.partition("=")
        if not sep:
            continue
        name = name.strip().lower()
        if name:
            tags[name] = re.sub(r"\s+", "", value) if name in {"b", "bh"} else value.strip()
    return tags


def parse_authentication_results(header_value: str) -> dict[str, str]:
    """Extract ``method=result`` pairs from an RFC 8601 header."""

    results: dict[str, str] = {}
    text = str(header_value)
    for method, outcome in re.findall(
        r"\b(spf|dkim|dmarc|arc|iprev|bimi)\s*=\s*([A-Za-z]+)", text, re.IGNORECASE
    ):
        # Keep the first occurrence; receivers list the authoritative result
        # before any per-signature detail.
        results.setdefault(method.lower(), outcome.lower())
    return results


def check_message(
    raw: bytes,
    bulk: bool = True,
    psl: PublicSuffixList | None = None,
    expected_domain: str | None = None,
) -> CheckResult:
    """Audit a single raw message.

    ``bulk`` marks the message as bulk/marketing mail, which is what triggers
    Google's one-click unsubscribe requirement.
    """

    result = CheckResult(name="message")
    psl = psl or PublicSuffixList()

    try:
        parsed = parse_message(raw)
    except Exception as exc:  # pragma: no cover - defensive
        result.add(
            Finding(
                code="MSG_UNPARSEABLE",
                title="Message could not be parsed",
                severity=Severity.BLOCKER,
                detail=str(exc),
                remediation="Export the message as a raw RFC 5322 .eml file.",
                reference="RFC 5322",
            )
        )
        return result

    result.data["from_domain"] = parsed.from_domain
    result.data["size_bytes"] = parsed.raw_size
    result.data["bulk"] = bulk

    _check_required_headers(parsed, result)
    _check_from_header(parsed, result, expected_domain, psl)
    _check_unsubscribe(parsed, result, bulk)
    _check_dkim_signatures(parsed, result, psl)
    _check_authentication_results(parsed, result)
    _check_arc(parsed, result)
    _check_body(parsed, result)
    return result


def _check_required_headers(parsed: ParsedMessage, result: CheckResult) -> None:
    message = parsed.message

    for header in ("From", "Date"):
        values = message.get_all(header, [])
        if not values:
            result.add(
                Finding(
                    code=f"MSG_NO_{header.upper()}",
                    title=f"Missing required '{header}:' header",
                    severity=Severity.BLOCKER,
                    detail=f"RFC 5322 requires exactly one '{header}:' header on every message.",
                    remediation=f"Emit a '{header}:' header.",
                    reference="RFC 5322 §3.6",
                )
            )
        elif len(values) > 1:
            result.add(
                Finding(
                    code=f"MSG_DUPLICATE_{header.upper()}",
                    title=f"Duplicate '{header}:' header",
                    severity=Severity.BLOCKER,
                    detail=(
                        f"{len(values)} '{header}:' headers are present. Receivers and clients "
                        "may disagree on which one applies, which is a classic spoofing vector."
                    ),
                    remediation=f"Emit exactly one '{header}:' header.",
                    reference="RFC 5322 §3.6",
                )
            )

    date_value = parsed.header("Date")
    if date_value:
        try:
            parsedate_to_datetime(date_value)
        except (TypeError, ValueError):
            result.add(
                Finding(
                    code="MSG_DATE_INVALID",
                    title="'Date:' header is not a valid RFC 5322 date",
                    severity=Severity.CRITICAL,
                    detail=f"Could not parse {date_value!r}.",
                    remediation="Emit a date such as 'Tue, 3 Jun 2025 09:15:00 +0000'.",
                    reference="RFC 5322 §3.3",
                )
            )

    message_id = parsed.header("Message-ID")
    if not message_id:
        result.add(
            Finding(
                code="MSG_NO_MESSAGE_ID",
                title="Missing 'Message-ID:' header",
                severity=Severity.CRITICAL,
                detail=(
                    "Gmail requires RFC 5322 compliance, and messages without a Message-ID are "
                    "hard to thread, deduplicate, or trace in postmaster reports."
                ),
                remediation="Generate a globally unique '<random@your-domain.example>' value.",
                reference="RFC 5322 §3.6.4",
            )
        )
    elif not _MESSAGE_ID_RE.match(message_id.strip()):
        result.add(
            Finding(
                code="MSG_MESSAGE_ID_MALFORMED",
                title="'Message-ID:' is malformed",
                severity=Severity.WARNING,
                detail=f"{message_id!r} is not of the form '<local@domain>'.",
                remediation="Emit the value inside angle brackets with a single '@'.",
                reference="RFC 5322 §3.6.4",
            )
        )

    if not message.get_all("To") and not message.get_all("Cc") and not message.get_all("Bcc"):
        result.add(
            Finding(
                code="MSG_NO_RECIPIENT_HEADER",
                title="No 'To:', 'Cc:' or 'Bcc:' header",
                severity=Severity.WARNING,
                detail=(
                    "Messages with no destination header look like bulk blasts and are a "
                    "long-standing spam signal."
                ),
                remediation="Include the recipient in a 'To:' header.",
                reference="RFC 5322 §3.6.3",
            )
        )

    if not parsed.header("Subject"):
        result.add(
            Finding(
                code="MSG_NO_SUBJECT",
                title="Missing 'Subject:' header",
                severity=Severity.WARNING,
                detail="Subject-less bulk mail is heavily penalised by spam filters.",
                remediation="Add a descriptive, non-deceptive subject.",
                reference="Google sender guidelines",
            )
        )

    defects = getattr(message, "defects", [])
    if defects:
        result.data["parse_defects"] = [type(d).__name__ for d in defects]
        result.add(
            Finding(
                code="MSG_RFC5322_DEFECTS",
                title="Message has RFC 5322 parse defects",
                severity=Severity.CRITICAL,
                detail=(
                    "The parser reported: "
                    + ", ".join(sorted({type(d).__name__ for d in defects}))
                    + ". Google requires messages to be formatted per RFC 5322."
                ),
                remediation="Fix the message generator so headers and MIME structure are valid.",
                reference="RFC 5322; Google sender guidelines",
            )
        )


def _check_from_header(
    parsed: ParsedMessage,
    result: CheckResult,
    expected_domain: str | None,
    psl: PublicSuffixList,
) -> None:
    if len(parsed.from_addresses) > 1 and not parsed.message.get("Sender"):
        result.add(
            Finding(
                code="MSG_MULTIPLE_FROM_NO_SENDER",
                title="Multiple 'From:' addresses without a 'Sender:' header",
                severity=Severity.CRITICAL,
                detail=(
                    "RFC 5322 requires a 'Sender:' header when 'From:' lists more than one "
                    "mailbox, and DMARC cannot evaluate a multi-valued From."
                ),
                remediation="Send from a single mailbox, or add a 'Sender:' header.",
                reference="RFC 5322 §3.6.2; RFC 7489 §6.6.1",
            )
        )

    from_domain = parsed.from_domain
    if not from_domain:
        return

    if psl.organizational_domain(from_domain) in {"gmail.com", "googlemail.com"}:
        result.add(
            Finding(
                code="MSG_IMPERSONATES_GMAIL",
                title="'From:' header uses a Gmail domain",
                severity=Severity.BLOCKER,
                detail=(
                    "Google explicitly prohibits bulk senders from putting gmail.com in the "
                    "'From:' header, and enforces a DMARC quarantine policy against it."
                ),
                remediation="Send from a domain you control and authenticate.",
                reference="Google sender guidelines",
            )
        )

    if expected_domain:
        alignment = check_alignment(from_domain, expected_domain, "r", psl)
        result.data["expected_domain_alignment"] = alignment.to_dict()
        if not alignment.aligned:
            result.add(
                Finding(
                    code="MSG_FROM_UNEXPECTED_DOMAIN",
                    title="'From:' domain does not match the audited domain",
                    severity=Severity.WARNING,
                    detail=(
                        f"The message is from '{from_domain}' but the audit targeted "
                        f"'{expected_domain}' ({alignment.reason}). The DNS findings in this "
                        "report may not apply to this message."
                    ),
                    remediation="Audit the domain the message is actually sent from.",
                    reference="RFC 7489 §3.1",
                )
            )

    for display_name, address in parsed.from_addresses:
        embedded = _ADDR_IN_DISPLAY_RE.findall(display_name)
        mismatched = [
            found
            for found in embedded
            if found.strip().lower() != address
            and not check_alignment(
                found.rpartition("@")[2], address.rpartition("@")[2], "r", psl
            ).aligned
        ]
        if mismatched:
            result.add(
                Finding(
                    code="MSG_DECEPTIVE_DISPLAY_NAME",
                    title="'From:' display name contains a different email address",
                    severity=Severity.CRITICAL,
                    detail=(
                        f"The display name advertises {', '.join(mismatched)} while the message "
                        f"is actually from {address}. This is the standard display-name "
                        "spoofing pattern used in business email compromise."
                    ),
                    remediation="Use a plain display name that does not embed an address.",
                    reference="Google sender guidelines",
                )
            )

    reply_to = getaddresses(parsed.headers("Reply-To"))
    for _, address in reply_to:
        domain = address.rpartition("@")[2].lower()
        if domain and not check_alignment(from_domain, domain, "r", psl).aligned:
            result.add(
                Finding(
                    code="MSG_REPLYTO_OFF_DOMAIN",
                    title="'Reply-To:' points to an unrelated domain",
                    severity=Severity.INFO,
                    detail=(
                        f"Replies go to '{domain}' rather than '{from_domain}'. This is "
                        "legitimate for helpdesk routing but is also a BEC hallmark, so filters "
                        "weigh it."
                    ),
                    remediation="Reply-To a subdomain of the From domain where possible.",
                    reference="RFC 5322 §3.6.2",
                )
            )
            break


def _check_unsubscribe(parsed: ParsedMessage, result: CheckResult, bulk: bool) -> None:
    header = parsed.header("List-Unsubscribe")
    post = parsed.header("List-Unsubscribe-Post")
    result.data["list_unsubscribe"] = header
    result.data["list_unsubscribe_post"] = post

    if not bulk:
        if header:
            result.add(
                Finding(
                    code="MSG_UNSUBSCRIBE_ON_TRANSACTIONAL",
                    title="Transactional message carries 'List-Unsubscribe'",
                    severity=Severity.INFO,
                    detail=(
                        "Harmless, but recipients who unsubscribe may then miss receipts or "
                        "security notices."
                    ),
                    remediation="Keep transactional and marketing streams separate.",
                    reference="RFC 8058 §1",
                )
            )
        return

    if not header:
        result.add(
            Finding(
                code="MSG_NO_LIST_UNSUBSCRIBE",
                title="Bulk message has no 'List-Unsubscribe:' header",
                severity=Severity.BLOCKER,
                detail=(
                    "Google requires one-click unsubscribe on all marketing and subscribed "
                    "mail. Messages without it are rejected."
                ),
                remediation=(
                    "Add 'List-Unsubscribe: <https://example.com/u/TOKEN>, "
                    "<mailto:unsubscribe@example.com>'."
                ),
                reference="Google sender guidelines; RFC 8058 §3",
            )
        )
        return

    uris = re.findall(r"<([^>]+)>", header)
    result.data["unsubscribe_uris"] = uris
    https_uris = [uri for uri in uris if uri.strip().lower().startswith("https://")]
    http_uris = [uri for uri in uris if uri.strip().lower().startswith("http://")]
    mailto_uris = [uri for uri in uris if uri.strip().lower().startswith("mailto:")]

    if not uris:
        result.add(
            Finding(
                code="MSG_UNSUBSCRIBE_MALFORMED",
                title="'List-Unsubscribe:' contains no angle-bracketed URI",
                severity=Severity.BLOCKER,
                detail=f"Got {header!r}; RFC 2369 requires each URI to be wrapped in '<...>'.",
                remediation="Wrap every URI in angle brackets, comma separated.",
                reference="RFC 2369 §2",
            )
        )
        return

    if http_uris and not https_uris:
        result.add(
            Finding(
                code="MSG_UNSUBSCRIBE_NOT_HTTPS",
                title="Unsubscribe URL uses plain HTTP",
                severity=Severity.CRITICAL,
                detail=(
                    "RFC 8058 one-click unsubscribe POSTs over HTTPS only. An http:// URL is "
                    "not actioned and leaks the recipient token in clear text."
                ),
                remediation="Serve the unsubscribe endpoint over HTTPS.",
                reference="RFC 8058 §3.1",
            )
        )

    if not https_uris and not http_uris and mailto_uris:
        result.add(
            Finding(
                code="MSG_UNSUBSCRIBE_MAILTO_ONLY",
                title="Unsubscribe offers only a mailto: address",
                severity=Severity.BLOCKER,
                detail=(
                    "One-click unsubscribe requires an HTTPS URI. A mailto:-only header does "
                    "not satisfy Google's requirement."
                ),
                remediation="Add an '<https://...>' URI alongside the mailto:.",
                reference="Google sender guidelines; RFC 8058 §3.1",
            )
        )
    elif not https_uris and not http_uris:
        result.add(
            Finding(
                code="MSG_UNSUBSCRIBE_NO_WEB_URI",
                title="Unsubscribe offers no HTTPS URI",
                severity=Severity.BLOCKER,
                detail=(
                    f"None of {uris} is an http(s) or mailto: URI, so there is nothing Gmail "
                    "can POST a one-click unsubscribe to."
                ),
                remediation="Add an '<https://...>' URI to the header.",
                reference="Google sender guidelines; RFC 8058 §3.1",
            )
        )
    elif https_uris and not mailto_uris:
        result.add(
            Finding(
                code="MSG_UNSUBSCRIBE_NO_MAILTO",
                title="Unsubscribe offers no mailto: fallback",
                severity=Severity.INFO,
                detail="A mailto: alternative keeps older clients working.",
                remediation="Add '<mailto:unsubscribe@your-domain.example>' as a second URI.",
                reference="RFC 2369 §3.2",
            )
        )

    normalized_post = re.sub(r"\s+", "", post or "").lower()
    if normalized_post != "list-unsubscribe=one-click":
        result.add(
            Finding(
                code="MSG_NO_ONE_CLICK_POST",
                title="Missing 'List-Unsubscribe-Post: List-Unsubscribe=One-Click'",
                severity=Severity.BLOCKER if not post else Severity.CRITICAL,
                detail=(
                    "Without this header the HTTPS URI is treated as an ordinary link, so the "
                    "message does not meet Google's one-click unsubscribe requirement. Found: "
                    + (repr(post) if post else "header not present")
                    + "."
                ),
                remediation=(
                    "Emit 'List-Unsubscribe-Post: List-Unsubscribe=One-Click' and accept the "
                    "resulting POST without requiring further interaction."
                ),
                reference="RFC 8058 §3.1",
            )
        )


def _check_dkim_signatures(
    parsed: ParsedMessage, result: CheckResult, psl: PublicSuffixList
) -> None:
    signatures = parsed.dkim_signatures
    result.data["dkim_signatures"] = [
        {k: v for k, v in sig.items() if k not in {"b", "bh"}} for sig in signatures
    ]

    if not signatures:
        result.add(
            Finding(
                code="MSG_NOT_DKIM_SIGNED",
                title="Message carries no DKIM signature",
                severity=Severity.BLOCKER,
                detail=(
                    "An unsigned message cannot pass DMARC via DKIM, so it depends entirely on "
                    "SPF — which breaks the moment the message is forwarded."
                ),
                remediation="Enable DKIM signing on the sending platform.",
                reference="Google sender guidelines; RFC 6376",
            )
        )
        return

    from_domain = parsed.from_domain
    aligned_any = False
    for sig in signatures:
        signing_domain = sig.get("d", "").strip().rstrip(".").lower()
        if not signing_domain:
            result.add(
                Finding(
                    code="MSG_DKIM_NO_D_TAG",
                    title="DKIM signature has no 'd=' tag",
                    severity=Severity.CRITICAL,
                    detail="The signature declares no signing domain and cannot be verified.",
                    remediation="Regenerate the signature with a 'd=' tag.",
                    reference="RFC 6376 §3.5",
                )
            )
            continue

        if from_domain:
            alignment = check_alignment(from_domain, signing_domain, "r", psl)
            aligned_any = aligned_any or alignment.aligned
            result.data.setdefault("dkim_alignment", []).append(alignment.to_dict())

        algorithm = sig.get("a", "").lower()
        if algorithm.endswith("sha1"):
            result.add(
                Finding(
                    code="MSG_DKIM_SHA1",
                    title=f"DKIM signature from '{signing_domain}' uses SHA-1",
                    severity=Severity.CRITICAL,
                    detail="RFC 8301 forbids rsa-sha1; receivers treat such signatures as invalid.",
                    remediation="Sign with 'a=rsa-sha256'.",
                    reference="RFC 8301 §3.1",
                )
            )

        if "l" in sig:
            result.add(
                Finding(
                    code="MSG_DKIM_LENGTH_TAG",
                    title=f"DKIM signature from '{signing_domain}' uses the 'l=' body-length tag",
                    severity=Severity.CRITICAL,
                    detail=(
                        "'l=' leaves everything past the signed prefix unprotected, letting an "
                        "attacker append arbitrary content to a message that still verifies."
                    ),
                    remediation="Remove 'l=' so the whole body is signed.",
                    reference="RFC 6376 §8.2",
                )
            )

        signed = {h.strip().lower() for h in sig.get("h", "").split(":") if h.strip()}
        if signed and "from" not in signed:
            result.add(
                Finding(
                    code="MSG_DKIM_FROM_UNSIGNED",
                    title=f"DKIM signature from '{signing_domain}' does not sign 'From:'",
                    severity=Severity.BLOCKER,
                    detail=(
                        "RFC 6376 requires the From header to be signed. Without it the "
                        "signature is invalid and DMARC cannot use it."
                    ),
                    remediation="Include 'from' in the 'h=' tag.",
                    reference="RFC 6376 §5.4",
                )
            )
        missing = [h for h in _RECOMMENDED_SIGNED_HEADERS if signed and h not in signed]
        if missing and "from" in signed:
            result.add(
                Finding(
                    code="MSG_DKIM_HEADERS_UNSIGNED",
                    title=f"DKIM signature from '{signing_domain}' leaves headers unsigned",
                    severity=Severity.WARNING,
                    detail=(
                        f"Unsigned: {', '.join(missing)}. An attacker replaying the message can "
                        "change these without breaking the signature."
                    ),
                    remediation="Add them to the 'h=' tag.",
                    reference="RFC 6376 §5.4",
                )
            )

    if from_domain and signatures and not aligned_any:
        signing = ", ".join(sorted({s.get("d", "?") for s in signatures}))
        result.add(
            Finding(
                code="MSG_DKIM_NOT_ALIGNED",
                title="No DKIM signature is aligned with the 'From:' domain",
                severity=Severity.BLOCKER,
                detail=(
                    f"The message is signed by {signing} but sent as '{from_domain}'. DMARC "
                    "requires the signing domain to align with From, so DKIM contributes "
                    "nothing here — a common symptom of ESP default signing."
                ),
                remediation=(
                    "Configure the sending platform to sign with a selector on your own domain "
                    "(often called custom or branded DKIM)."
                ),
                reference="RFC 7489 §3.1.1",
            )
        )


def _check_authentication_results(parsed: ParsedMessage, result: CheckResult) -> None:
    if not parsed.auth_results:
        return
    merged: dict[str, str] = {}
    for entry in parsed.auth_results:
        for method, outcome in entry.items():
            merged.setdefault(method, outcome)
    result.data["authentication_results"] = merged

    severities = {
        "fail": Severity.BLOCKER,
        "permerror": Severity.CRITICAL,
        "temperror": Severity.WARNING,
        "softfail": Severity.CRITICAL,
        "policy": Severity.CRITICAL,
        "neutral": Severity.WARNING,
        "none": Severity.WARNING,
    }
    for method in ("spf", "dkim", "dmarc"):
        outcome = merged.get(method)
        if outcome is None or outcome == "pass":
            continue
        result.add(
            Finding(
                code=f"MSG_AUTH_{method.upper()}_{outcome.upper()}",
                title=f"Receiver recorded {method.upper()}={outcome}",
                severity=severities.get(outcome, Severity.WARNING),
                detail=(
                    f"The 'Authentication-Results' header added by the receiving system reports "
                    f"{method}={outcome}. This is the verdict that actually decided delivery."
                ),
                remediation=f"Resolve the underlying {method.upper()} configuration.",
                reference="RFC 8601 §2.7",
            )
        )


def _check_arc(parsed: ParsedMessage, result: CheckResult) -> None:
    seals = parsed.message.get_all("ARC-Seal", [])
    signatures = parsed.message.get_all("ARC-Message-Signature", [])
    auth = parsed.message.get_all("ARC-Authentication-Results", [])
    present = bool(seals or signatures or auth)
    result.data["arc_present"] = present
    if not present:
        return

    result.data["arc_set_count"] = max(len(seals), len(signatures), len(auth))
    if not (len(seals) == len(signatures) == len(auth)):
        result.add(
            Finding(
                code="MSG_ARC_INCOMPLETE",
                title="ARC chain is incomplete",
                severity=Severity.WARNING,
                detail=(
                    f"Found {len(seals)} ARC-Seal, {len(signatures)} ARC-Message-Signature and "
                    f"{len(auth)} ARC-Authentication-Results headers. Each hop must add all "
                    "three or the chain fails validation."
                ),
                remediation="Fix the forwarding MTA's ARC implementation.",
                reference="RFC 8617 §5",
            )
        )
    else:
        result.add(
            Finding(
                code="MSG_ARC_PRESENT",
                title=f"Message carries an ARC chain ({len(seals)} hop(s))",
                severity=Severity.INFO,
                detail=(
                    "The message was relayed. ARC lets the final receiver honour the "
                    "authentication result from before the forward."
                ),
                remediation="No action needed; verify the chain validates at the destination.",
                reference="RFC 8617",
            )
        )


def _check_body(parsed: ParsedMessage, result: CheckResult) -> None:
    message = parsed.message
    content_type = (message.get_content_type() or "").lower()
    result.data["content_type"] = content_type

    if message.is_multipart():
        subtypes = {
            part.get_content_type().lower()
            for part in message.walk()
            if not part.is_multipart()
        }
        result.data["mime_parts"] = sorted(subtypes)
        if "text/html" in subtypes and "text/plain" not in subtypes:
            result.add(
                Finding(
                    code="MSG_HTML_ONLY",
                    title="Message is HTML-only",
                    severity=Severity.WARNING,
                    detail=(
                        "HTML without a text/plain alternative is a long-standing spam signal "
                        "and degrades accessibility."
                    ),
                    remediation="Send multipart/alternative with a plain-text part.",
                    reference="RFC 2046 §5.1.4",
                )
            )
    elif content_type == "text/html":
        result.add(
            Finding(
                code="MSG_HTML_ONLY",
                title="Message is HTML-only",
                severity=Severity.WARNING,
                detail="A single text/html body with no plain-text alternative.",
                remediation="Send multipart/alternative with a plain-text part.",
                reference="RFC 2046 §5.1.4",
            )
        )

    if not message.get("MIME-Version") and message.is_multipart():
        result.add(
            Finding(
                code="MSG_NO_MIME_VERSION",
                title="Multipart message has no 'MIME-Version:' header",
                severity=Severity.WARNING,
                detail="Clients may render the raw MIME boundaries instead of the content.",
                remediation="Add 'MIME-Version: 1.0'.",
                reference="RFC 2045 §4",
            )
        )
