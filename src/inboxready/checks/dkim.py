"""DKIM key audit (RFC 6376, RFC 8463).

Checks the public key records published at ``<selector>._domainkey.<domain>``.
The most consequential findings here are silent ones: a record with an empty
``p=`` tag (a revoked key) or a 512/768-bit RSA key still validates as
"present", but signatures either fail outright or are treated as untrusted.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from ..dnsresolver import NXDOMAIN, DnsError, Resolver
from ..models import CheckResult, Finding, Severity

__all__ = ["check_dkim", "parse_dkim_record", "DkimKey", "rsa_key_bits"]

#: Selectors worth probing when the caller does not name one. These cover the
#: default selectors of the largest ESPs, which is where bulk mail comes from.
COMMON_SELECTORS: tuple[str, ...] = (
    "google", "default", "selector1", "selector2", "s1", "s2", "k1", "k2",
    "mail", "dkim", "smtp", "mandrill", "sendgrid", "mailjet", "zoho",
    "pm", "pic", "amazonses", "sig1", "mte1", "ctct1",
)

_MIN_RSA_BITS_HARD = 1024
_RECOMMENDED_RSA_BITS = 2048


@dataclass
class DkimKey:
    """A parsed DKIM public-key record."""

    selector: str
    domain: str
    raw: str
    tags: dict[str, str] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def key_type(self) -> str:
        return self.tags.get("k", "rsa").lower()

    @property
    def public_key(self) -> str:
        return self.tags.get("p", "")

    @property
    def revoked(self) -> bool:
        """An empty ``p=`` tag means the key has been revoked (RFC 6376 3.6.1)."""

        return "p" in self.tags and not self.tags["p"].strip()

    @property
    def testing(self) -> bool:
        flags = self.tags.get("t", "")
        return "y" in {flag.strip().lower() for flag in flags.split(":")}

    @property
    def fqdn(self) -> str:
        return f"{self.selector}._domainkey.{self.domain}"

    def to_dict(self) -> dict[str, object]:
        return {
            "selector": self.selector,
            "domain": self.domain,
            "fqdn": self.fqdn,
            "raw": self.raw,
            "tags": {k: (v if k != "p" else f"<{len(v)} base64 chars>") for k, v in self.tags.items()},
            "key_type": self.key_type,
            "revoked": self.revoked,
            "testing": self.testing,
            "errors": list(self.errors),
        }


def parse_dkim_record(selector: str, domain: str, raw: str) -> DkimKey:
    """Parse a ``v=DKIM1; ...`` tag-value list."""

    key = DkimKey(selector=selector, domain=domain, raw=raw)
    for chunk in raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, value = chunk.partition("=")
        if not sep:
            key.errors.append(f"malformed tag {chunk!r} (expected name=value)")
            continue
        name = name.strip()
        # Whitespace inside base64 is legal and must be stripped before decode.
        key.tags[name] = re.sub(r"\s+", "", value) if name == "p" else value.strip()

    version = key.tags.get("v")
    if version is None:
        # RFC 6376 allows v= to be omitted, defaulting to DKIM1, but every
        # major publisher includes it; its absence usually means a broken record.
        key.errors.append("no 'v=DKIM1' tag; the record may be truncated")
    elif version.upper() != "DKIM1":
        key.errors.append(f"unexpected version {version!r} (expected DKIM1)")

    if "p" not in key.tags:
        key.errors.append("no 'p=' tag, so the record carries no public key")
    return key


def _read_der(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV. Returns ``(tag, value, next_offset)``."""

    if offset + 2 > len(data):
        raise ValueError("truncated DER element")
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        num_bytes = length & 0x7F
        if num_bytes == 0 or num_bytes > 4 or cursor + num_bytes > len(data):
            raise ValueError("unsupported or truncated DER length")
        length = int.from_bytes(data[cursor : cursor + num_bytes], "big")
        cursor += num_bytes
    if cursor + length > len(data):
        raise ValueError("DER element runs past end of buffer")
    return tag, data[cursor : cursor + length], cursor + length


def rsa_key_bits(public_key_b64: str) -> int | None:
    """Return the RSA modulus size in bits, or ``None`` if it cannot be read.

    Accepts either a DER ``SubjectPublicKeyInfo`` (what RFC 6376 specifies) or
    a bare PKCS#1 ``RSAPublicKey``, since both appear in the wild.
    """

    try:
        der = base64.b64decode(re.sub(r"\s+", "", public_key_b64), validate=True)
    except (ValueError, TypeError):
        return None
    if not der:
        return None

    try:
        tag, outer, _ = _read_der(der, 0)
        if tag != 0x30:  # SEQUENCE
            return None
        tag, first, next_offset = _read_der(outer, 0)
        if tag == 0x02:
            # Bare PKCS#1 RSAPublicKey: SEQUENCE { INTEGER n, INTEGER e }
            modulus = first
        else:
            # SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
            tag, bitstring, _ = _read_der(outer, next_offset)
            if tag != 0x03 or not bitstring:
                return None
            # Skip the "unused bits" octet that prefixes a BIT STRING body.
            tag, inner, _ = _read_der(bitstring[1:], 0)
            if tag != 0x30:
                return None
            tag, modulus, _ = _read_der(inner, 0)
            if tag != 0x02:
                return None
    except ValueError:
        return None

    trimmed = modulus.lstrip(b"\x00")
    if not trimmed:
        return None
    return (len(trimmed) - 1) * 8 + trimmed[0].bit_length()


def _fetch_key(resolver: Resolver, selector: str, domain: str) -> tuple[str | None, str | None]:
    fqdn = f"{selector}._domainkey.{domain}"
    try:
        txts = resolver.txt(fqdn)
    except NXDOMAIN:
        return None, None
    except (DnsError, ValueError) as exc:
        return None, str(exc)
    for txt in txts:
        if "p=" in txt or txt.strip().lower().startswith("v=dkim1"):
            return txt, None
    return None, None


def check_dkim(
    resolver: Resolver,
    domain: str,
    selectors: list[str] | None = None,
    probe_common: bool = True,
) -> CheckResult:
    """Audit DKIM keys for ``domain``.

    ``selectors`` are checked explicitly. When none are given and
    ``probe_common`` is set, a list of well-known ESP selectors is probed —
    DKIM offers no way to enumerate selectors from DNS, so discovery is
    necessarily a guess and is reported as such.
    """

    result = CheckResult(name="dkim")
    explicit = [s.strip() for s in (selectors or []) if s.strip()]
    candidates = explicit or (list(COMMON_SELECTORS) if probe_common else [])
    result.data["selectors_checked"] = candidates
    result.data["discovery_mode"] = "explicit" if explicit else "probed"

    if not candidates:
        result.skipped_reason = "no selectors supplied and probing disabled"
        return result

    found: list[DkimKey] = []
    errors: list[str] = []
    for selector in candidates:
        raw, error = _fetch_key(resolver, selector, domain)
        if error:
            errors.append(f"{selector}: {error}")
            continue
        if raw is None:
            if explicit:
                result.add(
                    Finding(
                        code="DKIM_SELECTOR_MISSING",
                        title=f"No DKIM key at selector '{selector}'",
                        severity=Severity.CRITICAL,
                        detail=f"{selector}._domainkey.{domain} returned no DKIM record.",
                        remediation=(
                            "Publish the key your sending platform generated, or correct the "
                            "selector name."
                        ),
                        reference="RFC 6376 §3.6.2",
                    )
                )
            continue
        found.append(parse_dkim_record(selector, domain, raw))

    result.data["keys"] = [key.to_dict() for key in found]
    if errors:
        result.data["errors"] = errors

    if not found:
        detail = (
            f"No DKIM key was found for {domain}."
            if explicit
            else (
                f"Probed {len(candidates)} well-known selectors and found none. DKIM selectors "
                "cannot be enumerated from DNS, so this is suggestive, not conclusive — rerun "
                "with --selector if you know yours."
            )
        )
        result.add(
            Finding(
                code="DKIM_MISSING",
                title="No DKIM key found",
                severity=Severity.BLOCKER if explicit else Severity.WARNING,
                detail=detail,
                remediation=(
                    "Enable DKIM signing at your sending platform and publish the public key."
                ),
                reference="Google sender guidelines; RFC 6376",
            )
        )
        return result

    for key in found:
        _audit_key(key, result)
    return result


def _audit_key(key: DkimKey, result: CheckResult) -> None:
    for message in key.errors:
        result.add(
            Finding(
                code="DKIM_RECORD_ERROR",
                title=f"DKIM record problem at '{key.selector}'",
                severity=Severity.CRITICAL,
                detail=message,
                remediation="Republish the key exactly as your provider generated it.",
                reference="RFC 6376 §3.6.1",
            )
        )

    if key.revoked:
        result.add(
            Finding(
                code="DKIM_KEY_REVOKED",
                title=f"DKIM key '{key.selector}' is revoked",
                severity=Severity.BLOCKER,
                detail=(
                    "An empty 'p=' tag means the key is revoked. Signatures made with this "
                    "selector fail verification."
                ),
                remediation="Publish the current public key, or stop signing with this selector.",
                reference="RFC 6376 §3.6.1",
            )
        )
        return

    if key.testing:
        result.add(
            Finding(
                code="DKIM_TESTING_MODE",
                title=f"DKIM selector '{key.selector}' is in testing mode",
                severity=Severity.WARNING,
                detail=(
                    "The 't=y' flag tells receivers to treat verification failures as if the "
                    "message were unsigned, which disables the protection DKIM provides."
                ),
                remediation="Remove 't=y' once signing is confirmed working.",
                reference="RFC 6376 §3.6.1",
            )
        )

    key_type = key.key_type
    if key_type == "rsa":
        bits = rsa_key_bits(key.public_key)
        if bits is None:
            result.add(
                Finding(
                    code="DKIM_KEY_UNREADABLE",
                    title=f"DKIM key '{key.selector}' could not be decoded",
                    severity=Severity.CRITICAL,
                    detail=(
                        "The 'p=' value is not decodable base64 DER. This usually means the "
                        "record was split or truncated when it was published."
                    ),
                    remediation=(
                        "Re-publish the key; long keys must be split into quoted "
                        "character-strings, not broken across separate TXT records."
                    ),
                    reference="RFC 6376 §3.6.1",
                )
            )
        else:
            result.data.setdefault("key_bits", {})[key.selector] = bits
            if bits < _MIN_RSA_BITS_HARD:
                result.add(
                    Finding(
                        code="DKIM_KEY_TOO_SHORT",
                        title=f"DKIM key '{key.selector}' is {bits}-bit RSA",
                        severity=Severity.BLOCKER,
                        detail=(
                            f"Keys below {_MIN_RSA_BITS_HARD} bits are considered forgeable and "
                            "are rejected or ignored by major receivers."
                        ),
                        remediation="Rotate to a 2048-bit key.",
                        reference="RFC 8301 §3.2",
                    )
                )
            elif bits < _RECOMMENDED_RSA_BITS:
                result.add(
                    Finding(
                        code="DKIM_KEY_WEAK",
                        title=f"DKIM key '{key.selector}' is {bits}-bit RSA",
                        severity=Severity.WARNING,
                        detail=f"{_RECOMMENDED_RSA_BITS}-bit keys are the current baseline.",
                        remediation="Rotate to a 2048-bit key at the next opportunity.",
                        reference="RFC 8301 §3.2",
                    )
                )
    elif key_type == "ed25519":
        result.add(
            Finding(
                code="DKIM_ED25519",
                title=f"DKIM selector '{key.selector}' uses Ed25519",
                severity=Severity.INFO,
                detail=(
                    "Ed25519 is strong but not universally verified yet; publish an RSA "
                    "selector alongside it so older receivers can still validate."
                ),
                remediation="Dual-sign with RSA-SHA256 and Ed25519.",
                reference="RFC 8463 §3",
            )
        )
    else:
        result.add(
            Finding(
                code="DKIM_KEY_TYPE_UNKNOWN",
                title=f"DKIM selector '{key.selector}' declares key type '{key_type}'",
                severity=Severity.CRITICAL,
                detail="Only 'rsa' and 'ed25519' are defined; receivers ignore anything else.",
                remediation="Republish with a supported key type.",
                reference="RFC 6376 §3.6.1",
            )
        )

    hashes = {h.strip().lower() for h in key.tags.get("h", "").split(":") if h.strip()}
    if hashes and hashes <= {"sha1"}:
        result.add(
            Finding(
                code="DKIM_SHA1_ONLY",
                title=f"DKIM selector '{key.selector}' permits only SHA-1",
                severity=Severity.CRITICAL,
                detail="RFC 8301 forbids SHA-1 in DKIM; signatures will not be trusted.",
                remediation="Set 'h=sha256' and sign with RSA-SHA256.",
                reference="RFC 8301 §3.1",
            )
        )
