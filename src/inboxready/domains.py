"""Organizational-domain resolution and DMARC identifier alignment.

DMARC (RFC 7489 section 3.2) is defined in terms of the *Organizational
Domain*: the registrable domain one label below a public suffix. Getting this
right is what decides whether ``mail.shop.example.co.uk`` is allowed to inherit
the DMARC policy of ``example.co.uk``.

A complete implementation needs Mozilla's Public Suffix List, which is a
~15,000 line file that changes weekly. Rather than vendor a stale copy,
InboxReady ships a curated table of the multi-label suffixes that actually
appear in bulk email, and lets callers supply the real list when they have it::

    resolver = PublicSuffixList.from_file("public_suffix_list.dat")

Single-label TLDs (``.com``, ``.io``, ``.app`` ...) need no table at all, so
the built-in behaviour is correct for the overwhelming majority of senders and
degrades gracefully — never silently — for the rest.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["PublicSuffixList", "AlignmentResult", "check_alignment", "DEFAULT_MULTI_LABEL_SUFFIXES"]


#: Multi-label public suffixes common in email. Anything not listed here is
#: treated as a single-label TLD, which is the correct default for gTLDs.
DEFAULT_MULTI_LABEL_SUFFIXES: frozenset[str] = frozenset(
    {
        # United Kingdom
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
        "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
        # Australia / New Zealand
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
        "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
        # Asia
        "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp", "co.in", "net.in",
        "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in",
        "res.in", "nic.in", "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.hk", "org.hk", "edu.hk", "gov.hk", "co.kr", "or.kr", "ne.kr",
        "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg", "com.my", "com.ph",
        "co.th", "in.th", "co.id", "com.tw", "org.tw", "edu.tw", "gov.tw",
        # Americas
        "com.br", "net.br", "org.br", "gov.br", "edu.br", "com.mx",
        "com.ar", "com.co", "com.pe", "com.ve", "com.uy", "gc.ca", "on.ca",
        "qc.ca", "bc.ca", "ab.ca",
        # Europe
        "co.at", "or.at", "ac.at", "gv.at", "com.es", "org.es", "edu.es",
        "gob.es", "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl",
        "com.pt", "edu.pt", "gov.pt", "com.tr", "net.tr", "org.tr", "gov.tr",
        "edu.tr", "com.ua", "com.ru", "org.ru", "net.ru", "co.il", "org.il",
        "ac.il", "gov.il", "com.gr", "edu.gr", "gov.gr", "co.hu", "com.ro",
        "com.hr", "com.cy", "com.mt",
        # Africa
        "co.za", "org.za", "net.za", "gov.za", "ac.za", "web.za",
        "com.ng", "com.eg", "com.gh", "co.ke", "or.ke", "go.ke",
        # Misc widely used
        "com.tn", "com.sa", "com.kw", "com.qa", "com.bh", "com.om",
        "co.ae", "net.ae", "org.ae", "gov.ae", "ac.ae",
    }
)


class PublicSuffixList:
    """Maps a hostname to its organizational (registrable) domain."""

    def __init__(self, suffixes: frozenset[str] | set[str] | None = None) -> None:
        self._suffixes = frozenset(
            s.strip().lower().lstrip(".")
            for s in (suffixes if suffixes is not None else DEFAULT_MULTI_LABEL_SUFFIXES)
            if s.strip()
        )
        #: True when the caller supplied a real Public Suffix List.
        self.authoritative = suffixes is not None

    @classmethod
    def from_file(cls, path: str | Path) -> "PublicSuffixList":
        """Load Mozilla's ``public_suffix_list.dat`` format.

        Comment lines (``//``) and blanks are skipped. Wildcard (``*.``) and
        exception (``!``) rules are normalized to their literal suffix, which
        is a close enough approximation for policy auditing.
        """

        suffixes: set[str] = set()
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("//"):
                continue
            suffixes.add(line.lstrip("!*.").lower())
        if not suffixes:
            raise ValueError(f"no public suffix rules found in {path}")
        return cls(suffixes)

    def public_suffix(self, hostname: str) -> str:
        """Return the public suffix portion of ``hostname``."""

        labels = _labels(hostname)
        if not labels:
            return ""
        # Prefer the longest matching multi-label suffix, then fall back to the
        # rightmost single label (the TLD).
        for start in range(len(labels) - 1):
            candidate = ".".join(labels[start:])
            if candidate in self._suffixes:
                return candidate
        return labels[-1]

    def organizational_domain(self, hostname: str) -> str:
        """Return the registrable domain, i.e. public suffix plus one label."""

        labels = _labels(hostname)
        if not labels:
            return ""
        suffix_labels = _labels(self.public_suffix(hostname))
        if len(labels) <= len(suffix_labels):
            # The hostname *is* a public suffix; nothing more to strip.
            return ".".join(labels)
        return ".".join(labels[-(len(suffix_labels) + 1) :])

    def is_subdomain_of(self, hostname: str, parent: str) -> bool:
        host = ".".join(_labels(hostname))
        base = ".".join(_labels(parent))
        return host == base or host.endswith("." + base)


def _labels(hostname: str) -> list[str]:
    return [label for label in hostname.strip().strip(".").lower().split(".") if label]


class AlignmentResult:
    """The outcome of a DMARC identifier-alignment comparison."""

    __slots__ = ("from_domain", "candidate", "mode", "aligned", "reason")

    def __init__(
        self,
        from_domain: str,
        candidate: str,
        mode: str,
        aligned: bool,
        reason: str,
    ) -> None:
        self.from_domain = from_domain
        self.candidate = candidate
        self.mode = mode
        self.aligned = aligned
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"AlignmentResult(from_domain={self.from_domain!r}, "
            f"candidate={self.candidate!r}, mode={self.mode!r}, aligned={self.aligned})"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "from_domain": self.from_domain,
            "candidate": self.candidate,
            "mode": self.mode,
            "aligned": self.aligned,
            "reason": self.reason,
        }


def check_alignment(
    from_domain: str,
    candidate: str,
    mode: str = "r",
    psl: PublicSuffixList | None = None,
) -> AlignmentResult:
    """Compare a DKIM ``d=`` or SPF ``MAIL FROM`` domain against ``From:``.

    ``mode`` is ``"s"`` for strict (exact match required) or ``"r"`` for
    relaxed (matching organizational domains suffice), per RFC 7489 3.1.
    """

    mode = (mode or "r").strip().lower()
    if mode not in {"r", "s"}:
        raise ValueError(f"alignment mode must be 'r' or 's', got {mode!r}")
    psl = psl or PublicSuffixList()

    left = ".".join(_labels(from_domain))
    right = ".".join(_labels(candidate))
    if not left or not right:
        return AlignmentResult(left, right, mode, False, "missing domain to compare")

    if left == right:
        return AlignmentResult(left, right, mode, True, "exact match")
    if mode == "s":
        return AlignmentResult(
            left, right, mode, False, "strict alignment requires an exact domain match"
        )

    left_org = psl.organizational_domain(left)
    right_org = psl.organizational_domain(right)
    if left_org and left_org == right_org:
        return AlignmentResult(
            left, right, mode, True, f"shared organizational domain {left_org}"
        )
    return AlignmentResult(
        left,
        right,
        mode,
        False,
        f"organizational domains differ ({left_org or '?'} vs {right_org or '?'})",
    )
